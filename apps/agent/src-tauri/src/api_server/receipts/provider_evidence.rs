//! Sensor-state and provider-evidence builders.
//!
//! Convert macOS host status snapshots into the `EndpointSensorState`
//! that endpoint receipts embed, derive provider degradation reasons,
//! detect provider recoveries between snapshots, and provide small
//! optional-value evidence-string formatters.

use super::super::*;

pub(crate) fn endpoint_sensor_state_from_macos_host(
    status: &CombinedSystemExtensionStatus,
) -> EndpointSensorState {
    EndpointSensorState {
        providers: vec![
            EndpointProviderState {
                provider_id: "agent-api".to_string(),
                provider_kind: EndpointProviderKind::AgentApi,
                installed: true,
                active: true,
                healthy: true,
                degraded: false,
                degradation_reasons: Vec::new(),
                dropped_event_count: 0,
                deadline_miss_count: 0,
                full_disk_access: None,
                last_seen: Some(chrono::Utc::now()),
            },
            endpoint_provider_state_from_macos_provider(
                "macos.endpoint_security",
                EndpointProviderKind::EndpointSecurity,
                status,
                &status.endpoint_security,
            ),
            endpoint_provider_state_from_macos_provider(
                "macos.network_extension",
                EndpointProviderKind::NetworkExtension,
                status,
                &status.network_extension,
            ),
        ],
    }
}

pub(crate) fn endpoint_provider_recoveries(
    previous_status: Option<&CombinedSystemExtensionStatus>,
    current_sensor_state: &EndpointSensorState,
) -> Vec<EdrProviderRecovery> {
    let Some(previous_status) = previous_status else {
        return Vec::new();
    };
    let previous_sensor_state = endpoint_sensor_state_from_macos_host(previous_status);
    let previous_providers = previous_sensor_state
        .providers
        .into_iter()
        .map(|provider| (provider.provider_id.clone(), provider))
        .collect::<BTreeMap<_, _>>();
    let mut recoveries = current_sensor_state
        .providers
        .iter()
        .filter_map(|current| {
            let previous = previous_providers.get(&current.provider_id)?;
            if !previous.installed
                || !previous.degraded
                || current.degraded
                || !current.healthy
                || !current.active
            {
                return None;
            }
            Some(EdrProviderRecovery {
                provider_id: current.provider_id.clone(),
                provider_kind: current.provider_kind.clone(),
                previous_active: previous.active,
                previous_healthy: previous.healthy,
                previous_degraded: previous.degraded,
                previous_degradation_reasons: previous.degradation_reasons.clone(),
                current_active: current.active,
                current_healthy: current.healthy,
                current_degraded: current.degraded,
                recovered_at: current.last_seen,
            })
        })
        .collect::<Vec<_>>();
    recoveries.sort_by(|left, right| left.provider_id.cmp(&right.provider_id));
    recoveries
}

pub(crate) fn provider_recovery_receipt_evidence(
    recoveries: &[EdrProviderRecovery],
) -> Vec<EndpointReceiptEvidence> {
    if recoveries.is_empty() {
        return Vec::new();
    }
    let recovered_ids = recoveries
        .iter()
        .map(|recovery| recovery.provider_id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    vec![
        EndpointReceiptEvidence::hashed("providerRecoveryCount", recoveries.len().to_string()),
        EndpointReceiptEvidence::hashed("providerRecoveredIds", recovered_ids),
    ]
}

pub(crate) fn provider_runtime_evidence_value(runtime: &ProviderRuntimeState) -> String {
    match runtime {
        ProviderRuntimeState::Unknown => "unknown".to_string(),
        ProviderRuntimeState::Inactive => "inactive".to_string(),
        ProviderRuntimeState::Active => "active".to_string(),
        ProviderRuntimeState::Degraded { reason } => {
            format!("degraded:{}", sanitize_provider_status_reason(reason))
        }
    }
}

pub(crate) fn optional_bool_evidence_value(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
}

pub(crate) fn optional_u64_evidence_value(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub(crate) fn endpoint_provider_state_from_macos_provider(
    provider_id: &str,
    provider_kind: EndpointProviderKind,
    host_status: &CombinedSystemExtensionStatus,
    provider: &ProviderStatus,
) -> EndpointProviderState {
    let installed = host_status.install_state == SystemExtensionInstallState::Installed
        || provider
            .provider_state
            .as_ref()
            .map(|state| state.installed)
            .unwrap_or(false);
    let active = matches!(provider.runtime, ProviderRuntimeState::Active)
        || provider
            .provider_state
            .as_ref()
            .map(|state| state.active)
            .unwrap_or(false);
    let dropped_event_count = provider_counter(
        provider,
        &["dropped_event_count", "dropped_events", "dropped"],
    );
    let deadline_miss_count =
        provider_counter(provider, &["deadline_miss_count", "deadline_misses"]);
    let full_disk_access = provider_full_disk_access(&provider_kind, provider);
    let provider_attestation_degraded = provider.provider_state.as_ref().is_some_and(|state| {
        !state.installed
            || !state.active
            || !state.healthy
            || matches!(
                state.availability,
                ProviderAvailability::Unavailable
                    | ProviderAvailability::Inactive
                    | ProviderAvailability::Degraded
            )
            || !state.degraded_reasons.is_empty()
    });
    let degraded = matches!(
        provider.runtime,
        ProviderRuntimeState::Unknown
            | ProviderRuntimeState::Inactive
            | ProviderRuntimeState::Degraded { .. }
    ) || !installed
        || !active
        || host_status.approval == SystemExtensionApproval::ApprovalBlocked
        || provider_attestation_degraded
        || dropped_event_count > 0
        || deadline_miss_count > 0
        || full_disk_access == Some(false)
        || provider.policy_synced == Some(false)
        || provider.enforcement_ready == Some(false)
        || provider.last_error.is_some();
    let mut degradation_reasons = macos_provider_degradation_reasons(
        host_status,
        provider,
        dropped_event_count,
        deadline_miss_count,
        full_disk_access,
    );
    if degraded && degradation_reasons.is_empty() {
        degradation_reasons.push("provider degraded without a specific reason".to_string());
    }
    let healthy = active && !degraded;

    EndpointProviderState {
        provider_id: provider_id.to_string(),
        provider_kind,
        installed,
        active,
        healthy,
        degraded,
        degradation_reasons,
        dropped_event_count,
        deadline_miss_count,
        full_disk_access,
        last_seen: provider_last_seen(provider).or_else(|| active.then(chrono::Utc::now)),
    }
}

pub(crate) fn macos_provider_degradation_reasons(
    host_status: &CombinedSystemExtensionStatus,
    provider: &ProviderStatus,
    dropped_event_count: u64,
    deadline_miss_count: u64,
    full_disk_access: Option<bool>,
) -> Vec<String> {
    let mut reasons = Vec::new();
    match provider.runtime.clone() {
        ProviderRuntimeState::Degraded { reason } if !reason.trim().is_empty() => {
            reasons.push(sanitize_provider_status_reason(&reason));
        }
        ProviderRuntimeState::Unknown => reasons.push("provider runtime unknown".to_string()),
        ProviderRuntimeState::Inactive => reasons.push("provider runtime inactive".to_string()),
        _ => {}
    }
    if host_status.install_state == SystemExtensionInstallState::NotInstalled {
        reasons.push("system extension not installed".to_string());
    }
    if host_status.approval == SystemExtensionApproval::ApprovalBlocked {
        reasons.push("system extension approval blocked".to_string());
    }
    if let Some(last_error) = provider
        .last_error
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        reasons.push(sanitize_provider_status_reason(last_error));
    }
    if provider.policy_synced == Some(false) {
        reasons.push("provider policy not synced".to_string());
    }
    if provider.enforcement_ready == Some(false) {
        reasons.push("provider enforcement not ready".to_string());
    }
    if let Some(provider_state) = &provider.provider_state {
        if !provider_state.installed {
            reasons.push("provider attestation reports not installed".to_string());
        }
        if !provider_state.active {
            reasons.push("provider attestation reports inactive".to_string());
        }
        if !provider_state.healthy {
            reasons.push("provider attestation reports unhealthy".to_string());
        }
        match provider_state.availability {
            ProviderAvailability::Unavailable => {
                reasons.push("provider attestation reports unavailable".to_string());
            }
            ProviderAvailability::Inactive => {
                reasons.push("provider attestation reports inactive".to_string());
            }
            ProviderAvailability::Active => {}
            ProviderAvailability::Degraded => {
                reasons.push("provider attestation reports degraded".to_string());
            }
        }
        reasons.extend(
            provider_state
                .degraded_reasons
                .iter()
                .map(|reason| sanitize_provider_status_reason(reason)),
        );
    }
    if dropped_event_count > 0 {
        reasons.push("provider dropped enforcement events".to_string());
    }
    if deadline_miss_count > 0 {
        reasons.push("provider authorization deadline misses".to_string());
    }
    if full_disk_access == Some(false) {
        reasons.push("missing_full_disk_access".to_string());
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

pub(crate) fn provider_full_disk_access(
    provider_kind: &EndpointProviderKind,
    provider: &ProviderStatus,
) -> Option<bool> {
    if provider_kind != &EndpointProviderKind::EndpointSecurity {
        return None;
    }
    if provider_reports_missing_full_disk_access(provider) {
        Some(false)
    } else {
        None
    }
}

pub(crate) fn provider_reports_missing_full_disk_access(provider: &ProviderStatus) -> bool {
    matches!(
        &provider.runtime,
        ProviderRuntimeState::Degraded { reason } if is_missing_full_disk_access_signal(reason)
    ) || provider.provider_state.as_ref().is_some_and(|state| {
        state
            .degraded_reasons
            .iter()
            .any(|reason| is_missing_full_disk_access_signal(reason))
    }) || provider
        .evidence_paths
        .iter()
        .any(|artifact| is_missing_full_disk_access_signal(&artifact.kind))
}

pub(crate) fn is_missing_full_disk_access_signal(value: &str) -> bool {
    let normalized = value
        .trim()
        .chars()
        .map(|ch| match ch {
            ' ' | '-' => '_',
            _ => ch.to_ascii_lowercase(),
        })
        .collect::<String>();
    normalized == "missing_full_disk_access"
}

pub(crate) fn provider_counter(provider: &ProviderStatus, keys: &[&str]) -> u64 {
    keys.iter()
        .find_map(|key| provider.counters.get(*key).copied())
        .unwrap_or(0)
}

pub(crate) fn provider_last_seen(
    provider: &ProviderStatus,
) -> Option<chrono::DateTime<chrono::Utc>> {
    provider
        .last_healthy_timestamp
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| value.with_timezone(&chrono::Utc))
}
