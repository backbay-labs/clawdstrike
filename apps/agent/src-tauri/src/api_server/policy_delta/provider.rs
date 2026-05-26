use super::*;

pub(crate) fn macos_provider_enforcement_applicable() -> bool {
    cfg!(target_os = "macos")
}

pub(crate) fn effective_macos_provider_ack_timeout_ms(timeout_ms: u64) -> u64 {
    if macos_provider_enforcement_applicable() {
        timeout_ms
    } else {
        0
    }
}

pub(crate) async fn refresh_macos_provider_status(
    state: &Arc<AgentApiState>,
    timeout_ms: u64,
) -> EdrProviderStatusRefreshResult {
    let timeout_ms = effective_macos_provider_ack_timeout_ms(timeout_ms);
    if timeout_ms == 0 {
        return EdrProviderStatusRefreshResult {
            requested: false,
            refreshed: false,
            timeout_ms,
            elapsed_ms: 0,
            error: None,
        };
    }

    let started = Instant::now();
    match state
        .macos_host
        .request_refresh(Duration::from_millis(timeout_ms))
        .await
    {
        Ok(_) => EdrProviderStatusRefreshResult {
            requested: true,
            refreshed: true,
            timeout_ms,
            elapsed_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            error: None,
        },
        Err(err) => EdrProviderStatusRefreshResult {
            requested: true,
            refreshed: false,
            timeout_ms,
            elapsed_ms: started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            error: Some(err.to_string()),
        },
    }
}

fn provider_policy_acknowledgements_for_policy(
    status: &CombinedSystemExtensionStatus,
    policy: &EndpointPolicySnapshot,
) -> Vec<EdrProviderPolicyAcknowledgement> {
    vec![
        provider_policy_acknowledgement(
            "macos.endpoint_security",
            EndpointProviderKind::EndpointSecurity,
            &status.endpoint_security,
            policy,
            false,
            false,
        ),
        provider_policy_acknowledgement(
            "macos.network_extension",
            EndpointProviderKind::NetworkExtension,
            &status.network_extension,
            policy,
            true,
            true,
        ),
    ]
}

pub(crate) async fn wait_for_provider_policy_acknowledgements(
    state: &Arc<AgentApiState>,
    policy: &EndpointPolicySnapshot,
    timeout_ms: u64,
) -> (
    CombinedSystemExtensionStatus,
    Vec<EdrProviderPolicyAcknowledgement>,
    EdrProviderAcknowledgementPoll,
) {
    if !macos_provider_enforcement_applicable() {
        return (
            CombinedSystemExtensionStatus::default(),
            Vec::new(),
            EdrProviderAcknowledgementPoll {
                requested: false,
                timeout_ms: 0,
                elapsed_ms: 0,
                attempts: 0,
                satisfied: true,
            },
        );
    }

    let started = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let mut attempts = 0u64;

    loop {
        attempts = attempts.saturating_add(1);
        let status = state.macos_host.snapshot().await;
        let acknowledgements = provider_policy_acknowledgements_for_policy(&status, policy);
        let satisfied = acknowledgements.iter().all(|ack| ack.acknowledged);
        let elapsed = started.elapsed();

        if satisfied || timeout_ms == 0 || elapsed >= timeout {
            return (
                status,
                acknowledgements,
                EdrProviderAcknowledgementPoll {
                    requested: timeout_ms > 0,
                    timeout_ms,
                    elapsed_ms: elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
                    attempts,
                    satisfied,
                },
            );
        }

        let remaining = timeout.saturating_sub(elapsed);
        tokio::time::sleep(remaining.min(EDR_PROVIDER_ACK_POLL_INTERVAL)).await;
    }
}

fn provider_policy_acknowledgement(
    provider_id: &str,
    provider_kind: EndpointProviderKind,
    provider: &ProviderStatus,
    policy: &EndpointPolicySnapshot,
    require_policy_synced: bool,
    require_enforcement_ready: bool,
) -> EdrProviderPolicyAcknowledgement {
    let active = provider_policy_ack_active(provider);
    let policy_epoch_matches = provider
        .policy_epoch
        .map(|observed| observed == policy.policy_epoch);
    let mut reasons = Vec::new();

    if !active {
        reasons.push("provider_not_active".to_string());
    }
    match &provider.runtime {
        ProviderRuntimeState::Degraded { reason } => {
            if reason.trim().is_empty() {
                reasons.push("provider_degraded".to_string());
            } else {
                reasons.push(format!(
                    "provider_degraded:{}",
                    sanitize_provider_status_reason(reason)
                ));
            }
        }
        ProviderRuntimeState::Unknown => reasons.push("provider_runtime_unknown".to_string()),
        ProviderRuntimeState::Inactive => reasons.push("provider_runtime_inactive".to_string()),
        ProviderRuntimeState::Active => {}
    }
    match policy_epoch_matches {
        Some(true) => {}
        Some(false) => reasons.push("policy_epoch_mismatch".to_string()),
        None => reasons.push("policy_epoch_unreported".to_string()),
    }
    if provider.policy_synced == Some(false) {
        reasons.push("policy_not_synced".to_string());
    } else if require_policy_synced && provider.policy_synced != Some(true) {
        reasons.push("policy_sync_unreported".to_string());
    }
    if provider.enforcement_ready == Some(false) {
        reasons.push("enforcement_not_ready".to_string());
    } else if require_enforcement_ready && provider.enforcement_ready != Some(true) {
        reasons.push("enforcement_readiness_unreported".to_string());
    }
    if let Some(last_error) = provider
        .last_error
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        reasons.push(format!(
            "provider_last_error:{}",
            sanitize_provider_status_reason(last_error)
        ));
    }
    append_provider_attestation_not_ready_reasons(provider, &mut reasons);

    reasons.sort();
    reasons.dedup();

    EdrProviderPolicyAcknowledgement {
        provider_id: provider_id.to_string(),
        provider_kind,
        active,
        observed_policy_epoch: provider.policy_epoch,
        expected_policy_epoch: policy.policy_epoch,
        policy_epoch_matches,
        policy_synced: provider.policy_synced,
        enforcement_ready: provider.enforcement_ready,
        acknowledged: reasons.is_empty(),
        reasons,
    }
}

fn provider_policy_ack_active(provider: &ProviderStatus) -> bool {
    matches!(provider.runtime, ProviderRuntimeState::Active)
        || provider
            .provider_state
            .as_ref()
            .map(|state| state.active)
            .unwrap_or(false)
}

fn append_provider_attestation_not_ready_reasons(
    provider: &ProviderStatus,
    reasons: &mut Vec<String>,
) {
    let Some(provider_state) = provider.provider_state.as_ref() else {
        return;
    };
    if !provider_state.active {
        reasons.push("provider_state_inactive".to_string());
    }
    if !provider_state.healthy {
        reasons.push("provider_state_unhealthy".to_string());
    }
    match provider_state.availability {
        ProviderAvailability::Unavailable => {
            reasons.push("provider_state_unavailable".to_string());
        }
        ProviderAvailability::Inactive => reasons.push("provider_state_inactive".to_string()),
        ProviderAvailability::Active => {}
        ProviderAvailability::Degraded => reasons.push("provider_state_degraded".to_string()),
    }
    reasons.extend(
        provider_state
            .degraded_reasons
            .iter()
            .map(|reason| reason.trim())
            .filter(|reason| !reason.is_empty())
            .map(|reason| {
                format!(
                    "provider_state_degraded:{}",
                    sanitize_provider_status_reason(reason)
                )
            }),
    );
}

pub(crate) fn network_extension_response_not_ready_reasons(
    provider: &ProviderStatus,
) -> Vec<String> {
    let mut reasons = Vec::new();

    if !provider_policy_ack_active(provider) {
        reasons.push("provider_not_active".to_string());
    }
    match &provider.runtime {
        ProviderRuntimeState::Degraded { reason } => {
            if reason.trim().is_empty() {
                reasons.push("provider_degraded".to_string());
            } else {
                reasons.push(format!(
                    "provider_degraded:{}",
                    sanitize_provider_status_reason(reason)
                ));
            }
        }
        ProviderRuntimeState::Unknown => reasons.push("provider_runtime_unknown".to_string()),
        ProviderRuntimeState::Inactive => reasons.push("provider_runtime_inactive".to_string()),
        ProviderRuntimeState::Active => {}
    }
    if provider.policy_synced == Some(false) {
        reasons.push("policy_not_synced".to_string());
    } else if provider.policy_synced != Some(true) {
        reasons.push("policy_sync_unreported".to_string());
    }
    if provider.enforcement_ready == Some(false) {
        reasons.push("enforcement_not_ready".to_string());
    } else if provider.enforcement_ready != Some(true) {
        reasons.push("enforcement_readiness_unreported".to_string());
    }
    if let Some(last_error) = provider
        .last_error
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        reasons.push(format!(
            "provider_last_error:{}",
            sanitize_provider_status_reason(last_error)
        ));
    }
    append_provider_attestation_not_ready_reasons(provider, &mut reasons);

    reasons.sort();
    reasons.dedup();
    reasons
}

pub(crate) fn network_extension_egress_policy_proof_enforcement_ready(
    snapshot_decodable: bool,
    provider: &ProviderStatus,
) -> bool {
    snapshot_decodable && network_extension_response_not_ready_reasons(provider).is_empty()
}

pub(crate) async fn ensure_network_extension_ready_for_restrict_egress(
    state: &AgentApiState,
) -> Result<(), (StatusCode, String)> {
    let status = state.macos_host.snapshot().await;
    let reasons = network_extension_response_not_ready_reasons(&status.network_extension);
    if reasons.is_empty() {
        return Ok(());
    }
    Err((
        StatusCode::CONFLICT,
        format!(
            "network extension provider is not ready for restrict_egress: {}",
            reasons.join(", ")
        ),
    ))
}
