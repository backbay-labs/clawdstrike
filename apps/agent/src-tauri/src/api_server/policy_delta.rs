use super::*;

pub(crate) struct PolicyDeltaApplyEnforcementProofInput<'a> {
    pub(crate) settings: &'a Settings,
    pub(crate) local_policy: EndpointPolicySnapshot,
    pub(crate) policy_delta_artifact: Option<&'a EdrPolicyDeltaArtifact>,
    pub(crate) cross_window_impact_hash: Option<&'a str>,
    pub(crate) cross_window_recommendation_hash: Option<&'a str>,
    pub(crate) daemon_policy_reload_requested: bool,
    pub(crate) daemon_restart_requested: bool,
    pub(crate) provider_ack_timeout_ms: u64,
}

pub(crate) async fn build_policy_delta_apply_enforcement_proof(
    state: &Arc<AgentApiState>,
    input: PolicyDeltaApplyEnforcementProofInput<'_>,
) -> Result<EdrPolicyDeltaApplyEnforcementProof> {
    let PolicyDeltaApplyEnforcementProofInput {
        settings,
        local_policy,
        policy_delta_artifact,
        cross_window_impact_hash,
        cross_window_recommendation_hash,
        daemon_policy_reload_requested,
        daemon_restart_requested,
        provider_ack_timeout_ms,
    } = input;
    let provider_ack_timeout_ms = effective_macos_provider_ack_timeout_ms(provider_ack_timeout_ms);
    let mut daemon_restarted = false;
    let mut daemon_restart_error = None;
    if daemon_restart_requested {
        match state.daemon_manager.restart().await {
            Ok(()) => {
                daemon_restarted = true;
            }
            Err(err) => {
                daemon_restart_error = Some(err.to_string());
            }
        }
    }

    let daemon_policy_reload =
        request_daemon_policy_reload(state.as_ref(), settings, daemon_policy_reload_requested)
            .await;
    let network_extension_policy_reload = request_policy_delta_network_extension_reload(
        state.as_ref(),
        settings,
        &local_policy,
        policy_delta_artifact,
        provider_ack_timeout_ms,
    )
    .await?;
    let daemon = state.daemon_manager.status().await;
    let daemon_policy_version = tokio::time::timeout(
        POLICY_VERSION_FETCH_TIMEOUT,
        fetch_daemon_policy_version(state.as_ref()),
    )
    .await
    .ok()
    .flatten();
    let provider_status_refresh =
        refresh_macos_provider_status(state, provider_ack_timeout_ms).await;
    let (macos_host, provider_policy_acknowledgements, provider_acknowledgement_poll) =
        wait_for_provider_policy_acknowledgements(state, &local_policy, provider_ack_timeout_ms)
            .await;
    let sensor_state = endpoint_sensor_state_from_macos_host(&macos_host);
    let receipt_evidence =
        policy_delta_apply_enforcement_receipt_evidence(PolicyDeltaApplyEnforcementEvidenceInput {
            local_policy: &local_policy,
            daemon_policy_reload: &daemon_policy_reload,
            network_extension_policy_reload: &network_extension_policy_reload,
            provider_status_refresh: &provider_status_refresh,
            provider_acknowledgement_poll: &provider_acknowledgement_poll,
            provider_policy_acknowledgements: &provider_policy_acknowledgements,
            daemon_restart_requested,
            daemon_restarted,
            daemon_restart_error: daemon_restart_error.as_deref(),
            daemon_policy_version: daemon_policy_version.as_deref(),
            cross_window_impact_hash,
            cross_window_recommendation_hash,
        });
    let receipt = emit_edr_sensor_state_receipt_with_evidence(
        state.as_ref(),
        local_policy.clone(),
        sensor_state.clone(),
        "post policy delta apply protection state",
        &receipt_evidence,
    )
    .await?;
    let degraded_provider_receipts = if macos_provider_enforcement_applicable() {
        emit_edr_provider_degradation_receipts(
            state.as_ref(),
            local_policy.clone(),
            sensor_state.clone(),
        )
        .await?
    } else {
        Vec::new()
    };

    Ok(EdrPolicyDeltaApplyEnforcementProof {
        policy_synced_to_disk: true,
        cross_window_impact_hash: cross_window_impact_hash.map(str::to_string),
        cross_window_recommendation_hash: cross_window_recommendation_hash.map(str::to_string),
        local_policy,
        daemon_policy_reload,
        network_extension_policy_reload,
        provider_status_refresh,
        provider_acknowledgement_poll,
        provider_policy_acknowledgements,
        daemon_restart_requested,
        daemon_restarted,
        daemon_restart_error,
        daemon,
        daemon_policy_version,
        sensor_state,
        receipt,
        degraded_provider_receipts,
    })
}

pub(crate) fn validate_policy_delta_apply_enforcement_for_live_apply(
    proof: &EdrPolicyDeltaApplyEnforcementProof,
) -> Result<(), String> {
    let mut reasons = Vec::new();
    if proof.daemon_policy_reload.requested && !proof.daemon_policy_reload.reloaded {
        let detail = proof
            .daemon_policy_reload
            .error
            .as_deref()
            .or(proof.daemon_policy_reload.message.as_deref())
            .unwrap_or("daemon did not report policy reload success");
        reasons.push(format!("daemon_policy_reload_failed:{detail}"));
    }
    if proof.daemon_restart_requested && !proof.daemon_restarted {
        let detail = proof
            .daemon_restart_error
            .as_deref()
            .unwrap_or("daemon restart did not complete");
        reasons.push(format!("daemon_restart_failed:{detail}"));
    }
    if macos_provider_enforcement_applicable() {
        if !proof.network_extension_policy_reload.requested {
            reasons.push("network_extension_reload_not_requested".to_string());
        }
        if !proof.network_extension_policy_reload.saved {
            reasons.push("network_extension_reload_not_saved".to_string());
        }
        if !proof
            .network_extension_policy_reload
            .provider_reload_matched
        {
            reasons.push("network_extension_reload_not_observed_by_provider".to_string());
        }
        if !proof.provider_acknowledgement_poll.satisfied {
            reasons.push("provider_policy_acknowledgement_timeout".to_string());
        }
        for acknowledgement in &proof.provider_policy_acknowledgements {
            if !acknowledgement.acknowledged {
                let detail = if acknowledgement.reasons.is_empty() {
                    "unacknowledged".to_string()
                } else {
                    acknowledgement.reasons.join("|")
                };
                reasons.push(format!(
                    "provider_policy_not_acknowledged:{}:{detail}",
                    acknowledgement.provider_id
                ));
            }
        }
    }
    reasons.sort();
    reasons.dedup();
    if reasons.is_empty() {
        Ok(())
    } else {
        Err(reasons.join(", "))
    }
}

fn macos_provider_enforcement_applicable() -> bool {
    cfg!(target_os = "macos")
}

fn effective_macos_provider_ack_timeout_ms(timeout_ms: u64) -> u64 {
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

async fn wait_for_provider_policy_acknowledgements(
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

pub(crate) struct PolicyDeltaApplyEnforcementEvidenceInput<'a> {
    local_policy: &'a EndpointPolicySnapshot,
    daemon_policy_reload: &'a EdrDaemonPolicyReloadResult,
    network_extension_policy_reload: &'a NetworkExtensionReloadRequestProof,
    provider_status_refresh: &'a EdrProviderStatusRefreshResult,
    provider_acknowledgement_poll: &'a EdrProviderAcknowledgementPoll,
    provider_policy_acknowledgements: &'a [EdrProviderPolicyAcknowledgement],
    daemon_restart_requested: bool,
    daemon_restarted: bool,
    daemon_restart_error: Option<&'a str>,
    daemon_policy_version: Option<&'a str>,
    cross_window_impact_hash: Option<&'a str>,
    cross_window_recommendation_hash: Option<&'a str>,
}

fn policy_delta_apply_enforcement_receipt_evidence(
    input: PolicyDeltaApplyEnforcementEvidenceInput<'_>,
) -> Vec<EndpointReceiptEvidence> {
    let mut evidence = vec![
        EndpointReceiptEvidence::hashed("policyDeltaApplyPolicySyncedToDisk", "true"),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyLocalPolicyHash",
            &input.local_policy.policy_hash,
        ),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyLocalPolicyEpoch",
            input.local_policy.policy_epoch.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyDaemonReloadRequested",
            input.daemon_policy_reload.requested.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyDaemonReloaded",
            input.daemon_policy_reload.reloaded.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyNetworkExtensionReloadRequested",
            input.network_extension_policy_reload.requested.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyNetworkExtensionReloadSaved",
            input.network_extension_policy_reload.saved.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyNetworkExtensionReloadGeneration",
            input.network_extension_policy_reload.generation.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyNetworkExtensionReloadPolicySnapshotPath",
            input
                .network_extension_policy_reload
                .policy_snapshot_path
                .as_str(),
        ),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyProviderRefreshRequested",
            input.provider_status_refresh.requested.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyProviderRefreshRefreshed",
            input.provider_status_refresh.refreshed.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyProviderRefreshTimeoutMs",
            input.provider_status_refresh.timeout_ms.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyProviderRefreshElapsedMs",
            input.provider_status_refresh.elapsed_ms.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyProviderAckPollRequested",
            input.provider_acknowledgement_poll.requested.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyProviderAckPollSatisfied",
            input.provider_acknowledgement_poll.satisfied.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyProviderAckPollAttempts",
            input.provider_acknowledgement_poll.attempts.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyDaemonRestartRequested",
            input.daemon_restart_requested.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "policyDeltaApplyDaemonRestarted",
            input.daemon_restarted.to_string(),
        ),
    ];
    if let Some(status_code) = input.daemon_policy_reload.status_code {
        evidence.push(EndpointReceiptEvidence::hashed(
            "policyDeltaApplyDaemonReloadStatusCode",
            status_code.to_string(),
        ));
    }
    if let Some(policy_hash) = input.daemon_policy_reload.policy_hash.as_deref() {
        evidence.push(EndpointReceiptEvidence::hashed(
            "policyDeltaApplyDaemonReloadPolicyHash",
            policy_hash,
        ));
    }
    if let Some(message) = input.daemon_policy_reload.message.as_deref() {
        evidence.push(EndpointReceiptEvidence::hashed(
            "policyDeltaApplyDaemonReloadMessage",
            message,
        ));
    }
    if let Some(error) = input.daemon_policy_reload.error.as_deref() {
        evidence.push(EndpointReceiptEvidence::hashed(
            "policyDeltaApplyDaemonReloadError",
            error,
        ));
    }
    if let Some(request_id) = input.network_extension_policy_reload.request_id.as_deref() {
        evidence.push(EndpointReceiptEvidence::hashed(
            "policyDeltaApplyNetworkExtensionReloadRequestId",
            request_id,
        ));
    }
    if let Some(error) = input.network_extension_policy_reload.error.as_deref() {
        evidence.push(EndpointReceiptEvidence::hashed(
            "policyDeltaApplyNetworkExtensionReloadError",
            error,
        ));
    }
    if let Some(error) = input.provider_status_refresh.error.as_deref() {
        evidence.push(EndpointReceiptEvidence::hashed(
            "policyDeltaApplyProviderRefreshError",
            error,
        ));
    }
    if let Some(error) = input.daemon_restart_error {
        evidence.push(EndpointReceiptEvidence::hashed(
            "policyDeltaApplyDaemonRestartError",
            error,
        ));
    }
    if let Some(version) = input.daemon_policy_version {
        evidence.push(EndpointReceiptEvidence::hashed(
            "policyDeltaApplyDaemonPolicyVersion",
            version,
        ));
    }
    if let Some(cross_window_impact_hash) = input.cross_window_impact_hash {
        evidence.push(EndpointReceiptEvidence::hashed(
            "policyDeltaApplyCrossWindowImpactHash",
            cross_window_impact_hash,
        ));
    }
    if let Some(cross_window_recommendation_hash) = input.cross_window_recommendation_hash {
        evidence.push(EndpointReceiptEvidence::hashed(
            "policyDeltaApplyCrossWindowRecommendationHash",
            cross_window_recommendation_hash,
        ));
    }
    for acknowledgement in input.provider_policy_acknowledgements {
        evidence.extend(provider_policy_acknowledgement_receipt_evidence(
            acknowledgement,
        ));
    }
    evidence
}

fn provider_policy_acknowledgement_receipt_evidence(
    acknowledgement: &EdrProviderPolicyAcknowledgement,
) -> Vec<EndpointReceiptEvidence> {
    let prefix = provider_policy_acknowledgement_evidence_prefix(&acknowledgement.provider_id);
    vec![
        EndpointReceiptEvidence::hashed(
            format!("{prefix}.active"),
            acknowledgement.active.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            format!("{prefix}.acknowledged"),
            acknowledgement.acknowledged.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            format!("{prefix}.observedPolicyEpoch"),
            optional_u64_evidence_value(acknowledgement.observed_policy_epoch),
        ),
        EndpointReceiptEvidence::hashed(
            format!("{prefix}.expectedPolicyEpoch"),
            acknowledgement.expected_policy_epoch.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            format!("{prefix}.policyEpochMatches"),
            optional_bool_evidence_value(acknowledgement.policy_epoch_matches),
        ),
        EndpointReceiptEvidence::hashed(
            format!("{prefix}.policySynced"),
            optional_bool_evidence_value(acknowledgement.policy_synced),
        ),
        EndpointReceiptEvidence::hashed(
            format!("{prefix}.enforcementReady"),
            optional_bool_evidence_value(acknowledgement.enforcement_ready),
        ),
        EndpointReceiptEvidence::hashed(
            format!("{prefix}.reasonCount"),
            acknowledgement.reasons.len().to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            format!("{prefix}.reasons"),
            acknowledgement.reasons.join("|"),
        ),
    ]
}

fn provider_policy_acknowledgement_evidence_prefix(provider_id: &str) -> String {
    let normalized = provider_id
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>();
    format!("providerAck.{normalized}")
}

async fn request_daemon_policy_reload(
    state: &AgentApiState,
    settings: &Settings,
    requested: bool,
) -> EdrDaemonPolicyReloadResult {
    if !requested {
        return EdrDaemonPolicyReloadResult {
            requested: false,
            reloaded: false,
            status_code: None,
            policy_hash: None,
            message: None,
            error: None,
        };
    }

    let url = format!(
        "{}/api/v1/policy/reload",
        settings.daemon_url().trim_end_matches('/')
    );
    let mut request = state.http_client.post(url);
    if let Some(api_key) = settings
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request = request.header(AUTHORIZATION.as_str(), format!("Bearer {}", api_key));
    }

    let response = match tokio::time::timeout(POLICY_VERSION_FETCH_TIMEOUT, request.send()).await {
        Ok(Ok(response)) => response,
        Ok(Err(err)) => {
            return EdrDaemonPolicyReloadResult {
                requested: true,
                reloaded: false,
                status_code: None,
                policy_hash: None,
                message: None,
                error: Some(err.to_string()),
            };
        }
        Err(_) => {
            return EdrDaemonPolicyReloadResult {
                requested: true,
                reloaded: false,
                status_code: None,
                policy_hash: None,
                message: None,
                error: Some("daemon policy reload timed out".to_string()),
            };
        }
    };

    let status = response.status();
    let status_code = Some(status.as_u16());
    let body = response.text().await.unwrap_or_default();
    let payload = serde_json::from_str::<Value>(&body).ok();
    let policy_hash = payload
        .as_ref()
        .and_then(|value| value.get("policy_hash"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let message = payload
        .as_ref()
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let success = status.is_success()
        && payload
            .as_ref()
            .and_then(|value| value.get("success"))
            .and_then(Value::as_bool)
            .unwrap_or(true);
    let error = if success {
        None
    } else {
        message
            .clone()
            .or_else(|| (!body.trim().is_empty()).then(|| body.trim().to_string()))
            .or_else(|| Some(format!("daemon policy reload returned HTTP {status}")))
    };

    EdrDaemonPolicyReloadResult {
        requested: true,
        reloaded: success,
        status_code,
        policy_hash,
        message,
        error,
    }
}

pub(crate) fn select_staged_detection_for_policy_delta(
    records: Vec<EdrStagedDetectionRecord>,
    staged_detection_id: Option<&str>,
    rule_id: Option<&str>,
    stage: Option<&str>,
) -> Result<EdrStagedDetectionRecord, (StatusCode, String)> {
    if staged_detection_id.is_none() && rule_id.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "stagedDetectionId or ruleId must be provided".to_string(),
        ));
    }
    records
        .into_iter()
        .rev()
        .find(|record| {
            staged_detection_id.map_or(true, |expected| record.staged_detection_id == expected)
                && rule_id.map_or(true, |expected| record.candidate.rule_id == expected)
                && stage.map_or(true, |expected| record.stage == expected)
        })
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "matching staged detection not found".to_string(),
            )
        })
}

pub(crate) fn staged_detection_stage_entry(
    record: &EdrStagedDetectionRecord,
) -> Result<&EdrDetectionCandidateStage, (StatusCode, String)> {
    record
        .stage_plan
        .iter()
        .find(|candidate| candidate.stage == record.stage)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!(
                    "staged detection {} has unknown stage {}",
                    record.staged_detection_id, record.stage
                ),
            )
        })
}

// build_edr_policy_delta_artifact, build_edr_policy_delta_patch,
// policy_delta_stage_is_enforcing, policy_delta_enforcement_action_supported,
// validate_policy_delta_stage_action, conventional_policy_guard_patch, merge_json_values
// moved to crate::edr::policy_events

pub(crate) fn policy_delta_artifact_hash(artifact: &EdrPolicyDeltaArtifact) -> Result<String> {
    let value = serde_json::to_value(artifact)
        .with_context(|| format!("serialize policy delta {}", artifact.policy_delta_id))?;
    let canonical = canonicalize_json(&value)
        .with_context(|| format!("canonicalize policy delta {}", artifact.policy_delta_id))?;
    Ok(sha256(canonical.as_bytes()).to_hex_prefixed())
}

pub(crate) async fn verify_policy_delta_record_before_apply(
    state: &AgentApiState,
    record: &EdrPolicyDeltaRecord,
) -> Result<(), (StatusCode, String)> {
    if record.policy_delta_id != record.artifact.policy_delta_id {
        return Err((
            StatusCode::CONFLICT,
            "policy delta record id does not match artifact id".to_string(),
        ));
    }
    if record.rule_id != record.artifact.candidate.rule_id {
        return Err((
            StatusCode::CONFLICT,
            "policy delta record rule does not match artifact rule".to_string(),
        ));
    }
    if record.stage != record.artifact.rollout.stage
        || record.action != record.artifact.rollout.action
    {
        return Err((
            StatusCode::CONFLICT,
            "policy delta record rollout does not match artifact rollout".to_string(),
        ));
    }
    let computed_artifact_hash =
        policy_delta_artifact_hash(&record.artifact).map_err(internal_error)?;
    if computed_artifact_hash != record.artifact_hash {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "policy delta artifact hash mismatch: expected {}, computed {}",
                record.artifact_hash, computed_artifact_hash
            ),
        ));
    }
    validate_policy_delta_artifact_materializes_required_guard(&record.artifact)?;

    let signer_public_key = {
        let ledger = state.edr_receipt_ledger.lock().await;
        ledger.signer_public_key.clone()
    };
    verify_endpoint_receipt_signature(
        &record.receipt,
        "policy delta generated receipt",
        signer_public_key.as_str(),
    )
    .map_err(|reason| {
        (
            StatusCode::CONFLICT,
            format!("policy delta generated receipt failed verification: {reason}"),
        )
    })?;

    if receipt_family(&record.receipt) != Some("policy_delta") {
        return Err((
            StatusCode::CONFLICT,
            "policy delta generated receipt has wrong family".to_string(),
        ));
    }
    if !receipt_evidence_hash_matches(&record.receipt, "policyDeltaId", &record.policy_delta_id) {
        return Err((
            StatusCode::CONFLICT,
            "policy delta generated receipt does not bind policy delta id".to_string(),
        ));
    }
    if !receipt_evidence_hash_matches(&record.receipt, "artifactHash", &record.artifact_hash) {
        return Err((
            StatusCode::CONFLICT,
            "policy delta generated receipt does not bind artifact hash".to_string(),
        ));
    }
    if !receipt_evidence_hash_matches(
        &record.receipt,
        "stagedDetectionId",
        &record.artifact.staged_detection_id,
    ) {
        return Err((
            StatusCode::CONFLICT,
            "policy delta generated receipt does not bind staged detection id".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn policy_delta_source_context_evidence_value<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| canonicalize_json(&value).ok())
        .unwrap_or_else(|| "null".to_string())
}

pub(crate) fn apply_policy_delta_patch_to_policy(
    current_bytes: &[u8],
    patch: &Value,
) -> Result<Vec<u8>> {
    let current_yaml: serde_yaml::Value =
        serde_yaml::from_slice(current_bytes).context("parse current policy yaml")?;
    let mut current_json =
        serde_json::to_value(current_yaml).context("convert current policy yaml to json value")?;
    merge_policy_patch_values(&mut current_json, patch.clone());
    let merged_yaml: serde_yaml::Value =
        serde_json::from_value(current_json).context("convert merged policy to yaml value")?;
    let mut rendered =
        serde_yaml::to_string(&merged_yaml).context("serialize merged policy yaml")?;
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    Ok(rendered.into_bytes())
}

fn merge_policy_patch_values(target: &mut Value, source: Value) {
    match (target, source) {
        (Value::Object(target_obj), Value::Object(source_obj)) => {
            for (key, value) in source_obj {
                if let Some(existing) = target_obj.get_mut(&key) {
                    merge_policy_patch_values(existing, value);
                } else {
                    target_obj.insert(key, value);
                }
            }
        }
        (Value::Array(target_items), Value::Array(source_items)) => {
            for value in source_items {
                if !target_items.iter().any(|existing| existing == &value) {
                    target_items.push(value);
                }
            }
        }
        (target_value, source_value) => {
            *target_value = source_value;
        }
    }
}

pub(crate) fn policy_delta_backup_path(
    policy_path: &FsPath,
    policy_delta_id: &str,
    applied_at: chrono::DateTime<chrono::Utc>,
) -> PathBuf {
    let parent = policy_path.parent().unwrap_or_else(|| FsPath::new("."));
    let file_name = policy_path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "policy.yaml".to_string());
    let id_fragment = policy_delta_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
        .take(40)
        .collect::<String>();
    let timestamp = applied_at.format("%Y%m%dT%H%M%SZ");
    parent.join(format!(
        "{file_name}.policy-delta-{id_fragment}-{timestamp}.bak"
    ))
}
