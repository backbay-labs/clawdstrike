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
