use super::*;

pub(crate) struct PolicyDeltaApplyEnforcementEvidenceInput<'a> {
    pub(crate) local_policy: &'a EndpointPolicySnapshot,
    pub(crate) daemon_policy_reload: &'a EdrDaemonPolicyReloadResult,
    pub(crate) network_extension_policy_reload: &'a NetworkExtensionReloadRequestProof,
    pub(crate) provider_status_refresh: &'a EdrProviderStatusRefreshResult,
    pub(crate) provider_acknowledgement_poll: &'a EdrProviderAcknowledgementPoll,
    pub(crate) provider_policy_acknowledgements: &'a [EdrProviderPolicyAcknowledgement],
    pub(crate) daemon_restart_requested: bool,
    pub(crate) daemon_restarted: bool,
    pub(crate) daemon_restart_error: Option<&'a str>,
    pub(crate) daemon_policy_version: Option<&'a str>,
    pub(crate) cross_window_impact_hash: Option<&'a str>,
    pub(crate) cross_window_recommendation_hash: Option<&'a str>,
}

pub(crate) fn policy_delta_apply_enforcement_receipt_evidence(
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
