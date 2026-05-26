//! Network-extension evidence builders.
//!
//! Computes the per-network-extension provider evidence embedded in
//! response execution and egress policy proof receipts, including flow
//! counters, live-enforcement proof reasons, and reload-delivery
//! observation matching.

use super::super::*;

pub(crate) fn network_extension_response_execution_evidence(
    provider: &ProviderStatus,
) -> Vec<EndpointReceiptEvidence> {
    let mut evidence = vec![
        EndpointReceiptEvidence::hashed(
            "networkExtensionRuntime",
            provider_runtime_evidence_value(&provider.runtime),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionPolicySynced",
            optional_bool_evidence_value(provider.policy_synced),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEnforcementReady",
            optional_bool_evidence_value(provider.enforcement_ready),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionPolicyEpoch",
            optional_u64_evidence_value(provider.policy_epoch),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionFlowsObserved",
            provider_counter(provider, &["flows_observed"]).to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionFlowsBlocked",
            provider_counter(provider, &["flows_blocked"]).to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionRemediationRequests",
            provider_counter(provider, &["remediation_requests"]).to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionDroppedVerdicts",
            provider_counter(provider, &["dropped_verdicts"]).to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadObserved",
            provider.last_reload_observation.is_some().to_string(),
        ),
    ];
    if let Some(observation) = provider.last_reload_observation.as_ref() {
        if let Some(command) = observation
            .command
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedCommand",
                command,
            ));
        }
        if let Some(request_id) = observation
            .request_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedRequestId",
                request_id,
            ));
        }
        if let Some(policy_snapshot_path) = observation
            .policy_snapshot_path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedPolicySnapshotPath",
                policy_snapshot_path,
            ));
        }
        if let Some(generation) = observation.generation {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedGeneration",
                generation.to_string(),
            ));
        }
        if let Some(accepted) = observation.accepted {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedAccepted",
                accepted.to_string(),
            ));
        }
        if let Some(reloaded) = observation.reloaded {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedReloaded",
                reloaded.to_string(),
            ));
        }
        if let Some(error) = observation
            .error
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            evidence.push(EndpointReceiptEvidence::hashed(
                "networkExtensionReloadObservedError",
                error,
            ));
        }
    }
    if let Some(last_error) = provider
        .last_error
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionLastError",
            last_error,
        ));
    }
    evidence
}

pub(crate) struct NetworkExtensionFlowCounterSummary {
    pub(crate) flow_counter_observed: bool,
    pub(crate) observed_flow_count: u64,
    pub(crate) blocked_flow_count: u64,
    pub(crate) remediation_request_count: u64,
    pub(crate) dropped_verdict_count: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NetworkExtensionReloadRequestProof {
    pub(crate) requested: bool,
    pub(crate) saved: bool,
    pub(crate) request_id: Option<String>,
    pub(crate) policy_snapshot_path: String,
    pub(crate) generation: u64,
    pub(crate) provider_reload_observed: bool,
    pub(crate) provider_reload_matched: bool,
    pub(crate) provider_reload_request_id_matches: bool,
    pub(crate) provider_reload_generation_matches: bool,
    pub(crate) provider_reload_policy_snapshot_path_matches: bool,
    pub(crate) provider_reloaded: Option<bool>,
    pub(crate) provider_policy_synced: Option<bool>,
    pub(crate) provider_enforcement_ready: Option<bool>,
    pub(crate) provider_reload_elapsed_ms: u64,
    pub(crate) provider_reload_attempts: u64,
    pub(crate) error: Option<String>,
}

pub(crate) fn network_extension_flow_counter_summary(
    provider: &ProviderStatus,
) -> NetworkExtensionFlowCounterSummary {
    let observed_flow_count = provider_counter(provider, &["flows_observed"]);
    let blocked_flow_count = provider_counter(provider, &["flows_blocked"]);
    let remediation_request_count = provider_counter(provider, &["remediation_requests"]);
    let dropped_verdict_count = provider_counter(provider, &["dropped_verdicts"]);
    NetworkExtensionFlowCounterSummary {
        flow_counter_observed: observed_flow_count > 0 || blocked_flow_count > 0,
        observed_flow_count,
        blocked_flow_count,
        remediation_request_count,
        dropped_verdict_count,
    }
}

pub(crate) struct NetworkExtensionLiveEnforcementProof {
    pub(crate) proven: bool,
    pub(crate) reasons: Vec<String>,
}

pub(crate) struct NetworkExtensionLiveEnforcementProofInput<'a> {
    pub(crate) snapshot_present: bool,
    pub(crate) snapshot_decodable: bool,
    pub(crate) active_restriction_count: usize,
    pub(crate) enforcement_ready: bool,
    pub(crate) flow_counters: &'a NetworkExtensionFlowCounterSummary,
    pub(crate) execution_id_provided: bool,
    pub(crate) provider_reload_delivery: Option<&'a EdrNetworkExtensionReloadDeliveryProof>,
}

pub(crate) fn network_extension_live_enforcement_proof(
    input: NetworkExtensionLiveEnforcementProofInput<'_>,
) -> NetworkExtensionLiveEnforcementProof {
    let mut reasons = Vec::new();
    if !input.snapshot_present {
        reasons.push("snapshot_missing".to_string());
    }
    if !input.snapshot_decodable {
        reasons.push("snapshot_not_decodable".to_string());
    }
    if input.active_restriction_count == 0 {
        reasons.push("no_active_restrictions".to_string());
    }
    if !input.enforcement_ready {
        reasons.push("provider_not_enforcement_ready".to_string());
    }
    if !input.flow_counters.flow_counter_observed {
        reasons.push("flow_counters_not_observed".to_string());
    }
    if input.flow_counters.blocked_flow_count == 0 {
        reasons.push("blocked_flow_counter_zero".to_string());
    }
    if input.flow_counters.dropped_verdict_count > 0 {
        reasons.push("dropped_verdicts_observed".to_string());
    }
    if !input.execution_id_provided {
        reasons.push("execution_id_required".to_string());
    }
    match input.provider_reload_delivery {
        Some(delivery) if delivery.matched => {}
        Some(_) => reasons.push("reload_delivery_not_matched".to_string()),
        None => reasons.push("reload_delivery_missing".to_string()),
    }
    reasons.sort();
    reasons.dedup();

    NetworkExtensionLiveEnforcementProof {
        proven: reasons.is_empty(),
        reasons,
    }
}

pub(crate) fn network_extension_reload_request_evidence(
    proof: &NetworkExtensionReloadRequestProof,
) -> Vec<EndpointReceiptEvidence> {
    let mut evidence = vec![
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadRequested",
            proof.requested.to_string(),
        ),
        EndpointReceiptEvidence::hashed("networkExtensionReloadSaved", proof.saved.to_string()),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadGeneration",
            proof.generation.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadPolicySnapshotPath",
            proof.policy_snapshot_path.as_str(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderObserved",
            proof.provider_reload_observed.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderMatched",
            proof.provider_reload_matched.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderRequestIdMatches",
            proof.provider_reload_request_id_matches.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderGenerationMatches",
            proof.provider_reload_generation_matches.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderPolicySnapshotPathMatches",
            proof
                .provider_reload_policy_snapshot_path_matches
                .to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderAttempts",
            proof.provider_reload_attempts.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderElapsedMs",
            proof.provider_reload_elapsed_ms.to_string(),
        ),
    ];
    if let Some(reloaded) = proof.provider_reloaded {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderReloaded",
            reloaded.to_string(),
        ));
    }
    if let Some(policy_synced) = proof.provider_policy_synced {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderPolicySynced",
            policy_synced.to_string(),
        ));
    }
    if let Some(enforcement_ready) = proof.provider_enforcement_ready {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionReloadProviderEnforcementReady",
            enforcement_ready.to_string(),
        ));
    }
    if let Some(request_id) = proof.request_id.as_deref() {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionReloadRequestId",
            request_id,
        ));
    }
    if let Some(error) = proof.error.as_deref() {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionReloadError",
            error,
        ));
    }
    evidence
}

pub(crate) async fn network_extension_reload_delivery_for_execution(
    state: &AgentApiState,
    execution_id: Option<&str>,
    provider: &ProviderStatus,
) -> Result<Option<EdrNetworkExtensionReloadDeliveryProof>, (StatusCode, String)> {
    let Some(execution_id) = execution_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let execution = {
        let ledger = state.edr_response_execution_ledger.lock().await;
        ledger
            .get(execution_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("response execution not found: {execution_id}"),
                )
            })?
    };
    if execution.action != EndpointDecisionAction::RestrictEgress {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "response execution {} is {}, not restrict_egress",
                execution.execution_id,
                execution.action.as_str()
            ),
        ));
    }
    let execution_receipt = {
        let ledger = state.edr_receipt_ledger.lock().await;
        latest_required_receipt(
            &ledger,
            "response_execution",
            execution.execution_id.as_str(),
            "response execution receipt",
        )
        .or_else(|err| {
            if err.0 == StatusCode::NOT_FOUND {
                latest_required_receipt_by_execution_id(
                    &ledger,
                    "response_execution",
                    execution.execution_id.as_str(),
                    "response execution receipt",
                )
            } else {
                Err(err)
            }
        })?
    };

    let observation = provider.last_reload_observation.as_ref();
    let request_id_matches = observation
        .and_then(|observation| observation.request_id.as_deref())
        .is_some_and(|request_id| {
            receipt_evidence_hash_matches(
                &execution_receipt,
                "networkExtensionReloadRequestId",
                request_id,
            )
        });
    let generation_matches = observation
        .and_then(|observation| observation.generation)
        .is_some_and(|generation| {
            receipt_evidence_hash_matches(
                &execution_receipt,
                "networkExtensionReloadGeneration",
                generation.to_string().as_str(),
            )
        });
    let policy_snapshot_path_matches = observation
        .and_then(|observation| observation.policy_snapshot_path.as_deref())
        .is_some_and(|policy_snapshot_path| {
            receipt_evidence_hash_matches(
                &execution_receipt,
                "networkExtensionReloadPolicySnapshotPath",
                policy_snapshot_path,
            )
        });
    let requested = receipt_evidence_hash_matches(
        &execution_receipt,
        "networkExtensionReloadRequested",
        "true",
    );
    let saved =
        receipt_evidence_hash_matches(&execution_receipt, "networkExtensionReloadSaved", "true");
    let provider_reloaded = observation.and_then(|observation| observation.reloaded);
    let matched = requested
        && saved
        && request_id_matches
        && generation_matches
        && policy_snapshot_path_matches
        && provider_reloaded == Some(true);

    Ok(Some(EdrNetworkExtensionReloadDeliveryProof {
        execution_id: execution.execution_id,
        observed: observation.is_some(),
        matched,
        request_id_matches,
        generation_matches,
        policy_snapshot_path_matches,
        provider_reloaded,
    }))
}

pub(crate) struct NetworkExtensionEgressPolicyProofEvidenceInput<'a> {
    pub(crate) provider_policy_path: &'a FsPath,
    pub(crate) snapshot_present: bool,
    pub(crate) snapshot_decodable: bool,
    pub(crate) snapshot_hash: Option<&'a str>,
    pub(crate) generated_at: Option<&'a chrono::DateTime<chrono::Utc>>,
    pub(crate) restriction_count: usize,
    pub(crate) active_restriction_count: usize,
    pub(crate) expired_restriction_count: usize,
    pub(crate) enforcement_ready: bool,
    pub(crate) live_enforcement_proven: bool,
    pub(crate) live_enforcement_proof_reasons: &'a [String],
    pub(crate) flow_counter_observed: bool,
    pub(crate) provider: &'a ProviderStatus,
    pub(crate) provider_status_refresh: &'a EdrProviderStatusRefreshResult,
    pub(crate) provider_reload_delivery: Option<&'a EdrNetworkExtensionReloadDeliveryProof>,
}

pub(crate) fn network_extension_egress_policy_proof_evidence(
    input: NetworkExtensionEgressPolicyProofEvidenceInput<'_>,
) -> Vec<EndpointReceiptEvidence> {
    let mut evidence = vec![
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyPath",
            input.provider_policy_path.display().to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicySnapshotPresent",
            input.snapshot_present.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicySnapshotDecodable",
            input.snapshot_decodable.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyRestrictionCount",
            input.restriction_count.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyActiveRestrictionCount",
            input.active_restriction_count.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyExpiredRestrictionCount",
            input.expired_restriction_count.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyEnforcementReady",
            input.enforcement_ready.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionLiveEnforcementProven",
            input.live_enforcement_proven.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionLiveEnforcementProofReasons",
            input.live_enforcement_proof_reasons.join(","),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionFlowCounterObserved",
            input.flow_counter_observed.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyProviderRefreshRequested",
            input.provider_status_refresh.requested.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyProviderRefreshRefreshed",
            input.provider_status_refresh.refreshed.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyProviderRefreshTimeoutMs",
            input.provider_status_refresh.timeout_ms.to_string(),
        ),
        EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyProviderRefreshElapsedMs",
            input.provider_status_refresh.elapsed_ms.to_string(),
        ),
    ];
    if let Some(snapshot_hash) = input.snapshot_hash.filter(|value| !value.trim().is_empty()) {
        evidence.push(EndpointReceiptEvidence {
            key: "networkExtensionEgressPolicySnapshotHash".to_string(),
            value_hash: snapshot_hash.to_string(),
            redaction_class: EndpointEvidenceRedactionClass::HashOnly,
            raw_value: None,
        });
    }
    if let Some(generated_at) = input.generated_at {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyGeneratedAt",
            generated_at.to_rfc3339(),
        ));
    }
    if let Some(error) = input.provider_status_refresh.error.as_deref() {
        evidence.push(EndpointReceiptEvidence::hashed(
            "networkExtensionEgressPolicyProviderRefreshError",
            error,
        ));
    }
    if let Some(delivery) = input.provider_reload_delivery {
        evidence.extend([
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryExecutionId",
                delivery.execution_id.as_str(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryObserved",
                delivery.observed.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryMatched",
                delivery.matched.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryRequestIdMatches",
                delivery.request_id_matches.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryGenerationMatches",
                delivery.generation_matches.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryPolicySnapshotPathMatches",
                delivery.policy_snapshot_path_matches.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "networkExtensionReloadDeliveryProviderReloaded",
                optional_bool_evidence_value(delivery.provider_reloaded),
            ),
        ]);
    }
    evidence.extend(network_extension_response_execution_evidence(
        input.provider,
    ));
    evidence
}
