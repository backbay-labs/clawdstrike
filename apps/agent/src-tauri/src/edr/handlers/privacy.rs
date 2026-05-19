//! Privacy, protection state, and network extension egress proof handlers.
#[allow(unused_imports, clippy::wildcard_imports)]
use crate::api_server::*;
#[allow(unused_imports)]
use std::collections::{BTreeMap, BTreeSet, HashMap};
#[allow(unused_imports)]
use axum::extract::{Path, Query, State};
#[allow(unused_imports)]
use axum::http::{HeaderMap, StatusCode};
#[allow(unused_imports)]
use axum::Json;
#[allow(unused_imports)]
use clawdstrike_policy_event::edr::*;
#[allow(unused_imports)]
use clawdstrike_policy_event::event::PolicyEvent;
#[allow(unused_imports)]
use hush_core::SignedReceipt;
#[allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use serde_json::Value;
#[allow(unused_imports)]
use std::sync::Arc;
#[allow(unused_imports)]
use std::fs;
#[allow(unused_imports)]
use hush_core::{sha256, canonicalize_json};

pub(crate) async fn agent_edr_privacy_report(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrPrivacyReportInput>,
) -> Result<Json<EdrPrivacyReportResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    validate_edr_request_sizes(input.observations.len(), 0)?;
    let raw_artifact_approval = validate_raw_artifact_approval(&input)?;
    let requested_privacy_mode = input.privacy_mode.unwrap_or_default();
    let settings = state.settings.read().await.clone();
    let privacy_policy = edr_privacy_policy_decision(
        &settings,
        requested_privacy_mode,
        raw_artifact_approval.as_ref(),
    )
    .map_err(internal_error)?;
    let report = EndpointTelemetryPrivacyReport::from_observations_with_raw_artifact_approval(
        &input.observations,
        privacy_policy.effective_privacy_mode.clone(),
        privacy_policy.raw_artifact_approval_id.as_deref(),
        privacy_policy.raw_artifact_approval_reason_hash.as_deref(),
    );
    let receipt = emit_edr_telemetry_privacy_receipt(&state, &report)
        .await
        .map_err(internal_error)?;

    Ok(Json(EdrPrivacyReportResponse {
        report,
        privacy_policy,
        receipt,
    }))
}


pub(crate) async fn agent_edr_network_extension_egress_policy_proof(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrNetworkExtensionEgressPolicyProofInput>,
) -> Result<Json<EdrNetworkExtensionEgressPolicyProofResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let refresh_providers = input.refresh_providers.unwrap_or(true);
    let provider_refresh_timeout_ms = if refresh_providers {
        bounded_provider_timeout_ms(
            "providerRefreshTimeoutMs",
            input.provider_refresh_timeout_ms,
        )?
    } else {
        0
    };
    let path = state.edr_network_extension_egress_policy_path.as_ref();
    let now = chrono::Utc::now();
    let (
        snapshot_present,
        snapshot_decodable,
        snapshot_hash,
        generated_at,
        restriction_count,
        active_restriction_count,
        expired_restriction_count,
        read_error,
    ) = match fs::read(path) {
        Ok(bytes) => {
            let snapshot_hash = Some(sha256(&bytes).to_hex_prefixed());
            match serde_json::from_slice::<NetworkExtensionEgressPolicySnapshot>(&bytes) {
                Ok(snapshot) => {
                    let restriction_count = snapshot.restrictions.len();
                    let active_restriction_count = snapshot
                        .restrictions
                        .iter()
                        .filter(|restriction| restriction.active && restriction.expires_at > now)
                        .count();
                    let expired_restriction_count =
                        restriction_count.saturating_sub(active_restriction_count);
                    (
                        true,
                        true,
                        snapshot_hash,
                        Some(snapshot.generated_at),
                        restriction_count,
                        active_restriction_count,
                        expired_restriction_count,
                        None,
                    )
                }
                Err(err) => (
                    true,
                    false,
                    snapshot_hash,
                    None,
                    0,
                    0,
                    0,
                    Some(format!("decode network extension egress policy: {err}")),
                ),
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (
            false,
            false,
            None,
            None,
            0,
            0,
            0,
            Some("network extension egress policy snapshot not found".to_string()),
        ),
        Err(err) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "read network extension egress policy {}: {err}",
                    path.display()
                ),
            ));
        }
    };

    let provider_status_refresh =
        refresh_macos_provider_status(&state, provider_refresh_timeout_ms).await;
    let macos_host = state.macos_host.snapshot().await;
    let network_extension_provider = macos_host.network_extension.clone();
    let sensor_state = endpoint_sensor_state_from_macos_host(&macos_host);
    let settings = state.settings.read().await.clone();
    let local_policy = endpoint_policy_snapshot_from_settings(&settings).map_err(internal_error)?;
    let flow_counters = network_extension_flow_counter_summary(&network_extension_provider);
    let enforcement_ready = network_extension_egress_policy_proof_enforcement_ready(
        snapshot_decodable,
        &network_extension_provider,
    );
    let provider_reload_delivery = network_extension_reload_delivery_for_execution(
        state.as_ref(),
        input.execution_id.as_deref(),
        &network_extension_provider,
    )
    .await?;
    let live_enforcement_proof =
        network_extension_live_enforcement_proof(NetworkExtensionLiveEnforcementProofInput {
            snapshot_present,
            snapshot_decodable,
            active_restriction_count,
            enforcement_ready,
            flow_counters: &flow_counters,
            execution_id_provided: input
                .execution_id
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
            provider_reload_delivery: provider_reload_delivery.as_ref(),
        });
    let proof_input = NetworkExtensionEgressPolicyProofEvidenceInput {
        provider_policy_path: path,
        snapshot_present,
        snapshot_decodable,
        snapshot_hash: snapshot_hash.as_deref(),
        generated_at: generated_at.as_ref(),
        restriction_count,
        active_restriction_count,
        expired_restriction_count,
        enforcement_ready,
        live_enforcement_proven: live_enforcement_proof.proven,
        live_enforcement_proof_reasons: &live_enforcement_proof.reasons,
        flow_counter_observed: flow_counters.flow_counter_observed,
        provider: &network_extension_provider,
        provider_status_refresh: &provider_status_refresh,
        provider_reload_delivery: provider_reload_delivery.as_ref(),
    };
    let proof_evidence = network_extension_egress_policy_proof_evidence(proof_input);
    let receipt = emit_edr_sensor_state_receipt_with_evidence(
        state.as_ref(),
        local_policy.clone(),
        sensor_state.clone(),
        "network extension egress policy proof",
        &proof_evidence,
    )
    .await
    .map_err(internal_error)?;
    let degraded_provider_receipts =
        emit_edr_provider_degradation_receipts(state.as_ref(), local_policy, sensor_state.clone())
            .await
            .map_err(internal_error)?;
    let provider_reload_observation = network_extension_provider.last_reload_observation.clone();

    Ok(Json(EdrNetworkExtensionEgressPolicyProofResponse {
        provider_policy_path: path.display().to_string(),
        snapshot_present,
        snapshot_decodable,
        snapshot_hash,
        generated_at,
        restriction_count,
        active_restriction_count,
        expired_restriction_count,
        enforcement_ready,
        live_enforcement_proven: live_enforcement_proof.proven,
        live_enforcement_proof_reasons: live_enforcement_proof.reasons,
        flow_counter_observed: flow_counters.flow_counter_observed,
        observed_flow_count: flow_counters.observed_flow_count,
        blocked_flow_count: flow_counters.blocked_flow_count,
        remediation_request_count: flow_counters.remediation_request_count,
        dropped_verdict_count: flow_counters.dropped_verdict_count,
        provider_reload_observed: provider_reload_observation.is_some(),
        provider_reload_request_id: provider_reload_observation
            .as_ref()
            .and_then(|observation| observation.request_id.clone()),
        provider_reload_generation: provider_reload_observation
            .as_ref()
            .and_then(|observation| observation.generation),
        provider_reload_policy_snapshot_path: provider_reload_observation
            .as_ref()
            .and_then(|observation| observation.policy_snapshot_path.clone()),
        provider_reload_accepted: provider_reload_observation
            .as_ref()
            .and_then(|observation| observation.accepted),
        provider_reload_reloaded: provider_reload_observation
            .as_ref()
            .and_then(|observation| observation.reloaded),
        provider_reload_error: provider_reload_observation
            .as_ref()
            .and_then(|observation| observation.error.clone()),
        provider_reload_delivery,
        read_error,
        provider_status_refresh,
        network_extension_provider,
        sensor_state,
        receipt,
        degraded_provider_receipts,
    }))
}


pub(crate) async fn agent_edr_protection_state(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<EdrProtectionStateResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let settings = state.settings.read().await.clone();
    let policy = endpoint_policy_snapshot_from_settings(&settings).map_err(internal_error)?;
    let macos_host_transition = state.macos_host.snapshot_transition().await;
    let sensor_state = endpoint_sensor_state_from_macos_host(&macos_host_transition.current);
    let provider_recoveries =
        endpoint_provider_recoveries(macos_host_transition.previous.as_ref(), &sensor_state);
    let recovery_evidence = provider_recovery_receipt_evidence(&provider_recoveries);
    let receipt = if recovery_evidence.is_empty() {
        emit_edr_sensor_state_receipt(
            &state,
            policy.clone(),
            sensor_state.clone(),
            "local protection state query",
        )
        .await
    } else {
        emit_edr_sensor_state_receipt_with_evidence(
            &state,
            policy.clone(),
            sensor_state.clone(),
            "local protection state query",
            &recovery_evidence,
        )
        .await
    }
    .map_err(internal_error)?;
    let degraded_provider_receipts =
        emit_edr_provider_degradation_receipts(&state, policy.clone(), sensor_state.clone())
            .await
            .map_err(internal_error)?;

    Ok(Json(EdrProtectionStateResponse {
        policy,
        sensor_state,
        receipt,
        degraded_provider_receipts,
        provider_recoveries,
    }))
}

