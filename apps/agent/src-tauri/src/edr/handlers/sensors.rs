//! Sensor data ingestion handlers.
#[allow(unused_imports, clippy::wildcard_imports)]
use crate::api_server::*;
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
use hush_core::{sha256, SignedReceipt};
#[allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use serde_json::Value;
#[allow(unused_imports)]
use std::collections::{BTreeMap, BTreeSet, HashMap};
#[allow(unused_imports)]
use std::sync::Arc;

pub(crate) async fn agent_edr_findings(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrFindingsInput>,
) -> Result<Json<EdrFindingsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let observations = redact_endpoint_observations(&input.observations);
    let evaluated = evaluate_record_and_receipt_edr_observations(
        &state,
        &input.observations,
        &observations,
        input.honey_artifacts,
    )
    .await?;
    let observation_receipts = emit_edr_provider_observation_receipts(
        &state,
        &observations,
        "agent_edr_findings_observation",
    )
    .await
    .map_err(internal_error)?;
    let receipt_count = evaluated.receipts.len() + observation_receipts.len();

    Ok(Json(EdrFindingsResponse {
        observation_count: observations.len(),
        finding_count: evaluated.findings.len(),
        receipt_count,
        findings: evaluated.findings,
        receipts: evaluated.receipts,
        observation_receipts,
    }))
}

pub(crate) async fn agent_edr_developer_activity(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrDeveloperActivityInput>,
) -> Result<Json<EdrDeveloperActivityResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    validate_edr_request_sizes(input.activities.len(), input.honey_artifacts.len())?;
    let observations = input
        .activities
        .iter()
        .enumerate()
        .map(|(index, activity)| developer_activity_observation(activity, index))
        .collect::<Result<Vec<_>, _>>()?;
    let recorded_observations = redact_endpoint_observations(&observations);
    let evaluated = evaluate_record_and_receipt_edr_observations(
        &state,
        &observations,
        &recorded_observations,
        input.honey_artifacts,
    )
    .await?;
    let observation_receipts = emit_edr_provider_observation_receipts(
        &state,
        &recorded_observations,
        "developer_activity_observation",
    )
    .await
    .map_err(internal_error)?;
    let receipt_count = evaluated.receipts.len() + observation_receipts.len();

    Ok(Json(EdrDeveloperActivityResponse {
        activity_count: input.activities.len(),
        observation_count: recorded_observations.len(),
        finding_count: evaluated.findings.len(),
        receipt_count,
        observations: recorded_observations,
        findings: evaluated.findings,
        receipts: evaluated.receipts,
        observation_receipts,
    }))
}

pub(crate) async fn agent_edr_package_manager_events(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrPackageManagerEventsInput>,
) -> Result<Json<EdrPackageManagerEventsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    validate_edr_request_sizes(input.events.len(), input.honey_artifacts.len())?;
    let observations = input
        .events
        .iter()
        .enumerate()
        .map(|(index, event)| package_manager_event_observation(event, index))
        .collect::<Result<Vec<_>, _>>()?;
    let recorded_observations = redact_endpoint_observations(&observations);
    let evaluated = evaluate_record_and_receipt_edr_observations(
        &state,
        &observations,
        &recorded_observations,
        input.honey_artifacts,
    )
    .await?;
    let observation_receipts = emit_edr_provider_observation_receipts(
        &state,
        &recorded_observations,
        "package_manager_observation",
    )
    .await
    .map_err(internal_error)?;
    let policy_decision_observations =
        package_manager_policy_decision_observations(&recorded_observations, &evaluated.findings);
    if !policy_decision_observations.is_empty() {
        record_edr_observations(&state, &policy_decision_observations).await?;
    }
    let policy_decision_receipts = emit_edr_provider_policy_decision_receipts(
        &state,
        &policy_decision_observations,
        "package_manager_policy_decision",
    )
    .await
    .map_err(internal_error)?;
    let receipt_count =
        evaluated.receipts.len() + observation_receipts.len() + policy_decision_receipts.len();

    Ok(Json(EdrPackageManagerEventsResponse {
        event_count: input.events.len(),
        observation_count: recorded_observations.len(),
        finding_count: evaluated.findings.len(),
        receipt_count,
        observations: recorded_observations,
        findings: evaluated.findings,
        receipts: evaluated.receipts,
        observation_receipts,
        policy_decision_receipts,
    }))
}

fn package_manager_policy_decision_observations(
    observations: &[EndpointObservation],
    findings: &[DetectionFinding],
) -> Vec<EndpointObservation> {
    observations
        .iter()
        .filter_map(|observation| {
            let EndpointEvent::PackageScript {
                manager,
                phase,
                script,
                package,
                working_directory,
            } = &observation.event
            else {
                return None;
            };
            let finding = findings
                .iter()
                .find(|finding| finding.observation_id == observation.observation_id);
            let script_hash = sha256(script.as_bytes()).to_hex_prefixed();
            let package_name = package.as_deref().unwrap_or("unknown-package");
            let target = format!(
                "endpoint.package_script:{}:{}:{}:{}",
                manager.as_str(),
                package_name,
                phase,
                script_hash
            );
            let guard = finding
                .map(|finding| finding.rule_id.clone())
                .or_else(|| Some("supply_chain.package_script.audit".to_string()));
            let severity = finding
                .map(|finding| format!("{:?}", finding.severity).to_ascii_lowercase())
                .or_else(|| Some("info".to_string()));
            let observation_id = local_stable_id(
                "package_manager_policy_decision_observation",
                [
                    observation.observation_id.as_str(),
                    manager.as_str(),
                    package_name,
                    phase.as_str(),
                    script_hash.as_str(),
                ],
            );
            let mut metadata = observation.metadata.clone();
            metadata.insert(
                "receiptSource".to_string(),
                serde_json::json!("package_manager_policy_decision"),
            );
            metadata.insert(
                "collectorKind".to_string(),
                serde_json::json!("package_manager"),
            );
            metadata.insert(
                "providerId".to_string(),
                serde_json::json!(format!("package_manager.{}", manager.as_str())),
            );
            metadata.insert(
                "policyDecisionMode".to_string(),
                serde_json::json!("audit_allow"),
            );
            metadata.insert(
                "packageManager".to_string(),
                serde_json::json!(manager.as_str()),
            );
            metadata.insert("packageManagerPhase".to_string(), serde_json::json!(phase));
            metadata.insert("scriptHash".to_string(), serde_json::json!(script_hash));
            if let Some(package) = package {
                metadata.insert("packageName".to_string(), serde_json::json!(package));
            }
            if let Some(working_directory) = working_directory {
                metadata.insert(
                    "workingDirectoryHash".to_string(),
                    serde_json::json!(sha256(working_directory.as_bytes()).to_hex_prefixed()),
                );
            }
            if let Some(finding) = finding {
                metadata.insert(
                    "detectionFindingId".to_string(),
                    serde_json::json!(finding.finding_id.as_str()),
                );
                metadata.insert(
                    "detectionRuleId".to_string(),
                    serde_json::json!(finding.rule_id.as_str()),
                );
            }

            Some(EndpointObservation {
                observation_id,
                timestamp: observation.timestamp,
                host_id: observation.host_id.clone(),
                user_id: observation.user_id.clone(),
                session_id: observation.session_id.clone(),
                process: observation.process.clone(),
                event: EndpointEvent::PolicyDecision {
                    action: "endpoint.package_script".to_string(),
                    target: Some(target),
                    decision: "allowed".to_string(),
                    guard,
                    severity,
                },
                metadata,
            })
        })
        .collect()
}

pub(crate) async fn agent_edr_endpoint_security_events(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrEndpointSecurityEventsInput>,
) -> Result<Json<EdrEndpointSecurityEventsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    validate_edr_request_sizes(input.events.len(), input.honey_artifacts.len())?;
    let observations = input
        .events
        .iter()
        .enumerate()
        .map(|(index, event)| endpoint_security_event_observation(event, index))
        .collect::<Result<Vec<_>, _>>()?;
    let recorded_observations = redact_endpoint_observations(&observations);
    let evaluated = evaluate_record_and_receipt_edr_observations(
        &state,
        &observations,
        &recorded_observations,
        input.honey_artifacts,
    )
    .await?;
    let observation_receipts = emit_edr_provider_observation_receipts(
        &state,
        &recorded_observations,
        "endpoint_security_observation",
    )
    .await
    .map_err(internal_error)?;
    let policy_decision_receipts = emit_edr_provider_policy_decision_receipts(
        &state,
        &recorded_observations,
        "endpoint_security_policy_decision",
    )
    .await
    .map_err(internal_error)?;
    let degraded_provider_receipts = if let Some(sensor_state) =
        endpoint_security_event_loss_sensor_state(&input.events)
    {
        let settings = state.settings.read().await.clone();
        let policy = endpoint_policy_snapshot_from_settings(&settings).map_err(internal_error)?;
        emit_edr_provider_degradation_receipts(state.as_ref(), policy, sensor_state)
            .await
            .map_err(internal_error)?
    } else {
        Vec::new()
    };
    let receipt_count = evaluated.receipts.len()
        + observation_receipts.len()
        + policy_decision_receipts.len()
        + degraded_provider_receipts.len();

    Ok(Json(EdrEndpointSecurityEventsResponse {
        event_count: input.events.len(),
        observation_count: recorded_observations.len(),
        finding_count: evaluated.findings.len(),
        receipt_count,
        observations: recorded_observations,
        findings: evaluated.findings,
        receipts: evaluated.receipts,
        observation_receipts,
        policy_decision_receipts,
        degraded_provider_receipts,
    }))
}

pub(crate) async fn agent_edr_network_extension_events(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrNetworkExtensionEventsInput>,
) -> Result<Json<EdrNetworkExtensionEventsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    validate_edr_request_sizes(
        input.events.len().saturating_mul(2),
        input.honey_artifacts.len(),
    )?;
    let observations = input
        .events
        .iter()
        .enumerate()
        .map(|(index, event)| network_extension_event_observations(event, index))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let recorded_observations = redact_endpoint_observations(&observations);
    let evaluated = evaluate_record_and_receipt_edr_observations(
        &state,
        &observations,
        &recorded_observations,
        input.honey_artifacts,
    )
    .await?;
    let observation_receipts = emit_edr_provider_observation_receipts(
        &state,
        &recorded_observations,
        "network_extension_observation",
    )
    .await
    .map_err(internal_error)?;
    let policy_decision_receipts = emit_edr_provider_policy_decision_receipts(
        &state,
        &recorded_observations,
        "network_extension_policy_decision",
    )
    .await
    .map_err(internal_error)?;
    let receipt_count =
        evaluated.receipts.len() + observation_receipts.len() + policy_decision_receipts.len();

    Ok(Json(EdrNetworkExtensionEventsResponse {
        event_count: input.events.len(),
        observation_count: recorded_observations.len(),
        finding_count: evaluated.findings.len(),
        receipt_count,
        observations: recorded_observations,
        findings: evaluated.findings,
        receipts: evaluated.receipts,
        observation_receipts,
        policy_decision_receipts,
    }))
}

pub(crate) async fn agent_edr_policy_events(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrPolicyEventsInput>,
) -> Result<Json<EdrPolicyEventsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    validate_edr_request_sizes(input.events.len(), input.honey_artifacts.len())?;
    for event in &input.events {
        validate_policy_event_submission(event, None)?;
    }

    let observations = input
        .events
        .iter()
        .map(EndpointObservation::from_policy_event)
        .collect::<Vec<_>>();
    let observations = redact_endpoint_observations(&observations);
    let evaluated = evaluate_record_and_receipt_edr_observations(
        &state,
        &observations,
        &observations,
        input.honey_artifacts,
    )
    .await?;
    let observation_receipts =
        emit_edr_provider_observation_receipts(&state, &observations, "policy_event_observation")
            .await
            .map_err(internal_error)?;
    let receipt_count = evaluated.receipts.len() + observation_receipts.len();

    Ok(Json(EdrPolicyEventsResponse {
        policy_event_count: input.events.len(),
        observation_count: observations.len(),
        finding_count: evaluated.findings.len(),
        receipt_count,
        observations,
        findings: evaluated.findings,
        receipts: evaluated.receipts,
        observation_receipts,
    }))
}

pub(crate) async fn agent_edr_policy_events_jsonl(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Json<EdrPolicyEventsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let events = parse_policy_event_jsonl(&body)?;
    validate_edr_request_sizes(events.len(), 0)?;

    let observations = events
        .iter()
        .map(EndpointObservation::from_policy_event)
        .collect::<Vec<_>>();
    let observations = redact_endpoint_observations(&observations);
    let evaluated = evaluate_record_and_receipt_edr_observations(
        &state,
        &observations,
        &observations,
        Vec::new(),
    )
    .await?;
    let observation_receipts =
        emit_edr_provider_observation_receipts(&state, &observations, "policy_event_observation")
            .await
            .map_err(internal_error)?;
    let receipt_count = evaluated.receipts.len() + observation_receipts.len();

    Ok(Json(EdrPolicyEventsResponse {
        policy_event_count: events.len(),
        observation_count: observations.len(),
        finding_count: evaluated.findings.len(),
        receipt_count,
        observations,
        findings: evaluated.findings,
        receipts: evaluated.receipts,
        observation_receipts,
    }))
}

pub(crate) async fn agent_edr_agent_secret_touches(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrAgentSecretTouchesInput>,
) -> Result<Json<EdrAgentSecretTouchesResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    collect_agent_secret_touches(state.as_ref(), input)
        .await
        .map(Json)
}

pub(crate) async fn agent_edr_agent_secret_touches_fleet_publish(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrAgentSecretTouchesInput>,
) -> Result<Json<EdrAgentSecretTouchesFleetPublishResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let publish_context = fleet_hunt_publish_context(state.as_ref()).await?;
    let response = collect_agent_secret_touches(state.as_ref(), input).await?;
    let events = publish_agent_secret_touches_to_fleet(&publish_context, &response.touches).await?;

    Ok(Json(EdrAgentSecretTouchesFleetPublishResponse {
        touch_count: response.touch_count,
        published_count: events.len(),
        events,
    }))
}
