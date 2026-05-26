//! Package manager event ingestion handler and policy-decision derivation.
use super::developer::{developer_activity_metadata_string, developer_activity_policy_allowed};
#[allow(unused_imports, clippy::wildcard_imports)]
use crate::api_server::*;
#[allow(unused_imports)]
use axum::extract::State;
#[allow(unused_imports)]
use axum::http::{HeaderMap, StatusCode};
#[allow(unused_imports)]
use axum::Json;
#[allow(unused_imports)]
use clawdstrike_policy_event::edr::*;
#[allow(unused_imports)]
use hush_core::sha256;
#[allow(unused_imports)]
use std::sync::Arc;

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
            let explicit_allowed = developer_activity_policy_allowed(observation);
            let action_type = developer_activity_metadata_string(observation, "policyActionType")
                .or_else(|| developer_activity_metadata_string(observation, "actionType"))
                .unwrap_or_else(|| "endpoint.package_script".to_string());
            let script_hash = sha256(script.as_bytes()).to_hex_prefixed();
            let package_name = package.as_deref().unwrap_or("unknown-package");
            let target = format!(
                "endpoint.package_script:{}:{}:{}:{}",
                manager.as_str(),
                package_name,
                phase,
                script_hash
            );
            let policy_guard = developer_activity_metadata_string(observation, "policyGuard");
            let policy_severity = developer_activity_metadata_string(observation, "policySeverity");
            let guard = if explicit_allowed.is_some() {
                policy_guard.or_else(|| finding.map(|finding| finding.rule_id.clone()))
            } else {
                finding
                    .map(|finding| finding.rule_id.clone())
                    .or(policy_guard)
            }
            .or_else(|| Some("supply_chain.package_script.audit".to_string()));
            let severity = if explicit_allowed.is_some() {
                policy_severity.or_else(|| {
                    finding.map(|finding| format!("{:?}", finding.severity).to_ascii_lowercase())
                })
            } else {
                finding
                    .map(|finding| format!("{:?}", finding.severity).to_ascii_lowercase())
                    .or(policy_severity)
            }
            .or_else(|| Some("info".to_string()));
            let allowed = explicit_allowed.unwrap_or_else(|| finding.is_none());
            let decision = if allowed { "allowed" } else { "blocked" }.to_string();
            let observation_id = local_stable_id(
                "package_manager_policy_decision_observation",
                [
                    observation.observation_id.as_str(),
                    manager.as_str(),
                    package_name,
                    phase.as_str(),
                    script_hash.as_str(),
                    decision.as_str(),
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
                serde_json::json!(if explicit_allowed.is_some() {
                    "policy_check"
                } else if finding.is_some() {
                    "derived_finding_block"
                } else {
                    "audit_allow"
                }),
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
                    action: action_type,
                    target: Some(target),
                    decision,
                    guard,
                    severity,
                },
                metadata,
            })
        })
        .collect()
}
