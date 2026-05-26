//! Developer activity ingestion handler and policy-decision derivation.
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
    let policy_decision_observations =
        developer_activity_policy_decision_observations(&recorded_observations);
    if !policy_decision_observations.is_empty() {
        record_edr_observations(&state, &policy_decision_observations).await?;
    }
    let policy_decision_receipts = emit_edr_provider_policy_decision_receipts(
        &state,
        &policy_decision_observations,
        "developer_activity_policy_decision",
    )
    .await
    .map_err(internal_error)?;
    let receipt_count =
        evaluated.receipts.len() + observation_receipts.len() + policy_decision_receipts.len();

    Ok(Json(EdrDeveloperActivityResponse {
        activity_count: input.activities.len(),
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

pub(super) fn developer_activity_policy_decision_observations(
    observations: &[EndpointObservation],
) -> Vec<EndpointObservation> {
    observations
        .iter()
        .filter_map(|observation| {
            let allowed = developer_activity_policy_allowed(observation)?;
            let action_type = developer_activity_metadata_string(observation, "policyActionType")
                .or_else(|| developer_activity_metadata_string(observation, "actionType"))
                .or_else(|| {
                    developer_activity_metadata_string(observation, "developerActivityKind")
                })?;
            let target = developer_activity_policy_decision_target(observation)?;
            let decision = if allowed { "allowed" } else { "blocked" }.to_string();
            let guard = developer_activity_metadata_string(observation, "policyGuard")
                .or_else(|| developer_activity_metadata_string(observation, "guard"));
            let severity = developer_activity_metadata_string(observation, "policySeverity")
                .or_else(|| developer_activity_metadata_string(observation, "severity"));
            let observation_id = local_stable_id(
                "developer_activity_policy_decision_observation",
                [
                    observation.observation_id.as_str(),
                    action_type.as_str(),
                    target.as_str(),
                    decision.as_str(),
                ],
            );
            let mut metadata = observation.metadata.clone();
            metadata.insert(
                "receiptSource".to_string(),
                serde_json::json!("developer_activity_policy_decision"),
            );
            metadata.insert(
                "collectorKind".to_string(),
                serde_json::json!("developer_activity"),
            );
            metadata.insert(
                "providerId".to_string(),
                serde_json::json!("developer_activity.policy_check"),
            );
            metadata.insert(
                "policyDecisionMode".to_string(),
                serde_json::json!("policy_check"),
            );
            metadata.insert(
                "sourceObservationId".to_string(),
                serde_json::json!(observation.observation_id.as_str()),
            );

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

pub(super) fn developer_activity_policy_allowed(observation: &EndpointObservation) -> Option<bool> {
    let value = observation.metadata.get("policyAllowed")?;
    if let Some(value) = value.as_bool() {
        return Some(value);
    }
    match value.as_str()?.trim().to_ascii_lowercase().as_str() {
        "allow" | "allowed" | "pass" | "passed" | "permit" | "permitted" | "true" => Some(true),
        "block" | "blocked" | "deny" | "denied" | "drop" | "dropped" | "false" => Some(false),
        _ => None,
    }
}

pub(super) fn developer_activity_metadata_string(
    observation: &EndpointObservation,
    key: &str,
) -> Option<String> {
    observation
        .metadata
        .get(key)
        .and_then(serde_json::Value::as_str)
        .and_then(|value| trimmed_owned(Some(value)))
}

fn developer_activity_policy_decision_target(observation: &EndpointObservation) -> Option<String> {
    match &observation.event {
        EndpointEvent::ToolCall { tool_name, .. } => {
            Some(format!("endpoint.developer_activity.tool:{tool_name}"))
        }
        EndpointEvent::DnsLookup { query, .. } => Some(format!("dns:{query}")),
        EndpointEvent::NetworkFlow { host, port, .. } => Some(format!("{host}:{port}")),
        EndpointEvent::FileAccess { path, .. } => Some(path.clone()),
        EndpointEvent::BrowserDownload {
            path, source_url, ..
        } => source_url.clone().or_else(|| Some(path.clone())),
        EndpointEvent::BrowserExtensionInstall {
            path, extension_id, ..
        } => extension_id
            .clone()
            .map(|extension_id| format!("browser_extension:{extension_id}"))
            .or_else(|| Some(path.clone())),
        EndpointEvent::PackageScript {
            manager,
            package,
            phase,
            script,
            ..
        } => Some(format!(
            "endpoint.package_script:{}:{}:{}:{}",
            manager.as_str(),
            package.as_deref().unwrap_or("unknown-package"),
            phase,
            sha256(script.as_bytes()).to_hex_prefixed()
        )),
        EndpointEvent::ProcessExec { image, args, .. } => Some(format!(
            "process_exec:{}:{}",
            image,
            sha256(args.join("\n").as_bytes()).to_hex_prefixed()
        )),
        EndpointEvent::DylibLoad { path, .. } => Some(path.clone()),
        EndpointEvent::CredentialAccess { path, name, .. } => path.clone().or_else(|| name.clone()),
        EndpointEvent::LaunchPersistence { path, .. } => Some(path.clone()),
        EndpointEvent::PolicyDecision { .. } => None,
        EndpointEvent::Other { category, .. } => Some(format!("other:{category}")),
    }
}
