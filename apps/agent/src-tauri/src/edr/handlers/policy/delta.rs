//! Policy delta generation and listing handlers.
#[allow(unused_imports, clippy::wildcard_imports)]
use crate::api_server::*;
#[allow(unused_imports)]
use axum::extract::{Query, State};
#[allow(unused_imports)]
use axum::http::{HeaderMap, StatusCode};
#[allow(unused_imports)]
use axum::Json;
#[allow(unused_imports)]
use clawdstrike_policy_event::edr::*;
#[allow(unused_imports)]
use std::sync::Arc;

pub(crate) async fn agent_edr_policy_delta(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrPolicyDeltaInput>,
) -> Result<Json<EdrPolicyDeltaResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let generated_by = input
        .generated_by
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("local-agent");
    if generated_by.len() > 256 {
        return Err((
            StatusCode::BAD_REQUEST,
            "generated_by must be at most 256 bytes".to_string(),
        ));
    }
    let note = input
        .note
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    if note.as_deref().is_some_and(|value| value.len() > 2048) {
        return Err((
            StatusCode::BAD_REQUEST,
            "policy delta note must be at most 2048 bytes".to_string(),
        ));
    }

    let staged_detection_id = query_value(&input.staged_detection_id).map(ToString::to_string);
    let rule_id = query_value(&input.rule_id).map(ToString::to_string);
    let stage = query_value(&input.stage).map(ToString::to_string);
    let staged = {
        let ledger = state.edr_staged_detection_ledger.lock().await;
        let records = ledger.all().map_err(internal_error)?;
        select_staged_detection_for_policy_delta(
            records,
            staged_detection_id.as_deref(),
            rule_id.as_deref(),
            stage.as_deref(),
        )?
    };
    let stage_entry = staged_detection_stage_entry(&staged)?;
    let settings = state.settings.read().await.clone();
    let endpoint_id = endpoint_id_for_settings(&settings);
    let generated_at = chrono::Utc::now();
    let generated_at_text = generated_at.to_rfc3339();
    let source_affected_identity_context =
        policy_delta_source_context_evidence_value(&staged.simulation.affected_identities);
    let source_affected_tool_context =
        policy_delta_source_context_evidence_value(&staged.simulation.affected_tools);
    let policy_delta_id = endpoint_policy_delta_id(EndpointPolicyDeltaIdInput {
        endpoint_id: endpoint_id.as_str(),
        rule_id: staged.candidate.rule_id.as_str(),
        action: &stage_entry.action,
        staged_detection_id: staged.staged_detection_id.as_str(),
        stage: staged.stage.as_str(),
        generated_at: generated_at_text.as_str(),
        simulation_id: staged.simulation.simulation_id.as_str(),
        graph_slice_id: staged.candidate.graph_slice_id.as_str(),
        root_node_id: staged.candidate.root_node_id.as_str(),
        source_affected_identity_context: source_affected_identity_context.as_str(),
        source_affected_tool_context: source_affected_tool_context.as_str(),
    });
    let artifact = build_edr_policy_delta_artifact(
        &staged,
        stage_entry,
        policy_delta_id,
        generated_at,
        generated_by,
        note,
    )?;
    let artifact_hash = policy_delta_artifact_hash(&artifact).map_err(internal_error)?;
    let sensor_state = endpoint_sensor_state_from_macos_host(&state.macos_host.snapshot().await);
    let receipt = {
        let mut ledger = state.edr_receipt_ledger.lock().await;
        ledger
            .sign_policy_delta_receipt(
                &settings,
                staged.policy.clone(),
                sensor_state,
                EdrPolicyDeltaReceiptSigningInput {
                    artifact: &artifact,
                    artifact_hash: &artifact_hash,
                    operation: "generated",
                    actor: None,
                    previous_policy_hash: None,
                    new_policy_hash: None,
                    backup_path: None,
                },
            )
            .map_err(internal_error)?
    };
    let mut record = EdrPolicyDeltaRecord {
        policy_delta_id: artifact.policy_delta_id.clone(),
        generated_at: artifact.generated_at,
        generated_by: artifact.generated_by.clone(),
        rule_id: artifact.candidate.rule_id.clone(),
        stage: artifact.rollout.stage.clone(),
        action: artifact.rollout.action.clone(),
        artifact_hash,
        artifact_path: None,
        artifact,
        receipt,
    };
    let path = {
        let mut store = state.edr_policy_delta_store.lock().await;
        store.append(&mut record).map_err(internal_error)?;
        store.path().map(|path| path.display().to_string())
    };

    Ok(Json(EdrPolicyDeltaResponse { path, record }))
}

pub(crate) async fn agent_edr_policy_deltas(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Query(query): Query<EdrPolicyDeltasQuery>,
) -> Result<Json<EdrPolicyDeltasResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let limit = bounded_request_limit("limit", query.limit, 50, EDR_MAX_STORED_FINDINGS)?;
    let stage = query_value(&query.stage).map(ToString::to_string);
    let rule_id = query_value(&query.rule_id).map(ToString::to_string);
    let store = state.edr_policy_delta_store.lock().await;
    let path = store.path().map(|path| path.display().to_string());
    let policy_deltas = store
        .read_recent(limit, stage.as_deref(), rule_id.as_deref())
        .map_err(internal_error)?;
    Ok(Json(EdrPolicyDeltasResponse {
        path,
        count: policy_deltas.len(),
        policy_deltas,
    }))
}
