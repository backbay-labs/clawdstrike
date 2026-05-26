//! Generic EDR findings ingestion handler.
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
