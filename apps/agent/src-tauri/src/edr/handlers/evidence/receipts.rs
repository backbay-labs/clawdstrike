//! Receipt query / upload / compaction handlers.
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
use hush_core::sha256;
#[allow(unused_imports)]
use std::sync::Arc;

pub(crate) async fn agent_edr_receipts(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Query(query): Query<EdrReceiptQuery>,
) -> Result<Json<EdrReceiptsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let limit = bounded_request_limit(
        "limit",
        query.limit,
        EDR_DEFAULT_RECEIPT_QUERY_LIMIT,
        EDR_MAX_RECEIPT_QUERY_LIMIT,
    )?;
    let family = query
        .family
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let filter = EdrReceiptFilter {
        receipt_id: query_value(&query.receipt_id),
        family,
        action: query_value(&query.action),
        finding_id: query_value(&query.finding_id),
        rule_id: query_value(&query.rule_id),
        graph_slice_id: query_value(&query.graph_slice_id),
        root_node_id: query_value(&query.root_node_id),
        execution_id: query_value(&query.execution_id),
        status: query_value(&query.status),
        actor_endpoint_id: query_value(&query.actor_endpoint_id),
        actor_user_id: query_value(&query.actor_user_id),
        actor_session_id: query_value(&query.actor_session_id),
        actor_agent_id: query_value(&query.actor_agent_id),
        actor_workload_id: query_value(&query.actor_workload_id),
        actor_approval_id: query_value(&query.actor_approval_id),
        local_sequence: query.local_sequence,
    };
    let ledger = state.edr_receipt_ledger.lock().await;
    let path = ledger.path().map(|path| path.display().to_string());
    let receipts = ledger.read_recent(limit, filter).map_err(internal_error)?;

    Ok(Json(EdrReceiptsResponse {
        path,
        receipt_count: receipts.len(),
        receipts,
    }))
}

pub(crate) async fn agent_edr_receipts_upload(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrReceiptUploadInput>,
) -> Result<Json<EdrReceiptUploadResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let limit = bounded_request_limit(
        "limit",
        input.limit,
        EDR_DEFAULT_RECEIPT_QUERY_LIMIT,
        EDR_MAX_RECEIPT_QUERY_LIMIT,
    )?;
    let family = input
        .family
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let filter = EdrReceiptFilter {
        receipt_id: query_value(&input.receipt_id),
        family,
        action: query_value(&input.action),
        finding_id: query_value(&input.finding_id),
        rule_id: query_value(&input.rule_id),
        graph_slice_id: query_value(&input.graph_slice_id),
        root_node_id: query_value(&input.root_node_id),
        execution_id: query_value(&input.execution_id),
        status: query_value(&input.status),
        actor_endpoint_id: query_value(&input.actor_endpoint_id),
        actor_user_id: query_value(&input.actor_user_id),
        actor_session_id: query_value(&input.actor_session_id),
        actor_agent_id: query_value(&input.actor_agent_id),
        actor_workload_id: query_value(&input.actor_workload_id),
        actor_approval_id: query_value(&input.actor_approval_id),
        local_sequence: input.local_sequence,
    };
    let (path, receipts) = {
        let ledger = state.edr_receipt_ledger.lock().await;
        let path = ledger.path().map(|path| path.display().to_string());
        let receipts = ledger.read_recent(limit, filter).map_err(internal_error)?;
        (path, receipts)
    };
    let dry_run = input.dry_run.unwrap_or(true);
    let mut control_receipts = Vec::with_capacity(receipts.len());
    let mut records = Vec::with_capacity(receipts.len());
    for receipt in &receipts {
        let control_receipt = control_store_receipt_from_endpoint_receipt(receipt)
            .map_err(|message| (StatusCode::CONFLICT, message))?;
        records.push(EdrReceiptUploadRecord {
            receipt_id: receipt.receipt.receipt_id.clone(),
            timestamp: control_receipt.timestamp.clone(),
            family: receipt_family(receipt).map(ToString::to_string),
            verdict: control_receipt.verdict.clone(),
            guard: control_receipt.guard.clone(),
            policy_name: control_receipt.policy_name.clone(),
            local_sequence: receipt_local_sequence(receipt),
        });
        control_receipts.push(control_receipt);
    }

    let settings = state.settings.read().await.clone();
    let control_api_url = non_empty(settings.control_api.url.as_deref()).map(ToString::to_string);
    if control_receipts.is_empty() {
        return Ok(Json(EdrReceiptUploadResponse {
            path,
            dry_run,
            control_api_url,
            selected_count: 0,
            attempted: false,
            accepted: true,
            uploaded_count: 0,
            http_status: None,
            response_hash: None,
            error_hash: None,
            skipped_reason: Some("no receipts matched upload filter".to_string()),
            records,
        }));
    }
    if dry_run {
        return Ok(Json(EdrReceiptUploadResponse {
            path,
            dry_run,
            control_api_url,
            selected_count: control_receipts.len(),
            attempted: false,
            accepted: false,
            uploaded_count: 0,
            http_status: None,
            response_hash: None,
            error_hash: None,
            skipped_reason: Some("dry run".to_string()),
            records,
        }));
    }
    require_cloud_mode_enrolled_receipt_signer(&state, "endpoint receipt upload").await?;
    require_cloud_mode_receipts_signed_by_current_signer(
        &state,
        &receipts,
        "endpoint receipt upload",
    )
    .await?;
    if !settings.control_api.enabled {
        return Err((
            StatusCode::CONFLICT,
            "control API is not enabled for endpoint receipt upload".to_string(),
        ));
    }
    let Some(control_api_url) = control_api_url else {
        return Err((
            StatusCode::BAD_REQUEST,
            "control API URL is not configured for endpoint receipt upload".to_string(),
        ));
    };
    let Some(api_key) = non_empty(settings.control_api.api_key.as_deref()).map(ToString::to_string)
    else {
        return Err((
            StatusCode::BAD_REQUEST,
            "control API key is not configured for endpoint receipt upload".to_string(),
        ));
    };
    let url = control_api_receipt_batch_upload_url(&control_api_url)?;
    let selected_count = control_receipts.len();
    let payload = ControlBatchStoreReceiptsRequest {
        receipts: control_receipts,
    };
    let response = state
        .http_client
        .post(url)
        .header("x-api-key", api_key)
        .json(&payload)
        .send()
        .await
        .map_err(|err| {
            (
                StatusCode::BAD_GATEWAY,
                format!("endpoint receipt upload failed: {err}"),
            )
        })?;
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let bytes = response.bytes().await.map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!("endpoint receipt upload response body read failed: {err}"),
        )
    })?;
    let response_hash = Some(sha256(&bytes).to_hex_prefixed());
    let response_value: serde_json::Value =
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    let uploaded_count = if status.is_success() {
        response_value
            .get("count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as usize
    } else {
        0
    };
    let error_hash = if status.is_success() {
        None
    } else {
        response_hash.clone()
    };

    Ok(Json(EdrReceiptUploadResponse {
        path,
        dry_run,
        control_api_url: Some(control_api_url),
        selected_count,
        attempted: true,
        accepted: status.is_success(),
        uploaded_count,
        http_status: Some(status.as_u16()),
        response_hash,
        error_hash,
        skipped_reason: None,
        records,
    }))
}

pub(crate) async fn agent_edr_receipts_compact(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrReceiptCompactionInput>,
) -> Result<Json<EdrReceiptCompactionResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    if input.max_receipts.is_none() && input.min_age_seconds.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "max_receipts or min_age_seconds must be provided".to_string(),
        ));
    }
    let dry_run = input.dry_run.unwrap_or(true);
    let min_age_seconds = input.min_age_seconds.unwrap_or(0);
    let now = chrono::Utc::now();
    let mut ledger = state.edr_receipt_ledger.lock().await;
    let path = ledger.path().map(|path| path.display().to_string());
    let report = ledger
        .compact(input.max_receipts, min_age_seconds, dry_run, now)
        .map_err(internal_error)?;

    Ok(Json(EdrReceiptCompactionResponse {
        path,
        dry_run,
        max_receipts: input.max_receipts,
        min_age_seconds,
        receipt_count: report.receipt_count,
        candidate_count: report.records.len(),
        removed_count: report
            .records
            .iter()
            .filter(|record| record.removed)
            .count(),
        retained_count: report.retained_count,
        records: report.records,
    }))
}
