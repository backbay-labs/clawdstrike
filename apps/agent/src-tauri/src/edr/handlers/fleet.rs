//! Fleet operations and control retry handlers.
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
use hush_core::SignedReceipt;
#[allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use serde_json::Value;
#[allow(unused_imports)]
use std::collections::{BTreeMap, BTreeSet, HashMap};
#[allow(unused_imports)]
use std::sync::Arc;

pub(crate) async fn agent_edr_fleet_hunt_events_retry(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrFleetHuntEventRetryInput>,
) -> Result<Json<EdrFleetHuntEventRetryResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let limit = bounded_request_limit("limit", input.limit, 25, 100)?;
    let publisher = state
        .fleet_hunt_publisher
        .as_ref()
        .cloned()
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "fleet hunt publisher is unavailable because NATS is not connected".to_string(),
            )
        })?;
    drain_fleet_hunt_event_outbox(state.as_ref(), publisher, limit, input.force)
        .await
        .map(Json)
}

pub(crate) async fn agent_edr_control_archive_uploads_backfill(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrControlArchiveUploadBackfillInput>,
) -> Result<Json<EdrControlArchiveUploadBackfillResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let approval_resource =
        raw_artifact_approval_resource_for_control_archive_backfill(input.bundle_id.as_deref());
    let raw_artifact_approval = validate_resolved_raw_artifact_approval(
        &state,
        validate_raw_artifact_approval_fields(
            input.raw_artifact_approval_id.as_deref(),
            input.raw_artifact_approval_reason.as_deref(),
        )?,
        &approval_resource,
    )
    .await?;
    let limit = bounded_request_limit("limit", input.limit, 25, 100)?;
    let bundle_ids = control_archive_backfill_bundle_ids(&state, &input, limit).await?;
    let endpoint_agent_id = local_endpoint_agent_id(&state).await;

    let mut records = Vec::new();
    let mut attempted = 0usize;
    let mut delivered = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;
    for bundle_id in bundle_ids {
        let archive_response = evidence_bundle_archive_response(&state, &bundle_id).await?;
        if !archive_response.verification.verified {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "evidence bundle archive verification failed for {}; refusing Control API backfill",
                    archive_response.archive.bundle.bundle_id
                ),
            ));
        }
        let raw_ref = evidence_bundle_archive_raw_ref(
            &archive_response.archive_id,
            &archive_response.archive_hash,
        );
        let event_id = format!(
            "evidence-bundle-archive-backfill:{}:{}",
            endpoint_agent_id, archive_response.archive_id
        );
        let control_upload = post_control_endpoint_evidence_archive(
            &state,
            &archive_response,
            &endpoint_agent_id,
            &event_id,
            &raw_ref,
            "local_backfill",
            raw_artifact_approval.as_ref(),
        )
        .await?;
        match control_upload.as_ref() {
            Some(report) if report.attempted && report.accepted => {
                attempted += 1;
                delivered += 1;
            }
            Some(report) if report.attempted => {
                attempted += 1;
                failed += 1;
            }
            Some(_) | None => {
                skipped += 1;
            }
        }
        records.push(EdrControlArchiveUploadBackfillRecord {
            bundle_id: archive_response.archive.bundle.bundle_id,
            archive_id: archive_response.archive_id,
            archive_hash: archive_response.archive_hash,
            raw_ref,
            control_upload,
        });
    }

    Ok(Json(EdrControlArchiveUploadBackfillResponse {
        attempted,
        delivered,
        failed,
        skipped,
        records,
    }))
}

pub(crate) async fn agent_edr_control_archive_uploads_retry(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrControlArchiveUploadRetryInput>,
) -> Result<Json<EdrControlArchiveUploadRetryResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let limit = bounded_request_limit("limit", input.limit, 25, 100)?;
    let now = chrono::Utc::now();
    let (path, pending_before, due) = {
        let ledger = state.edr_control_archive_upload_retry_ledger.lock().await;
        (
            ledger.path().map(|path| path.display().to_string()),
            ledger.pending_count(),
            ledger.due(now, limit, input.force),
        )
    };

    let mut attempts = Vec::new();
    let mut delivered = 0usize;
    let mut failed = 0usize;
    for retry in due {
        let outcome = send_control_archive_upload_retry(&state, &retry).await;
        let attempted_count = retry.attempt_count.saturating_add(1);
        if outcome.accepted {
            delivered += 1;
            let mut ledger = state.edr_control_archive_upload_retry_ledger.lock().await;
            ledger
                .mark_delivered(&retry.retry_id)
                .map_err(internal_error)?;
            attempts.push(EdrControlArchiveUploadRetryAttemptRecord {
                retry_id: retry.retry_id,
                archive_id: retry.archive_id,
                archive_hash: retry.archive_hash,
                raw_ref: retry.raw_ref,
                bundle_id: retry.bundle_id,
                control_api_url: retry.control_api_url,
                delivered: true,
                attempt_count: attempted_count,
                next_attempt_at: None,
                http_status: outcome.http_status,
                response_hash: outcome.response_hash,
                error_hash: outcome.error_hash,
            });
        } else {
            failed += 1;
            let mut ledger = state.edr_control_archive_upload_retry_ledger.lock().await;
            let updated = ledger
                .mark_failed(
                    &retry.retry_id,
                    chrono::Utc::now(),
                    outcome.http_status,
                    outcome.response_hash.clone(),
                    outcome.error_hash.clone(),
                )
                .map_err(internal_error)?
                .unwrap_or_else(|| retry.clone());
            attempts.push(EdrControlArchiveUploadRetryAttemptRecord {
                retry_id: retry.retry_id,
                archive_id: retry.archive_id,
                archive_hash: retry.archive_hash,
                raw_ref: retry.raw_ref,
                bundle_id: retry.bundle_id,
                control_api_url: retry.control_api_url,
                delivered: false,
                attempt_count: updated.attempt_count,
                next_attempt_at: Some(updated.next_attempt_at),
                http_status: outcome.http_status,
                response_hash: outcome.response_hash,
                error_hash: outcome.error_hash,
            });
        }
    }

    let pending = state
        .edr_control_archive_upload_retry_ledger
        .lock()
        .await
        .pending_count();
    Ok(Json(EdrControlArchiveUploadRetryResponse {
        path,
        attempted: attempts.len(),
        delivered,
        failed,
        skipped: pending_before.saturating_sub(attempts.len()),
        pending,
        attempts,
    }))
}

pub(crate) async fn agent_edr_control_receipt_uploads_retry(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrControlReceiptUploadRetryInput>,
) -> Result<Json<EdrControlReceiptUploadRetryResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let limit = bounded_request_limit("limit", input.limit, 25, 100)?;
    drain_control_receipt_upload_retries(&state, limit, input.force)
        .await
        .map(Json)
}

pub(crate) async fn agent_edr_control_ack_postbacks_retry(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrControlAckPostbackRetryInput>,
) -> Result<Json<EdrControlAckPostbackRetryResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let limit = bounded_request_limit("limit", input.limit, 25, 100)?;
    drain_control_ack_postback_retries(&state, limit, input.force)
        .await
        .map(Json)
}
