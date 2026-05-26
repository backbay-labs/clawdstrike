use super::*;

pub(crate) async fn local_endpoint_agent_id(state: &AgentApiState) -> String {
    let mut settings = state.settings.write().await;
    resolve_effective_endpoint_agent_id(&mut settings, None)
}

pub(crate) async fn control_archive_backfill_bundle_ids(
    state: &AgentApiState,
    input: &EdrControlArchiveUploadBackfillInput,
    limit: usize,
) -> Result<Vec<String>, (StatusCode, String)> {
    if let Some(bundle_id) = input.bundle_id.as_deref() {
        let bundle_id = bundle_id.trim();
        if bundle_id.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "bundleId must not be empty when provided".to_string(),
            ));
        }
        return Ok(vec![bundle_id.to_string()]);
    }

    let mut store = state.edr_evidence_bundle_store.lock().await;
    let bundles = store.list().map_err(internal_error)?;
    Ok(bundles
        .into_iter()
        .take(limit)
        .map(|stored| stored.bundle.bundle_id)
        .collect())
}

pub(crate) async fn drain_control_receipt_upload_retries(
    state: &Arc<AgentApiState>,
    limit: usize,
    force: bool,
) -> Result<EdrControlReceiptUploadRetryResponse, (StatusCode, String)> {
    let limit = limit.clamp(1, 100);
    let now = chrono::Utc::now();
    let (path, pending_before, due) = {
        let ledger = state.edr_control_receipt_upload_retry_ledger.lock().await;
        (
            ledger.path().map(|path| path.display().to_string()),
            ledger.pending_count(),
            ledger.due(now, limit, force),
        )
    };

    let mut attempts = Vec::new();
    let mut delivered = 0usize;
    let mut failed = 0usize;
    for retry in due {
        let outcome = send_control_receipt_upload_retry(state, &retry).await;
        let attempted_count = retry.attempt_count.saturating_add(1);
        if outcome.accepted {
            delivered += 1;
            let mut ledger = state.edr_control_receipt_upload_retry_ledger.lock().await;
            ledger
                .mark_delivered(&retry.retry_id)
                .map_err(internal_error)?;
            attempts.push(EdrControlReceiptUploadRetryAttemptRecord {
                retry_id: retry.retry_id,
                receipt_id: retry.receipt_id,
                receipt_hash: retry.receipt_hash,
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
            let mut ledger = state.edr_control_receipt_upload_retry_ledger.lock().await;
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
            attempts.push(EdrControlReceiptUploadRetryAttemptRecord {
                retry_id: retry.retry_id,
                receipt_id: retry.receipt_id,
                receipt_hash: retry.receipt_hash,
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
        .edr_control_receipt_upload_retry_ledger
        .lock()
        .await
        .pending_count();
    Ok(EdrControlReceiptUploadRetryResponse {
        path,
        attempted: attempts.len(),
        delivered,
        failed,
        skipped: pending_before.saturating_sub(attempts.len()),
        pending,
        attempts,
    })
}

pub(crate) async fn drain_control_ack_postback_retries(
    state: &Arc<AgentApiState>,
    limit: usize,
    force: bool,
) -> Result<EdrControlAckPostbackRetryResponse, (StatusCode, String)> {
    let limit = limit.clamp(1, 100);
    let now = chrono::Utc::now();
    let (path, pending_before, due) = {
        let ledger = state.edr_control_ack_postback_retry_ledger.lock().await;
        (
            ledger.path().map(|path| path.display().to_string()),
            ledger.pending_count(),
            ledger.due(now, limit, force),
        )
    };

    let mut attempts = Vec::new();
    let mut delivered = 0usize;
    let mut failed = 0usize;
    for retry in due {
        let outcome = send_control_ack_postback_retry(state, &retry).await;
        let attempted_count = retry.attempt_count.saturating_add(1);
        if outcome.accepted {
            delivered += 1;
            let mut ledger = state.edr_control_ack_postback_retry_ledger.lock().await;
            ledger
                .mark_delivered(&retry.retry_id)
                .map_err(internal_error)?;
            attempts.push(EdrControlAckPostbackRetryAttemptRecord {
                retry_id: retry.retry_id,
                response_action_id: retry.response_action_id,
                control_api_url: retry.control_api_url,
                route: outcome.route,
                delivered: true,
                attempt_count: attempted_count,
                next_attempt_at: None,
                http_status: outcome.http_status,
                response_hash: outcome.response_hash,
                error_hash: outcome.error_hash,
            });
        } else {
            failed += 1;
            let mut ledger = state.edr_control_ack_postback_retry_ledger.lock().await;
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
            attempts.push(EdrControlAckPostbackRetryAttemptRecord {
                retry_id: retry.retry_id,
                response_action_id: retry.response_action_id,
                control_api_url: retry.control_api_url,
                route: outcome.route,
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
        .edr_control_ack_postback_retry_ledger
        .lock()
        .await
        .pending_count();
    Ok(EdrControlAckPostbackRetryResponse {
        path,
        attempted: attempts.len(),
        delivered,
        failed,
        skipped: pending_before.saturating_sub(attempts.len()),
        pending,
        attempts,
    })
}
