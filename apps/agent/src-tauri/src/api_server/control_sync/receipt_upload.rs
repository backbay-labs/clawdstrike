use super::*;

pub(crate) struct ControlReceiptUploadAttemptFailure {
    http_status: Option<u16>,
    response_hash: Option<String>,
    error_hash: Option<String>,
}

pub(crate) async fn enqueue_control_receipt_upload_retry(
    state: &AgentApiState,
    control_api_url: &str,
    receipt: &ControlStoreReceiptRequest,
    failure: ControlReceiptUploadAttemptFailure,
) -> Result<(String, chrono::DateTime<chrono::Utc>), (StatusCode, String)> {
    let signed_receipt = receipt.signed_receipt.as_ref().ok_or_else(|| {
        internal_error(anyhow::anyhow!(
            "control receipt upload retry requires signed_receipt"
        ))
    })?;
    let receipt_hash =
        canonical_json_hash(signed_receipt, "control receipt upload signed receipt")
            .map_err(internal_error)?;
    let receipt_id = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("receiptId"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let control_api_url = control_api_url.trim().trim_end_matches('/').to_string();
    let now = chrono::Utc::now();
    let attempt_count = 1;
    let retry_id = sha256(format!("{control_api_url}:{receipt_hash}").as_bytes()).to_hex_prefixed();
    let next_attempt_at =
        now + chrono::Duration::seconds(control_ack_retry_backoff_seconds(attempt_count));
    let retry = EndpointControlReceiptUploadRetry {
        retry_id: retry_id.clone(),
        control_api_url,
        receipt_id,
        receipt_hash,
        payload: receipt.clone(),
        attempt_count,
        next_attempt_at,
        last_attempt_at: Some(now),
        last_http_status: failure.http_status,
        last_response_hash: failure.response_hash,
        last_error_hash: failure.error_hash,
        created_at: now,
        updated_at: now,
    };
    state
        .edr_control_receipt_upload_retry_ledger
        .lock()
        .await
        .append(retry)
        .map_err(internal_error)?;
    Ok((retry_id, next_attempt_at))
}

pub(crate) async fn resolve_control_receipt_upload_api_key(
    state: &AgentApiState,
    retry: &EndpointControlReceiptUploadRetry,
) -> Option<String> {
    let settings = state.settings.read().await;
    let configured_url = settings
        .control_api
        .url
        .as_deref()
        .map(str::trim)
        .map(|url| url.trim_end_matches('/'));
    let retry_url = retry.control_api_url.trim().trim_end_matches('/');
    if settings.control_api.enabled && configured_url == Some(retry_url) {
        non_empty(settings.control_api.api_key.as_deref()).map(ToString::to_string)
    } else {
        None
    }
}

pub(crate) struct ControlReceiptUploadRetryAttemptOutcome {
    pub(crate) accepted: bool,
    pub(crate) http_status: Option<u16>,
    pub(crate) response_hash: Option<String>,
    pub(crate) error_hash: Option<String>,
}

pub(crate) async fn send_control_receipt_upload_retry(
    state: &AgentApiState,
    retry: &EndpointControlReceiptUploadRetry,
) -> ControlReceiptUploadRetryAttemptOutcome {
    if let Err((_status, message)) =
        require_cloud_mode_enrolled_receipt_signer(state, "endpoint receipt upload retry").await
    {
        let error = truncate_delivery_error(&message);
        return ControlReceiptUploadRetryAttemptOutcome {
            accepted: false,
            http_status: None,
            response_hash: None,
            error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
        };
    }
    let settings = state.settings.read().await.clone();
    if edr_receipt_signer_requires_enrollment(&settings) {
        let signer_public_key = {
            let ledger = state.edr_receipt_ledger.lock().await;
            ledger.signer_public_key.clone()
        };
        if retry.payload.public_key != signer_public_key {
            let error = truncate_delivery_error(
                "endpoint receipt upload retry payload is not signed by the current enrolled EDR signer",
            );
            return ControlReceiptUploadRetryAttemptOutcome {
                accepted: false,
                http_status: None,
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    }
    let Some(api_key) = resolve_control_receipt_upload_api_key(state, retry).await else {
        let error = truncate_delivery_error(
            "control API key is unavailable or URL no longer matches for endpoint receipt upload retry",
        );
        return ControlReceiptUploadRetryAttemptOutcome {
            accepted: false,
            http_status: None,
            response_hash: None,
            error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
        };
    };
    let url = match control_api_receipt_batch_upload_url(&retry.control_api_url) {
        Ok(url) => url,
        Err((_status, message)) => {
            let error = truncate_delivery_error(&message);
            return ControlReceiptUploadRetryAttemptOutcome {
                accepted: false,
                http_status: None,
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    };
    let payload = ControlBatchStoreReceiptsRequest {
        receipts: vec![retry.payload.clone()],
    };
    let response = match state
        .http_client
        .post(url)
        .header("x-api-key", api_key)
        .json(&payload)
        .timeout(EDR_CONTROL_RECEIPT_UPLOAD_REQUEST_TIMEOUT)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            return ControlReceiptUploadRetryAttemptOutcome {
                accepted: false,
                http_status: None,
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    };
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    match response.bytes().await {
        Ok(bytes) => ControlReceiptUploadRetryAttemptOutcome {
            accepted: status.is_success(),
            http_status: Some(status.as_u16()),
            response_hash: Some(sha256(&bytes).to_hex_prefixed()),
            error_hash: None,
        },
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            ControlReceiptUploadRetryAttemptOutcome {
                accepted: false,
                http_status: Some(status.as_u16()),
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            }
        }
    }
}

pub(crate) async fn post_control_endpoint_receipts_best_effort(
    state: &AgentApiState,
    receipts: &[SignedReceipt],
    upload_path: &str,
) {
    if receipts.is_empty() {
        return;
    }
    let settings = state.settings.read().await.clone();
    if !settings.control_api.enabled {
        return;
    }
    if let Err((_status, err)) =
        require_cloud_mode_enrolled_receipt_signer(state, "automatic endpoint receipt upload").await
    {
        tracing::warn!(
            error = %err,
            upload_path,
            "Skipping automatic endpoint receipt upload because the EDR signer is not enrolled"
        );
        return;
    }
    if let Err((_status, err)) = require_cloud_mode_receipts_signed_by_current_signer(
        state,
        receipts,
        "automatic endpoint receipt upload",
    )
    .await
    {
        tracing::warn!(
            error = %err,
            upload_path,
            "Skipping automatic endpoint receipt upload because a receipt is not signed by the current enrolled signer"
        );
        return;
    }
    let Some(control_api_url) =
        non_empty(settings.control_api.url.as_deref()).map(ToString::to_string)
    else {
        return;
    };
    let Some(api_key) = non_empty(settings.control_api.api_key.as_deref()).map(ToString::to_string)
    else {
        return;
    };
    let url = match control_api_receipt_batch_upload_url(&control_api_url) {
        Ok(url) => url,
        Err((_status, err)) => {
            tracing::warn!(
                error = %err,
                upload_path,
                "Skipping automatic endpoint receipt upload because Control API URL is invalid"
            );
            return;
        }
    };
    let mut control_receipts = Vec::with_capacity(receipts.len());
    for receipt in receipts {
        match control_store_receipt_from_endpoint_receipt(receipt) {
            Ok(control_receipt) => control_receipts.push(control_receipt),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    receipt_id = receipt.receipt.receipt_id.as_deref().unwrap_or("<missing>"),
                    upload_path,
                    "Skipping invalid automatic endpoint receipt upload candidate"
                );
            }
        }
    }
    if control_receipts.is_empty() {
        return;
    }
    let payload = ControlBatchStoreReceiptsRequest {
        receipts: control_receipts.clone(),
    };
    let response = match state
        .http_client
        .post(url)
        .header("x-api-key", api_key)
        .json(&payload)
        .timeout(EDR_CONTROL_RECEIPT_UPLOAD_REQUEST_TIMEOUT)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            let error_hash = Some(sha256(error.as_bytes()).to_hex_prefixed());
            for receipt in &control_receipts {
                if let Err((_status, enqueue_err)) = enqueue_control_receipt_upload_retry(
                    state,
                    &control_api_url,
                    receipt,
                    ControlReceiptUploadAttemptFailure {
                        http_status: None,
                        response_hash: None,
                        error_hash: error_hash.clone(),
                    },
                )
                .await
                {
                    tracing::warn!(
                        error = %enqueue_err,
                        upload_path,
                        "Failed to queue automatic endpoint receipt upload retry"
                    );
                }
            }
            return;
        }
    };
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let response_hash = match response.bytes().await {
        Ok(bytes) => Some(sha256(&bytes).to_hex_prefixed()),
        Err(err) => Some(sha256(err.to_string().as_bytes()).to_hex_prefixed()),
    };
    if status.is_success() {
        tracing::debug!(
            count = control_receipts.len(),
            upload_path,
            "Uploaded endpoint receipts to Control API"
        );
        return;
    }
    for receipt in &control_receipts {
        if let Err((_status, enqueue_err)) = enqueue_control_receipt_upload_retry(
            state,
            &control_api_url,
            receipt,
            ControlReceiptUploadAttemptFailure {
                http_status: Some(status.as_u16()),
                response_hash: response_hash.clone(),
                error_hash: None,
            },
        )
        .await
        {
            tracing::warn!(
                error = %enqueue_err,
                upload_path,
                "Failed to queue automatic endpoint receipt upload retry"
            );
        }
    }
}
