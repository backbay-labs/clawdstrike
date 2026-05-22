use super::*;

pub(crate) fn required_control_ack_field(
    field: &str,
    value: Option<&str>,
    max_len: usize,
) -> Result<String, (StatusCode, String)> {
    let value = non_empty(value).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("control response acknowledgement {field} is required"),
        )
    })?;
    if value.len() > max_len {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("control response acknowledgement {field} must be at most {max_len} bytes"),
        ));
    }
    Ok(value.to_string())
}

pub(crate) fn optional_control_ack_field(
    field: &str,
    value: Option<&str>,
    max_len: usize,
) -> Result<Option<String>, (StatusCode, String)> {
    let Some(value) = non_empty(value) else {
        return Ok(None);
    };
    if value.len() > max_len {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("control response acknowledgement {field} must be at most {max_len} bytes"),
        ));
    }
    Ok(Some(value.to_string()))
}

pub(crate) fn validate_control_ack_uuid(
    field: &str,
    value: &str,
) -> Result<(), (StatusCode, String)> {
    uuid::Uuid::parse_str(value).map(|_| ()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("control response acknowledgement {field} must be a UUID"),
        )
    })
}

pub(crate) fn default_control_ack_status(status: &EndpointResponseExecutionStatus) -> &'static str {
    match status {
        EndpointResponseExecutionStatus::Failed
        | EndpointResponseExecutionStatus::RollbackFailed => "failed",
        EndpointResponseExecutionStatus::Expired => "expired",
        EndpointResponseExecutionStatus::RolledBack => "rolled_back",
        _ => "acknowledged",
    }
}

pub(crate) fn normalize_control_ack_status(
    status: Option<&str>,
    execution_status: &EndpointResponseExecutionStatus,
) -> Result<String, (StatusCode, String)> {
    let status = non_empty(status).unwrap_or_else(|| default_control_ack_status(execution_status));
    match status {
        "acknowledged" | "rejected" | "failed" | "expired" | "rolled_back" => {
            Ok(status.to_string())
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unsupported control response acknowledgement status; allowed values: {EDR_CONTROL_ACK_STATUS_ALLOWLIST}"
            ),
        )),
    }
}

pub(crate) fn normalize_control_ack_target_kind(
    target_kind: &str,
) -> Result<String, (StatusCode, String)> {
    match target_kind {
        "endpoint" | "runtime" | "session" | "principal" | "grant" | "swarm" | "project" => {
            Ok(target_kind.to_string())
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unsupported control response acknowledgement targetKind; allowed values: {EDR_CONTROL_ACK_TARGET_KIND_ALLOWLIST}"
            ),
        )),
    }
}

pub(crate) fn endpoint_response_control_correlation(
    input: Option<&EdrResponseControlAcknowledgementInput>,
    execution: &EndpointResponseExecutionReport,
) -> Result<Option<EndpointResponseControlCorrelation>, (StatusCode, String)> {
    let Some(input) = input else {
        return Ok(None);
    };

    let response_action_id =
        required_control_ack_field("responseActionId", input.response_action_id.as_deref(), 128)?;
    validate_control_ack_uuid("responseActionId", &response_action_id)?;
    let delivery_id = optional_control_ack_field("deliveryId", input.delivery_id.as_deref(), 128)?;
    if let Some(delivery_id) = delivery_id.as_deref() {
        validate_control_ack_uuid("deliveryId", delivery_id)?;
    }
    let target_kind = required_control_ack_field("targetKind", input.target_kind.as_deref(), 64)?;
    let target_kind = normalize_control_ack_target_kind(&target_kind)?;
    let target_id = required_control_ack_field("targetId", input.target_id.as_deref(), 256)?;
    let ack_token = required_control_ack_field("ackToken", input.ack_token.as_deref(), 1024)?;
    let ack_status = normalize_control_ack_status(input.status.as_deref(), &execution.status)?;
    let resulting_state =
        optional_control_ack_field("resultingState", input.resulting_state.as_deref(), 256)?
            .or_else(|| Some(execution.status.as_str().to_string()));

    Ok(Some(EndpointResponseControlCorrelation {
        response_action_id,
        delivery_id,
        target_kind,
        target_id,
        ack_token_hash: sha256(ack_token.as_bytes()).to_hex_prefixed(),
        ack_status,
        resulting_state,
    }))
}

pub(crate) fn control_api_ack_postback_url(
    control_api_url: &str,
    response_action_id: &str,
    route: ControlResponseAckPostbackRoute,
) -> Result<String, (StatusCode, String)> {
    let trimmed = control_api_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "control response acknowledgement controlApiUrl must not be empty".to_string(),
        ));
    }
    let parsed = reqwest::Url::parse(trimmed).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("control response acknowledgement controlApiUrl is invalid: {err}"),
        )
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "control response acknowledgement controlApiUrl must not contain userinfo".to_string(),
        ));
    }
    match parsed.scheme() {
        "https" => {}
        "http" if control_api_url_is_loopback(&parsed) => {}
        "http" => {
            return Err((
                StatusCode::BAD_REQUEST,
                "control response acknowledgement controlApiUrl may use http only for loopback hosts"
                    .to_string(),
            ));
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "control response acknowledgement controlApiUrl must use http or https, got {other}"
                ),
            ));
        }
    }
    Ok(format!(
        "{trimmed}/api/v1/response-actions/{response_action_id}/{}",
        route.path_segment()
    ))
}

pub(crate) fn control_api_url_is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|addr| addr.is_loopback())
            .unwrap_or(false)
}

pub(crate) fn control_api_endpoint_archive_upload_url(
    control_api_url: &str,
) -> Result<String, (StatusCode, String)> {
    let trimmed = control_api_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "endpoint evidence archive controlApiUrl must not be empty".to_string(),
        ));
    }
    let parsed = reqwest::Url::parse(trimmed).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("endpoint evidence archive controlApiUrl is invalid: {err}"),
        )
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "endpoint evidence archive controlApiUrl must not contain userinfo".to_string(),
        ));
    }
    match parsed.scheme() {
        "https" => {}
        "http" if control_api_url_is_loopback(&parsed) => {}
        "http" => {
            return Err((
                StatusCode::BAD_REQUEST,
                "endpoint evidence archive controlApiUrl may use http only for loopback hosts"
                    .to_string(),
            ));
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "endpoint evidence archive controlApiUrl must use http or https, got {other}"
                ),
            ));
        }
    }
    Ok(format!("{trimmed}/api/v1/hunt/evidence-bundle-archives"))
}

pub(crate) fn control_api_receipt_batch_upload_url(
    control_api_url: &str,
) -> Result<String, (StatusCode, String)> {
    let trimmed = control_api_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "endpoint receipt upload control API URL must not be empty".to_string(),
        ));
    }
    let parsed = reqwest::Url::parse(trimmed).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("endpoint receipt upload control API URL is invalid: {err}"),
        )
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            "endpoint receipt upload control API URL must not contain userinfo".to_string(),
        ));
    }
    match parsed.scheme() {
        "https" => {}
        "http" if control_api_url_is_loopback(&parsed) => {}
        "http" => {
            return Err((
                StatusCode::BAD_REQUEST,
                "endpoint receipt upload control API URL may use http only for loopback hosts"
                    .to_string(),
            ));
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "endpoint receipt upload control API URL must use http or https, got {other}"
                ),
            ));
        }
    }
    Ok(format!("{trimmed}/api/v1/receipts/batch"))
}

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
    let receipt_hash = canonical_json_hash(
        &receipt.signed_receipt,
        "control receipt upload signed receipt",
    )
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
    accepted: bool,
    http_status: Option<u16>,
    response_hash: Option<String>,
    error_hash: Option<String>,
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

pub(crate) fn skipped_control_endpoint_archive_upload_report(
    control_api_url: Option<String>,
    raw_policy: EdrRawArtifactUploadPolicy,
    raw_artifact_approval: Option<&EdrRawArtifactApproval>,
    reason: impl Into<String>,
) -> EdrEvidenceBundleControlUploadReport {
    let reason = reason.into();
    let effective_raw_artifact_approval = raw_policy
        .allowed
        .then_some(raw_artifact_approval)
        .flatten();
    EdrEvidenceBundleControlUploadReport {
        control_api_url,
        attempted: false,
        accepted: false,
        raw_artifact_upload_allowed: raw_policy.allowed,
        raw_artifact_approval_required: raw_policy.allowed,
        raw_artifact_approval_provided: raw_artifact_approval.is_some(),
        raw_artifact_approval_id: effective_raw_artifact_approval
            .map(|approval| approval.approval_id.clone()),
        raw_artifact_approval_reason_hash: effective_raw_artifact_approval
            .map(|approval| approval.reason_hash.clone()),
        policy_source: raw_policy.source,
        skipped_reason: Some(reason.clone()),
        http_status: None,
        response_hash: None,
        error_hash: Some(sha256(reason.as_bytes()).to_hex_prefixed()),
        error: None,
        retry_queued: false,
        retry_id: None,
        next_retry_at: None,
    }
}

pub(crate) struct ControlArchiveUploadAttemptFailure {
    http_status: Option<u16>,
    response_hash: Option<String>,
    error_hash: Option<String>,
}

pub(crate) fn required_control_archive_retry_payload_string(
    payload: &serde_json::Value,
    key: &str,
) -> Result<String, (StatusCode, String)> {
    payload
        .get(key)
        .and_then(serde_json::Value::as_str)
        .and_then(|value| non_empty(Some(value)))
        .map(ToString::to_string)
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("endpoint evidence archive retry payload is missing {key}"),
            )
        })
}

pub(crate) fn control_archive_retry_payload_has_raw_artifact_approval(
    payload: &serde_json::Value,
) -> bool {
    payload
        .get("rawArtifactApprovalId")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| non_empty(Some(value)))
        .is_some()
        && payload
            .get("rawArtifactApprovalReasonHash")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| non_empty(Some(value)))
            .is_some_and(|hash| hash.starts_with("0x"))
}

pub(crate) async fn enqueue_control_archive_upload_retry(
    state: &AgentApiState,
    control_api_url: &str,
    payload: serde_json::Value,
    failure: ControlArchiveUploadAttemptFailure,
) -> Result<(String, chrono::DateTime<chrono::Utc>), (StatusCode, String)> {
    let archive_id = required_control_archive_retry_payload_string(&payload, "archiveId")?;
    let archive_hash = required_control_archive_retry_payload_string(&payload, "archiveHash")?;
    let raw_ref = required_control_archive_retry_payload_string(&payload, "rawRef")?;
    let bundle_id = required_control_archive_retry_payload_string(&payload, "bundleId")?;
    let control_api_url = control_api_url.trim().trim_end_matches('/').to_string();
    let now = chrono::Utc::now();
    let attempt_count = 1;
    let retry_id =
        sha256(format!("{control_api_url}:{archive_id}:{archive_hash}:{raw_ref}").as_bytes())
            .to_hex_prefixed();
    let next_attempt_at =
        now + chrono::Duration::seconds(control_ack_retry_backoff_seconds(attempt_count));
    let retry = EndpointControlArchiveUploadRetry {
        retry_id: retry_id.clone(),
        control_api_url,
        archive_id,
        archive_hash,
        raw_ref,
        bundle_id,
        payload,
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
        .edr_control_archive_upload_retry_ledger
        .lock()
        .await
        .append(retry)
        .map_err(internal_error)?;
    Ok((retry_id, next_attempt_at))
}

pub(crate) async fn post_control_endpoint_evidence_archive(
    state: &AgentApiState,
    archive_response: &EdrEvidenceBundleArchiveResponse,
    endpoint_agent_id: &str,
    event_id: &str,
    raw_ref: &str,
    upload_path: &str,
    raw_artifact_approval: Option<&EdrRawArtifactApproval>,
) -> Result<Option<EdrEvidenceBundleControlUploadReport>, (StatusCode, String)> {
    let settings = state.settings.read().await.clone();
    if !settings.control_api.enabled {
        return Ok(None);
    }
    require_cloud_mode_enrolled_receipt_signer(state, "raw endpoint evidence archive upload")
        .await?;
    require_cloud_mode_receipts_signed_by_current_signer(
        state,
        &archive_response.archive.receipts,
        "raw endpoint evidence archive upload",
    )
    .await?;

    let raw_policy = edr_raw_artifact_upload_policy(&settings).map_err(internal_error)?;
    let control_api_url = non_empty(settings.control_api.url.as_deref()).map(ToString::to_string);
    if !raw_policy.allowed {
        return Ok(Some(skipped_control_endpoint_archive_upload_report(
            control_api_url,
            raw_policy,
            raw_artifact_approval,
            "local policy does not allow raw endpoint evidence archive upload",
        )));
    }
    let Some(raw_artifact_approval) = raw_artifact_approval else {
        return Ok(Some(skipped_control_endpoint_archive_upload_report(
            control_api_url,
            raw_policy,
            None,
            "raw endpoint evidence archive upload requires rawArtifactApprovalId and rawArtifactApprovalReason",
        )));
    };
    let Some(control_api_url) = control_api_url else {
        return Ok(Some(skipped_control_endpoint_archive_upload_report(
            None,
            raw_policy,
            Some(raw_artifact_approval),
            "control API URL is not configured",
        )));
    };
    let Some(api_key) = non_empty(settings.control_api.api_key.as_deref()).map(ToString::to_string)
    else {
        return Ok(Some(skipped_control_endpoint_archive_upload_report(
            Some(control_api_url),
            raw_policy,
            Some(raw_artifact_approval),
            "control API key is not configured for raw endpoint evidence archive upload",
        )));
    };
    let url = control_api_endpoint_archive_upload_url(&control_api_url)?;
    let payload = serde_json::json!({
        "archiveId": archive_response.archive_id,
        "archiveHash": archive_response.archive_hash,
        "rawRef": raw_ref,
        "bundleId": archive_response.archive.bundle.bundle_id,
        "endpointAgentId": endpoint_agent_id,
        "eventId": event_id,
        "rawArtifactApprovalId": raw_artifact_approval.approval_id.as_str(),
        "rawArtifactApprovalReasonHash": raw_artifact_approval.reason_hash.as_str(),
        "archive": archive_response.archive,
        "verification": archive_response.verification,
        "metadata": {
            "source": "clawdstrike-agent",
            "uploadPath": upload_path,
            "generatedAt": archive_response.generated_at,
            "receiptCount": archive_response.receipt_count,
            "rawArtifactApprovalId": raw_artifact_approval.approval_id.as_str(),
            "rawArtifactApprovalReasonHash": raw_artifact_approval.reason_hash.as_str(),
        }
    });

    let response = match state
        .http_client
        .post(url)
        .header("x-api-key", api_key)
        .json(&payload)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            let error_hash = Some(sha256(error.as_bytes()).to_hex_prefixed());
            let (retry_id, next_retry_at) = enqueue_control_archive_upload_retry(
                state,
                &control_api_url,
                payload,
                ControlArchiveUploadAttemptFailure {
                    http_status: None,
                    response_hash: None,
                    error_hash: error_hash.clone(),
                },
            )
            .await?;
            return Ok(Some(EdrEvidenceBundleControlUploadReport {
                control_api_url: Some(control_api_url),
                attempted: true,
                accepted: false,
                raw_artifact_upload_allowed: raw_policy.allowed,
                raw_artifact_approval_required: true,
                raw_artifact_approval_provided: true,
                raw_artifact_approval_id: Some(raw_artifact_approval.approval_id.clone()),
                raw_artifact_approval_reason_hash: Some(raw_artifact_approval.reason_hash.clone()),
                policy_source: raw_policy.source,
                skipped_reason: None,
                http_status: None,
                response_hash: None,
                error_hash,
                error: Some(error),
                retry_queued: true,
                retry_id: Some(retry_id),
                next_retry_at: Some(next_retry_at),
            }));
        }
    };
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let (response_hash, error_hash, error) = match response.bytes().await {
        Ok(bytes) => (Some(sha256(&bytes).to_hex_prefixed()), None, None),
        Err(err) => {
            let error = truncate_delivery_error(&format!(
                "endpoint evidence archive upload response body read failed: {err}"
            ));
            (
                None,
                Some(sha256(error.as_bytes()).to_hex_prefixed()),
                Some(error),
            )
        }
    };
    let (retry_queued, retry_id, next_retry_at) = if status.is_success() {
        (false, None, None)
    } else {
        let (retry_id, next_retry_at) = enqueue_control_archive_upload_retry(
            state,
            &control_api_url,
            payload,
            ControlArchiveUploadAttemptFailure {
                http_status: Some(status.as_u16()),
                response_hash: response_hash.clone(),
                error_hash: error_hash.clone(),
            },
        )
        .await?;
        (true, Some(retry_id), Some(next_retry_at))
    };
    Ok(Some(EdrEvidenceBundleControlUploadReport {
        control_api_url: Some(control_api_url),
        attempted: true,
        accepted: status.is_success(),
        raw_artifact_upload_allowed: raw_policy.allowed,
        raw_artifact_approval_required: true,
        raw_artifact_approval_provided: true,
        raw_artifact_approval_id: Some(raw_artifact_approval.approval_id.clone()),
        raw_artifact_approval_reason_hash: Some(raw_artifact_approval.reason_hash.clone()),
        policy_source: raw_policy.source,
        skipped_reason: None,
        http_status: Some(status.as_u16()),
        response_hash,
        error_hash,
        error,
        retry_queued,
        retry_id,
        next_retry_at,
    }))
}

pub(crate) async fn resolve_control_archive_upload_retry_api_key(
    state: &AgentApiState,
    retry: &EndpointControlArchiveUploadRetry,
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

pub(crate) struct ControlArchiveUploadRetryAttemptOutcome {
    pub(crate) accepted: bool,
    pub(crate) http_status: Option<u16>,
    pub(crate) response_hash: Option<String>,
    pub(crate) error_hash: Option<String>,
}

pub(crate) async fn send_control_archive_upload_retry(
    state: &AgentApiState,
    retry: &EndpointControlArchiveUploadRetry,
) -> ControlArchiveUploadRetryAttemptOutcome {
    if let Err((_status, message)) =
        require_cloud_mode_enrolled_receipt_signer(state, "raw endpoint evidence archive retry")
            .await
    {
        let error = truncate_delivery_error(&message);
        return ControlArchiveUploadRetryAttemptOutcome {
            accepted: false,
            http_status: None,
            response_hash: None,
            error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
        };
    }
    if let Some(receipts_value) = retry
        .payload
        .get("archive")
        .and_then(|archive| archive.get("receipts"))
    {
        let receipts = match serde_json::from_value::<Vec<SignedReceipt>>(receipts_value.clone()) {
            Ok(receipts) => receipts,
            Err(err) => {
                let error = truncate_delivery_error(&format!(
                    "raw endpoint evidence archive retry payload receipts are invalid: {err}"
                ));
                return ControlArchiveUploadRetryAttemptOutcome {
                    accepted: false,
                    http_status: None,
                    response_hash: None,
                    error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
                };
            }
        };
        if let Err((_status, message)) = require_cloud_mode_receipts_signed_by_current_signer(
            state,
            &receipts,
            "raw endpoint evidence archive retry",
        )
        .await
        {
            let error = truncate_delivery_error(&message);
            return ControlArchiveUploadRetryAttemptOutcome {
                accepted: false,
                http_status: None,
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    }
    if !control_archive_retry_payload_has_raw_artifact_approval(&retry.payload) {
        let error = truncate_delivery_error(
            "raw endpoint evidence archive retry payload is missing raw artifact approval evidence",
        );
        return ControlArchiveUploadRetryAttemptOutcome {
            accepted: false,
            http_status: None,
            response_hash: None,
            error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
        };
    }
    let Some(api_key) = resolve_control_archive_upload_retry_api_key(state, retry).await else {
        let error = truncate_delivery_error(
            "control API key is unavailable or URL no longer matches for raw endpoint evidence archive retry",
        );
        return ControlArchiveUploadRetryAttemptOutcome {
            accepted: false,
            http_status: None,
            response_hash: None,
            error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
        };
    };
    let url = match control_api_endpoint_archive_upload_url(&retry.control_api_url) {
        Ok(url) => url,
        Err((_status, message)) => {
            let error = truncate_delivery_error(&message);
            return ControlArchiveUploadRetryAttemptOutcome {
                accepted: false,
                http_status: None,
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    };
    let response = match state
        .http_client
        .post(url)
        .header("x-api-key", api_key)
        .json(&retry.payload)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            return ControlArchiveUploadRetryAttemptOutcome {
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
        Ok(bytes) => ControlArchiveUploadRetryAttemptOutcome {
            accepted: status.is_success(),
            http_status: Some(status.as_u16()),
            response_hash: Some(sha256(&bytes).to_hex_prefixed()),
            error_hash: None,
        },
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            ControlArchiveUploadRetryAttemptOutcome {
                accepted: false,
                http_status: Some(status.as_u16()),
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ControlResponseAckPostbackRoute {
    AuthenticatedAcks,
    AgentAcks,
}

impl ControlResponseAckPostbackRoute {
    fn path_segment(self) -> &'static str {
        match self {
            Self::AuthenticatedAcks => "acks",
            Self::AgentAcks => "agent-acks",
        }
    }
}

pub(crate) struct ControlResponseAckPostbackConfig {
    pub(crate) control_api_url: String,
    pub(crate) api_key: Option<String>,
    pub(crate) route: ControlResponseAckPostbackRoute,
}

pub(crate) async fn resolve_control_response_ack_postback_config(
    state: &AgentApiState,
    input: &EdrResponseControlAcknowledgementInput,
) -> Result<Option<ControlResponseAckPostbackConfig>, (StatusCode, String)> {
    let explicit_url = non_empty(input.control_api_url.as_deref()).map(ToString::to_string);
    let explicit_api_key = non_empty(input.control_api_token.as_deref()).map(ToString::to_string);

    if let Some(control_api_url) = explicit_url {
        let configured_api_key = {
            let settings = state.settings.read().await;
            if settings.control_api.enabled {
                non_empty(settings.control_api.api_key.as_deref()).map(ToString::to_string)
            } else {
                None
            }
        };
        let api_key = explicit_api_key.or(configured_api_key);
        return Ok(Some(ControlResponseAckPostbackConfig {
            control_api_url,
            route: if api_key.is_some() {
                ControlResponseAckPostbackRoute::AuthenticatedAcks
            } else {
                ControlResponseAckPostbackRoute::AgentAcks
            },
            api_key,
        }));
    }

    let settings = state.settings.read().await;
    if !settings.control_api.enabled {
        return Ok(None);
    }
    let Some(control_api_url) =
        non_empty(settings.control_api.url.as_deref()).map(ToString::to_string)
    else {
        return Ok(None);
    };
    let Some(api_key) = non_empty(settings.control_api.api_key.as_deref()).map(ToString::to_string)
    else {
        return Ok(Some(ControlResponseAckPostbackConfig {
            control_api_url,
            api_key: None,
            route: ControlResponseAckPostbackRoute::AgentAcks,
        }));
    };
    Ok(Some(ControlResponseAckPostbackConfig {
        control_api_url,
        api_key: Some(api_key),
        route: ControlResponseAckPostbackRoute::AuthenticatedAcks,
    }))
}

pub(crate) fn control_ack_retry_backoff_seconds(attempt_count: u32) -> i64 {
    let exponent = attempt_count.saturating_sub(1).min(4);
    let multiplier = 1_i64.checked_shl(exponent).unwrap_or(16);
    EDR_CONTROL_ACK_RETRY_INITIAL_BACKOFF_SECONDS
        .saturating_mul(multiplier)
        .min(EDR_CONTROL_ACK_RETRY_MAX_BACKOFF_SECONDS)
}

pub(crate) struct ControlAckPostbackPayloadInput<'a> {
    target_kind: &'a str,
    target_id: &'a str,
    ack_token: &'a str,
    status: &'a str,
    observed_at: chrono::DateTime<chrono::Utc>,
    message: Option<&'a str>,
    resulting_state: Option<&'a str>,
    raw_payload: serde_json::Value,
}

pub(crate) fn control_ack_postback_payload(
    input: ControlAckPostbackPayloadInput<'_>,
) -> serde_json::Value {
    serde_json::json!({
        "targetKind": input.target_kind,
        "targetId": input.target_id,
        "ackToken": input.ack_token,
        "status": input.status,
        "observedAt": input.observed_at,
        "message": input.message,
        "resultingState": input.resulting_state,
        "rawPayload": input.raw_payload,
    })
}

pub(crate) struct ControlAckPostbackRetryEnqueueInput<'a> {
    postback_config: &'a ControlResponseAckPostbackConfig,
    response_action_id: &'a str,
    ack_token: &'a str,
    acknowledgement: &'a EndpointResponseAcknowledgementReport,
    control: &'a EndpointResponseControlCorrelation,
    raw_payload: serde_json::Value,
    failure: ControlAckPostbackAttemptFailure,
}

pub(crate) async fn enqueue_control_ack_postback_retry(
    state: &AgentApiState,
    input: ControlAckPostbackRetryEnqueueInput<'_>,
) -> Result<(String, chrono::DateTime<chrono::Utc>), (StatusCode, String)> {
    let now = chrono::Utc::now();
    let attempt_count = 1;
    let retry_id = sha256(
        format!(
            "{}:{}:{}:{}:{}",
            input.acknowledgement.acknowledgement_id,
            input.response_action_id,
            input.control.target_kind,
            input.control.target_id,
            input.control.ack_token_hash
        )
        .as_bytes(),
    )
    .to_hex_prefixed();
    let next_attempt_at =
        now + chrono::Duration::seconds(control_ack_retry_backoff_seconds(attempt_count));
    let retry = EndpointControlAckPostbackRetry {
        retry_id: retry_id.clone(),
        response_action_id: input.response_action_id.to_string(),
        control_api_url: input.postback_config.control_api_url.clone(),
        preferred_route: input.postback_config.route,
        target_kind: input.control.target_kind.clone(),
        target_id: input.control.target_id.clone(),
        ack_token: input.ack_token.to_string(),
        ack_token_hash: input.control.ack_token_hash.clone(),
        status: input.control.ack_status.clone(),
        observed_at: input.acknowledgement.acknowledged_at,
        message: input.acknowledgement.note.clone(),
        resulting_state: input.control.resulting_state.clone(),
        raw_payload: input.raw_payload,
        attempt_count,
        next_attempt_at,
        last_attempt_at: Some(now),
        last_http_status: input.failure.http_status,
        last_response_hash: input.failure.response_hash,
        last_error_hash: input.failure.error_hash,
        created_at: now,
        updated_at: now,
    };
    state
        .edr_control_ack_postback_retry_ledger
        .lock()
        .await
        .append(retry)
        .map_err(internal_error)?;
    Ok((retry_id, next_attempt_at))
}

impl ControlAckPostbackRetrySink {
    pub async fn sign_response_acknowledgement_receipt(
        &self,
        acknowledgement: &EndpointResponseAcknowledgementReport,
    ) -> Result<SignedReceipt> {
        append_edr_response_acknowledgement(&self.state, acknowledgement)
            .await
            .map_err(|(status, message)| {
                anyhow::anyhow!(
                    "append response acknowledgement ledger entry failed with HTTP {}: {}",
                    status.as_u16(),
                    message
                )
            })?;
        let graph = CausalGraph::default();
        emit_edr_response_acknowledgement_receipt(&self.state, acknowledgement, &graph).await
    }

    pub async fn enqueue(&self, input: ControlAckPostbackRetryRequest) -> Result<()> {
        let now = chrono::Utc::now();
        let attempt_count = 1;
        let ack_token_hash = sha256(input.ack_token.as_bytes()).to_hex_prefixed();
        let retry_id = sha256(
            format!(
                "{}:{}:{}:{}",
                input.response_action_id, input.target_kind, input.target_id, ack_token_hash
            )
            .as_bytes(),
        )
        .to_hex_prefixed();
        let next_attempt_at =
            now + chrono::Duration::seconds(control_ack_retry_backoff_seconds(attempt_count));
        let failure = truncate_delivery_error(&input.failure_message);
        let retry = EndpointControlAckPostbackRetry {
            retry_id: retry_id.clone(),
            response_action_id: input.response_action_id,
            control_api_url: input
                .control_api_url
                .trim()
                .trim_end_matches('/')
                .to_string(),
            preferred_route: if input.use_authenticated_route {
                ControlResponseAckPostbackRoute::AuthenticatedAcks
            } else {
                ControlResponseAckPostbackRoute::AgentAcks
            },
            target_kind: input.target_kind,
            target_id: input.target_id,
            ack_token: input.ack_token,
            ack_token_hash,
            status: input.status,
            observed_at: input.observed_at,
            message: input.message,
            resulting_state: input.resulting_state,
            raw_payload: input.raw_payload,
            attempt_count,
            next_attempt_at,
            last_attempt_at: Some(now),
            last_http_status: None,
            last_response_hash: None,
            last_error_hash: Some(sha256(failure.as_bytes()).to_hex_prefixed()),
            created_at: now,
            updated_at: now,
        };
        self.state
            .edr_control_ack_postback_retry_ledger
            .lock()
            .await
            .append(retry)?;
        Ok(())
    }
}

pub(crate) struct ControlAckPostbackAttemptFailure {
    http_status: Option<u16>,
    response_hash: Option<String>,
    error_hash: Option<String>,
}

pub(crate) struct ControlAckPostbackRetryAttemptOutcome {
    route: ControlResponseAckPostbackRoute,
    accepted: bool,
    http_status: Option<u16>,
    response_hash: Option<String>,
    error_hash: Option<String>,
}

pub(crate) async fn resolve_control_ack_retry_route(
    state: &AgentApiState,
    retry: &EndpointControlAckPostbackRetry,
) -> (ControlResponseAckPostbackRoute, Option<String>) {
    let settings = state.settings.read().await;
    let configured_url = settings
        .control_api
        .url
        .as_deref()
        .map(str::trim)
        .map(|url| url.trim_end_matches('/'));
    let retry_url = retry.control_api_url.trim().trim_end_matches('/');
    if settings.control_api.enabled && configured_url == Some(retry_url) {
        if let Some(api_key) = non_empty(settings.control_api.api_key.as_deref()) {
            return (
                ControlResponseAckPostbackRoute::AuthenticatedAcks,
                Some(api_key.to_string()),
            );
        }
    }
    (ControlResponseAckPostbackRoute::AgentAcks, None)
}

pub(crate) async fn send_control_ack_postback_retry(
    state: &AgentApiState,
    retry: &EndpointControlAckPostbackRetry,
) -> ControlAckPostbackRetryAttemptOutcome {
    let (route, api_key) = resolve_control_ack_retry_route(state, retry).await;
    let url = match control_api_ack_postback_url(
        &retry.control_api_url,
        &retry.response_action_id,
        route,
    ) {
        Ok(url) => url,
        Err((_status, message)) => {
            let error = truncate_delivery_error(&message);
            return ControlAckPostbackRetryAttemptOutcome {
                route,
                accepted: false,
                http_status: None,
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    };
    let payload = control_ack_postback_payload(ControlAckPostbackPayloadInput {
        target_kind: &retry.target_kind,
        target_id: &retry.target_id,
        ack_token: &retry.ack_token,
        status: &retry.status,
        observed_at: retry.observed_at,
        message: retry.message.as_deref(),
        resulting_state: retry.resulting_state.as_deref(),
        raw_payload: retry.raw_payload.clone(),
    });
    let mut request = state.http_client.post(&url).json(&payload);
    if let Some(api_key) = api_key {
        request = request.header("x-api-key", api_key);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            return ControlAckPostbackRetryAttemptOutcome {
                route,
                accepted: false,
                http_status: None,
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    };
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            return ControlAckPostbackRetryAttemptOutcome {
                route,
                accepted: false,
                http_status: Some(status.as_u16()),
                response_hash: None,
                error_hash: Some(sha256(error.as_bytes()).to_hex_prefixed()),
            };
        }
    };
    ControlAckPostbackRetryAttemptOutcome {
        route,
        accepted: status.is_success(),
        http_status: Some(status.as_u16()),
        response_hash: Some(sha256(&bytes).to_hex_prefixed()),
        error_hash: None,
    }
}

pub(crate) async fn post_control_response_acknowledgement(
    state: &AgentApiState,
    input: &EdrResponseControlAcknowledgementInput,
    acknowledgement: &EndpointResponseAcknowledgementReport,
    receipt: &SignedReceipt,
) -> Result<Option<EdrResponseControlPostbackReport>, (StatusCode, String)> {
    let Some(postback_config) = resolve_control_response_ack_postback_config(state, input).await?
    else {
        return Ok(None);
    };
    let response_action_id =
        required_control_ack_field("responseActionId", input.response_action_id.as_deref(), 128)?;
    validate_control_ack_uuid("responseActionId", &response_action_id)?;
    let ack_token = required_control_ack_field("ackToken", input.ack_token.as_deref(), 1024)?;
    let url = control_api_ack_postback_url(
        &postback_config.control_api_url,
        &response_action_id,
        postback_config.route,
    )?;
    let control = acknowledgement
        .control_correlation
        .as_ref()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "control response acknowledgement correlation is required for postback".to_string(),
            )
        })?;
    let local_receipt_hash =
        canonical_json_hash(receipt, "response acknowledgement control postback receipt")
            .map_err(internal_error)?;
    let raw_payload = serde_json::json!({
        "source": "clawdstrike-agent",
        "localAcknowledgementId": acknowledgement.acknowledgement_id,
        "localExecutionId": acknowledgement.execution_id,
        "localActionId": acknowledgement.action_id,
        "localGraphSliceId": acknowledgement.graph_slice_id,
        "localReceiptHash": local_receipt_hash,
        "signedReceipt": receipt,
        "localEffectCount": acknowledgement.effects.len(),
    });
    let payload = control_ack_postback_payload(ControlAckPostbackPayloadInput {
        target_kind: &control.target_kind,
        target_id: &control.target_id,
        ack_token: &ack_token,
        status: &control.ack_status,
        observed_at: acknowledgement.acknowledged_at,
        message: acknowledgement.note.as_deref(),
        resulting_state: control.resulting_state.as_deref(),
        raw_payload: raw_payload.clone(),
    });

    let mut request = state.http_client.post(&url).json(&payload);
    if let Some(api_key) = postback_config.api_key.as_deref() {
        request = request.header("x-api-key", api_key);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(err) => {
            let error = truncate_delivery_error(&err.to_string());
            let error_hash = sha256(error.as_bytes()).to_hex_prefixed();
            let (retry_id, next_retry_at) = enqueue_control_ack_postback_retry(
                state,
                ControlAckPostbackRetryEnqueueInput {
                    postback_config: &postback_config,
                    response_action_id: &response_action_id,
                    ack_token: &ack_token,
                    acknowledgement,
                    control,
                    raw_payload,
                    failure: ControlAckPostbackAttemptFailure {
                        http_status: None,
                        response_hash: None,
                        error_hash: Some(error_hash.clone()),
                    },
                },
            )
            .await?;
            return Ok(Some(EdrResponseControlPostbackReport {
                control_api_url: postback_config.control_api_url,
                response_action_id,
                accepted: false,
                retry_queued: true,
                retry_id: Some(retry_id),
                next_retry_at: Some(next_retry_at),
                http_status: None,
                response_hash: None,
                error_hash: Some(error_hash),
                error: Some(error),
            }));
        }
    };
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let bytes = response.bytes().await.map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!("control response acknowledgement postback body read failed: {err}"),
        )
    })?;
    let response_hash = sha256(&bytes).to_hex_prefixed();
    let (retry_queued, retry_id, next_retry_at) = if status.is_success() {
        (false, None, None)
    } else {
        let (retry_id, next_retry_at) = enqueue_control_ack_postback_retry(
            state,
            ControlAckPostbackRetryEnqueueInput {
                postback_config: &postback_config,
                response_action_id: &response_action_id,
                ack_token: &ack_token,
                acknowledgement,
                control,
                raw_payload,
                failure: ControlAckPostbackAttemptFailure {
                    http_status: Some(status.as_u16()),
                    response_hash: Some(response_hash.clone()),
                    error_hash: None,
                },
            },
        )
        .await?;
        (true, Some(retry_id), Some(next_retry_at))
    };
    Ok(Some(EdrResponseControlPostbackReport {
        control_api_url: postback_config.control_api_url,
        response_action_id,
        accepted: status.is_success(),
        retry_queued,
        retry_id,
        next_retry_at,
        http_status: Some(status.as_u16()),
        response_hash: Some(response_hash),
        error_hash: None,
        error: None,
    }))
}

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
