use super::*;

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
