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
