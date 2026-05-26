use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ControlResponseAckPostbackRoute {
    AuthenticatedAcks,
    AgentAcks,
}

impl ControlResponseAckPostbackRoute {
    pub(crate) fn path_segment(self) -> &'static str {
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
    pub(crate) http_status: Option<u16>,
    pub(crate) response_hash: Option<String>,
    pub(crate) error_hash: Option<String>,
}

pub(crate) struct ControlAckPostbackRetryAttemptOutcome {
    pub(crate) route: ControlResponseAckPostbackRoute,
    pub(crate) accepted: bool,
    pub(crate) http_status: Option<u16>,
    pub(crate) response_hash: Option<String>,
    pub(crate) error_hash: Option<String>,
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
