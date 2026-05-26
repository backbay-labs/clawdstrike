//! Control-API acknowledgement postback configuration and dispatch.
//!
//! Builds the control-API URL the agent must POST a signed acknowledgement
//! to, sends it best-effort, and queues a retry on the durable ack
//! postback sink if the upload fails.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::net::IpAddr;
use tokio::sync::RwLock;

use crate::agent_auth;
use crate::api_server::{ControlAckPostbackRetryRequest, ControlAckPostbackRetrySink};
use crate::settings::Settings;

use super::dto::{ControlAckContext, ControlAckPostbackConfig, PolicyRuleDiffValidationCommand};
use super::validate::truncate_message;

pub(super) async fn post_control_acknowledgement(
    http_client: &reqwest::Client,
    settings: &RwLock<Settings>,
    command: &PolicyRuleDiffValidationCommand,
    context: &ControlAckContext<'_>,
    raw_payload: Value,
) -> Result<()> {
    let config = {
        let settings = settings.read().await;
        control_ack_postback_config(&settings, &command.response_action_id)?.ok_or_else(|| {
            anyhow::anyhow!("Control API acknowledgement postback is not configured")
        })?
    };
    let payload = control_ack_postback_payload(
        command,
        context.status,
        context.message,
        context.resulting_state,
        context.observed_at,
        raw_payload,
    );

    let mut request = http_client.post(&config.url).json(&payload);
    if let Some(api_key) = config.api_key.as_deref() {
        request = request.header("x-api-key", api_key);
    }
    let response = request
        .send()
        .await
        .context("send Control API acknowledgement postback")?;
    let status_code = response.status();
    let body = response
        .bytes()
        .await
        .context("read Control API acknowledgement postback response")?;
    if !status_code.is_success() {
        anyhow::bail!(
            "Control API acknowledgement postback failed with HTTP {}: {}",
            status_code.as_u16(),
            truncate_message(&String::from_utf8_lossy(&body), 512)
        );
    }
    Ok(())
}

pub(super) async fn enqueue_control_ack_retry(
    sink: Option<&ControlAckPostbackRetrySink>,
    settings: &RwLock<Settings>,
    command: &PolicyRuleDiffValidationCommand,
    context: ControlAckContext<'_>,
    raw_payload: Value,
) -> Result<bool> {
    let Some(sink) = sink else {
        return Ok(false);
    };
    let config = {
        let settings = settings.read().await;
        control_ack_postback_config(&settings, &command.response_action_id)?.ok_or_else(|| {
            anyhow::anyhow!("Control API acknowledgement postback is not configured")
        })?
    };
    sink.enqueue(ControlAckPostbackRetryRequest {
        control_api_url: config.base_url,
        use_authenticated_route: config.api_key.is_some(),
        response_action_id: command.response_action_id.clone(),
        target_kind: "endpoint".to_string(),
        target_id: command.target_id.clone(),
        ack_token: command.ack_token.clone(),
        status: context.status.to_string(),
        observed_at: context.observed_at,
        message: context.message.map(ToString::to_string),
        resulting_state: context.resulting_state.map(ToString::to_string),
        raw_payload,
        failure_message: context.failure_message.to_string(),
    })
    .await?;
    Ok(true)
}

pub(super) fn control_ack_postback_payload(
    command: &PolicyRuleDiffValidationCommand,
    status: &str,
    message: Option<&str>,
    resulting_state: Option<&str>,
    observed_at: chrono::DateTime<chrono::Utc>,
    raw_payload: Value,
) -> Value {
    json!({
        "targetKind": "endpoint",
        "targetId": command.target_id,
        "ackToken": command.ack_token,
        "status": status,
        "observedAt": observed_at,
        "message": message,
        "resultingState": resulting_state,
        "rawPayload": raw_payload,
    })
}

pub(super) fn control_ack_postback_config(
    settings: &Settings,
    response_action_id: &str,
) -> Result<Option<ControlAckPostbackConfig>> {
    if !settings.control_api.enabled {
        return Ok(None);
    }
    let Some(control_api_url) = settings
        .control_api
        .url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let api_key = settings
        .control_api
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let path_segment = if api_key.is_some() {
        "acks"
    } else {
        "agent-acks"
    };
    Ok(Some(ControlAckPostbackConfig {
        base_url: control_api_url.to_string(),
        url: control_ack_postback_url(control_api_url, response_action_id, path_segment)?,
        api_key,
    }))
}

fn control_ack_postback_url(
    control_api_url: &str,
    response_action_id: &str,
    path_segment: &str,
) -> Result<String> {
    let trimmed = control_api_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        anyhow::bail!("Control API URL must not be empty");
    }
    let parsed = reqwest::Url::parse(trimmed).context("Control API URL is invalid")?;
    if parsed.host_str().is_none() {
        anyhow::bail!("Control API URL must include a host");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("Control API URL must not contain userinfo");
    }
    match parsed.scheme() {
        "https" => {}
        "http" if control_api_url_is_loopback(&parsed) => {}
        "http" => anyhow::bail!("Control API URL may use http only for loopback hosts"),
        other => anyhow::bail!("Control API URL must use http or https, got {other}"),
    }
    Ok(format!(
        "{trimmed}/api/v1/response-actions/{response_action_id}/{path_segment}"
    ))
}

fn control_api_url_is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|addr| addr.is_loopback())
            .unwrap_or(false)
}

pub(super) fn current_local_api_token(fallback: &str) -> String {
    match agent_auth::read_local_api_token() {
        Ok(token) => token,
        Err(err) => {
            tracing::debug!(
                error = %err,
                "Falling back to startup local API token for response-action command"
            );
            fallback.to_string()
        }
    }
}
