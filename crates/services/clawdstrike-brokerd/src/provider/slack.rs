use std::collections::BTreeMap;

use clawdstrike_broker_protocol::{sha256_hex, BrokerRequest, HttpMethod};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;
use url::Url;

use crate::api::ApiError;
use crate::provider::{
    extract_response_headers, map_method, ProviderExecutionResponse, ProviderStreamResponse,
};
use crate::state::AppState;

pub async fn execute_slack(
    state: &AppState,
    request: &BrokerRequest,
    secret: &str,
) -> Result<ProviderExecutionResponse, ApiError> {
    let prepared = prepare_slack_request(request)?;
    let response = execute_slack_request(state, request, secret, prepared.request_body).await?;
    let status = response.status().as_u16();
    let (headers, content_type) = extract_response_headers(&response);
    let body = response
        .text()
        .await
        .map_err(|error| ApiError::bad_gateway("BROKER_UPSTREAM_READ_FAILED", error.to_string()))?;
    let bytes_received = body.len();
    let mut provider_metadata = prepared.provider_metadata;
    if let Ok(response_json) = serde_json::from_str::<Value>(&body) {
        if let Some(ok) = response_json.get("ok").and_then(Value::as_bool) {
            provider_metadata.insert("slack_ok".to_string(), ok.to_string());
        }
        if let Some(channel) = response_json.get("channel").and_then(Value::as_str) {
            provider_metadata.insert("response_channel".to_string(), channel.to_string());
        }
        if let Some(ts) = response_json.get("ts").and_then(Value::as_str) {
            provider_metadata.insert("response_ts".to_string(), ts.to_string());
        }
        if let Some(error) = response_json.get("error").and_then(Value::as_str) {
            provider_metadata.insert("response_error".to_string(), error.to_string());
        }
    }

    let response_body_sha256 = Some(sha256_hex(&body));
    Ok(ProviderExecutionResponse {
        status,
        headers,
        body: Some(body),
        content_type,
        response_body_sha256,
        bytes_received,
        provider_metadata,
    })
}

pub async fn execute_slack_stream(
    _state: &AppState,
    _request: &BrokerRequest,
    _secret: &str,
) -> Result<ProviderStreamResponse, ApiError> {
    Err(ApiError::forbidden(
        "BROKER_STREAM_UNSUPPORTED",
        "streaming Slack broker execution is not supported",
    ))
}

struct PreparedSlackRequest<'a> {
    request_body: &'a str,
    provider_metadata: BTreeMap<String, String>,
}

fn prepare_slack_request(request: &BrokerRequest) -> Result<PreparedSlackRequest<'_>, ApiError> {
    let request_body = request.body.as_deref().ok_or_else(|| {
        ApiError::bad_request(
            "BROKER_SLACK_BODY_REQUIRED",
            "slack broker execution requires a JSON request body",
        )
    })?;
    let request_json: Value = serde_json::from_str(request_body)
        .map_err(|error| ApiError::bad_request("BROKER_SLACK_BODY_INVALID", error.to_string()))?;
    let parsed = Url::parse(&request.url)
        .map_err(|error| ApiError::bad_request("BROKER_SLACK_URL_INVALID", error.to_string()))?;

    let mut provider_metadata = match (request.method, parsed.path()) {
        (HttpMethod::POST, "/api/chat.postMessage") => {
            require_string_field(&request_json, "channel", "BROKER_SLACK_FIELD_REQUIRED")?;
            require_text_or_blocks(&request_json)?;
            BTreeMap::from([("operation".to_string(), "chat.postMessage".to_string())])
        }
        (HttpMethod::POST, "/api/chat.update") => {
            require_string_field(&request_json, "channel", "BROKER_SLACK_FIELD_REQUIRED")?;
            require_string_field(&request_json, "ts", "BROKER_SLACK_FIELD_REQUIRED")?;
            require_text_or_blocks(&request_json)?;
            BTreeMap::from([("operation".to_string(), "chat.update".to_string())])
        }
        _ => {
            return Err(ApiError::bad_request(
                "BROKER_SLACK_OPERATION_UNSUPPORTED",
                "slack broker execution only supports chat.postMessage and chat.update",
            ))
        }
    };

    if let Some(channel) = request_json.get("channel").and_then(Value::as_str) {
        provider_metadata.insert("channel".to_string(), channel.to_string());
    }
    if let Some(ts) = request_json.get("ts").and_then(Value::as_str) {
        provider_metadata.insert("message_ts".to_string(), ts.to_string());
    }
    if let Some(thread_ts) = request_json.get("thread_ts").and_then(Value::as_str) {
        provider_metadata.insert("thread_ts".to_string(), thread_ts.to_string());
    }

    Ok(PreparedSlackRequest {
        request_body,
        provider_metadata,
    })
}

async fn execute_slack_request(
    state: &AppState,
    request: &BrokerRequest,
    secret: &str,
    request_body: &str,
) -> Result<reqwest::Response, ApiError> {
    let mut builder = state
        .upstream_client
        .request(map_method(&request.method), request.url.as_str())
        .header(AUTHORIZATION, format!("Bearer {secret}"));

    for (name, value) in &request.headers {
        builder = builder.header(name, value);
    }

    if !request
        .headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case("content-type"))
    {
        builder = builder.header(CONTENT_TYPE, "application/json; charset=utf-8");
    }

    builder
        .body(request_body.to_string())
        .send()
        .await
        .map_err(|error| ApiError::bad_gateway("BROKER_UPSTREAM_REQUEST_FAILED", error.to_string()))
}

fn require_string_field<'a>(
    value: &'a Value,
    field: &str,
    code: &str,
) -> Result<&'a str, ApiError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::bad_request(
                code,
                format!("slack broker execution requires a non-empty '{field}' field"),
            )
        })
}

fn require_text_or_blocks(value: &Value) -> Result<(), ApiError> {
    let has_text = value
        .get("text")
        .and_then(Value::as_str)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let has_blocks = value.get("blocks").is_some();
    if has_text || has_blocks {
        return Ok(());
    }

    Err(ApiError::bad_request(
        "BROKER_SLACK_FIELD_REQUIRED",
        "slack broker execution requires either a non-empty 'text' field or 'blocks'",
    ))
}
