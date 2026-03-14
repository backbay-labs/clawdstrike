use std::collections::BTreeMap;

use clawdstrike_broker_protocol::{sha256_hex, BrokerRequest};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;

use crate::api::ApiError;
use crate::provider::{
    extract_response_headers, map_method, ProviderExecutionResponse, ProviderStreamResponse,
};
use crate::state::AppState;

pub async fn execute_openai(
    state: &AppState,
    request: &BrokerRequest,
    secret: &str,
) -> Result<ProviderExecutionResponse, ApiError> {
    let (request_body, request_json) = parse_openai_request_body(request)?;
    if request_json
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(ApiError::forbidden(
            "BROKER_STREAM_UNSUPPORTED",
            "streaming OpenAI broker execution is not supported in brokerd v1",
        ));
    }

    let mut provider_metadata = build_provider_metadata(&request_json);
    let response = execute_openai_request(state, request, secret, request_body).await?;
    let status = response.status().as_u16();
    let (headers, content_type) = extract_response_headers(&response);

    let body = response
        .text()
        .await
        .map_err(|error| ApiError::bad_gateway("BROKER_UPSTREAM_READ_FAILED", error.to_string()))?;
    let bytes_received = body.len();
    if let Ok(response_json) = serde_json::from_str::<Value>(&body) {
        if let Some(response_id) = response_json.get("id").and_then(Value::as_str) {
            provider_metadata.insert("response_id".to_string(), response_id.to_string());
        }
        if let Some(response_model) = response_json.get("model").and_then(Value::as_str) {
            provider_metadata.insert("response_model".to_string(), response_model.to_string());
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

pub async fn execute_openai_stream(
    state: &AppState,
    request: &BrokerRequest,
    secret: &str,
) -> Result<ProviderStreamResponse, ApiError> {
    let (request_body, request_json) = parse_openai_request_body(request)?;
    if !request_json
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err(ApiError::bad_request(
            "BROKER_STREAM_REQUEST_INVALID",
            "openai streaming broker execution requires stream=true in the request body",
        ));
    }

    let response = execute_openai_request(state, request, secret, request_body).await?;
    let status = response.status().as_u16();
    let (headers, content_type) = extract_response_headers(&response);

    Ok(ProviderStreamResponse {
        status,
        headers,
        content_type,
        response,
        provider_metadata: build_provider_metadata(&request_json),
    })
}

fn parse_openai_request_body(request: &BrokerRequest) -> Result<(&str, Value), ApiError> {
    let request_body = request.body.as_deref().ok_or_else(|| {
        ApiError::bad_request(
            "BROKER_OPENAI_BODY_REQUIRED",
            "openai broker execution requires a JSON request body",
        )
    })?;
    let request_json: Value = serde_json::from_str(request_body)
        .map_err(|error| ApiError::bad_request("BROKER_OPENAI_BODY_INVALID", error.to_string()))?;
    Ok((request_body, request_json))
}

async fn execute_openai_request(
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
        builder = builder.header(CONTENT_TYPE, "application/json");
    }

    builder
        .body(request_body.to_string())
        .send()
        .await
        .map_err(|error| ApiError::bad_gateway("BROKER_UPSTREAM_REQUEST_FAILED", error.to_string()))
}

fn build_provider_metadata(request_json: &Value) -> BTreeMap<String, String> {
    let mut provider_metadata =
        BTreeMap::from([("operation".to_string(), "responses.create".to_string())]);
    if let Some(model) = request_json.get("model").and_then(Value::as_str) {
        provider_metadata.insert("request_model".to_string(), model.to_string());
    }
    if request_json
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        provider_metadata.insert("response_mode".to_string(), "stream".to_string());
    }
    provider_metadata
}
