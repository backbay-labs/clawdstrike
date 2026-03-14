use std::collections::BTreeMap;

use clawdstrike_broker_protocol::{sha256_hex, BrokerRequest, HttpMethod};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use serde_json::Value;
use url::Url;

use crate::api::ApiError;
use crate::provider::{
    extract_response_headers, map_method, ProviderExecutionResponse, ProviderStreamResponse,
};
use crate::state::AppState;

pub async fn execute_github(
    state: &AppState,
    request: &BrokerRequest,
    secret: &str,
) -> Result<ProviderExecutionResponse, ApiError> {
    let prepared = prepare_github_request(request)?;
    let response = execute_github_request(state, request, secret, prepared.request_body).await?;
    let status = response.status().as_u16();
    let (headers, content_type) = extract_response_headers(&response);
    let body = response
        .text()
        .await
        .map_err(|error| ApiError::bad_gateway("BROKER_UPSTREAM_READ_FAILED", error.to_string()))?;
    let bytes_received = body.len();
    let mut provider_metadata = prepared.provider_metadata;
    if let Ok(response_json) = serde_json::from_str::<Value>(&body) {
        if let Some(id) = response_json.get("id").and_then(Value::as_i64) {
            provider_metadata.insert("response_id".to_string(), id.to_string());
        }
        if let Some(html_url) = response_json.get("html_url").and_then(Value::as_str) {
            provider_metadata.insert("response_html_url".to_string(), html_url.to_string());
        }
        if let Some(node_id) = response_json.get("node_id").and_then(Value::as_str) {
            provider_metadata.insert("response_node_id".to_string(), node_id.to_string());
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

pub async fn execute_github_stream(
    _state: &AppState,
    _request: &BrokerRequest,
    _secret: &str,
) -> Result<ProviderStreamResponse, ApiError> {
    Err(ApiError::forbidden(
        "BROKER_STREAM_UNSUPPORTED",
        "streaming GitHub broker execution is not supported",
    ))
}

struct PreparedGithubRequest<'a> {
    request_body: &'a str,
    provider_metadata: BTreeMap<String, String>,
}

fn prepare_github_request(request: &BrokerRequest) -> Result<PreparedGithubRequest<'_>, ApiError> {
    let request_body = request.body.as_deref().ok_or_else(|| {
        ApiError::bad_request(
            "BROKER_GITHUB_BODY_REQUIRED",
            "github broker execution requires a JSON request body",
        )
    })?;
    let request_json: Value = serde_json::from_str(request_body)
        .map_err(|error| ApiError::bad_request("BROKER_GITHUB_BODY_INVALID", error.to_string()))?;
    let parsed = Url::parse(&request.url)
        .map_err(|error| ApiError::bad_request("BROKER_GITHUB_URL_INVALID", error.to_string()))?;
    let segments = parsed
        .path_segments()
        .map(|segments| segments.collect::<Vec<_>>())
        .unwrap_or_default();

    let (operation, mut provider_metadata) = match (request.method, segments.as_slice()) {
        (HttpMethod::POST, ["repos", owner, repo, "issues"]) => {
            require_string_field(&request_json, "title", "BROKER_GITHUB_FIELD_REQUIRED")?;
            ("issues.create", repo_metadata(owner, repo))
        }
        (HttpMethod::POST, ["repos", owner, repo, "issues", issue_number, "comments"]) => {
            require_string_field(&request_json, "body", "BROKER_GITHUB_FIELD_REQUIRED")?;
            let mut meta = repo_metadata(owner, repo);
            meta.insert("issue_number".to_string(), (*issue_number).to_string());
            ("issues.comment.create", meta)
        }
        (HttpMethod::POST, ["repos", owner, repo, "check-runs"]) => {
            require_string_field(&request_json, "name", "BROKER_GITHUB_FIELD_REQUIRED")?;
            require_string_field(&request_json, "head_sha", "BROKER_GITHUB_FIELD_REQUIRED")?;
            ("checks.create", repo_metadata(owner, repo))
        }
        _ => return Err(ApiError::bad_request(
            "BROKER_GITHUB_OPERATION_UNSUPPORTED",
            "github broker execution only supports issue creation, issue comments, and check-runs",
        )),
    };

    provider_metadata.insert("operation".to_string(), operation.to_string());
    Ok(PreparedGithubRequest {
        request_body,
        provider_metadata,
    })
}

async fn execute_github_request(
    state: &AppState,
    request: &BrokerRequest,
    secret: &str,
    request_body: &str,
) -> Result<reqwest::Response, ApiError> {
    let mut builder = state
        .upstream_client
        .request(map_method(&request.method), request.url.as_str())
        .header(AUTHORIZATION, format!("Bearer {secret}"))
        .header(ACCEPT, "application/vnd.github+json")
        .header(USER_AGENT, "clawdstrike-brokerd")
        .header("x-github-api-version", "2022-11-28");

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

fn repo_metadata(owner: &str, repo: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("repository".to_string(), format!("{owner}/{repo}")),
        ("repo_owner".to_string(), owner.to_string()),
        ("repo_name".to_string(), repo.to_string()),
    ])
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
                format!("github broker execution requires a non-empty '{field}' field"),
            )
        })
}
