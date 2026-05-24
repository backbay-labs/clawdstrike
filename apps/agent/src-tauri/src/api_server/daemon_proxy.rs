//! HTTP forwarders that proxy local agent requests to the policy daemon.
//!
//! The agent owns the local-network surface; these helpers extend that surface
//! to the daemon without exposing daemon credentials to the caller.

use super::{
    internal_error, merged_authorization_header, require_auth, AgentApiState,
    AGENT_API_MAX_BODY_BYTES, BROKER_MUTATION_MAX_BODY_BYTES,
};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::{ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use futures::TryStreamExt;
use std::sync::Arc;

pub(super) fn build_daemon_proxy_target(
    daemon_url: &str,
    uri: &Uri,
) -> Result<String, (StatusCode, String)> {
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| uri.path());

    if !path_and_query.starts_with('/') {
        return Err((StatusCode::BAD_REQUEST, "invalid proxy path".to_string()));
    }

    Ok(format!(
        "{}{}",
        daemon_url.trim_end_matches('/'),
        path_and_query
    ))
}

async fn send_daemon_get_request(
    state: &AgentApiState,
    request_headers: &HeaderMap,
    uri: &Uri,
) -> Result<reqwest::Response, (StatusCode, String)> {
    send_daemon_request(state, request_headers, reqwest::Method::GET, uri, None).await
}

async fn send_daemon_request(
    state: &AgentApiState,
    request_headers: &HeaderMap,
    method: reqwest::Method,
    uri: &Uri,
    body: Option<Vec<u8>>,
) -> Result<reqwest::Response, (StatusCode, String)> {
    let (daemon_url, daemon_api_key) = {
        let settings = state.settings.read().await;
        (settings.daemon_url(), settings.api_key.clone())
    };

    let target_url = build_daemon_proxy_target(&daemon_url, uri)?;
    let mut request = state.http_client.request(method, target_url);

    if let Some(value) = request_headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
    {
        request = request.header(ACCEPT.as_str(), value);
    }
    if let Some(value) = request_headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    {
        request = request.header(CONTENT_TYPE.as_str(), value);
    }

    if let Some(auth_header) =
        merged_authorization_header(request_headers, daemon_api_key.as_deref())
    {
        request = request.header(AUTHORIZATION.as_str(), auth_header);
    }
    if let Some(body) = body {
        request = request.body(body);
    }

    request
        .send()
        .await
        .map_err(|err| internal_error(err.into()))
}

async fn proxy_http_response(
    response: reqwest::Response,
) -> Result<Response, (StatusCode, String)> {
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = response.headers().get(CONTENT_TYPE).cloned();
    let body = response
        .bytes()
        .await
        .map_err(|err| internal_error(err.into()))?;

    let mut headers = HeaderMap::new();
    if let Some(value) = content_type {
        headers.insert(CONTENT_TYPE, value);
    }

    Ok((status, headers, body).into_response())
}

pub(super) async fn proxy_daemon_get(
    State(state): State<Arc<AgentApiState>>,
    mut headers: HeaderMap,
    uri: Uri,
) -> Result<Response, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    // Do not forward the local agent auth token to hushd.
    // A caller can provide a daemon token via `X-Hushd-Authorization`; otherwise we
    // fall back to the configured daemon API key from settings.
    headers.remove(AUTHORIZATION);
    let response = send_daemon_get_request(&state, &headers, &uri).await?;
    proxy_http_response(response).await
}

pub(super) async fn proxy_daemon_events(
    State(state): State<Arc<AgentApiState>>,
    mut headers: HeaderMap,
    uri: Uri,
) -> Result<Response, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    // Do not forward the local agent auth token to hushd.
    // A caller can provide a daemon token via `X-Hushd-Authorization`; otherwise we
    // fall back to the configured daemon API key from settings.
    headers.remove(AUTHORIZATION);
    let response = send_daemon_get_request(&state, &headers, &uri).await?;
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

    if !status.is_success() {
        return proxy_http_response(response).await;
    }

    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("text/event-stream"));
    let stream = response.bytes_stream().map_err(std::io::Error::other);
    let body = Body::from_stream(stream);

    let mut out_headers = HeaderMap::new();
    out_headers.insert(CONTENT_TYPE, content_type);
    out_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    out_headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));

    Ok((status, out_headers, body).into_response())
}

pub(super) async fn proxy_daemon_mutation(
    State(state): State<Arc<AgentApiState>>,
    mut headers: HeaderMap,
    uri: Uri,
    request: Request,
) -> Result<Response, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    headers.remove(AUTHORIZATION);

    let method = reqwest::Method::from_bytes(request.method().as_str().as_bytes())
        .map_err(|err| internal_error(err.into()))?;
    let max_bytes = if uri.path().starts_with("/api/v1/broker/") {
        BROKER_MUTATION_MAX_BODY_BYTES
    } else {
        AGENT_API_MAX_BODY_BYTES
    };
    let body = axum::body::to_bytes(request.into_body(), max_bytes)
        .await
        .map_err(|err| internal_error(err.into()))?;
    let body = if body.is_empty() {
        None
    } else {
        Some(body.to_vec())
    };
    let response = send_daemon_request(&state, &headers, method, &uri, body).await?;
    proxy_http_response(response).await
}
