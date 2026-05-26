//! Server-Sent Events / event-stream proxy handler.

use super::super::*;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use futures::TryStreamExt;
use std::sync::Arc;

pub(crate) async fn proxy_daemon_events(
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
