//! POST/PUT/PATCH/DELETE proxy handler.

use super::super::*;
use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use std::sync::Arc;

pub(crate) async fn proxy_daemon_mutation(
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
