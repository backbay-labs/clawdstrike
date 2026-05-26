//! Authentication for incoming MCP JSON-RPC requests.

use crate::agent_auth::read_local_api_token;
use crate::security::auth::constant_time_eq_token;
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;

/// Verify the bearer token on an incoming MCP JSON-RPC request.
pub(super) fn mcp_authorized(headers: &HeaderMap, auth_token: &str) -> bool {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim);

    let expected_token = match read_local_api_token() {
        Ok(token) => token,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Falling back to startup MCP auth token because current token could not be read"
            );
            auth_token.to_string()
        }
    };

    match token {
        Some(candidate) => constant_time_eq_token(candidate, &expected_token),
        None => false,
    }
}
