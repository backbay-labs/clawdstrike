//! Typed error enum for the agent API surface.
//!
//! `AgentApiError` is the long-term replacement for the `(StatusCode, String)`
//! tuple that 164 handler signatures still return today. Migration is gradual:
//! this module ships the enum, its `IntoResponse` impl, an `ApiResult` alias,
//! and the back-compat shims (`From<AgentApiError> for (StatusCode, String)`,
//! `From<anyhow::Error> for AgentApiError`, etc.) so handlers can adopt it one
//! at a time without breaking the call graph or the test fixtures.
//!
//! Adopters should prefer `AgentApiError::*` constructors over hand-rolled
//! tuples; the older `internal_error()` and `map_openclaw_error()` helpers in
//! `api_server.rs` build the same StatusCode + String shape via the From shim.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

// Variants ship before they have call sites so handler migration can land in
// follow-up commits without first touching this file.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum AgentApiError {
    Unauthorized(&'static str),
    BadRequest(String),
    Conflict(String),
    NotFound(String),
    RateLimited { retry_after_secs: u64 },
    UpstreamUnavailable(String),
    // OpenClaw-style transport errors that previously routed through
    // `map_openclaw_error`; the discriminant lets future logging hook in
    // separately from generic internal failures.
    OpenClawTransport(String),
    Validation { field: &'static str, message: String },
    Internal(anyhow::Error),
}

// `ApiResult` ships now so the next round of handler migrations can adopt it
// without a separate scaffolding commit; until the first handler is migrated,
// the alias has no in-tree users.
#[allow(dead_code)]
pub(crate) type ApiResult<T> = std::result::Result<T, AgentApiError>;

impl AgentApiError {
    pub(crate) fn status_and_message(&self) -> (StatusCode, String) {
        match self {
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, (*msg).to_string()),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            Self::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            Self::RateLimited { retry_after_secs } => (
                StatusCode::TOO_MANY_REQUESTS,
                format!("rate limit exceeded; retry after {retry_after_secs} seconds"),
            ),
            Self::UpstreamUnavailable(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
            Self::OpenClawTransport(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            Self::Validation { field, message } => (
                StatusCode::BAD_REQUEST,
                format!("{field}: {message}"),
            ),
            Self::Internal(err) => {
                tracing::error!(error = %err, "Agent API error");
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
            }
        }
    }
}

impl IntoResponse for AgentApiError {
    fn into_response(self) -> Response {
        let (status, message) = self.status_and_message();
        (status, message).into_response()
    }
}

impl From<anyhow::Error> for AgentApiError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal(err)
    }
}

// Back-compat shim: existing handlers return `Result<_, (StatusCode, String)>`.
// Once a handler is migrated to `ApiResult<_>` it can still propagate via `?`
// from helpers that still return the tuple type, and vice versa. The shim is
// removed when the migration is complete.
impl From<AgentApiError> for (StatusCode, String) {
    fn from(err: AgentApiError) -> Self {
        err.status_and_message()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauthorized_maps_to_401() {
        let err = AgentApiError::Unauthorized("nope");
        let (status, message) = err.status_and_message();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(message, "nope");
    }

    #[test]
    fn bad_request_maps_to_400() {
        let err = AgentApiError::BadRequest("missing field foo".to_string());
        let (status, _) = err.status_and_message();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn conflict_maps_to_409() {
        let err = AgentApiError::Conflict("already exists".to_string());
        let (status, _) = err.status_and_message();
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[test]
    fn not_found_maps_to_404() {
        let err = AgentApiError::NotFound("nope".to_string());
        let (status, _) = err.status_and_message();
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[test]
    fn rate_limited_maps_to_429() {
        let err = AgentApiError::RateLimited {
            retry_after_secs: 30,
        };
        let (status, message) = err.status_and_message();
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(message.contains("30"));
    }

    #[test]
    fn upstream_unavailable_maps_to_502() {
        let err = AgentApiError::UpstreamUnavailable("hushd offline".to_string());
        let (status, _) = err.status_and_message();
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn openclaw_transport_maps_to_400() {
        let err = AgentApiError::OpenClawTransport("invalid gateway_url".to_string());
        let (status, _) = err.status_and_message();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validation_includes_field_in_message() {
        let err = AgentApiError::Validation {
            field: "ttl_seconds",
            message: "must be >0".to_string(),
        };
        let (status, message) = err.status_and_message();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.starts_with("ttl_seconds:"));
    }

    #[test]
    fn internal_maps_to_500_from_anyhow() {
        let err: AgentApiError = anyhow::anyhow!("boom").into();
        let (status, _) = err.status_and_message();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn into_tuple_shim_preserves_status_and_message() {
        let err = AgentApiError::BadRequest("oops".to_string());
        let (status, message): (StatusCode, String) = err.into();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(message, "oops");
    }
}
