//! Error types for the registry service.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    #[allow(dead_code)]
    Unauthorized(String),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("integrity error: {0}")]
    Integrity(String),

    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: String,
    message: String,
    request_id: String,
}

impl IntoResponse for RegistryError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            RegistryError::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            RegistryError::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT"),
            RegistryError::BadRequest(_) => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            RegistryError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            RegistryError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR"),
            RegistryError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "IO_ERROR"),
            RegistryError::Integrity(_) => (StatusCode::BAD_REQUEST, "INTEGRITY_ERROR"),
            RegistryError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
        };

        let body = ErrorBody {
            error: ErrorDetail {
                code: code.to_string(),
                message: self.to_string(),
                request_id: format!("req_{}", uuid::Uuid::new_v4()),
            },
        };

        (status, Json(body)).into_response()
    }
}
