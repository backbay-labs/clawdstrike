use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("not found")]
    NotFound,
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("agent limit reached")]
    AgentLimitReached,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("plan upgrade required: {0}")]
    PlanUpgradeRequired(&'static str),
    #[error("database error: {0}")]
    Database(#[from] sqlx::error::Error),
    #[error("nats error: {0}")]
    Nats(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ApiError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, self.to_string()),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            ApiError::AgentLimitReached => (StatusCode::CONFLICT, self.to_string()),
            ApiError::InvalidPublicKey => (StatusCode::BAD_REQUEST, self.to_string()),
            ApiError::InvalidSignature => (StatusCode::UNAUTHORIZED, self.to_string()),
            ApiError::PlanUpgradeRequired(feature) => {
                (StatusCode::PAYMENT_REQUIRED, format!("plan upgrade required for: {feature}"))
            }
            ApiError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "database error".to_string()),
            ApiError::Nats(_) => (StatusCode::INTERNAL_SERVER_ERROR, "messaging error".to_string()),
            ApiError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".to_string())
            }
        };

        let body = serde_json::json!({ "error": message });
        (status, Json(body)).into_response()
    }
}
