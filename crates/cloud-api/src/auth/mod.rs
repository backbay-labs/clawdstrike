pub mod api_key;
pub mod jwt;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;

/// Authenticated identity extracted from either a JWT or API key.
#[derive(Debug, Clone)]
pub struct AuthenticatedTenant {
    pub tenant_id: Uuid,
    pub slug: String,
    pub plan: String,
    pub agent_limit: i32,
    pub user_id: Option<Uuid>,
    pub role: String,
}

/// Auth middleware that checks for JWT bearer token or API key header.
pub async fn require_auth(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let headers = request.headers();

    // Try Bearer token first
    if let Some(auth_header) = headers.get("authorization") {
        let header_str = auth_header.to_str().map_err(|_| ApiError::Unauthorized)?;
        if let Some(token) = header_str.strip_prefix("Bearer ") {
            let tenant = jwt::validate_token(token, &state).await?;
            request.extensions_mut().insert(tenant);
            return Ok(next.run(request).await);
        }
    }

    // Try API key header
    if let Some(api_key_header) = headers.get("x-api-key") {
        let raw_key = api_key_header.to_str().map_err(|_| ApiError::Unauthorized)?;
        let tenant = api_key::validate_key(raw_key, &state).await?;
        request.extensions_mut().insert(tenant);
        return Ok(next.run(request).await);
    }

    Err(ApiError::Unauthorized)
}

impl<S: Send + Sync> FromRequestParts<S> for AuthenticatedTenant {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthenticatedTenant>()
            .cloned()
            .ok_or(ApiError::Unauthorized)
    }
}
