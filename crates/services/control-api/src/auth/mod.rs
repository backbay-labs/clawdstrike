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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthSource {
    Jwt,
    ApiKey,
}

/// Authenticated identity extracted from either a JWT or API key.
#[derive(Debug, Clone)]
pub struct AuthenticatedTenant {
    pub tenant_id: Uuid,
    pub slug: String,
    pub plan: String,
    pub agent_limit: i32,
    pub user_id: Option<Uuid>,
    pub api_key_id: Option<Uuid>,
    pub role: String,
    pub auth_source: AuthSource,
}

impl AuthenticatedTenant {
    pub fn is_api_key(&self) -> bool {
        self.auth_source == AuthSource::ApiKey
    }

    pub fn actor_type(&self) -> &'static str {
        match self.auth_source {
            AuthSource::Jwt => "user",
            AuthSource::ApiKey => "service",
        }
    }

    pub fn actor_id(&self) -> String {
        match self.auth_source {
            AuthSource::Jwt => self
                .user_id
                .map(|user_id| user_id.to_string())
                .unwrap_or_else(|| format!("tenant:{}:{}", self.slug, self.role)),
            AuthSource::ApiKey => self
                .api_key_id
                .map(|api_key_id| api_key_id.to_string())
                .unwrap_or_else(|| format!("tenant:{}:{}", self.slug, self.role)),
        }
    }
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
        let raw_key = api_key_header
            .to_str()
            .map_err(|_| ApiError::Unauthorized)?;
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn actor_id_prefers_user_identity() {
        let auth = AuthenticatedTenant {
            tenant_id: Uuid::new_v4(),
            slug: "acme".to_string(),
            plan: "enterprise".to_string(),
            agent_limit: 100,
            user_id: Some(Uuid::nil()),
            api_key_id: None,
            role: "admin".to_string(),
            auth_source: AuthSource::Jwt,
        };

        assert_eq!(auth.actor_id(), Uuid::nil().to_string());
    }

    #[test]
    fn actor_id_falls_back_to_slug_and_role() {
        let auth = AuthenticatedTenant {
            tenant_id: Uuid::new_v4(),
            slug: "acme".to_string(),
            plan: "enterprise".to_string(),
            agent_limit: 100,
            user_id: None,
            api_key_id: None,
            role: "admin".to_string(),
            auth_source: AuthSource::ApiKey,
        };

        assert_eq!(auth.actor_id(), "tenant:acme:admin");
    }
}
