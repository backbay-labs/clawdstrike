use chrono::Utc;
use jsonwebtoken::{DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sqlx::row::Row;
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub tenant_id: Uuid,
    pub role: String,
    pub exp: i64,
    pub iat: i64,
}

/// Validate a JWT token and return the authenticated tenant context.
pub async fn validate_token(token: &str, state: &AppState) -> Result<AuthenticatedTenant, ApiError> {
    let key = DecodingKey::from_secret(state.config.jwt_secret.as_bytes());
    let validation = Validation::default();

    let token_data =
        jsonwebtoken::decode::<Claims>(token, &key, &validation).map_err(|_| ApiError::Unauthorized)?;

    let claims = token_data.claims;
    if claims.exp < Utc::now().timestamp() {
        return Err(ApiError::Unauthorized);
    }

    let row = sqlx::query::query(
        "SELECT id, slug, plan, agent_limit FROM tenants WHERE id = $1 AND status = 'active'",
    )
    .bind(claims.tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::Unauthorized)?;

    Ok(AuthenticatedTenant {
        tenant_id: row.try_get("id").map_err(ApiError::Database)?,
        slug: row.try_get("slug").map_err(ApiError::Database)?,
        plan: row.try_get("plan").map_err(ApiError::Database)?,
        agent_limit: row.try_get("agent_limit").map_err(ApiError::Database)?,
        user_id: Some(claims.sub),
        role: claims.role,
    })
}
