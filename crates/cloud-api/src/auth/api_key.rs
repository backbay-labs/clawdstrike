use sha2::{Digest, Sha256};
use sqlx::row::Row;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::state::AppState;

/// Validate a raw API key by hashing it and comparing against the stored hash.
pub async fn validate_key(raw_key: &str, state: &AppState) -> Result<AuthenticatedTenant, ApiError> {
    let key_hash = hash_api_key(raw_key);

    let row = sqlx::query::query(
        r#"SELECT ak.tenant_id, ak.scopes, t.slug, t.plan, t.agent_limit
           FROM api_keys ak
           JOIN tenants t ON t.id = ak.tenant_id
           WHERE ak.key_hash = $1
             AND ak.revoked_at IS NULL
             AND (ak.expires_at IS NULL OR ak.expires_at > now())
             AND t.status = 'active'"#,
    )
    .bind(&key_hash)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::Unauthorized)?;

    let scopes: Vec<String> = row.try_get("scopes").map_err(ApiError::Database)?;

    // Determine effective role from scopes
    let role = if scopes.iter().any(|s| s == "admin") {
        "admin".to_string()
    } else if scopes.iter().any(|s| s == "write") {
        "member".to_string()
    } else {
        "viewer".to_string()
    };

    Ok(AuthenticatedTenant {
        tenant_id: row.try_get("tenant_id").map_err(ApiError::Database)?,
        slug: row.try_get("slug").map_err(ApiError::Database)?,
        plan: row.try_get("plan").map_err(ApiError::Database)?,
        agent_limit: row.try_get("agent_limit").map_err(ApiError::Database)?,
        user_id: None,
        role,
    })
}

/// Hash an API key with SHA-256 for storage comparison.
pub fn hash_api_key(raw_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw_key.as_bytes());
    hex::encode(hasher.finalize())
}
