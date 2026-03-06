use axum::extract::{Path, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::crypto::hash_enrollment_token;
use crate::error::ApiError;
use crate::models::tenant::{CreateTenantRequest, Tenant, UpdateTenantRequest};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/tenants", post(create_tenant))
        .route("/tenants", get(list_tenants))
        .route("/tenants/{id}", get(get_tenant))
        .route("/tenants/{id}", put(update_tenant))
        .route(
            "/tenants/{id}/enrollment-tokens",
            post(create_enrollment_token),
        )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateEnrollmentTokenRequest {
    #[serde(default)]
    expires_in_hours: Option<i64>,
}

#[derive(Debug, Serialize)]
struct CreateEnrollmentTokenResponse {
    enrollment_token: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

async fn create_tenant(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<CreateTenantRequest>,
) -> Result<Json<Tenant>, ApiError> {
    if auth.role != "owner" && auth.role != "admin" {
        return Err(ApiError::Forbidden);
    }
    if !is_valid_tenant_slug(&req.slug) {
        return Err(ApiError::BadRequest(
            "tenant slug must use lowercase letters, digits, '-' or '.', and cannot start/end with separators"
                .to_string(),
        ));
    }

    let plan = req.plan.as_deref().unwrap_or("team");

    let row = sqlx::query::query(
        r#"INSERT INTO tenants (name, slug, plan)
           VALUES ($1, $2, $3)
           RETURNING *"#,
    )
    .bind(&req.name)
    .bind(&req.slug)
    .bind(plan)
    .fetch_one(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let tenant = Tenant::from_row(row).map_err(ApiError::Database)?;

    // Provision NATS account for the new tenant.
    // Fail closed: if provisioning fails, remove the tenant row so we do not
    // persist a tenant that lacks the required isolation primitives.
    if let Err(e) = state
        .provisioner
        .provision_tenant(tenant.id, &tenant.slug)
        .await
    {
        tracing::error!(
            tenant_id = %tenant.id,
            error = %e,
            "Failed to provision NATS account; rolling back tenant creation"
        );
        if let Err(cleanup_err) = sqlx::query::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant.id)
            .execute(&state.db)
            .await
        {
            tracing::error!(
                tenant_id = %tenant.id,
                error = %cleanup_err,
                "Failed to rollback tenant after provisioning error"
            );
            return Err(ApiError::Internal(
                "failed to provision tenant NATS account and failed to rollback tenant row"
                    .to_string(),
            ));
        }
        return Err(ApiError::Nats(format!(
            "failed to provision tenant NATS account: {e}"
        )));
    }

    Ok(Json(tenant))
}

async fn list_tenants(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<Vec<Tenant>>, ApiError> {
    let rows = sqlx::query::query("SELECT * FROM tenants WHERE id = $1 ORDER BY created_at DESC")
        .bind(auth.tenant_id)
        .fetch_all(&state.db)
        .await
        .map_err(ApiError::Database)?;

    let tenants: Vec<Tenant> = rows
        .into_iter()
        .map(Tenant::from_row)
        .collect::<Result<_, _>>()
        .map_err(ApiError::Database)?;

    Ok(Json(tenants))
}

async fn get_tenant(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<Tenant>, ApiError> {
    ensure_tenant_scope(&auth, id)?;

    let row = sqlx::query::query("SELECT * FROM tenants WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .map_err(ApiError::Database)?
        .ok_or(ApiError::NotFound)?;

    let tenant = Tenant::from_row(row).map_err(ApiError::Database)?;
    Ok(Json(tenant))
}

async fn update_tenant(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateTenantRequest>,
) -> Result<Json<Tenant>, ApiError> {
    if auth.role != "owner" && auth.role != "admin" {
        return Err(ApiError::Forbidden);
    }
    ensure_tenant_scope(&auth, id)?;

    let row = sqlx::query::query(
        r#"UPDATE tenants
           SET name = COALESCE($2, name),
               plan = COALESCE($3, plan),
               agent_limit = COALESCE($4, agent_limit),
               retention_days = COALESCE($5, retention_days),
               updated_at = now()
           WHERE id = $1
           RETURNING *"#,
    )
    .bind(id)
    .bind(req.name.as_deref())
    .bind(req.plan.as_deref())
    .bind(req.agent_limit)
    .bind(req.retention_days)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    let tenant = Tenant::from_row(row).map_err(ApiError::Database)?;
    Ok(Json(tenant))
}

async fn create_enrollment_token(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateEnrollmentTokenRequest>,
) -> Result<Json<CreateEnrollmentTokenResponse>, ApiError> {
    if auth.role != "owner" && auth.role != "admin" {
        return Err(ApiError::Forbidden);
    }
    ensure_tenant_scope(&auth, id)?;

    let expires_in_hours = req.expires_in_hours.unwrap_or(24).clamp(1, 168);
    let expires_at = Utc::now() + Duration::hours(expires_in_hours);

    // Retry a few times in the extremely unlikely event of a token hash collision.
    for _ in 0..3 {
        let enrollment_token = generate_enrollment_token();
        let token_hash = hash_enrollment_token(&enrollment_token);
        let inserted = sqlx::query::query(
            r#"INSERT INTO tenant_enrollment_tokens (tenant_id, token_hash, expires_at)
               VALUES ($1, $2, $3)
               RETURNING id"#,
        )
        .bind(id)
        .bind(token_hash)
        .bind(expires_at)
        .fetch_optional(&state.db)
        .await;

        match inserted {
            Ok(Some(_)) => {
                return Ok(Json(CreateEnrollmentTokenResponse {
                    enrollment_token,
                    expires_at,
                }));
            }
            Ok(None) => return Err(ApiError::NotFound),
            Err(err) => {
                if is_unique_violation(&err) {
                    continue;
                }
                return Err(ApiError::Database(err));
            }
        }
    }

    Err(ApiError::Internal(
        "failed to generate unique enrollment token".to_string(),
    ))
}

fn ensure_tenant_scope(auth: &AuthenticatedTenant, tenant_id: Uuid) -> Result<(), ApiError> {
    if auth.tenant_id != tenant_id {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

fn is_valid_tenant_slug(slug: &str) -> bool {
    if slug.is_empty()
        || slug.starts_with('-')
        || slug.starts_with('.')
        || slug.ends_with('-')
        || slug.ends_with('.')
        || slug.contains("..")
    {
        return false;
    }

    slug.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
}

fn generate_enrollment_token() -> String {
    let salt = Uuid::new_v4().simple().to_string();
    let secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    format!("cset_{}_{}", salt, secret)
}

fn is_unique_violation(err: &sqlx::error::Error) -> bool {
    match err {
        sqlx::error::Error::Database(db) => db.code().as_deref() == Some("23505"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_auth(tenant_id: Uuid, role: &str) -> AuthenticatedTenant {
        AuthenticatedTenant {
            tenant_id,
            slug: "tenant".to_string(),
            plan: "team".to_string(),
            agent_limit: 10,
            user_id: None,
            api_key_id: None,
            role: role.to_string(),
            auth_source: crate::auth::AuthSource::Jwt,
        }
    }

    #[test]
    fn ensure_tenant_scope_allows_matching_tenant() {
        let tenant_id = Uuid::new_v4();
        let auth = make_auth(tenant_id, "owner");

        assert!(ensure_tenant_scope(&auth, tenant_id).is_ok());
    }

    #[test]
    fn ensure_tenant_scope_rejects_cross_tenant_access() {
        let auth = make_auth(Uuid::new_v4(), "admin");
        let other_tenant = Uuid::new_v4();

        assert!(matches!(
            ensure_tenant_scope(&auth, other_tenant),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn tenant_slug_validation_supports_dotted_slugs() {
        assert!(is_valid_tenant_slug("acme"));
        assert!(is_valid_tenant_slug("acme.dev"));
        assert!(is_valid_tenant_slug("acme-prod.01"));
        assert!(!is_valid_tenant_slug(""));
        assert!(!is_valid_tenant_slug("Acme"));
        assert!(!is_valid_tenant_slug("acme..dev"));
        assert!(!is_valid_tenant_slug(".acme"));
        assert!(!is_valid_tenant_slug("acme."));
        assert!(!is_valid_tenant_slug("acme/*"));
    }

    #[test]
    fn enrollment_token_generation_and_hash_contract() {
        let token = generate_enrollment_token();
        assert!(token.starts_with("cset_"));
        assert_eq!(token.matches('_').count(), 2);
        assert_eq!(hash_enrollment_token(&token).len(), 64);
    }
}
