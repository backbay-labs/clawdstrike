use axum::extract::{Path, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::models::tenant::{CreateTenantRequest, Tenant, UpdateTenantRequest};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/tenants", post(create_tenant))
        .route("/tenants", get(list_tenants))
        .route("/tenants/{id}", get(get_tenant))
        .route("/tenants/{id}", put(update_tenant))
}

async fn create_tenant(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<CreateTenantRequest>,
) -> Result<Json<Tenant>, ApiError> {
    if auth.role != "owner" && auth.role != "admin" {
        return Err(ApiError::Forbidden);
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

    // Provision NATS account for the new tenant
    if let Err(e) = state
        .provisioner
        .provision_tenant(tenant.id, &tenant.slug)
        .await
    {
        tracing::error!(tenant_id = %tenant.id, error = %e, "Failed to provision NATS account");
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

fn ensure_tenant_scope(auth: &AuthenticatedTenant, tenant_id: Uuid) -> Result<(), ApiError> {
    if auth.tenant_id != tenant_id {
        return Err(ApiError::Forbidden);
    }
    Ok(())
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
            role: role.to_string(),
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
}
