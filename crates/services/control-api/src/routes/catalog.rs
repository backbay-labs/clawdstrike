use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde_json::json;
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::models::catalog::{
    CatalogCategory, CatalogTemplate, CatalogTemplateListQuery, CreateCatalogTemplateRequest,
    UpdateCatalogTemplateRequest,
};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/catalog/templates", get(list_templates))
        .route("/catalog/templates", post(create_template))
        .route("/catalog/templates/{id}", get(get_template))
        .route("/catalog/templates/{id}", put(update_template))
        .route("/catalog/templates/{id}", delete(delete_template))
        .route("/catalog/templates/{id}/fork", post(fork_template))
        .route("/catalog/categories", get(list_categories))
}

async fn list_templates(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Query(query): Query<CatalogTemplateListQuery>,
) -> Result<Json<Vec<CatalogTemplate>>, ApiError> {
    let templates = state.catalog.list_templates(auth.tenant_id, &query).await;
    Ok(Json(templates))
}

async fn get_template(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<CatalogTemplate>, ApiError> {
    let template = state.catalog.get_template(auth.tenant_id, id).await?;
    Ok(Json(template))
}

async fn create_template(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<CreateCatalogTemplateRequest>,
) -> Result<Json<CatalogTemplate>, ApiError> {
    ensure_write_access(&auth)?;

    let template = state.catalog.create_template(auth.tenant_id, req).await?;

    tracing::info!(
        tenant = %auth.slug,
        template_id = %template.id,
        operation = "create",
        "Catalog template created"
    );

    Ok(Json(template))
}

async fn update_template(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCatalogTemplateRequest>,
) -> Result<Json<CatalogTemplate>, ApiError> {
    ensure_write_access(&auth)?;

    let template = state
        .catalog
        .update_template(auth.tenant_id, id, req)
        .await?;

    tracing::info!(
        tenant = %auth.slug,
        template_id = %id,
        operation = "update",
        "Catalog template updated"
    );

    Ok(Json(template))
}

async fn delete_template(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_admin_access(&auth)?;

    state.catalog.delete_template(auth.tenant_id, id).await?;

    tracing::info!(
        tenant = %auth.slug,
        template_id = %id,
        operation = "delete",
        "Catalog template deleted"
    );

    Ok(Json(json!({ "deleted": true })))
}

async fn fork_template(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<CatalogTemplate>, ApiError> {
    ensure_write_access(&auth)?;

    let forked = state.catalog.fork_template(auth.tenant_id, id).await?;

    tracing::info!(
        tenant = %auth.slug,
        template_id = %forked.id,
        source_template_id = %id,
        operation = "fork",
        "Catalog template forked"
    );

    Ok(Json(forked))
}

async fn list_categories(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<Vec<CatalogCategory>>, ApiError> {
    let categories = state.catalog.list_categories(auth.tenant_id).await;
    Ok(Json(categories))
}

/// Allow-list check: member, admin, and owner may write.
fn ensure_write_access(auth: &AuthenticatedTenant) -> Result<(), ApiError> {
    if !matches!(auth.role.as_str(), "member" | "admin" | "owner") {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

/// Admin-only operations (e.g., catalog delete).
fn ensure_admin_access(auth: &AuthenticatedTenant) -> Result<(), ApiError> {
    if !matches!(auth.role.as_str(), "admin" | "owner") {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}
