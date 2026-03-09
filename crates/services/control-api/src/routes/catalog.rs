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
    _auth: AuthenticatedTenant,
    Query(query): Query<CatalogTemplateListQuery>,
) -> Result<Json<Vec<CatalogTemplate>>, ApiError> {
    let templates = state.catalog.list_templates(&query).await;
    Ok(Json(templates))
}

async fn get_template(
    State(state): State<AppState>,
    _auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<CatalogTemplate>, ApiError> {
    let template = state.catalog.get_template(id).await?;
    Ok(Json(template))
}

async fn create_template(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<CreateCatalogTemplateRequest>,
) -> Result<Json<CatalogTemplate>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }

    let template = state.catalog.create_template(req).await?;
    Ok(Json(template))
}

async fn update_template(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCatalogTemplateRequest>,
) -> Result<Json<CatalogTemplate>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }

    let template = state.catalog.update_template(id, req).await?;
    Ok(Json(template))
}

async fn delete_template(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if auth.role == "viewer" || auth.role == "member" {
        return Err(ApiError::Forbidden);
    }

    state.catalog.delete_template(id).await?;
    Ok(Json(json!({ "deleted": true })))
}

async fn fork_template(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<CatalogTemplate>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }

    let forked = state.catalog.fork_template(id).await?;
    Ok(Json(forked))
}

async fn list_categories(
    State(state): State<AppState>,
    _auth: AuthenticatedTenant,
) -> Result<Json<Vec<CatalogCategory>>, ApiError> {
    let categories = state.catalog.list_categories().await;
    Ok(Json(categories))
}
