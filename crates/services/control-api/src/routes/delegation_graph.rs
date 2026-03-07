use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::models::delegation_graph::{
    DelegationGraphSnapshot, FleetGrant, GrantExerciseRequest, GraphPathQuery, IngestGrantRequest,
    ListGrantsQuery, RevokeGrantRequest, RevokeGrantResponse,
};
use crate::services::delegation_graph as delegation_graph_service;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/grants", get(list_grants).post(ingest_grant))
        .route("/grants/{id}", get(get_grant))
        .route("/grants/{id}/lineage", get(get_grant_lineage))
        .route("/grants/{id}/exercise", post(exercise_grant))
        .route("/grants/{id}/revoke", post(revoke_grant))
        .route(
            "/principals/{id}/delegation-graph",
            get(get_principal_delegation_graph),
        )
        .route(
            "/principals/{id}/delegation-lineage",
            get(get_principal_delegation_lineage),
        )
        .route("/graph/paths", get(get_graph_path))
}

async fn list_grants(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Query(query): Query<ListGrantsQuery>,
) -> Result<Json<Vec<FleetGrant>>, ApiError> {
    let grants = delegation_graph_service::list_grants(&state.db, auth.tenant_id, &query).await?;
    Ok(Json(grants))
}

async fn ingest_grant(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(request): Json<IngestGrantRequest>,
) -> Result<Json<FleetGrant>, ApiError> {
    ensure_grant_write_access(&auth)?;
    let grant = delegation_graph_service::ingest_grant(&state.db, auth.tenant_id, request).await?;
    Ok(Json(grant))
}

async fn get_grant(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<FleetGrant>, ApiError> {
    let grant = delegation_graph_service::get_grant(&state.db, auth.tenant_id, id).await?;
    Ok(Json(grant))
}

async fn get_grant_lineage(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<DelegationGraphSnapshot>, ApiError> {
    let snapshot =
        delegation_graph_service::grant_lineage_snapshot(&state.db, auth.tenant_id, id).await?;
    Ok(Json(snapshot))
}

async fn exercise_grant(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(request): Json<GrantExerciseRequest>,
) -> Result<Json<DelegationGraphSnapshot>, ApiError> {
    ensure_grant_write_access(&auth)?;
    let snapshot =
        delegation_graph_service::exercise_grant(&state.db, auth.tenant_id, id, request).await?;
    Ok(Json(snapshot))
}

async fn revoke_grant(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(request): Json<RevokeGrantRequest>,
) -> Result<Json<RevokeGrantResponse>, ApiError> {
    ensure_grant_write_access(&auth)?;
    let response =
        delegation_graph_service::revoke_grant(&state.db, auth.tenant_id, id, request).await?;
    Ok(Json(response))
}

fn ensure_grant_write_access(auth: &AuthenticatedTenant) -> Result<(), ApiError> {
    if !matches!(auth.role.as_str(), "owner" | "admin") {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

async fn get_principal_delegation_graph(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<String>,
) -> Result<Json<DelegationGraphSnapshot>, ApiError> {
    let snapshot =
        delegation_graph_service::principal_graph_snapshot(&state.db, auth.tenant_id, &id, true)
            .await?;
    Ok(Json(snapshot))
}

async fn get_principal_delegation_lineage(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<String>,
) -> Result<Json<DelegationGraphSnapshot>, ApiError> {
    let snapshot =
        delegation_graph_service::principal_graph_snapshot(&state.db, auth.tenant_id, &id, false)
            .await?;
    Ok(Json(snapshot))
}

async fn get_graph_path(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Query(query): Query<GraphPathQuery>,
) -> Result<Json<DelegationGraphSnapshot>, ApiError> {
    let snapshot = delegation_graph_service::graph_path_snapshot(
        &state.db,
        auth.tenant_id,
        &query.from,
        &query.to,
    )
    .await?;
    Ok(Json(snapshot))
}
