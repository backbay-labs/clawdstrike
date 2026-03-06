use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use hunt_correlate::service::{CorrelateRequest, IocMatchRequest};
use hunt_query::service::{CreateSavedHuntRequest, HuntQueryRequest, UpdateSavedHuntRequest};
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::models::hunt::IngestHuntEventRequest;
use crate::services::hunt;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/hunt/events/ingest", post(ingest_event))
        .route("/hunt/search", post(search_events))
        .route("/hunt/timeline", post(timeline_events))
        .route("/hunt/correlate", post(correlate))
        .route("/hunt/ioc/match", post(ioc_match))
        .route("/hunt/jobs/{id}", get(get_job))
        .route("/hunt/saved", get(list_saved_hunts).post(create_saved_hunt))
        .route(
            "/hunt/saved/{id}",
            get(get_saved_hunt)
                .patch(update_saved_hunt)
                .delete(delete_saved_hunt),
        )
        .route("/hunt/saved/{id}/run", post(run_saved_hunt))
}

async fn ingest_event(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(request): Json<IngestHuntEventRequest>,
) -> Result<Json<hunt_query::service::HuntEvent>, ApiError> {
    if auth.role == "viewer" || !auth.is_api_key() {
        return Err(ApiError::Forbidden);
    }

    let raw_envelope = request
        .raw_envelope
        .ok_or_else(|| ApiError::BadRequest("rawEnvelope is required".to_string()))?;
    let event = hunt::ingest_event(
        &state.db,
        auth.tenant_id,
        request.event,
        raw_envelope,
        state.signing_keypair.as_deref(),
    )
    .await?;
    Ok(Json(event))
}

async fn search_events(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(request): Json<HuntQueryRequest>,
) -> Result<Json<hunt_query::service::HuntQueryResponse>, ApiError> {
    Ok(Json(
        hunt::search_events(&state.db, auth.tenant_id, &request).await?,
    ))
}

async fn timeline_events(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(request): Json<HuntQueryRequest>,
) -> Result<Json<hunt_query::service::HuntTimelineResponse>, ApiError> {
    Ok(Json(
        hunt::timeline_events(&state.db, auth.tenant_id, &request).await?,
    ))
}

async fn correlate(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(request): Json<CorrelateRequest>,
) -> Result<Json<hunt_query::service::HuntJobRecord>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }
    let created_by = auth.actor_id();
    Ok(Json(
        hunt::run_correlation_job(&state.db, auth.tenant_id, &created_by, &request).await?,
    ))
}

async fn ioc_match(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(request): Json<IocMatchRequest>,
) -> Result<Json<hunt_query::service::HuntJobRecord>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }
    let created_by = auth.actor_id();
    Ok(Json(
        hunt::run_ioc_job(&state.db, auth.tenant_id, &created_by, &request).await?,
    ))
}

async fn get_job(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<hunt_query::service::HuntJobRecord>, ApiError> {
    Ok(Json(hunt::get_job(&state.db, auth.tenant_id, id).await?))
}

async fn list_saved_hunts(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<Vec<hunt_query::service::SavedHuntRecord>>, ApiError> {
    Ok(Json(
        hunt::list_saved_hunts(&state.db, auth.tenant_id).await?,
    ))
}

async fn create_saved_hunt(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(request): Json<CreateSavedHuntRequest>,
) -> Result<Json<hunt_query::service::SavedHuntRecord>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }
    let created_by = auth.actor_id();
    Ok(Json(
        hunt::create_saved_hunt(&state.db, auth.tenant_id, &created_by, &request).await?,
    ))
}

async fn get_saved_hunt(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<hunt_query::service::SavedHuntRecord>, ApiError> {
    Ok(Json(
        hunt::get_saved_hunt(&state.db, auth.tenant_id, id).await?,
    ))
}

async fn update_saved_hunt(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateSavedHuntRequest>,
) -> Result<Json<hunt_query::service::SavedHuntRecord>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }
    Ok(Json(
        hunt::update_saved_hunt(&state.db, auth.tenant_id, id, &request).await?,
    ))
}

async fn delete_saved_hunt(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }
    hunt::delete_saved_hunt(&state.db, auth.tenant_id, id).await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

async fn run_saved_hunt(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<hunt_query::service::HuntJobRecord>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }
    let created_by = auth.actor_id();
    Ok(Json(
        hunt::run_saved_hunt(&state.db, auth.tenant_id, id, &created_by).await?,
    ))
}
