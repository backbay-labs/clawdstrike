use axum::extract::{Path, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::services::alerter::AlertConfig;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/alerts", post(create_alert))
        .route("/alerts", get(list_alerts))
        .route("/alerts/{id}", get(get_alert))
        .route("/alerts/{id}", put(update_alert))
        .route("/alerts/{id}", delete(delete_alert))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAlertRequest {
    pub name: String,
    pub channel: String,
    pub config: serde_json::Value,
    pub guard_filter: Option<Vec<String>>,
    pub severity_threshold: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateAlertRequest {
    pub name: Option<String>,
    pub config: Option<serde_json::Value>,
    pub guard_filter: Option<Vec<String>>,
    pub severity_threshold: Option<String>,
    pub enabled: Option<bool>,
}

async fn create_alert(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<CreateAlertRequest>,
) -> Result<Json<AlertConfig>, ApiError> {
    if auth.role == "viewer" || auth.role == "member" {
        return Err(ApiError::Forbidden);
    }

    let severity = req.severity_threshold.as_deref().unwrap_or("warn");

    let row = sqlx::query::query(
        r#"INSERT INTO alert_configs (tenant_id, name, channel, config, guard_filter, severity_threshold)
           VALUES ($1, $2, $3, $4, $5, $6)
           RETURNING *"#,
    )
    .bind(auth.tenant_id)
    .bind(&req.name)
    .bind(&req.channel)
    .bind(&req.config)
    .bind(req.guard_filter.as_deref())
    .bind(severity)
    .fetch_one(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let config = AlertConfig::from_row(row).map_err(ApiError::Database)?;
    Ok(Json(config))
}

async fn list_alerts(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<Vec<AlertConfig>>, ApiError> {
    let rows = sqlx::query::query(
        "SELECT * FROM alert_configs WHERE tenant_id = $1 ORDER BY created_at DESC",
    )
    .bind(auth.tenant_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let configs: Vec<AlertConfig> = rows
        .into_iter()
        .map(AlertConfig::from_row)
        .collect::<Result<_, _>>()
        .map_err(ApiError::Database)?;

    Ok(Json(configs))
}

async fn get_alert(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<AlertConfig>, ApiError> {
    let row = sqlx::query::query(
        "SELECT * FROM alert_configs WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(auth.tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    let config = AlertConfig::from_row(row).map_err(ApiError::Database)?;
    Ok(Json(config))
}

async fn update_alert(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateAlertRequest>,
) -> Result<Json<AlertConfig>, ApiError> {
    if auth.role == "viewer" || auth.role == "member" {
        return Err(ApiError::Forbidden);
    }

    let row = sqlx::query::query(
        r#"UPDATE alert_configs
           SET name = COALESCE($3, name),
               config = COALESCE($4, config),
               guard_filter = COALESCE($5, guard_filter),
               severity_threshold = COALESCE($6, severity_threshold),
               enabled = COALESCE($7, enabled)
           WHERE id = $1 AND tenant_id = $2
           RETURNING *"#,
    )
    .bind(id)
    .bind(auth.tenant_id)
    .bind(req.name.as_deref())
    .bind(req.config.as_ref())
    .bind(req.guard_filter.as_deref())
    .bind(req.severity_threshold.as_deref())
    .bind(req.enabled)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    let config = AlertConfig::from_row(row).map_err(ApiError::Database)?;
    Ok(Json(config))
}

async fn delete_alert(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if auth.role == "viewer" || auth.role == "member" {
        return Err(ApiError::Forbidden);
    }

    let result = sqlx::query::query("DELETE FROM alert_configs WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(auth.tenant_id)
        .execute(&state.db)
        .await
        .map_err(ApiError::Database)?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    Ok(Json(serde_json::json!({ "deleted": true })))
}
