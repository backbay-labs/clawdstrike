use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::services::alerter::{
    ActivateDetectionPackRequest, AlertConfig, CreateDetectionRule, CreateDetectionSuppression,
    DetectionRuleTestApiResponse, FindingActionRequest, InstallDetectionPackRequest,
    RuleTestRequest, UpdateDetectionRule,
};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/alerts", post(create_alert))
        .route("/alerts", get(list_alerts))
        .route("/alerts/{id}", get(get_alert))
        .route("/alerts/{id}", put(update_alert))
        .route("/alerts/{id}", delete(delete_alert))
        .route("/detections/rules", post(create_detection_rule))
        .route("/detections/rules", get(list_detection_rules))
        .route("/detections/rules/{id}", get(get_detection_rule))
        .route("/detections/rules/{id}", patch(update_detection_rule))
        .route("/detections/rules/{id}", delete(delete_detection_rule))
        .route("/detections/rules/{id}/test", post(test_detection_rule))
        .route("/detections/rules/import/sigma", post(import_sigma_rule))
        .route("/detections/rules/import/yara", post(import_yara_rule))
        .route("/detections/findings", get(list_detection_findings))
        .route("/detections/findings/{id}", get(get_detection_finding))
        .route(
            "/detections/findings/{id}/suppress",
            post(suppress_detection_finding),
        )
        .route(
            "/detections/findings/{id}/resolve",
            post(resolve_detection_finding),
        )
        .route(
            "/detections/findings/{id}/false-positive",
            post(false_positive_detection_finding),
        )
        .route("/detections/suppressions", get(list_detection_suppressions))
        .route(
            "/detections/suppressions",
            post(create_detection_suppression),
        )
        .route(
            "/detections/suppressions/{id}",
            get(get_detection_suppression),
        )
        .route(
            "/detections/suppressions/{id}/revoke",
            post(revoke_detection_suppression),
        )
        .route("/detections/packs", get(list_detection_packs))
        .route("/detections/packs/install", post(install_detection_pack))
        .route(
            "/detections/packs/{name}/{version}",
            get(get_detection_pack),
        )
        .route(
            "/detections/packs/{name}/{version}/activate",
            post(activate_detection_pack),
        )
        .route(
            "/detections/packs/{name}/{version}/deactivate",
            post(deactivate_detection_pack),
        )
        .route(
            "/detections/packs/{name}/{version}/rules",
            get(list_detection_pack_rules),
        )
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

#[derive(Debug, Deserialize)]
pub struct DetectionFindingListQuery {
    pub status: Option<String>,
    pub severity: Option<String>,
    pub rule_id: Option<Uuid>,
    pub principal_id: Option<Uuid>,
}

fn ensure_detection_write_access(auth: &AuthenticatedTenant) -> Result<(), ApiError> {
    if auth.role == "viewer" || auth.role == "member" {
        return Err(ApiError::Forbidden);
    }
    Ok(())
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
    let row = sqlx::query::query("SELECT * FROM alert_configs WHERE id = $1 AND tenant_id = $2")
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

    Ok(Json(json!({ "deleted": true })))
}

async fn create_detection_rule(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<CreateDetectionRule>,
) -> Result<Json<crate::services::alerter::DetectionRuleRecord>, ApiError> {
    ensure_detection_write_access(&auth)?;
    let actor_id = auth.actor_id();
    let created = state
        .alerter
        .create_detection_rule(auth.tenant_id, &actor_id, req)
        .await?;
    Ok(Json(created))
}

async fn list_detection_rules(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<Vec<crate::services::alerter::DetectionRuleRecord>>, ApiError> {
    Ok(Json(
        state.alerter.list_detection_rules(auth.tenant_id).await?,
    ))
}

async fn get_detection_rule(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::services::alerter::DetectionRuleRecord>, ApiError> {
    Ok(Json(
        state.alerter.get_detection_rule(auth.tenant_id, id).await?,
    ))
}

async fn update_detection_rule(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateDetectionRule>,
) -> Result<Json<crate::services::alerter::DetectionRuleRecord>, ApiError> {
    ensure_detection_write_access(&auth)?;
    let actor_id = auth.actor_id();
    let updated = state
        .alerter
        .update_detection_rule(auth.tenant_id, id, &actor_id, req)
        .await?;
    Ok(Json(updated))
}

async fn delete_detection_rule(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    ensure_detection_write_access(&auth)?;
    state
        .alerter
        .delete_detection_rule(auth.tenant_id, id)
        .await?;
    Ok(Json(json!({ "deleted": true })))
}

async fn test_detection_rule(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<RuleTestRequest>,
) -> Result<Json<DetectionRuleTestApiResponse>, ApiError> {
    ensure_detection_write_access(&auth)?;
    Ok(Json(
        state
            .alerter
            .test_detection_rule(auth.tenant_id, id, req)
            .await?,
    ))
}

async fn import_sigma_rule(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<CreateDetectionRule>,
) -> Result<Json<crate::services::alerter::DetectionRuleRecord>, ApiError> {
    ensure_detection_write_access(&auth)?;
    let actor_id = auth.actor_id();
    Ok(Json(
        state
            .alerter
            .import_detection_rule(auth.tenant_id, &actor_id, req, "sigma")
            .await?,
    ))
}

async fn import_yara_rule(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<CreateDetectionRule>,
) -> Result<Json<crate::services::alerter::DetectionRuleRecord>, ApiError> {
    ensure_detection_write_access(&auth)?;
    let actor_id = auth.actor_id();
    Ok(Json(
        state
            .alerter
            .import_detection_rule(auth.tenant_id, &actor_id, req, "yara")
            .await?,
    ))
}

async fn list_detection_findings(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Query(query): Query<DetectionFindingListQuery>,
) -> Result<Json<Vec<crate::services::alerter::DetectionFindingRecord>>, ApiError> {
    Ok(Json(
        state
            .alerter
            .list_detection_findings(
                auth.tenant_id,
                query.status.as_deref(),
                query.severity.as_deref(),
                query.rule_id,
                query.principal_id,
            )
            .await?,
    ))
}

async fn get_detection_finding(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::services::alerter::DetectionFindingRecord>, ApiError> {
    Ok(Json(
        state
            .alerter
            .get_detection_finding(auth.tenant_id, id)
            .await?,
    ))
}

async fn suppress_detection_finding(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<FindingActionRequest>,
) -> Result<Json<crate::services::alerter::DetectionFindingRecord>, ApiError> {
    ensure_detection_write_access(&auth)?;
    let actor_id = auth.actor_id();
    Ok(Json(
        state
            .alerter
            .suppress_detection_finding(auth.tenant_id, id, &actor_id, &req.reason)
            .await?,
    ))
}

async fn resolve_detection_finding(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<FindingActionRequest>,
) -> Result<Json<crate::services::alerter::DetectionFindingRecord>, ApiError> {
    ensure_detection_write_access(&auth)?;
    Ok(Json(
        state
            .alerter
            .resolve_detection_finding(auth.tenant_id, id, &req.reason)
            .await?,
    ))
}

async fn false_positive_detection_finding(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<FindingActionRequest>,
) -> Result<Json<crate::services::alerter::DetectionFindingRecord>, ApiError> {
    ensure_detection_write_access(&auth)?;
    Ok(Json(
        state
            .alerter
            .false_positive_detection_finding(auth.tenant_id, id, &req.reason)
            .await?,
    ))
}

async fn list_detection_suppressions(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<Vec<crate::services::alerter::DetectionSuppressionRecord>>, ApiError> {
    Ok(Json(
        state
            .alerter
            .list_detection_suppressions(auth.tenant_id)
            .await?,
    ))
}

async fn create_detection_suppression(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<CreateDetectionSuppression>,
) -> Result<Json<crate::services::alerter::DetectionSuppressionRecord>, ApiError> {
    ensure_detection_write_access(&auth)?;
    let actor_id = auth.actor_id();
    Ok(Json(
        state
            .alerter
            .create_detection_suppression(auth.tenant_id, &actor_id, req)
            .await?,
    ))
}

async fn get_detection_suppression(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::services::alerter::DetectionSuppressionRecord>, ApiError> {
    Ok(Json(
        state
            .alerter
            .get_detection_suppression(auth.tenant_id, id)
            .await?,
    ))
}

async fn revoke_detection_suppression(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<crate::services::alerter::DetectionSuppressionRecord>, ApiError> {
    ensure_detection_write_access(&auth)?;
    Ok(Json(
        state
            .alerter
            .revoke_detection_suppression(auth.tenant_id, id)
            .await?,
    ))
}

async fn list_detection_packs(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<Vec<crate::services::alerter::InstalledDetectionPackRecord>>, ApiError> {
    Ok(Json(
        state.alerter.list_detection_packs(auth.tenant_id).await?,
    ))
}

async fn install_detection_pack(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<InstallDetectionPackRequest>,
) -> Result<Json<crate::services::alerter::InstalledDetectionPackRecord>, ApiError> {
    ensure_detection_write_access(&auth)?;
    let actor_id = auth.actor_id();
    Ok(Json(
        state
            .alerter
            .install_detection_pack(auth.tenant_id, &actor_id, req)
            .await?,
    ))
}

async fn get_detection_pack(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path((name, version)): Path<(String, String)>,
) -> Result<Json<crate::services::alerter::InstalledDetectionPackRecord>, ApiError> {
    Ok(Json(
        state
            .alerter
            .get_detection_pack(auth.tenant_id, &name, &version)
            .await?,
    ))
}

async fn activate_detection_pack(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path((name, version)): Path<(String, String)>,
    Json(req): Json<ActivateDetectionPackRequest>,
) -> Result<Json<crate::services::alerter::InstalledDetectionPackRecord>, ApiError> {
    ensure_detection_write_access(&auth)?;
    Ok(Json(
        state
            .alerter
            .activate_detection_pack(auth.tenant_id, &name, &version, req)
            .await?,
    ))
}

async fn deactivate_detection_pack(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path((name, version)): Path<(String, String)>,
) -> Result<Json<crate::services::alerter::InstalledDetectionPackRecord>, ApiError> {
    ensure_detection_write_access(&auth)?;
    Ok(Json(
        state
            .alerter
            .deactivate_detection_pack(auth.tenant_id, &name, &version)
            .await?,
    ))
}

async fn list_detection_pack_rules(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path((name, version)): Path<(String, String)>,
) -> Result<Json<Vec<crate::services::alerter::DetectionRuleRecord>>, ApiError> {
    Ok(Json(
        state
            .alerter
            .list_detection_pack_rules(auth.tenant_id, &name, &version)
            .await?,
    ))
}
