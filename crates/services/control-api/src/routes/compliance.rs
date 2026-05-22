use axum::extract::{Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::row::Row;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/compliance/export", get(export_audit_log))
        .route("/compliance/retention", get(get_retention))
        .route("/compliance/retention", put(update_retention))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditExportQuery {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    pub format: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuditEntry {
    tenant_id: uuid::Uuid,
    event_type: String,
    quantity: i32,
    metadata: Option<serde_json::Value>,
    recorded_at: DateTime<Utc>,
}

async fn export_audit_log(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Query(params): Query<AuditExportQuery>,
) -> Result<axum::response::Response, ApiError> {
    if auth.plan != "enterprise" {
        return Err(ApiError::PlanUpgradeRequired("audit_export"));
    }

    let rows = sqlx::query::query(
        r#"SELECT tenant_id, event_type, quantity, metadata, recorded_at
           FROM usage_events
           WHERE tenant_id = $1 AND recorded_at >= $2 AND recorded_at <= $3
           ORDER BY recorded_at ASC"#,
    )
    .bind(auth.tenant_id)
    .bind(params.from)
    .bind(params.to)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let entries: Vec<AuditEntry> = rows
        .into_iter()
        .map(|r| -> Result<AuditEntry, sqlx::error::Error> {
            Ok(AuditEntry {
                tenant_id: r.try_get("tenant_id")?,
                event_type: r.try_get("event_type")?,
                quantity: r.try_get("quantity")?,
                metadata: r.try_get("metadata")?,
                recorded_at: r.try_get("recorded_at")?,
            })
        })
        .collect::<Result<_, _>>()
        .map_err(ApiError::Database)?;

    let format = params.format.as_deref().unwrap_or("json");

    match format {
        "csv" => {
            let mut csv = String::from("tenant_id,event_type,quantity,recorded_at,metadata\n");
            for entry in &entries {
                let metadata = audit_metadata_string(&entry.metadata)?;
                csv.push_str(&format!(
                    "{},{},{},{},{}\n",
                    csv_field(&entry.tenant_id.to_string()),
                    csv_field(&entry.event_type),
                    entry.quantity,
                    csv_field(&entry.recorded_at.to_rfc3339()),
                    csv_field(&metadata)
                ));
            }
            Ok((
                [
                    (header::CONTENT_TYPE, "text/csv"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=audit-export.csv",
                    ),
                ],
                csv,
            )
                .into_response())
        }
        "cef" => {
            let mut cef = String::new();
            for entry in &entries {
                let metadata = audit_metadata_string(&entry.metadata)?;
                let metadata_extension = if metadata.is_empty() {
                    String::new()
                } else {
                    format!(" cs1Label=metadata cs1={}", cef_field(&metadata))
                };
                cef.push_str(&format!(
                    "CEF:0|ClawdStrike|Cloud|1.0|{}|{}|1|tenant={} quantity={} rt={}{}\n",
                    entry.event_type,
                    entry.event_type,
                    entry.tenant_id,
                    entry.quantity,
                    entry.recorded_at.timestamp_millis(),
                    metadata_extension
                ));
            }
            Ok((
                [
                    (header::CONTENT_TYPE, "text/plain"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=audit-export.cef",
                    ),
                ],
                cef,
            )
                .into_response())
        }
        _ => {
            let body = serde_json::to_string_pretty(&entries)
                .map_err(|e| ApiError::Internal(e.to_string()))?;
            Ok((
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=audit-export.json",
                    ),
                ],
                body,
            )
                .into_response())
        }
    }
}

fn audit_metadata_string(metadata: &Option<serde_json::Value>) -> Result<String, ApiError> {
    match metadata {
        Some(metadata) => {
            serde_json::to_string(metadata).map_err(|err| ApiError::Internal(err.to_string()))
        }
        None => Ok(String::new()),
    }
}

fn csv_field(value: &str) -> String {
    let needs_quotes =
        value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r');
    if needs_quotes {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn cef_field(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace(' ', "\\ ")
}

#[derive(Debug, Serialize)]
struct RetentionSettings {
    tenant_id: uuid::Uuid,
    retention_days: i32,
    plan: String,
}

async fn get_retention(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<RetentionSettings>, ApiError> {
    let row = sqlx::query::query("SELECT id, retention_days, plan FROM tenants WHERE id = $1")
        .bind(auth.tenant_id)
        .fetch_one(&state.db)
        .await
        .map_err(ApiError::Database)?;

    Ok(Json(RetentionSettings {
        tenant_id: row.try_get("id").map_err(ApiError::Database)?,
        retention_days: row.try_get("retention_days").map_err(ApiError::Database)?,
        plan: row.try_get("plan").map_err(ApiError::Database)?,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRetentionRequest {
    pub retention_days: i32,
}

async fn update_retention(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<UpdateRetentionRequest>,
) -> Result<Json<RetentionSettings>, ApiError> {
    if auth.role == "viewer" || auth.role == "member" {
        return Err(ApiError::Forbidden);
    }

    let max_days = if auth.plan == "enterprise" { 730 } else { 30 };
    if req.retention_days < 1 || req.retention_days > max_days {
        return Err(ApiError::BadRequest(format!(
            "retention_days must be between 1 and {max_days}"
        )));
    }

    sqlx::query::query("UPDATE tenants SET retention_days = $2, updated_at = now() WHERE id = $1")
        .bind(auth.tenant_id)
        .bind(req.retention_days)
        .execute(&state.db)
        .await
        .map_err(ApiError::Database)?;

    Ok(Json(RetentionSettings {
        tenant_id: auth.tenant_id,
        retention_days: req.retention_days,
        plan: auth.plan,
    }))
}
