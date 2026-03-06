use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::row::Row;
use uuid::Uuid;

use crate::db::PgRow;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetCase {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub severity: String,
    pub status: String,
    pub created_by: String,
    pub principal_ids: Vec<String>,
    pub detection_ids: Vec<String>,
    pub response_action_ids: Vec<String>,
    pub grant_ids: Vec<String>,
    pub tags: Vec<String>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl FleetCase {
    pub fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            title: row.try_get("title")?,
            summary: row.try_get("summary")?,
            severity: row.try_get("severity")?,
            status: row.try_get("status")?,
            created_by: row.try_get("created_by")?,
            principal_ids: row.try_get("principal_ids")?,
            detection_ids: row.try_get("detection_ids")?,
            response_action_ids: row.try_get("response_action_ids")?,
            grant_ids: row.try_get("grant_ids")?,
            tags: row.try_get("tags")?,
            metadata: row.try_get("metadata")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseArtifactRef {
    pub id: Uuid,
    pub case_id: Uuid,
    pub artifact_kind: String,
    pub artifact_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub metadata: Value,
    pub added_by: String,
    pub added_at: DateTime<Utc>,
}

impl CaseArtifactRef {
    pub fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            case_id: row.try_get("case_id")?,
            artifact_kind: row.try_get("artifact_kind")?,
            artifact_id: row.try_get("artifact_id")?,
            summary: row.try_get("summary")?,
            metadata: row.try_get("metadata")?,
            added_by: row.try_get("added_by")?,
            added_at: row.try_get("added_at")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetEvidenceBundle {
    pub export_id: String,
    pub tenant_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_id: Option<Uuid>,
    pub status: String,
    pub requested_by: String,
    pub requested_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub retention_days: i32,
    pub filters: Value,
    pub artifact_counts: Value,
    pub metadata: Value,
}

impl FleetEvidenceBundle {
    pub fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        let status: String = row.try_get("status")?;
        let expires_at: Option<DateTime<Utc>> = row.try_get("expires_at")?;
        let status = if status == "completed" && expires_at.is_some_and(|ts| ts <= Utc::now()) {
            "expired".to_string()
        } else {
            status
        };

        Ok(Self {
            export_id: row.try_get("export_id")?,
            tenant_id: row.try_get("tenant_id")?,
            case_id: row.try_get("case_id")?,
            status,
            requested_by: row.try_get("requested_by")?,
            requested_at: row.try_get("requested_at")?,
            completed_at: row.try_get("completed_at")?,
            file_path: row.try_get("file_path")?,
            sha256: row.try_get("sha256")?,
            size_bytes: row.try_get("size_bytes")?,
            manifest_ref: row.try_get("manifest_ref")?,
            expires_at,
            retention_days: row.try_get("retention_days")?,
            filters: row.try_get("filters")?,
            artifact_counts: row.try_get("artifact_counts")?,
            metadata: row.try_get("metadata")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaseTimelineEvent {
    pub id: Uuid,
    pub case_id: Uuid,
    pub event_kind: String,
    pub actor_id: String,
    pub payload: Value,
    pub created_at: DateTime<Utc>,
}

impl CaseTimelineEvent {
    pub fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            case_id: row.try_get("case_id")?,
            event_kind: row.try_get("event_kind")?,
            actor_id: row.try_get("actor_id")?,
            payload: row.try_get("payload")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetCaseDetail {
    pub case: FleetCase,
    pub artifacts: Vec<CaseArtifactRef>,
    pub evidence_bundles: Vec<FleetEvidenceBundle>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateFleetCaseRequest {
    pub title: String,
    pub summary: Option<String>,
    pub severity: String,
    pub status: Option<String>,
    #[serde(default)]
    pub principal_ids: Vec<String>,
    #[serde(default)]
    pub detection_ids: Vec<String>,
    #[serde(default)]
    pub response_action_ids: Vec<String>,
    #[serde(default)]
    pub grant_ids: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateFleetCaseRequest {
    pub title: Option<String>,
    pub summary: Option<String>,
    pub severity: Option<String>,
    pub status: Option<String>,
    pub principal_ids: Option<Vec<String>>,
    pub detection_ids: Option<Vec<String>>,
    pub response_action_ids: Option<Vec<String>>,
    pub grant_ids: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AddCaseArtifactRequest {
    pub artifact_kind: String,
    pub artifact_id: String,
    pub summary: Option<String>,
    #[serde(default = "default_metadata")]
    pub metadata: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExportEvidenceBundleRequest {
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub principal_ids: Option<Vec<String>>,
    pub detection_ids: Option<Vec<String>>,
    pub response_action_ids: Option<Vec<String>>,
    pub source_families: Option<Vec<String>>,
    pub include_raw_envelopes: Option<bool>,
    pub include_ocsf: Option<bool>,
    pub retention_days: Option<i32>,
}

pub fn default_metadata() -> Value {
    Value::Object(Default::default())
}
