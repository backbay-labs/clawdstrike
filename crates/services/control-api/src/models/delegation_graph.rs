use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::row::Row;
use uuid::Uuid;

use crate::db::PgRow;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetGrant {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub issuer_principal_id: String,
    pub subject_principal_id: String,
    pub grant_type: String,
    pub audience: String,
    pub token_jti: String,
    pub parent_grant_id: Option<Uuid>,
    pub parent_token_jti: Option<String>,
    pub delegation_depth: i32,
    pub lineage_chain: Vec<String>,
    pub lineage_resolved: bool,
    pub capabilities: serde_json::Value,
    pub capability_ceiling: serde_json::Value,
    pub purpose: Option<String>,
    pub context: serde_json::Value,
    pub source_approval_id: Option<String>,
    pub source_session_id: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub status: String,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_by: Option<String>,
    pub revoke_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl FleetGrant {
    pub fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        let lineage_chain_value: serde_json::Value = row.try_get("lineage_chain")?;
        let lineage_chain = serde_json::from_value(lineage_chain_value)
            .map_err(|err| sqlx::error::Error::Decode(Box::new(err)))?;

        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            issuer_principal_id: row.try_get("issuer_principal_id")?,
            subject_principal_id: row.try_get("subject_principal_id")?,
            grant_type: row.try_get("grant_type")?,
            audience: row.try_get("audience")?,
            token_jti: row.try_get("token_jti")?,
            parent_grant_id: row.try_get("parent_grant_id")?,
            parent_token_jti: row.try_get("parent_token_jti")?,
            delegation_depth: row.try_get("delegation_depth")?,
            lineage_chain,
            lineage_resolved: row.try_get("lineage_resolved")?,
            capabilities: row.try_get("capabilities")?,
            capability_ceiling: row.try_get("capability_ceiling")?,
            purpose: row.try_get("purpose")?,
            context: row.try_get("context")?,
            source_approval_id: row.try_get("source_approval_id")?,
            source_session_id: row.try_get("source_session_id")?,
            issued_at: row.try_get("issued_at")?,
            not_before: row.try_get("not_before")?,
            expires_at: row.try_get("expires_at")?,
            status: row.try_get("status")?,
            revoked_at: row.try_get("revoked_at")?,
            revoked_by: row.try_get("revoked_by")?,
            revoke_reason: row.try_get("revoke_reason")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationGraphNode {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub state: Option<String>,
    pub metadata: serde_json::Value,
}

impl DelegationGraphNode {
    pub fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            kind: row.try_get("kind")?,
            label: row.try_get("label")?,
            state: row.try_get("state")?,
            metadata: row.try_get("metadata")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationGraphEdge {
    pub id: Uuid,
    pub from: String,
    pub to: String,
    pub kind: String,
    pub metadata: serde_json::Value,
}

impl DelegationGraphEdge {
    pub fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            from: row.try_get("from_node_id")?,
            to: row.try_get("to_node_id")?,
            kind: row.try_get("kind")?,
            metadata: row.try_get("metadata")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationGraphSnapshot {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_node_id: Option<String>,
    pub nodes: Vec<DelegationGraphNode>,
    pub edges: Vec<DelegationGraphEdge>,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ListGrantsQuery {
    pub principal_id: Option<String>,
    pub status: Option<String>,
    pub token_jti: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GraphPathQuery {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IngestGrantRequest {
    pub token: hush_multi_agent::SignedDelegationToken,
    #[serde(default)]
    pub grant_type: Option<String>,
    #[serde(default)]
    pub source_approval_id: Option<String>,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub issuer_public_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GrantExerciseRequest {
    #[serde(default)]
    pub event_id: Option<String>,
    #[serde(default)]
    pub event_label: Option<String>,
    #[serde(default)]
    pub event_state: Option<String>,
    #[serde(default)]
    pub event_metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub response_action_id: Option<String>,
    #[serde(default)]
    pub response_action_label: Option<String>,
    #[serde(default)]
    pub response_action_state: Option<String>,
    #[serde(default)]
    pub response_action_metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub session_label: Option<String>,
    #[serde(default)]
    pub session_state: Option<String>,
    #[serde(default)]
    pub session_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RevokeGrantRequest {
    pub reason: String,
    #[serde(default)]
    pub revoke_descendants: Option<bool>,
    #[serde(default)]
    pub revoked_by: Option<String>,
    #[serde(default)]
    pub response_action_id: Option<String>,
    #[serde(default)]
    pub response_action_label: Option<String>,
    #[serde(default)]
    pub response_action_state: Option<String>,
    #[serde(default)]
    pub response_action_metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokeGrantResponse {
    pub grant: FleetGrant,
    pub revoked_grant_ids: Vec<Uuid>,
}
