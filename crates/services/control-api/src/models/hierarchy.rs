use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::row::Row;
use uuid::Uuid;

use crate::db::PgRow;

// ---------------------------------------------------------------------------
// Node type enum
// ---------------------------------------------------------------------------

/// The kind of hierarchy node: org, team, project, or agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HierarchyNodeType {
    Org,
    Team,
    Project,
    Agent,
}

impl HierarchyNodeType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Org => "org",
            Self::Team => "team",
            Self::Project => "project",
            Self::Agent => "agent",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "org" => Some(Self::Org),
            "team" => Some(Self::Team),
            "project" => Some(Self::Project),
            "agent" => Some(Self::Agent),
            _ => None,
        }
    }
}

impl std::fmt::Display for HierarchyNodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Domain model
// ---------------------------------------------------------------------------

/// A hierarchy node stored in the database.
#[derive(Debug, Clone, Serialize)]
pub struct HierarchyNode {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub node_type: String,
    pub parent_id: Option<Uuid>,
    pub policy_id: Option<Uuid>,
    pub policy_name: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl HierarchyNode {
    pub fn from_row(row: PgRow) -> Result<Self, sqlx::error::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            name: row.try_get("name")?,
            node_type: row.try_get("node_type")?,
            parent_id: row.try_get("parent_id")?,
            policy_id: row.try_get("policy_id")?,
            policy_name: row.try_get("policy_name")?,
            metadata: row.try_get("metadata")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

/// A node enriched with its ordered children IDs, used in tree responses.
#[derive(Debug, Clone, Serialize)]
pub struct HierarchyTreeNode {
    pub id: Uuid,
    pub name: String,
    pub node_type: String,
    pub parent_id: Option<Uuid>,
    pub policy_id: Option<Uuid>,
    pub policy_name: Option<String>,
    pub metadata: serde_json::Value,
    pub children: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Full tree response returned by GET /hierarchy/tree.
#[derive(Debug, Clone, Serialize)]
pub struct HierarchyTreeResponse {
    pub root_id: Option<Uuid>,
    pub nodes: Vec<HierarchyTreeNode>,
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateHierarchyNodeRequest {
    pub name: String,
    pub node_type: String,
    pub parent_id: Option<Uuid>,
    pub policy_id: Option<Uuid>,
    pub policy_name: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateHierarchyNodeRequest {
    pub name: Option<String>,
    pub node_type: Option<String>,
    pub parent_id: Option<Uuid>,
    pub policy_id: Option<Uuid>,
    pub policy_name: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteHierarchyNodeQuery {
    /// When `reparent=true`, children are moved to the deleted node's parent.
    /// When `false` (default), children are cascade-deleted.
    #[serde(default)]
    pub reparent: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct DeleteHierarchyNodeResponse {
    pub deleted_count: i64,
    pub reparented_count: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_type_round_trip() {
        for nt in [
            HierarchyNodeType::Org,
            HierarchyNodeType::Team,
            HierarchyNodeType::Project,
            HierarchyNodeType::Agent,
        ] {
            assert_eq!(HierarchyNodeType::from_str(nt.as_str()), Some(nt));
        }
    }

    #[test]
    fn node_type_rejects_unknown() {
        assert_eq!(HierarchyNodeType::from_str("unknown"), None);
        assert_eq!(HierarchyNodeType::from_str(""), None);
    }

    #[test]
    fn node_type_serde_round_trip() {
        let json = serde_json::to_string(&HierarchyNodeType::Project).expect("serialize");
        assert_eq!(json, "\"project\"");
        let deserialized: HierarchyNodeType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized, HierarchyNodeType::Project);
    }

    #[test]
    fn create_request_rejects_unknown_fields() {
        let json = r#"{"name":"x","node_type":"org","unknown_field":true}"#;
        let result = serde_json::from_str::<CreateHierarchyNodeRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn update_request_rejects_unknown_fields() {
        let json = r#"{"name":"x","extra":1}"#;
        let result = serde_json::from_str::<UpdateHierarchyNodeRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn delete_query_defaults_reparent_to_none() {
        let json = "{}";
        let q: DeleteHierarchyNodeQuery = serde_json::from_str(json).expect("parse");
        assert_eq!(q.reparent, None);
    }
}
