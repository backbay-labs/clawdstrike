use chrono::{DateTime, Utc};
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use sqlx::row::Row;
use uuid::Uuid;

use crate::db::PgRow;

// ---------------------------------------------------------------------------
// Node type enum
// ---------------------------------------------------------------------------

/// The kind of hierarchy node: org, team, project, endpoint, or runtime.
///
/// The `Agent` variant is kept for backward-compatible deserialization of data
/// written before the endpoint/runtime split.  New code should use `Endpoint`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HierarchyNodeType {
    Org,
    Team,
    Project,
    /// Legacy alias — kept so old rows deserialize correctly.
    Agent,
    /// A hushd daemon instance (replaces the old "agent" concept).
    Endpoint,
    /// An AI agent runtime, always a child of an Endpoint.
    Runtime,
}

impl HierarchyNodeType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Org => "org",
            Self::Team => "team",
            Self::Project => "project",
            Self::Agent => "agent",
            Self::Endpoint => "endpoint",
            Self::Runtime => "runtime",
        }
    }

    /// Parse a node type string.
    ///
    /// `"agent"` maps to `Endpoint` for backward compatibility — callers that
    /// need to distinguish truly-old `Agent` rows should match the raw DB
    /// string instead.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "org" => Some(Self::Org),
            "team" => Some(Self::Team),
            "project" => Some(Self::Project),
            "agent" => Some(Self::Endpoint),
            "endpoint" => Some(Self::Endpoint),
            "runtime" => Some(Self::Runtime),
            _ => None,
        }
    }
}

impl std::fmt::Display for HierarchyNodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl HierarchyNodeType {
    /// Returns true if this variant represents the legacy "agent" type that was
    /// superseded by `Endpoint`.
    pub fn is_legacy_agent(self) -> bool {
        matches!(self, Self::Agent)
    }
}

// ---------------------------------------------------------------------------
// Domain model
// ---------------------------------------------------------------------------

/// A hierarchy node stored in the database.
#[derive(Debug, Clone, Serialize)]
pub struct HierarchyNode {
    pub id: Uuid,
    #[serde(skip_serializing)]
    pub tenant_id: Uuid,
    pub name: String,
    pub node_type: String,
    pub parent_id: Option<Uuid>,
    pub external_id: Option<String>,
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
            external_id: row.try_get("external_id")?,
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
    pub external_id: Option<String>,
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
    pub external_id: Option<String>,
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
    #[serde(default)]
    pub parent_id: NullableField<Uuid>,
    #[serde(default)]
    pub external_id: NullableField<String>,
    #[serde(default)]
    pub policy_id: NullableField<Uuid>,
    #[serde(default)]
    pub policy_name: NullableField<String>,
    #[serde(default)]
    pub metadata: NullableField<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum NullableField<T> {
    #[default]
    Missing,
    Set(T),
    Clear,
}

impl<T> NullableField<T> {
    pub fn as_ref(&self) -> NullableField<&T> {
        match self {
            Self::Missing => NullableField::Missing,
            Self::Set(value) => NullableField::Set(value),
            Self::Clear => NullableField::Clear,
        }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> NullableField<U> {
        match self {
            Self::Missing => NullableField::Missing,
            Self::Set(value) => NullableField::Set(f(value)),
            Self::Clear => NullableField::Clear,
        }
    }

    pub fn into_option(self) -> Option<T> {
        match self {
            Self::Missing => None,
            Self::Set(value) => Some(value),
            Self::Clear => None,
        }
    }
}

impl<'de, T> Deserialize<'de> for NullableField<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<T>::deserialize(deserializer)? {
            Some(value) => Ok(Self::Set(value)),
            None => Ok(Self::Clear),
        }
    }
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
    /// Number of descendant nodes that were cascade-deleted (excluded from `deleted_count`
    /// which includes the target node itself).
    pub descendant_count: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_type_round_trip() {
        // Endpoint and Runtime round-trip through their canonical string forms.
        for nt in [
            HierarchyNodeType::Org,
            HierarchyNodeType::Team,
            HierarchyNodeType::Project,
            HierarchyNodeType::Endpoint,
            HierarchyNodeType::Runtime,
        ] {
            assert_eq!(HierarchyNodeType::from_str(nt.as_str()), Some(nt));
        }
    }

    #[test]
    fn node_type_agent_backward_compat() {
        // "agent" in from_str maps to Endpoint for backward compatibility.
        assert_eq!(
            HierarchyNodeType::from_str("agent"),
            Some(HierarchyNodeType::Endpoint)
        );
        // The Agent variant still serializes as "agent".
        assert_eq!(HierarchyNodeType::Agent.as_str(), "agent");
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
    fn node_type_serde_endpoint_and_runtime() {
        let endpoint_json = serde_json::to_string(&HierarchyNodeType::Endpoint).expect("serialize");
        assert_eq!(endpoint_json, "\"endpoint\"");
        let deserialized: HierarchyNodeType =
            serde_json::from_str(&endpoint_json).expect("deserialize");
        assert_eq!(deserialized, HierarchyNodeType::Endpoint);

        let runtime_json = serde_json::to_string(&HierarchyNodeType::Runtime).expect("serialize");
        assert_eq!(runtime_json, "\"runtime\"");
        let deserialized: HierarchyNodeType =
            serde_json::from_str(&runtime_json).expect("deserialize");
        assert_eq!(deserialized, HierarchyNodeType::Runtime);
    }

    #[test]
    fn node_type_serde_deserializes_legacy_agent() {
        // Old data stored as "agent" should still deserialize via serde.
        let deserialized: HierarchyNodeType =
            serde_json::from_str("\"agent\"").expect("deserialize");
        assert_eq!(deserialized, HierarchyNodeType::Agent);
    }

    #[test]
    fn is_legacy_agent() {
        assert!(HierarchyNodeType::Agent.is_legacy_agent());
        assert!(!HierarchyNodeType::Endpoint.is_legacy_agent());
        assert!(!HierarchyNodeType::Runtime.is_legacy_agent());
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
    fn update_request_distinguishes_missing_and_null_for_clearable_fields() {
        let missing: UpdateHierarchyNodeRequest = serde_json::from_str("{}").expect("parse");
        assert_eq!(missing.parent_id, NullableField::Missing);
        assert_eq!(missing.policy_id, NullableField::Missing);
        assert_eq!(missing.policy_name, NullableField::Missing);
        assert_eq!(missing.metadata, NullableField::Missing);

        let explicit_null: UpdateHierarchyNodeRequest = serde_json::from_str(
            r#"{"parent_id":null,"policy_id":null,"policy_name":null,"metadata":null}"#,
        )
        .expect("parse");
        assert_eq!(explicit_null.parent_id, NullableField::Clear);
        assert_eq!(explicit_null.policy_id, NullableField::Clear);
        assert_eq!(explicit_null.policy_name, NullableField::Clear);
        assert_eq!(explicit_null.metadata, NullableField::Clear);
    }

    #[test]
    fn update_request_preserves_values_for_clearable_fields() {
        let policy_id = Uuid::new_v4();
        let parent_id = Uuid::new_v4();
        let req: UpdateHierarchyNodeRequest = serde_json::from_str(&format!(
            r#"{{"parent_id":"{parent_id}","policy_id":"{policy_id}","policy_name":"strict","metadata":{{"tier":"prod"}}}}"#,
        ))
        .expect("parse");

        assert_eq!(req.parent_id, NullableField::Set(parent_id));
        assert_eq!(req.policy_id, NullableField::Set(policy_id));
        assert_eq!(req.policy_name, NullableField::Set("strict".to_string()));
        assert_eq!(
            req.metadata,
            NullableField::Set(serde_json::json!({ "tier": "prod" }))
        );
    }

    #[test]
    fn delete_query_defaults_reparent_to_none() {
        let json = "{}";
        let q: DeleteHierarchyNodeQuery = serde_json::from_str(json).expect("parse");
        assert_eq!(q.reparent, None);
    }
}
