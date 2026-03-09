use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A policy template in the catalog registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogTemplate {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub category: String,
    pub tags: Vec<String>,
    pub policy_yaml: String,
    pub author: String,
    pub version: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub downloads: u64,
    pub forked_from: Option<Uuid>,
}

/// A category grouping for catalog templates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogCategory {
    pub id: String,
    pub name: String,
    pub description: String,
    pub template_count: u64,
}

/// Request body for creating a new catalog template.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCatalogTemplateRequest {
    pub name: String,
    pub description: String,
    pub category: String,
    pub tags: Option<Vec<String>>,
    pub policy_yaml: String,
    pub author: Option<String>,
    pub version: Option<String>,
}

/// Request body for updating an existing catalog template.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateCatalogTemplateRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub category: Option<String>,
    pub tags: Option<Vec<String>>,
    pub policy_yaml: Option<String>,
    pub version: Option<String>,
}

/// Query parameters for listing catalog templates.
#[derive(Debug, Deserialize)]
pub struct CatalogTemplateListQuery {
    pub category: Option<String>,
    pub tag: Option<String>,
}
