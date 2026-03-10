use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A policy template in the catalog registry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[serde(deny_unknown_fields)]
pub struct CatalogTemplateListQuery {
    pub category: Option<String>,
    pub tag: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_request_rejects_unknown_fields() {
        let json = r#"{
            "name": "Baseline",
            "description": "Default catalog template",
            "category": "starter",
            "policy_yaml": "version: \"1.0.0\"\n",
            "unexpected": true
        }"#;

        let result = serde_json::from_str::<CreateCatalogTemplateRequest>(json);
        assert!(result.is_err());
    }

    #[test]
    fn update_request_rejects_unknown_fields() {
        let result = serde_json::from_str::<UpdateCatalogTemplateRequest>(
            r#"{"name":"Updated","extra":"nope"}"#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn catalog_template_and_category_round_trip() {
        let template = CatalogTemplate {
            id: Uuid::new_v4(),
            name: "Baseline".to_string(),
            description: "Default catalog template".to_string(),
            category: "starter".to_string(),
            tags: vec!["default".to_string(), "starter".to_string()],
            policy_yaml: "version: \"1.0.0\"\n".to_string(),
            author: "ClawdStrike".to_string(),
            version: "2026.03".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            downloads: 7,
            forked_from: None,
        };
        let category = CatalogCategory {
            id: "starter".to_string(),
            name: "Starter".to_string(),
            description: "Ready-to-run templates".to_string(),
            template_count: 3,
        };

        let template_json = serde_json::to_value(&template).expect("serialize template");
        let category_json = serde_json::to_value(&category).expect("serialize category");

        assert_eq!(
            serde_json::from_value::<CatalogTemplate>(template_json).expect("deserialize template"),
            template
        );
        assert_eq!(
            serde_json::from_value::<CatalogCategory>(category_json).expect("deserialize category"),
            category
        );
    }

    #[test]
    fn list_query_deserializes_filters() {
        let query: CatalogTemplateListQuery =
            serde_json::from_str(r#"{"category":"starter","tag":"default"}"#)
                .expect("deserialize query");

        assert_eq!(query.category.as_deref(), Some("starter"));
        assert_eq!(query.tag.as_deref(), Some("default"));
    }
}
