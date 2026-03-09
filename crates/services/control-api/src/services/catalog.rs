use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::ApiError;
use crate::models::catalog::{
    CatalogCategory, CatalogTemplate, CatalogTemplateListQuery, CreateCatalogTemplateRequest,
    UpdateCatalogTemplateRequest,
};

/// In-memory catalog registry for policy templates.
#[derive(Debug, Clone)]
pub struct CatalogStore {
    inner: Arc<RwLock<CatalogStoreInner>>,
}

#[derive(Debug)]
struct CatalogStoreInner {
    templates: HashMap<Uuid, CatalogTemplate>,
    /// Known categories with their metadata.
    categories: HashMap<String, CategoryMeta>,
}

#[derive(Debug, Clone)]
struct CategoryMeta {
    name: String,
    description: String,
}

/// Seed entry derived from a built-in ruleset YAML file.
pub struct SeedEntry {
    pub name: String,
    pub description: String,
    pub category: String,
    pub tags: Vec<String>,
    pub policy_yaml: String,
}

impl CatalogStore {
    /// Create a new empty catalog store.
    pub fn new() -> Self {
        let mut categories = HashMap::new();
        for (id, name, description) in Self::default_categories() {
            categories.insert(
                id.to_string(),
                CategoryMeta {
                    name: name.to_string(),
                    description: description.to_string(),
                },
            );
        }

        Self {
            inner: Arc::new(RwLock::new(CatalogStoreInner {
                templates: HashMap::new(),
                categories,
            })),
        }
    }

    fn default_categories() -> Vec<(&'static str, &'static str, &'static str)> {
        vec![
            ("general", "General", "General-purpose security policies"),
            (
                "ai-agent",
                "AI Agent",
                "Policies optimized for AI coding assistants",
            ),
            (
                "cicd",
                "CI/CD",
                "Policies for continuous integration and deployment pipelines",
            ),
            (
                "remote-desktop",
                "Remote Desktop",
                "Policies for computer-use agent (CUA) remote desktop sessions",
            ),
            (
                "detection",
                "Detection",
                "Threat detection and screening policies",
            ),
            (
                "origin",
                "Origin Enclaves",
                "Origin-aware enforcement policies with enclave profiles",
            ),
        ]
    }

    /// Seed the store with built-in ruleset templates.
    pub async fn seed(&self, entries: Vec<SeedEntry>) {
        let mut inner = self.inner.write().await;
        let now = Utc::now();

        for entry in entries {
            let id = Uuid::new_v4();
            let template = CatalogTemplate {
                id,
                name: entry.name,
                description: entry.description,
                category: entry.category,
                tags: entry.tags,
                policy_yaml: entry.policy_yaml,
                author: "clawdstrike".to_string(),
                version: "1.0.0".to_string(),
                created_at: now,
                updated_at: now,
                downloads: 0,
                forked_from: None,
            };
            inner.templates.insert(id, template);
        }
    }

    /// List all templates, optionally filtered by category and/or tag.
    pub async fn list_templates(&self, query: &CatalogTemplateListQuery) -> Vec<CatalogTemplate> {
        let inner = self.inner.read().await;
        let mut results: Vec<CatalogTemplate> = inner
            .templates
            .values()
            .filter(|t| {
                if let Some(ref category) = query.category {
                    if t.category != *category {
                        return false;
                    }
                }
                if let Some(ref tag) = query.tag {
                    if !t.tags.iter().any(|t_tag| t_tag == tag) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        results.sort_by(|a, b| a.name.cmp(&b.name));
        results
    }

    /// Get a single template by ID.
    pub async fn get_template(&self, id: Uuid) -> Result<CatalogTemplate, ApiError> {
        let inner = self.inner.read().await;
        inner.templates.get(&id).cloned().ok_or(ApiError::NotFound)
    }

    /// Create a new template from a request.
    pub async fn create_template(
        &self,
        req: CreateCatalogTemplateRequest,
    ) -> Result<CatalogTemplate, ApiError> {
        // Validate that the policy YAML is parseable.
        serde_yaml::from_str::<serde_json::Value>(&req.policy_yaml)
            .map_err(|e| ApiError::BadRequest(format!("invalid policy YAML: {e}")))?;

        let now = Utc::now();
        let id = Uuid::new_v4();
        let template = CatalogTemplate {
            id,
            name: req.name,
            description: req.description,
            category: req.category,
            tags: req.tags.unwrap_or_default(),
            policy_yaml: req.policy_yaml,
            author: req.author.unwrap_or_else(|| "anonymous".to_string()),
            version: req.version.unwrap_or_else(|| "0.1.0".to_string()),
            created_at: now,
            updated_at: now,
            downloads: 0,
            forked_from: None,
        };

        let mut inner = self.inner.write().await;
        inner.templates.insert(id, template.clone());
        Ok(template)
    }

    /// Update an existing template.
    pub async fn update_template(
        &self,
        id: Uuid,
        req: UpdateCatalogTemplateRequest,
    ) -> Result<CatalogTemplate, ApiError> {
        if let Some(ref yaml) = req.policy_yaml {
            serde_yaml::from_str::<serde_json::Value>(yaml)
                .map_err(|e| ApiError::BadRequest(format!("invalid policy YAML: {e}")))?;
        }

        let mut inner = self.inner.write().await;
        let template = inner.templates.get_mut(&id).ok_or(ApiError::NotFound)?;

        if let Some(name) = req.name {
            template.name = name;
        }
        if let Some(description) = req.description {
            template.description = description;
        }
        if let Some(category) = req.category {
            template.category = category;
        }
        if let Some(tags) = req.tags {
            template.tags = tags;
        }
        if let Some(policy_yaml) = req.policy_yaml {
            template.policy_yaml = policy_yaml;
        }
        if let Some(version) = req.version {
            template.version = version;
        }
        template.updated_at = Utc::now();

        Ok(template.clone())
    }

    /// Delete a template by ID.
    pub async fn delete_template(&self, id: Uuid) -> Result<(), ApiError> {
        let mut inner = self.inner.write().await;
        inner
            .templates
            .remove(&id)
            .map(|_| ())
            .ok_or(ApiError::NotFound)
    }

    /// Fork a template: create a copy with a new ID and a reference to the original.
    pub async fn fork_template(&self, id: Uuid) -> Result<CatalogTemplate, ApiError> {
        let inner = self.inner.read().await;
        let source = inner
            .templates
            .get(&id)
            .cloned()
            .ok_or(ApiError::NotFound)?;
        drop(inner);

        let now = Utc::now();
        let new_id = Uuid::new_v4();
        let forked = CatalogTemplate {
            id: new_id,
            name: format!("{} (fork)", source.name),
            description: source.description.clone(),
            category: source.category.clone(),
            tags: source.tags.clone(),
            policy_yaml: source.policy_yaml.clone(),
            author: source.author.clone(),
            version: source.version.clone(),
            created_at: now,
            updated_at: now,
            downloads: 0,
            forked_from: Some(id),
        };

        let mut inner = self.inner.write().await;
        inner.templates.insert(new_id, forked.clone());
        Ok(forked)
    }

    /// List categories with computed template counts.
    pub async fn list_categories(&self) -> Vec<CatalogCategory> {
        let inner = self.inner.read().await;

        // Count templates per category.
        let mut counts: HashMap<String, u64> = HashMap::new();
        for template in inner.templates.values() {
            *counts.entry(template.category.clone()).or_default() += 1;
        }

        let mut categories: Vec<CatalogCategory> = inner
            .categories
            .iter()
            .map(|(id, meta)| CatalogCategory {
                id: id.clone(),
                name: meta.name.clone(),
                description: meta.description.clone(),
                template_count: counts.get(id).copied().unwrap_or(0),
            })
            .collect();

        categories.sort_by(|a, b| a.name.cmp(&b.name));
        categories
    }
}

/// Load built-in rulesets from the embedded YAML files and return seed entries.
pub fn load_builtin_rulesets() -> Vec<SeedEntry> {
    let rulesets: Vec<(&str, &str, &str, Vec<&str>)> = vec![
        (
            "default",
            include_str!("../../../../../rulesets/default.yaml"),
            "general",
            vec!["default", "balanced"],
        ),
        (
            "permissive",
            include_str!("../../../../../rulesets/permissive.yaml"),
            "general",
            vec!["permissive", "development"],
        ),
        (
            "strict",
            include_str!("../../../../../rulesets/strict.yaml"),
            "general",
            vec!["strict", "hardened"],
        ),
        (
            "ai-agent",
            include_str!("../../../../../rulesets/ai-agent.yaml"),
            "ai-agent",
            vec!["ai", "coding-assistant"],
        ),
        (
            "ai-agent-posture",
            include_str!("../../../../../rulesets/ai-agent-posture.yaml"),
            "ai-agent",
            vec!["ai", "posture", "progressive"],
        ),
        (
            "cicd",
            include_str!("../../../../../rulesets/cicd.yaml"),
            "cicd",
            vec!["ci", "cd", "pipeline", "automation"],
        ),
        (
            "remote-desktop",
            include_str!("../../../../../rulesets/remote-desktop.yaml"),
            "remote-desktop",
            vec!["cua", "remote-desktop"],
        ),
        (
            "remote-desktop-permissive",
            include_str!("../../../../../rulesets/remote-desktop-permissive.yaml"),
            "remote-desktop",
            vec!["cua", "remote-desktop", "permissive"],
        ),
        (
            "remote-desktop-strict",
            include_str!("../../../../../rulesets/remote-desktop-strict.yaml"),
            "remote-desktop",
            vec!["cua", "remote-desktop", "strict"],
        ),
        (
            "spider-sense",
            include_str!("../../../../../rulesets/spider-sense.yaml"),
            "detection",
            vec!["spider-sense", "threat-screening", "embedding"],
        ),
        (
            "origin-enclaves-example",
            include_str!("../../../../../rulesets/origin-enclaves-example.yaml"),
            "origin",
            vec!["origin", "enclaves", "example"],
        ),
    ];

    rulesets
        .into_iter()
        .map(|(file_stem, yaml_content, category, tags)| {
            // Parse name and description from the YAML front-matter.
            let parsed: serde_yaml::Value =
                serde_yaml::from_str(yaml_content).unwrap_or(serde_yaml::Value::Null);
            let name = parsed
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or(file_stem)
                .to_string();
            let description = parsed
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            SeedEntry {
                name,
                description,
                category: category.to_string(),
                tags: tags.into_iter().map(|s| s.to_string()).collect(),
                policy_yaml: yaml_content.to_string(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn seed_populates_templates_from_builtin_rulesets() {
        let store = CatalogStore::new();
        let entries = load_builtin_rulesets();
        let count = entries.len();
        assert!(
            count >= 10,
            "expected at least 10 built-in rulesets, got {count}"
        );

        store.seed(entries).await;

        let all = store
            .list_templates(&CatalogTemplateListQuery {
                category: None,
                tag: None,
            })
            .await;
        assert_eq!(all.len(), count);
    }

    #[tokio::test]
    async fn list_filters_by_category() {
        let store = CatalogStore::new();
        store.seed(load_builtin_rulesets()).await;

        let ai_templates = store
            .list_templates(&CatalogTemplateListQuery {
                category: Some("ai-agent".to_string()),
                tag: None,
            })
            .await;
        assert!(
            ai_templates.len() >= 2,
            "expected at least 2 ai-agent templates, got {}",
            ai_templates.len()
        );
        for t in &ai_templates {
            assert_eq!(t.category, "ai-agent");
        }
    }

    #[tokio::test]
    async fn list_filters_by_tag() {
        let store = CatalogStore::new();
        store.seed(load_builtin_rulesets()).await;

        let strict_templates = store
            .list_templates(&CatalogTemplateListQuery {
                category: None,
                tag: Some("strict".to_string()),
            })
            .await;
        assert!(
            !strict_templates.is_empty(),
            "expected at least one template with tag 'strict'"
        );
        for t in &strict_templates {
            assert!(t.tags.contains(&"strict".to_string()));
        }
    }

    #[tokio::test]
    async fn create_and_get_template() {
        let store = CatalogStore::new();
        let created = store
            .create_template(CreateCatalogTemplateRequest {
                name: "test".to_string(),
                description: "test template".to_string(),
                category: "general".to_string(),
                tags: Some(vec!["test".to_string()]),
                policy_yaml: "version: \"1.1.0\"\nname: test\n".to_string(),
                author: Some("tester".to_string()),
                version: Some("0.1.0".to_string()),
            })
            .await
            .expect("create should succeed");

        let fetched = store
            .get_template(created.id)
            .await
            .expect("get should succeed");
        assert_eq!(fetched.name, "test");
        assert_eq!(fetched.author, "tester");
    }

    #[tokio::test]
    async fn create_rejects_invalid_yaml() {
        let store = CatalogStore::new();
        let result = store
            .create_template(CreateCatalogTemplateRequest {
                name: "bad".to_string(),
                description: "bad template".to_string(),
                category: "general".to_string(),
                tags: None,
                policy_yaml: "not: valid: yaml: [".to_string(),
                author: None,
                version: None,
            })
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn update_template_applies_partial_fields() {
        let store = CatalogStore::new();
        let created = store
            .create_template(CreateCatalogTemplateRequest {
                name: "original".to_string(),
                description: "original desc".to_string(),
                category: "general".to_string(),
                tags: None,
                policy_yaml: "version: \"1.1.0\"\nname: original\n".to_string(),
                author: None,
                version: None,
            })
            .await
            .expect("create should succeed");

        let updated = store
            .update_template(
                created.id,
                UpdateCatalogTemplateRequest {
                    name: Some("updated".to_string()),
                    description: None,
                    category: None,
                    tags: None,
                    policy_yaml: None,
                    version: None,
                },
            )
            .await
            .expect("update should succeed");

        assert_eq!(updated.name, "updated");
        assert_eq!(updated.description, "original desc");
    }

    #[tokio::test]
    async fn delete_template_removes_it() {
        let store = CatalogStore::new();
        let created = store
            .create_template(CreateCatalogTemplateRequest {
                name: "to-delete".to_string(),
                description: "will be deleted".to_string(),
                category: "general".to_string(),
                tags: None,
                policy_yaml: "version: \"1.1.0\"\nname: delete-me\n".to_string(),
                author: None,
                version: None,
            })
            .await
            .expect("create should succeed");

        store
            .delete_template(created.id)
            .await
            .expect("delete should succeed");

        assert!(store.get_template(created.id).await.is_err());
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_not_found() {
        let store = CatalogStore::new();
        let result = store.delete_template(Uuid::new_v4()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn fork_template_creates_copy_with_reference() {
        let store = CatalogStore::new();
        let original = store
            .create_template(CreateCatalogTemplateRequest {
                name: "original".to_string(),
                description: "the original".to_string(),
                category: "general".to_string(),
                tags: Some(vec!["source".to_string()]),
                policy_yaml: "version: \"1.1.0\"\nname: original\n".to_string(),
                author: Some("author".to_string()),
                version: Some("1.0.0".to_string()),
            })
            .await
            .expect("create should succeed");

        let forked = store
            .fork_template(original.id)
            .await
            .expect("fork should succeed");

        assert_ne!(forked.id, original.id);
        assert_eq!(forked.name, "original (fork)");
        assert_eq!(forked.forked_from, Some(original.id));
        assert_eq!(forked.policy_yaml, original.policy_yaml);
        assert_eq!(forked.downloads, 0);
    }

    #[tokio::test]
    async fn fork_nonexistent_returns_not_found() {
        let store = CatalogStore::new();
        let result = store.fork_template(Uuid::new_v4()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn categories_include_computed_counts() {
        let store = CatalogStore::new();
        store.seed(load_builtin_rulesets()).await;

        let categories = store.list_categories().await;
        assert!(!categories.is_empty());

        // The general category should have at least default, permissive, strict.
        let general = categories.iter().find(|c| c.id == "general");
        assert!(general.is_some());
        assert!(general.expect("general category").template_count >= 3);
    }

    #[tokio::test]
    async fn builtin_rulesets_parse_names_and_descriptions() {
        let entries = load_builtin_rulesets();
        for entry in &entries {
            assert!(!entry.name.is_empty(), "seed entry should have a name");
            // All built-in rulesets have descriptions in YAML.
            assert!(
                !entry.description.is_empty(),
                "seed entry '{}' should have a description",
                entry.name
            );
        }
    }
}
