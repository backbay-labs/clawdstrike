//! Policy `extends` resolution: locations, sources, and resolvers.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::RuleSet;
use crate::error::{Error, Result};

fn default_true() -> bool {
    true
}

fn default_json_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// Policy-driven custom guard configuration (`policy.custom_guards[]`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCustomGuardSpec {
    /// Installed guard id (resolved via `CustomGuardRegistry`).
    pub id: String,
    /// Enable/disable this custom guard.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Factory configuration (JSON object).
    #[serde(default = "default_json_object")]
    pub config: serde_json::Value,
}

/// Location context for resolving policy `extends`.
///
/// This is used by `PolicyResolver` implementations to resolve relative references and enforce
/// security rules around remote resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyLocation {
    /// No location context (inline YAML).
    None,
    /// A local file path.
    File(PathBuf),
    /// A remote URL (without fragment).
    Url(String),
    /// A file path within a git repository.
    Git {
        repo: String,
        commit: String,
        path: String,
    },
    /// A built-in ruleset identifier.
    Ruleset { id: String },
    /// An installed package reference.
    Package { name: String, version: String },
}

/// A resolved policy source returned by a `PolicyResolver`.
#[derive(Clone, Debug)]
pub struct ResolvedPolicySource {
    /// Canonical key for cycle detection (stable across equivalent references).
    pub key: String,
    /// YAML content.
    pub yaml: String,
    /// Location context for resolving nested `extends`.
    pub location: PolicyLocation,
}

/// Extends resolver interface.
///
/// Implementations may resolve local files, built-in rulesets, and/or remote sources.
pub trait PolicyResolver {
    fn resolve(&self, reference: &str, from: &PolicyLocation) -> Result<ResolvedPolicySource>;
}

/// Default resolver that supports only built-in rulesets and local filesystem paths.
#[derive(Clone, Debug, Default)]
pub struct LocalPolicyResolver;

impl LocalPolicyResolver {
    pub fn new() -> Self {
        Self
    }
}

impl PolicyResolver for LocalPolicyResolver {
    fn resolve(&self, reference: &str, from: &PolicyLocation) -> Result<ResolvedPolicySource> {
        if let Some((yaml, id)) = RuleSet::yaml_by_name(reference) {
            return Ok(ResolvedPolicySource {
                key: format!("ruleset:{}", id),
                yaml: yaml.to_string(),
                location: PolicyLocation::Ruleset { id },
            });
        }

        let extends_path = match from {
            PolicyLocation::File(base_path) => base_path
                .parent()
                .unwrap_or(base_path.as_path())
                .join(reference),
            _ => PathBuf::from(reference),
        };

        if !extends_path.exists() {
            return Err(Error::ConfigError(format!(
                "Unknown ruleset or file not found: {}",
                reference
            )));
        }

        let yaml = std::fs::read_to_string(&extends_path)?;
        let key = std::fs::canonicalize(&extends_path)
            .map(|p| format!("file:{}", p.display()))
            .unwrap_or_else(|_| format!("file:{}", extends_path.display()));

        Ok(ResolvedPolicySource {
            key,
            yaml,
            location: PolicyLocation::File(extends_path),
        })
    }
}
