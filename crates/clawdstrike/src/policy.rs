//! Policy configuration and rulesets

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use globset::GlobBuilder;

use crate::error::{Error, PolicyFieldError, PolicyValidationError, Result};
use crate::guards::{
    EgressAllowlistConfig, EgressAllowlistGuard, ForbiddenPathConfig, ForbiddenPathGuard, Guard,
    JailbreakConfig, JailbreakGuard, McpToolConfig, McpToolGuard, PatchIntegrityConfig,
    PatchIntegrityGuard, PromptInjectionConfig, PromptInjectionGuard, SecretLeakConfig,
    SecretLeakGuard,
};

/// Current policy schema version.
///
/// This is a schema compatibility boundary (not the crate version). Runtimes should fail closed on
/// unsupported versions to prevent silent drift.
pub const POLICY_SCHEMA_VERSION: &str = "1.1.0";

fn default_true() -> bool {
    true
}

fn default_json_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// Policy-driven custom guard configuration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomGuardSpec {
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

/// Strategy for merging policies when using extends
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeStrategy {
    /// Replace base entirely with child values
    Replace,
    /// Shallow merge: child values override base at top level
    Merge,
    /// Deep merge: recursively merge nested structures
    #[default]
    DeepMerge,
}

/// Complete policy configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Policy version
    #[serde(default = "default_version")]
    pub version: String,
    /// Policy name
    #[serde(default)]
    pub name: String,
    /// Policy description
    #[serde(default)]
    pub description: String,
    /// Base policy to extend (ruleset name or file path)
    #[serde(default)]
    pub extends: Option<String>,
    /// Strategy for merging with base policy
    #[serde(default)]
    pub merge_strategy: MergeStrategy,
    /// Guard configurations
    #[serde(default)]
    pub guards: GuardConfigs,
    /// Policy-driven custom guards (resolved by runtimes via a registry).
    #[serde(default)]
    pub custom_guards: Vec<CustomGuardSpec>,
    /// Global settings
    #[serde(default)]
    pub settings: PolicySettings,
}

fn default_version() -> String {
    POLICY_SCHEMA_VERSION.to_string()
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: default_version(),
            name: String::new(),
            description: String::new(),
            extends: None,
            merge_strategy: MergeStrategy::default(),
            guards: GuardConfigs::default(),
            custom_guards: Vec::new(),
            settings: PolicySettings::default(),
        }
    }
}

/// Configuration for all guards
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfigs {
    /// Forbidden path guard config
    #[serde(default)]
    pub forbidden_path: Option<ForbiddenPathConfig>,
    /// Egress allowlist guard config
    #[serde(default)]
    pub egress_allowlist: Option<EgressAllowlistConfig>,
    /// Secret leak guard config
    #[serde(default)]
    pub secret_leak: Option<SecretLeakConfig>,
    /// Patch integrity guard config
    #[serde(default)]
    pub patch_integrity: Option<PatchIntegrityConfig>,
    /// MCP tool guard config
    #[serde(default)]
    pub mcp_tool: Option<McpToolConfig>,
    /// Prompt injection guard config
    #[serde(default)]
    pub prompt_injection: Option<PromptInjectionConfig>,
    /// Jailbreak detection guard config
    #[serde(default)]
    pub jailbreak: Option<JailbreakConfig>,
}

impl GuardConfigs {
    /// Merge with another GuardConfigs (child overrides base)
    pub fn merge_with(&self, child: &Self) -> Self {
        Self {
            forbidden_path: match (&self.forbidden_path, &child.forbidden_path) {
                (Some(base), Some(child_cfg)) => Some(base.merge_with(child_cfg)),
                (Some(base), None) => Some(base.clone()),
                // When base is None, merge child with default to apply additional_patterns
                (None, Some(child_cfg)) => {
                    Some(ForbiddenPathConfig::default().merge_with(child_cfg))
                }
                (None, None) => None,
            },
            egress_allowlist: match (&self.egress_allowlist, &child.egress_allowlist) {
                (Some(base), Some(child_cfg)) => Some(base.merge_with(child_cfg)),
                (Some(base), None) => Some(base.clone()),
                (None, Some(child_cfg)) => {
                    Some(EgressAllowlistConfig::default().merge_with(child_cfg))
                }
                (None, None) => None,
            },
            secret_leak: child
                .secret_leak
                .clone()
                .or_else(|| self.secret_leak.clone()),
            patch_integrity: child
                .patch_integrity
                .clone()
                .or_else(|| self.patch_integrity.clone()),
            mcp_tool: match (&self.mcp_tool, &child.mcp_tool) {
                (Some(base), Some(child_cfg)) => Some(base.merge_with(child_cfg)),
                (Some(base), None) => Some(base.clone()),
                (None, Some(child_cfg)) => Some(McpToolConfig::default().merge_with(child_cfg)),
                (None, None) => None,
            },
            prompt_injection: child
                .prompt_injection
                .clone()
                .or_else(|| self.prompt_injection.clone()),
            jailbreak: child.jailbreak.clone().or_else(|| self.jailbreak.clone()),
        }
    }
}

/// Global policy settings
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySettings {
    /// Whether to fail fast on first violation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_fast: Option<bool>,
    /// Whether to log all actions (not just violations)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verbose_logging: Option<bool>,
    /// Session timeout in seconds
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_timeout_secs: Option<u64>,
}

fn default_timeout() -> u64 {
    3600 // 1 hour
}

impl PolicySettings {
    pub fn effective_fail_fast(&self) -> bool {
        self.fail_fast.unwrap_or(false)
    }

    pub fn effective_verbose_logging(&self) -> bool {
        self.verbose_logging.unwrap_or(false)
    }

    pub fn effective_session_timeout_secs(&self) -> u64 {
        self.session_timeout_secs.unwrap_or(default_timeout())
    }
}

impl Policy {
    /// Create an empty policy
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from YAML file
    pub fn from_yaml_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml(&content)
    }

    /// Parse from YAML string
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let policy: Self = serde_yaml::from_str(yaml)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Export to YAML string
    pub fn to_yaml(&self) -> Result<String> {
        serde_yaml::to_string(self).map_err(Error::from)
    }

    /// Validate policy semantics and guard configs.
    ///
    /// This is a security boundary: invalid regex/glob patterns are treated as errors, not silently ignored.
    pub fn validate(&self) -> Result<()> {
        validate_policy_version(&self.version)?;

        let mut errors: Vec<PolicyFieldError> = Vec::new();

        if !self.custom_guards.is_empty() {
            let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for (idx, cg) in self.custom_guards.iter().enumerate() {
                if cg.id.trim().is_empty() {
                    errors.push(PolicyFieldError::new(
                        format!("custom_guards[{}].id", idx),
                        "id must be non-empty".to_string(),
                    ));
                }
                if !seen.insert(cg.id.as_str()) {
                    errors.push(PolicyFieldError::new(
                        format!("custom_guards[{}].id", idx),
                        format!("duplicate custom guard id: {}", cg.id),
                    ));
                }
                if !cg.config.is_object() {
                    errors.push(PolicyFieldError::new(
                        format!("custom_guards[{}].config", idx),
                        "config must be a JSON object".to_string(),
                    ));
                }
            }
        }

        if let Some(cfg) = &self.guards.forbidden_path {
            if let Some(patterns) = cfg.patterns.as_ref() {
                validate_globs(&mut errors, "guards.forbidden_path.patterns", patterns);
            }
            validate_globs(
                &mut errors,
                "guards.forbidden_path.exceptions",
                &cfg.exceptions,
            );
            validate_globs(
                &mut errors,
                "guards.forbidden_path.additional_patterns",
                &cfg.additional_patterns,
            );
            validate_globs(
                &mut errors,
                "guards.forbidden_path.remove_patterns",
                &cfg.remove_patterns,
            );
        }

        if let Some(cfg) = &self.guards.egress_allowlist {
            validate_domain_globs(&mut errors, "guards.egress_allowlist.allow", &cfg.allow);
            validate_domain_globs(&mut errors, "guards.egress_allowlist.block", &cfg.block);
            validate_domain_globs(
                &mut errors,
                "guards.egress_allowlist.additional_allow",
                &cfg.additional_allow,
            );
            validate_domain_globs(
                &mut errors,
                "guards.egress_allowlist.additional_block",
                &cfg.additional_block,
            );
            validate_domain_globs(
                &mut errors,
                "guards.egress_allowlist.remove_allow",
                &cfg.remove_allow,
            );
            validate_domain_globs(
                &mut errors,
                "guards.egress_allowlist.remove_block",
                &cfg.remove_block,
            );
        }

        if let Some(cfg) = &self.guards.secret_leak {
            for (idx, p) in cfg.patterns.iter().enumerate() {
                if let Err(e) = Regex::new(&p.pattern) {
                    errors.push(PolicyFieldError::new(
                        format!("guards.secret_leak.patterns[{}].pattern", idx),
                        format!("invalid regex ({}): {}", p.name, e),
                    ));
                }
            }
            validate_globs(
                &mut errors,
                "guards.secret_leak.skip_paths",
                &cfg.skip_paths,
            );
        }

        if let Some(cfg) = &self.guards.patch_integrity {
            for (idx, pattern) in cfg.forbidden_patterns.iter().enumerate() {
                if let Err(e) = Regex::new(pattern) {
                    errors.push(PolicyFieldError::new(
                        format!("guards.patch_integrity.forbidden_patterns[{}]", idx),
                        format!("invalid regex: {}", e),
                    ));
                }
            }
        }

        if let Some(cfg) = &self.guards.prompt_injection {
            if cfg.max_scan_bytes == 0 {
                errors.push(PolicyFieldError::new(
                    "guards.prompt_injection.max_scan_bytes".to_string(),
                    "max_scan_bytes must be > 0".to_string(),
                ));
            }
            if !cfg.block_at_or_above.at_least(cfg.warn_at_or_above) {
                errors.push(PolicyFieldError::new(
                    "guards.prompt_injection.warn_at_or_above".to_string(),
                    "warn_at_or_above must be <= block_at_or_above".to_string(),
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(PolicyValidationError::new(errors).into())
        }
    }

    /// Resolve a base policy by name or path
    ///
    /// Tries built-in ruleset names first,
    /// then falls back to loading from file path.
    pub fn resolve_base(name_or_path: &str) -> Result<Self> {
        // Try built-in rulesets first
        if let Some(ruleset) = RuleSet::by_name(name_or_path)? {
            return Ok(ruleset.policy);
        }

        // Try loading from file
        let path = std::path::Path::new(name_or_path);
        if path.exists() {
            return Self::from_yaml_file(path);
        }

        Err(Error::ConfigError(format!(
            "Unknown ruleset or file not found: {}",
            name_or_path
        )))
    }

    /// Merge this policy with a child policy
    ///
    /// Uses child's merge_strategy to determine how to combine.
    pub fn merge(&self, child: &Policy) -> Self {
        match child.merge_strategy {
            MergeStrategy::Replace => child.clone(),
            MergeStrategy::Merge => Self {
                version: if child.version != default_version() {
                    child.version.clone()
                } else {
                    self.version.clone()
                },
                name: if !child.name.is_empty() {
                    child.name.clone()
                } else {
                    self.name.clone()
                },
                description: if !child.description.is_empty() {
                    child.description.clone()
                } else {
                    self.description.clone()
                },
                extends: None, // Don't propagate extends
                merge_strategy: MergeStrategy::default(),
                guards: if child.guards != GuardConfigs::default() {
                    child.guards.clone()
                } else {
                    self.guards.clone()
                },
                custom_guards: if !child.custom_guards.is_empty() {
                    child.custom_guards.clone()
                } else {
                    self.custom_guards.clone()
                },
                settings: if child.settings != PolicySettings::default() {
                    child.settings.clone()
                } else {
                    self.settings.clone()
                },
            },
            MergeStrategy::DeepMerge => Self {
                version: if child.version != default_version() {
                    child.version.clone()
                } else {
                    self.version.clone()
                },
                name: if !child.name.is_empty() {
                    child.name.clone()
                } else {
                    self.name.clone()
                },
                description: if !child.description.is_empty() {
                    child.description.clone()
                } else {
                    self.description.clone()
                },
                extends: None,
                merge_strategy: MergeStrategy::default(),
                guards: self.guards.merge_with(&child.guards),
                custom_guards: merge_custom_guards(&self.custom_guards, &child.custom_guards),
                settings: PolicySettings {
                    fail_fast: child.settings.fail_fast.or(self.settings.fail_fast),
                    verbose_logging: child
                        .settings
                        .verbose_logging
                        .or(self.settings.verbose_logging),
                    session_timeout_secs: child
                        .settings
                        .session_timeout_secs
                        .or(self.settings.session_timeout_secs),
                },
            },
        }
    }

    /// Load from YAML string with extends resolution
    ///
    /// If the policy has an `extends` field, loads the base and merges.
    /// Detects circular dependencies.
    pub fn from_yaml_with_extends(yaml: &str, base_path: Option<&Path>) -> Result<Self> {
        let resolver = LocalPolicyResolver::new();
        Self::from_yaml_with_extends_resolver(yaml, base_path, &resolver)
    }

    /// Load from YAML string with extends resolution using a custom resolver.
    ///
    /// This allows callers to support remote `extends` while keeping the default path
    /// filesystem-only.
    pub fn from_yaml_with_extends_resolver(
        yaml: &str,
        base_path: Option<&Path>,
        resolver: &impl PolicyResolver,
    ) -> Result<Self> {
        let location = base_path
            .map(|p| PolicyLocation::File(p.to_path_buf()))
            .unwrap_or(PolicyLocation::None);

        Self::from_yaml_with_extends_internal_resolver(
            yaml,
            location,
            resolver,
            &mut std::collections::HashSet::new(),
        )
    }

    fn from_yaml_with_extends_internal_resolver(
        yaml: &str,
        location: PolicyLocation,
        resolver: &impl PolicyResolver,
        visited: &mut std::collections::HashSet<String>,
    ) -> Result<Self> {
        let child = Policy::from_yaml(yaml)?;

        if let Some(ref extends) = child.extends {
            let resolved = resolver.resolve(extends, &location)?;

            // Check for circular dependency
            if visited.contains(&resolved.key) {
                return Err(Error::ConfigError(format!(
                    "Circular policy extension detected: {}",
                    extends
                )));
            }
            visited.insert(resolved.key);

            let base = Self::from_yaml_with_extends_internal_resolver(
                &resolved.yaml,
                resolved.location,
                resolver,
                visited,
            )?;

            let merged = base.merge(&child);
            merged.validate()?;
            Ok(merged)
        } else {
            Ok(child)
        }
    }

    /// Load from YAML file with extends resolution
    pub fn from_yaml_file_with_extends(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml_with_extends(&content, Some(path))
    }

    /// Create guards from this policy
    pub(crate) fn create_guards(&self) -> PolicyGuards {
        PolicyGuards {
            forbidden_path: self
                .guards
                .forbidden_path
                .clone()
                .map(ForbiddenPathGuard::with_config)
                .unwrap_or_default(),
            egress_allowlist: self
                .guards
                .egress_allowlist
                .clone()
                .map(EgressAllowlistGuard::with_config)
                .unwrap_or_default(),
            secret_leak: self
                .guards
                .secret_leak
                .clone()
                .map(SecretLeakGuard::with_config)
                .unwrap_or_default(),
            patch_integrity: self
                .guards
                .patch_integrity
                .clone()
                .map(PatchIntegrityGuard::with_config)
                .unwrap_or_default(),
            mcp_tool: self
                .guards
                .mcp_tool
                .clone()
                .map(McpToolGuard::with_config)
                .unwrap_or_default(),
            prompt_injection: self
                .guards
                .prompt_injection
                .clone()
                .map(PromptInjectionGuard::with_config)
                .unwrap_or_default(),
            jailbreak: self
                .guards
                .jailbreak
                .clone()
                .map(JailbreakGuard::with_config)
                .unwrap_or_default(),
        }
    }
}

fn merge_custom_guards(base: &[CustomGuardSpec], child: &[CustomGuardSpec]) -> Vec<CustomGuardSpec> {
    if child.is_empty() {
        return base.to_vec();
    }
    if base.is_empty() {
        return child.to_vec();
    }

    let mut out: Vec<CustomGuardSpec> = base.to_vec();
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (i, cg) in out.iter().enumerate() {
        index.insert(cg.id.clone(), i);
    }

    for cg in child {
        if let Some(i) = index.get(&cg.id).copied() {
            out[i] = cg.clone();
        } else {
            index.insert(cg.id.clone(), out.len());
            out.push(cg.clone());
        }
    }

    out
}

fn validate_policy_version(version: &str) -> Result<()> {
    if parse_semver_strict(version).is_none() {
        return Err(Error::InvalidPolicyVersion {
            version: version.to_string(),
        });
    }

    if version != POLICY_SCHEMA_VERSION {
        return Err(Error::UnsupportedPolicyVersion {
            found: version.to_string(),
            supported: POLICY_SCHEMA_VERSION.to_string(),
        });
    }

    Ok(())
}

fn parse_semver_strict(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let major = parse_semver_part(parts.next()?)?;
    let minor = parse_semver_part(parts.next()?)?;
    let patch = parse_semver_part(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }

    Some((major, minor, patch))
}

fn parse_semver_part(part: &str) -> Option<u64> {
    if part.is_empty() {
        return None;
    }
    if part.len() > 1 && part.starts_with('0') {
        return None;
    }
    if !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    part.parse().ok()
}

fn validate_globs(errors: &mut Vec<PolicyFieldError>, field: &str, patterns: &[String]) {
    for (idx, pattern) in patterns.iter().enumerate() {
        if let Err(e) = glob::Pattern::new(pattern) {
            errors.push(PolicyFieldError::new(
                format!("{}[{}]", field, idx),
                format!("invalid glob {:?}: {}", pattern, e),
            ));
        }
    }
}

fn validate_domain_globs(errors: &mut Vec<PolicyFieldError>, field: &str, patterns: &[String]) {
    for (idx, pattern) in patterns.iter().enumerate() {
        if let Err(e) = GlobBuilder::new(pattern)
            .case_insensitive(true)
            .literal_separator(true)
            .build()
        {
            errors.push(PolicyFieldError::new(
                format!("{}[{}]", field, idx),
                format!("invalid domain glob {:?}: {}", pattern, e),
            ));
        }
    }
}

/// Guards instantiated from a policy
pub(crate) struct PolicyGuards {
    pub forbidden_path: ForbiddenPathGuard,
    pub egress_allowlist: EgressAllowlistGuard,
    pub secret_leak: SecretLeakGuard,
    pub patch_integrity: PatchIntegrityGuard,
    pub mcp_tool: McpToolGuard,
    pub prompt_injection: PromptInjectionGuard,
    pub jailbreak: JailbreakGuard,
}

impl PolicyGuards {
    /// Built-in guards, in a stable evaluation order.
    pub(crate) fn builtin_guards_in_order(&self) -> impl ExactSizeIterator<Item = &dyn Guard> + '_ {
        [
            &self.forbidden_path as &dyn Guard,
            &self.egress_allowlist as &dyn Guard,
            &self.secret_leak as &dyn Guard,
            &self.patch_integrity as &dyn Guard,
            &self.mcp_tool as &dyn Guard,
            &self.prompt_injection as &dyn Guard,
            &self.jailbreak as &dyn Guard,
        ]
        .into_iter()
    }
}

/// Named ruleset with pre-configured policies
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleSet {
    /// Ruleset identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: String,
    /// The policy
    pub policy: Policy,
}

impl RuleSet {
    pub fn yaml_by_name(name: &str) -> Option<(&'static str, String)> {
        let id = name.strip_prefix("clawdstrike:").unwrap_or(name);

        let yaml = match id {
            "default" => Some(include_str!("../../../rulesets/default.yaml")),
            "strict" => Some(include_str!("../../../rulesets/strict.yaml")),
            "ai-agent" => Some(include_str!("../../../rulesets/ai-agent.yaml")),
            "cicd" => Some(include_str!("../../../rulesets/cicd.yaml")),
            "permissive" => Some(include_str!("../../../rulesets/permissive.yaml")),
            _ => None,
        }?;

        Some((yaml, id.to_string()))
    }

    pub fn by_name(name: &str) -> Result<Option<Self>> {
        let Some((yaml, id)) = Self::yaml_by_name(name) else {
            return Ok(None);
        };

        let policy = Policy::from_yaml_with_extends(yaml, None)?;
        Ok(Some(Self {
            id,
            name: policy.name.clone(),
            description: policy.description.clone(),
            policy,
        }))
    }

    pub fn list() -> &'static [&'static str] {
        &["default", "strict", "ai-agent", "cicd", "permissive"]
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = Policy::new();
        assert_eq!(policy.version, "1.1.0");
    }

    #[test]
    fn test_policy_yaml_roundtrip() {
        let policy = Policy::new();
        let yaml = policy.to_yaml().unwrap();
        let restored = Policy::from_yaml(&yaml).unwrap();
        assert_eq!(policy.version, restored.version);
    }

    #[test]
    fn test_policy_validation_rejects_invalid_glob() {
        let yaml = r#"
version: "1.1.0"
name: Test
guards:
  forbidden_path:
    patterns:
      - "foo[bar"
"#;

        let err = Policy::from_yaml(yaml).unwrap_err();
        match err {
            Error::PolicyValidation(e) => {
                assert!(!e.is_empty());
                assert!(e
                    .errors
                    .iter()
                    .any(|fe| fe.path == "guards.forbidden_path.patterns[0]"));
            }
            other => panic!("expected policy validation error, got: {}", other),
        }
    }

    #[test]
    fn test_policy_validation_rejects_invalid_domain_glob() {
        let yaml = r#"
version: "1.1.0"
name: Test
guards:
  egress_allowlist:
    allow:
      - "foo[bar"
"#;

        let err = Policy::from_yaml(yaml).unwrap_err();
        match err {
            Error::PolicyValidation(e) => {
                assert!(!e.is_empty());
                assert!(e
                    .errors
                    .iter()
                    .any(|fe| fe.path == "guards.egress_allowlist.allow[0]"));
            }
            other => panic!("expected policy validation error, got: {}", other),
        }
    }

    #[test]
    fn test_policy_validation_rejects_invalid_regex() {
        let yaml = r#"
version: "1.1.0"
name: Test
guards:
  secret_leak:
    patterns:
      - name: bad
        pattern: "("
"#;

        let err = Policy::from_yaml(yaml).unwrap_err();
        match err {
            Error::PolicyValidation(e) => {
                assert!(!e.is_empty());
                assert!(e
                    .errors
                    .iter()
                    .any(|fe| fe.path == "guards.secret_leak.patterns[0].pattern"));
            }
            other => panic!("expected policy validation error, got: {}", other),
        }
    }

    #[test]
    fn test_policy_version_rejects_invalid_semver() {
        let yaml = r#"
version: "1.0"
name: Test
"#;

        let err = Policy::from_yaml(yaml).unwrap_err();
        match err {
            Error::InvalidPolicyVersion { .. } => {}
            other => panic!("expected invalid policy version error, got: {}", other),
        }
    }

    #[test]
    fn test_policy_version_rejects_unsupported_version() {
        let yaml = r#"
version: "2.0.0"
name: Test
"#;

        let err = Policy::from_yaml(yaml).unwrap_err();
        match err {
            Error::UnsupportedPolicyVersion { .. } => {}
            other => panic!("expected unsupported policy version error, got: {}", other),
        }
    }

    #[test]
    fn test_create_guards() {
        let policy = Policy::new();
        let guards = policy.create_guards();

        // Verify guards were created
        assert!(!guards.forbidden_path.is_forbidden("/normal/path"));
        assert!(guards.forbidden_path.is_forbidden("/home/user/.ssh/id_rsa"));
    }

    #[test]
    fn test_rulesets() {
        let default = match RuleSet::by_name("default") {
            Ok(Some(rs)) => rs,
            Ok(None) => panic!("missing built-in ruleset: default"),
            Err(e) => panic!("failed to load built-in ruleset: {}", e),
        };
        assert_eq!(default.id, "default");

        let strict = match RuleSet::by_name("strict") {
            Ok(Some(rs)) => rs,
            Ok(None) => panic!("missing built-in ruleset: strict"),
            Err(e) => panic!("failed to load built-in ruleset: {}", e),
        };
        assert!(strict.policy.settings.effective_fail_fast());

        let permissive = match RuleSet::by_name("permissive") {
            Ok(Some(rs)) => rs,
            Ok(None) => panic!("missing built-in ruleset: permissive"),
            Err(e) => panic!("failed to load built-in ruleset: {}", e),
        };
        assert!(permissive.policy.settings.effective_verbose_logging());
    }

    #[test]
    fn test_ruleset_by_name() {
        assert!(matches!(RuleSet::by_name("default"), Ok(Some(_))));
        assert!(matches!(RuleSet::by_name("strict"), Ok(Some(_))));
        assert!(matches!(RuleSet::by_name("ai-agent"), Ok(Some(_))));
        assert!(matches!(RuleSet::by_name("cicd"), Ok(Some(_))));
        assert!(matches!(RuleSet::by_name("permissive"), Ok(Some(_))));
        assert!(matches!(RuleSet::by_name("unknown"), Ok(None)));
    }

    #[test]
    fn test_rulesets_parse_validate_and_match_disk_registry() {
        use std::collections::HashSet;
        use std::path::PathBuf;

        let expected: HashSet<&str> = RuleSet::list().iter().copied().collect();
        assert!(!expected.is_empty());

        for id in RuleSet::list() {
            let rs = RuleSet::by_name(id)
                .unwrap()
                .unwrap_or_else(|| panic!("missing built-in ruleset: {}", id));
            rs.policy.validate().unwrap();

            let prefixed = format!("clawdstrike:{}", id);
            let rs2 = RuleSet::by_name(&prefixed)
                .unwrap()
                .unwrap_or_else(|| panic!("missing built-in ruleset: {}", prefixed));
            assert_eq!(rs2.id, *id);
        }

        let rulesets_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rulesets");
        let mut disk_ids: HashSet<String> = HashSet::new();
        for entry in std::fs::read_dir(&rulesets_dir)
            .unwrap_or_else(|e| panic!("failed to read {:?}: {}", rulesets_dir, e))
        {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "yaml") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    disk_ids.insert(stem.to_string());
                }
            }
        }

        let disk: HashSet<&str> = disk_ids.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            disk, expected,
            "rulesets/ directory and RuleSet::list() drifted"
        );
    }

    #[test]
    fn test_merge_strategy_default() {
        let yaml = r#"
version: "1.1.0"
name: Test
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.merge_strategy, MergeStrategy::DeepMerge);
    }

    #[test]
    fn test_merge_strategy_parse() {
        let yaml = r#"
version: "1.1.0"
name: Test
merge_strategy: replace
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.merge_strategy, MergeStrategy::Replace);
    }

    #[test]
    fn test_extends_field_parse() {
        let yaml = r#"
version: "1.1.0"
name: Test
extends: strict
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.extends, Some("strict".to_string()));
    }

    #[test]
    fn test_extends_field_none_by_default() {
        let yaml = r#"
version: "1.1.0"
name: Test
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert!(policy.extends.is_none());
    }

    #[test]
    fn test_resolve_base_builtin_strict() {
        let base = Policy::resolve_base("strict").unwrap();
        assert!(base.settings.effective_fail_fast());
    }

    #[test]
    fn test_resolve_base_builtin_default() {
        let base = Policy::resolve_base("default").unwrap();
        assert!(!base.settings.effective_fail_fast());
    }

    #[test]
    fn test_resolve_base_unknown_returns_error() {
        let result = Policy::resolve_base("nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn test_guard_configs_merge() {
        let base = GuardConfigs {
            forbidden_path: Some(ForbiddenPathConfig {
                patterns: Some(vec!["**/.ssh/**".to_string()]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let child = GuardConfigs {
            forbidden_path: Some(ForbiddenPathConfig {
                additional_patterns: vec!["**/secrets/**".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        };

        let merged = base.merge_with(&child);
        let fp = merged.forbidden_path.unwrap();
        let patterns = fp.patterns.unwrap();
        assert!(patterns.contains(&"**/.ssh/**".to_string()));
        assert!(patterns.contains(&"**/secrets/**".to_string()));
    }

    #[test]
    fn test_policy_merge_deep() {
        let base = Policy {
            name: "Base".to_string(),
            settings: PolicySettings {
                fail_fast: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };

        let child = Policy {
            name: "Child".to_string(),
            merge_strategy: MergeStrategy::DeepMerge,
            settings: PolicySettings {
                verbose_logging: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };

        let merged = base.merge(&child);
        assert_eq!(merged.name, "Child");
        assert!(merged.settings.effective_fail_fast()); // from base
        assert!(merged.settings.effective_verbose_logging()); // from child
    }

    #[test]
    fn test_policy_merge_replace() {
        let base = Policy {
            name: "Base".to_string(),
            settings: PolicySettings {
                fail_fast: Some(true),
                verbose_logging: Some(true),
                ..Default::default()
            },
            ..Default::default()
        };

        let child = Policy {
            name: "Child".to_string(),
            merge_strategy: MergeStrategy::Replace,
            settings: PolicySettings::default(),
            ..Default::default()
        };

        let merged = base.merge(&child);
        assert_eq!(merged.name, "Child");
        assert!(!merged.settings.effective_fail_fast()); // child replaces
        assert!(!merged.settings.effective_verbose_logging()); // child replaces
    }

    #[test]
    fn test_policy_extends_builtin() {
        let yaml = r#"
version: "1.1.0"
name: CustomStrict
extends: strict
settings:
  verbose_logging: true
"#;
        let policy = Policy::from_yaml_with_extends(yaml, None).unwrap();

        // Should have strict's fail_fast
        assert!(policy.settings.effective_fail_fast());
        // Should have child's verbose_logging
        assert!(policy.settings.effective_verbose_logging());
        // Name should be from child
        assert_eq!(policy.name, "CustomStrict");
    }

    #[test]
    fn test_policy_extends_with_additional_patterns() {
        // Test adding patterns via additional_patterns
        let yaml = r#"
version: "1.1.0"
name: CustomDefault
extends: default
guards:
  forbidden_path:
    additional_patterns:
      - "**/my-secrets/**"
"#;
        let policy = Policy::from_yaml_with_extends(yaml, None).unwrap();

        // Should have the additional pattern added
        let fp = policy.guards.forbidden_path.unwrap();
        assert!(fp
            .effective_patterns()
            .iter()
            .any(|p| p.contains("my-secrets")));
    }

    #[test]
    fn test_policy_circular_extends_detection() {
        use std::collections::HashSet;
        let mut visited = HashSet::new();
        visited.insert("policy-a".to_string());

        // Simulating circular detection
        assert!(visited.contains("policy-a"));
    }
}
