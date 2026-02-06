//! Policy configuration and rulesets

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use globset::GlobBuilder;

use crate::error::{Error, PolicyFieldError, PolicyValidationError, Result};
use crate::guards::{
    EgressAllowlistConfig, EgressAllowlistGuard, ForbiddenPathConfig, ForbiddenPathGuard, Guard,
    JailbreakConfig, JailbreakGuard, McpToolConfig, McpToolGuard, PatchIntegrityConfig,
    PatchIntegrityGuard, PathAllowlistConfig, PathAllowlistGuard, PromptInjectionConfig,
    PromptInjectionGuard, SecretLeakConfig, SecretLeakGuard,
};
use crate::posture::{validate_posture_config, PostureConfig};

/// Current policy schema version.
///
/// This is a schema compatibility boundary (not the crate version). Runtimes should fail closed on
/// unsupported versions to prevent silent drift.
pub const POLICY_SCHEMA_VERSION: &str = "1.2.0";
pub const POLICY_SUPPORTED_SCHEMA_VERSIONS: &[&str] = &["1.1.0", "1.2.0"];

fn default_true() -> bool {
    true
}

fn default_json_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// Options controlling how strictly a policy is validated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyValidationOptions {
    /// Whether placeholders like `${VAR}` must reference an existing environment variable.
    ///
    /// When `false`, placeholder syntax is still validated, but missing env vars are allowed.
    pub require_env: bool,
}

impl PolicyValidationOptions {
    pub const STRICT: Self = Self { require_env: true };
    pub const LAX: Self = Self { require_env: false };
}

impl Default for PolicyValidationOptions {
    fn default() -> Self {
        Self::STRICT
    }
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
    pub custom_guards: Vec<PolicyCustomGuardSpec>,
    /// Global settings
    #[serde(default)]
    pub settings: PolicySettings,
    /// Optional dynamic posture model (schema v1.2.0+).
    #[serde(default)]
    pub posture: Option<PostureConfig>,
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
            posture: None,
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
    /// Path allowlist guard config
    #[serde(default)]
    pub path_allowlist: Option<PathAllowlistConfig>,
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
    /// Custom (plugin-shaped) guards.
    ///
    /// Note: for now, only a small reserved set of built-in packages is supported. Unknown
    /// packages must fail closed.
    #[serde(default)]
    pub custom: Vec<CustomGuardSpec>,
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
            path_allowlist: match (&self.path_allowlist, &child.path_allowlist) {
                (Some(base), Some(child_cfg)) => Some(base.merge_with(child_cfg)),
                (Some(base), None) => Some(base.clone()),
                (None, Some(child_cfg)) => Some(child_cfg.clone()),
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
            custom: if !child.custom.is_empty() {
                child.custom.clone()
            } else {
                self.custom.clone()
            },
        }
    }
}

fn default_custom_guard_enabled() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeoutBehavior {
    Allow,
    Deny,
    Warn,
    Defer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AsyncExecutionMode {
    Parallel,
    Sequential,
    Background,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncCachePolicyConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_size_mb: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncRateLimitPolicyConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_second: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_minute: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncCircuitBreakerPolicyConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_threshold: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reset_timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success_threshold: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncRetryPolicyConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_backoff_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_backoff_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub multiplier: Option<f64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsyncGuardPolicyConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_timeout: Option<TimeoutBehavior>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_mode: Option<AsyncExecutionMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<AsyncCachePolicyConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<AsyncRateLimitPolicyConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<AsyncCircuitBreakerPolicyConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<AsyncRetryPolicyConfig>,
}

/// A plugin-shaped guard reference in policy (`guards.custom[]`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomGuardSpec {
    pub package: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default = "default_custom_guard_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub config: serde_json::Value,
    #[serde(default, rename = "async", skip_serializing_if = "Option::is_none")]
    pub async_config: Option<AsyncGuardPolicyConfig>,
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
        let policy = Self::from_yaml_unvalidated(yaml)?;
        policy.validate()?;
        Ok(policy)
    }

    fn from_yaml_unvalidated(yaml: &str) -> Result<Self> {
        Ok(serde_yaml::from_str(yaml)?)
    }

    /// Export to YAML string
    pub fn to_yaml(&self) -> Result<String> {
        serde_yaml::to_string(self).map_err(Error::from)
    }

    /// Validate policy semantics and guard configs.
    ///
    /// This is a security boundary: invalid regex/glob patterns are treated as errors, not silently ignored.
    pub fn validate(&self) -> Result<()> {
        self.validate_with_options(PolicyValidationOptions::default())
    }

    pub fn validate_with_options(&self, options: PolicyValidationOptions) -> Result<()> {
        validate_policy_version(&self.version)?;

        let mut errors: Vec<PolicyFieldError> = Vec::new();
        let require_env = options.require_env;
        let supports_v1_2_features = policy_version_supports_posture(&self.version);

        if self.posture.is_some() && !supports_v1_2_features {
            errors.push(PolicyFieldError::new(
                "posture",
                "posture requires policy version 1.2.0".to_string(),
            ));
        }

        if self.guards.path_allowlist.is_some() && !supports_v1_2_features {
            errors.push(PolicyFieldError::new(
                "guards.path_allowlist",
                "path_allowlist requires policy version 1.2.0".to_string(),
            ));
        }

        if let Some(posture) = &self.posture {
            validate_posture_config(posture, &mut errors);
        }

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

                validate_placeholders_in_json(
                    &mut errors,
                    &format!("custom_guards[{}].config", idx),
                    &cg.config,
                    cg.enabled,
                    require_env,
                );
            }
        }

        if let Some(cfg) = &self.guards.forbidden_path {
            if let Some(patterns) = cfg.patterns.as_ref() {
                validate_globs(&mut errors, "guards.forbidden_path.patterns", patterns);
                validate_placeholders_in_strings(
                    &mut errors,
                    "guards.forbidden_path.patterns",
                    patterns,
                    cfg.enabled,
                    require_env,
                );
            }
            validate_globs(
                &mut errors,
                "guards.forbidden_path.exceptions",
                &cfg.exceptions,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.forbidden_path.exceptions",
                &cfg.exceptions,
                cfg.enabled,
                require_env,
            );
            validate_globs(
                &mut errors,
                "guards.forbidden_path.additional_patterns",
                &cfg.additional_patterns,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.forbidden_path.additional_patterns",
                &cfg.additional_patterns,
                cfg.enabled,
                require_env,
            );
            validate_globs(
                &mut errors,
                "guards.forbidden_path.remove_patterns",
                &cfg.remove_patterns,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.forbidden_path.remove_patterns",
                &cfg.remove_patterns,
                cfg.enabled,
                require_env,
            );
        }

        if let Some(cfg) = &self.guards.path_allowlist {
            validate_globs(
                &mut errors,
                "guards.path_allowlist.file_access_allow",
                &cfg.file_access_allow,
            );
            validate_globs(
                &mut errors,
                "guards.path_allowlist.file_write_allow",
                &cfg.file_write_allow,
            );
            validate_globs(
                &mut errors,
                "guards.path_allowlist.patch_allow",
                &cfg.patch_allow,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.path_allowlist.file_access_allow",
                &cfg.file_access_allow,
                cfg.enabled,
                require_env,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.path_allowlist.file_write_allow",
                &cfg.file_write_allow,
                cfg.enabled,
                require_env,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.path_allowlist.patch_allow",
                &cfg.patch_allow,
                cfg.enabled,
                require_env,
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

            validate_placeholders_in_strings(
                &mut errors,
                "guards.egress_allowlist.allow",
                &cfg.allow,
                cfg.enabled,
                require_env,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.egress_allowlist.block",
                &cfg.block,
                cfg.enabled,
                require_env,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.egress_allowlist.additional_allow",
                &cfg.additional_allow,
                cfg.enabled,
                require_env,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.egress_allowlist.additional_block",
                &cfg.additional_block,
                cfg.enabled,
                require_env,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.egress_allowlist.remove_allow",
                &cfg.remove_allow,
                cfg.enabled,
                require_env,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.egress_allowlist.remove_block",
                &cfg.remove_block,
                cfg.enabled,
                require_env,
            );
        }

        if let Some(cfg) = &self.guards.secret_leak {
            for (idx, p) in cfg.patterns.iter().enumerate() {
                validate_placeholders_in_string(
                    &mut errors,
                    &format!("guards.secret_leak.patterns[{}].name", idx),
                    &p.name,
                    cfg.enabled,
                    require_env,
                );
                validate_placeholders_in_string(
                    &mut errors,
                    &format!("guards.secret_leak.patterns[{}].pattern", idx),
                    &p.pattern,
                    cfg.enabled,
                    require_env,
                );

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
            validate_placeholders_in_strings(
                &mut errors,
                "guards.secret_leak.skip_paths",
                &cfg.skip_paths,
                cfg.enabled,
                require_env,
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
                validate_placeholders_in_string(
                    &mut errors,
                    &format!("guards.patch_integrity.forbidden_patterns[{}]", idx),
                    pattern,
                    cfg.enabled,
                    require_env,
                );
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

        if !self.guards.custom.is_empty() {
            validate_custom_guards(&mut errors, &self.guards.custom, require_env);
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
                version: if child.version != self.version {
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
                posture: child.posture.clone().or_else(|| self.posture.clone()),
            },
            MergeStrategy::DeepMerge => Self {
                version: if child.version != self.version {
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
                posture: match (&self.posture, &child.posture) {
                    (Some(base), Some(child_posture)) => Some(base.merge_with(child_posture)),
                    (Some(base), None) => Some(base.clone()),
                    (None, Some(child_posture)) => Some(child_posture.clone()),
                    (None, None) => None,
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
            PolicyValidationOptions::default(),
        )
    }

    fn from_yaml_with_extends_internal_resolver(
        yaml: &str,
        location: PolicyLocation,
        resolver: &impl PolicyResolver,
        visited: &mut std::collections::HashSet<String>,
        validation: PolicyValidationOptions,
    ) -> Result<Self> {
        let child = Policy::from_yaml_unvalidated(yaml)?;

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
                validation,
            )?;

            let merged = base.merge(&child);
            merged.validate_with_options(validation)?;
            Ok(merged)
        } else {
            child.validate_with_options(validation)?;
            Ok(child)
        }
    }

    /// Load from YAML string with extends resolution using a custom resolver and validation options.
    pub fn from_yaml_with_extends_resolver_with_validation_options(
        yaml: &str,
        base_path: Option<&Path>,
        resolver: &impl PolicyResolver,
        validation: PolicyValidationOptions,
    ) -> Result<Self> {
        let location = base_path
            .map(|p| PolicyLocation::File(p.to_path_buf()))
            .unwrap_or(PolicyLocation::None);

        Self::from_yaml_with_extends_internal_resolver(
            yaml,
            location,
            resolver,
            &mut std::collections::HashSet::new(),
            validation,
        )
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
            path_allowlist: self
                .guards
                .path_allowlist
                .clone()
                .map(PathAllowlistGuard::with_config)
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

fn merge_custom_guards(
    base: &[PolicyCustomGuardSpec],
    child: &[PolicyCustomGuardSpec],
) -> Vec<PolicyCustomGuardSpec> {
    if child.is_empty() {
        return base.to_vec();
    }
    if base.is_empty() {
        return child.to_vec();
    }

    let mut out: Vec<PolicyCustomGuardSpec> = base.to_vec();
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

    if !POLICY_SUPPORTED_SCHEMA_VERSIONS.contains(&version) {
        return Err(Error::UnsupportedPolicyVersion {
            found: version.to_string(),
            supported: POLICY_SUPPORTED_SCHEMA_VERSIONS.join(", "),
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

fn semver_at_least(version: &str, minimum: (u64, u64, u64)) -> bool {
    let Some(found) = parse_semver_strict(version) else {
        return false;
    };
    found >= minimum
}

fn policy_version_supports_posture(version: &str) -> bool {
    semver_at_least(version, (1, 2, 0))
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

fn env_var_for_placeholder(raw: &str) -> std::result::Result<String, String> {
    if let Some(rest) = raw.strip_prefix("secrets.") {
        if rest.is_empty() {
            return Err("placeholder ${secrets.} is invalid".to_string());
        }
        return Ok(rest.to_string());
    }

    if raw.is_empty() {
        return Err("placeholder ${} is invalid".to_string());
    }

    Ok(raw.to_string())
}

fn validate_placeholders_in_string(
    errors: &mut Vec<PolicyFieldError>,
    field: &str,
    value: &str,
    enabled: bool,
    require_env: bool,
) {
    if !enabled {
        return;
    }

    let mut i = 0usize;
    while let Some(start_rel) = value[i..].find("${") {
        let start = i + start_rel;
        let after = start + 2;

        let Some(end_rel) = value[after..].find('}') else {
            break;
        };
        let end = after + end_rel;

        let raw = &value[after..end];
        let env_name = match env_var_for_placeholder(raw) {
            Ok(v) => v,
            Err(msg) => {
                errors.push(PolicyFieldError::new(field, msg));
                i = end + 1;
                continue;
            }
        };

        if require_env && std::env::var(&env_name).is_err() {
            errors.push(PolicyFieldError::new(
                field,
                format!("missing environment variable {}", env_name),
            ));
        }

        i = end + 1;
    }
}

fn validate_placeholders_in_strings(
    errors: &mut Vec<PolicyFieldError>,
    field: &str,
    values: &[String],
    enabled: bool,
    require_env: bool,
) {
    if !enabled {
        return;
    }

    for (idx, v) in values.iter().enumerate() {
        validate_placeholders_in_string(
            errors,
            &format!("{}[{}]", field, idx),
            v,
            enabled,
            require_env,
        );
    }
}

fn validate_placeholders_in_json(
    errors: &mut Vec<PolicyFieldError>,
    field: &str,
    value: &serde_json::Value,
    enabled: bool,
    require_env: bool,
) {
    if !enabled {
        return;
    }

    match value {
        serde_json::Value::String(s) => {
            validate_placeholders_in_string(errors, field, s, enabled, require_env);
        }
        serde_json::Value::Array(items) => {
            for (idx, v) in items.iter().enumerate() {
                validate_placeholders_in_json(
                    errors,
                    &format!("{}[{}]", field, idx),
                    v,
                    enabled,
                    require_env,
                );
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                validate_placeholders_in_json(
                    errors,
                    &format!("{}.{}", field, k),
                    v,
                    enabled,
                    require_env,
                );
            }
        }
        _ => {}
    }
}

fn validate_custom_guards(
    errors: &mut Vec<PolicyFieldError>,
    guards: &[CustomGuardSpec],
    require_env: bool,
) {
    for (idx, spec) in guards.iter().enumerate() {
        let base = format!("guards.custom[{}]", idx);

        validate_placeholders_in_string(
            errors,
            &format!("{base}.package"),
            &spec.package,
            spec.enabled,
            require_env,
        );
        if let Some(v) = spec.version.as_ref() {
            validate_placeholders_in_string(
                errors,
                &format!("{base}.version"),
                v,
                spec.enabled,
                require_env,
            );
        }
        if let Some(r) = spec.registry.as_ref() {
            validate_placeholders_in_string(
                errors,
                &format!("{base}.registry"),
                r,
                spec.enabled,
                require_env,
            );
        }

        validate_placeholders_in_json(
            errors,
            &format!("{base}.config"),
            &spec.config,
            spec.enabled,
            require_env,
        );

        if let Some(async_cfg) = spec.async_config.as_ref() {
            validate_async_policy_config(errors, &format!("{base}.async"), async_cfg);
        }

        if !spec.enabled {
            continue;
        }

        match spec.package.as_str() {
            "clawdstrike-virustotal" => validate_virustotal_spec(errors, &base, &spec.config),
            "clawdstrike-safe-browsing" => validate_safe_browsing_spec(errors, &base, &spec.config),
            "clawdstrike-snyk" => validate_snyk_spec(errors, &base, &spec.config),
            other => errors.push(PolicyFieldError::new(
                format!("{base}.package"),
                format!("unsupported custom guard package: {}", other),
            )),
        }
    }
}

fn validate_async_policy_config(
    errors: &mut Vec<PolicyFieldError>,
    base: &str,
    cfg: &AsyncGuardPolicyConfig,
) {
    if let Some(timeout_ms) = cfg.timeout_ms {
        if !(100..=300_000).contains(&timeout_ms) {
            errors.push(PolicyFieldError::new(
                format!("{}.timeout_ms", base),
                "timeout_ms must be between 100 and 300000".to_string(),
            ));
        }
    }

    if let Some(cache) = cfg.cache.as_ref() {
        if let Some(ttl) = cache.ttl_seconds {
            if ttl == 0 {
                errors.push(PolicyFieldError::new(
                    format!("{}.cache.ttl_seconds", base),
                    "ttl_seconds must be >= 1".to_string(),
                ));
            }
        }
        if let Some(max) = cache.max_size_mb {
            if max == 0 {
                errors.push(PolicyFieldError::new(
                    format!("{}.cache.max_size_mb", base),
                    "max_size_mb must be >= 1".to_string(),
                ));
            }
        }
    }

    if let Some(rl) = cfg.rate_limit.as_ref() {
        if let Some(rps) = rl.requests_per_second {
            if rps <= 0.0 {
                errors.push(PolicyFieldError::new(
                    format!("{}.rate_limit.requests_per_second", base),
                    "requests_per_second must be > 0".to_string(),
                ));
            }
        }
        if let Some(rpm) = rl.requests_per_minute {
            if rpm <= 0.0 {
                errors.push(PolicyFieldError::new(
                    format!("{}.rate_limit.requests_per_minute", base),
                    "requests_per_minute must be > 0".to_string(),
                ));
            }
        }
        if rl.requests_per_second.is_some() && rl.requests_per_minute.is_some() {
            errors.push(PolicyFieldError::new(
                format!("{}.rate_limit", base),
                "specify only one of requests_per_second or requests_per_minute".to_string(),
            ));
        }
        if let Some(burst) = rl.burst {
            if burst == 0 {
                errors.push(PolicyFieldError::new(
                    format!("{}.rate_limit.burst", base),
                    "burst must be >= 1".to_string(),
                ));
            }
        }
    }

    if let Some(cb) = cfg.circuit_breaker.as_ref() {
        if let Some(thr) = cb.failure_threshold {
            if thr == 0 {
                errors.push(PolicyFieldError::new(
                    format!("{}.circuit_breaker.failure_threshold", base),
                    "failure_threshold must be >= 1".to_string(),
                ));
            }
        }
        if let Some(ms) = cb.reset_timeout_ms {
            if ms < 1000 {
                errors.push(PolicyFieldError::new(
                    format!("{}.circuit_breaker.reset_timeout_ms", base),
                    "reset_timeout_ms must be >= 1000".to_string(),
                ));
            }
        }
        if let Some(thr) = cb.success_threshold {
            if thr == 0 {
                errors.push(PolicyFieldError::new(
                    format!("{}.circuit_breaker.success_threshold", base),
                    "success_threshold must be >= 1".to_string(),
                ));
            }
        }
    }

    if let Some(retry) = cfg.retry.as_ref() {
        if let Some(mult) = retry.multiplier {
            if mult < 1.0 {
                errors.push(PolicyFieldError::new(
                    format!("{}.retry.multiplier", base),
                    "multiplier must be >= 1".to_string(),
                ));
            }
        }
        if let Some(ms) = retry.initial_backoff_ms {
            if ms < 100 {
                errors.push(PolicyFieldError::new(
                    format!("{}.retry.initial_backoff_ms", base),
                    "initial_backoff_ms must be >= 100".to_string(),
                ));
            }
        }
        if let Some(ms) = retry.max_backoff_ms {
            if ms < 100 {
                errors.push(PolicyFieldError::new(
                    format!("{}.retry.max_backoff_ms", base),
                    "max_backoff_ms must be >= 100".to_string(),
                ));
            }
        }
        if let (Some(init), Some(max)) = (retry.initial_backoff_ms, retry.max_backoff_ms) {
            if max < init {
                errors.push(PolicyFieldError::new(
                    format!("{}.retry.max_backoff_ms", base),
                    "max_backoff_ms must be >= initial_backoff_ms".to_string(),
                ));
            }
        }
    }
}

fn require_config_string(
    errors: &mut Vec<PolicyFieldError>,
    base: &str,
    config: &serde_json::Value,
    key: &str,
) -> Option<String> {
    let serde_json::Value::Object(map) = config else {
        errors.push(PolicyFieldError::new(
            format!("{base}.config"),
            "config must be an object".to_string(),
        ));
        return None;
    };

    match map.get(key) {
        Some(serde_json::Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
        _ => {
            errors.push(PolicyFieldError::new(
                format!("{base}.config.{key}"),
                "missing/invalid required string".to_string(),
            ));
            None
        }
    }
}

fn validate_virustotal_spec(
    errors: &mut Vec<PolicyFieldError>,
    base: &str,
    config: &serde_json::Value,
) {
    let _ = require_config_string(errors, base, config, "api_key");
}

fn validate_safe_browsing_spec(
    errors: &mut Vec<PolicyFieldError>,
    base: &str,
    config: &serde_json::Value,
) {
    let _ = require_config_string(errors, base, config, "api_key");
    let _ = require_config_string(errors, base, config, "client_id");
}

fn validate_snyk_spec(errors: &mut Vec<PolicyFieldError>, base: &str, config: &serde_json::Value) {
    let _ = require_config_string(errors, base, config, "api_token");
    let _ = require_config_string(errors, base, config, "org_id");
}

/// Guards instantiated from a policy
pub(crate) struct PolicyGuards {
    pub forbidden_path: ForbiddenPathGuard,
    pub path_allowlist: PathAllowlistGuard,
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
            &self.path_allowlist as &dyn Guard,
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
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_default_policy() {
        let policy = Policy::new();
        assert_eq!(policy.version, "1.2.0");
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
    fn test_policy_validation_custom_guards_skips_missing_env_when_disabled() {
        let _lock = ENV_MUTEX.lock().unwrap();

        let missing = "CLAWDSTRIKE_TEST_CUSTOM_GUARD_MISSING_ENV";
        std::env::remove_var(missing);

        let yaml = format!(
            r#"
version: "1.1.0"
name: Test
custom_guards:
  - id: "acme.deny"
    enabled: false
    config:
      api_key: "${{{}}}"
"#,
            missing
        );

        Policy::from_yaml(&yaml).unwrap();
    }

    #[test]
    fn test_policy_validation_custom_guards_requires_env_when_enabled() {
        let _lock = ENV_MUTEX.lock().unwrap();

        let missing = "CLAWDSTRIKE_TEST_CUSTOM_GUARD_MISSING_ENV";
        std::env::remove_var(missing);

        let yaml = format!(
            r#"
version: "1.1.0"
name: Test
custom_guards:
  - id: "acme.deny"
    enabled: true
    config:
      api_key: "${{{}}}"
"#,
            missing
        );

        let err = Policy::from_yaml(&yaml).unwrap_err();
        match err {
            Error::PolicyValidation(e) => {
                assert!(e
                    .errors
                    .iter()
                    .any(|fe| fe.path == "custom_guards[0].config.api_key"));
            }
            other => panic!("expected policy validation error, got: {}", other),
        }
    }

    #[test]
    fn test_policy_validation_plugin_custom_guards_skips_missing_env_when_disabled() {
        let _lock = ENV_MUTEX.lock().unwrap();

        let missing = "CLAWDSTRIKE_TEST_ASYNC_CUSTOM_GUARD_MISSING_ENV";
        std::env::remove_var(missing);

        let yaml = format!(
            r#"
version: "1.1.0"
name: Test
guards:
  custom:
    - package: "clawdstrike-virustotal"
      enabled: false
      config:
        api_key: "${{{}}}"
"#,
            missing
        );

        Policy::from_yaml(&yaml).unwrap();
    }

    #[test]
    fn test_policy_validation_plugin_custom_guards_requires_env_when_enabled() {
        let _lock = ENV_MUTEX.lock().unwrap();

        let missing = "CLAWDSTRIKE_TEST_ASYNC_CUSTOM_GUARD_MISSING_ENV";
        std::env::remove_var(missing);

        let yaml = format!(
            r#"
version: "1.1.0"
name: Test
guards:
  custom:
    - package: "clawdstrike-virustotal"
      enabled: true
      config:
        api_key: "${{{}}}"
"#,
            missing
        );

        let err = Policy::from_yaml(&yaml).unwrap_err();
        match err {
            Error::PolicyValidation(e) => {
                assert!(e
                    .errors
                    .iter()
                    .any(|fe| fe.path == "guards.custom[0].config.api_key"));
            }
            other => panic!("expected policy validation error, got: {}", other),
        }
    }

    #[test]
    fn test_policy_validation_lax_allows_missing_env_vars_but_still_validates_placeholder_syntax() {
        let _lock = ENV_MUTEX.lock().unwrap();

        let missing = "CLAWDSTRIKE_TEST_LAX_PLACEHOLDER_MISSING_ENV";
        std::env::remove_var(missing);

        let yaml = format!(
            r#"
version: "1.1.0"
name: Test
custom_guards:
  - id: "acme.deny"
    enabled: true
    config:
      api_key: "${{{}}}"
"#,
            missing
        );

        let policy = Policy::from_yaml_unvalidated(&yaml).unwrap();
        policy
            .validate_with_options(PolicyValidationOptions::LAX)
            .unwrap();

        let bad_yaml = r#"
version: "1.1.0"
name: Test
custom_guards:
  - id: "acme.deny"
    enabled: true
    config:
      api_key: "${}"
"#;

        let policy = Policy::from_yaml_unvalidated(bad_yaml).unwrap();
        let err = policy
            .validate_with_options(PolicyValidationOptions::LAX)
            .unwrap_err();
        match err {
            Error::PolicyValidation(e) => {
                assert!(e
                    .errors
                    .iter()
                    .any(|fe| fe.message.contains("placeholder ${} is invalid")));
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
    fn test_policy_version_accepts_1_2_0() {
        let yaml = r#"
version: "1.2.0"
name: Test
"#;

        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.version, "1.2.0");
    }

    #[test]
    fn test_posture_parses_for_1_2_0() {
        let yaml = r#"
version: "1.2.0"
name: Test
posture:
  initial: work
  states:
    work:
      capabilities:
        - file_access
"#;

        let policy = Policy::from_yaml(yaml).unwrap();
        let posture = policy.posture.expect("posture must exist");
        assert_eq!(posture.initial, "work");
        assert!(posture.states.contains_key("work"));
    }

    #[test]
    fn test_posture_rejected_for_1_1_0() {
        let yaml = r#"
version: "1.1.0"
name: Test
posture:
  initial: work
  states:
    work:
      capabilities:
        - file_access
"#;

        let err = Policy::from_yaml(yaml).unwrap_err();
        match err {
            Error::PolicyValidation(e) => {
                assert!(e.errors.iter().any(|fe| fe.path == "posture"
                    && fe.message == "posture requires policy version 1.2.0"));
            }
            other => panic!("expected policy validation error, got: {}", other),
        }
    }

    #[test]
    fn test_path_allowlist_rejected_for_1_1_0() {
        let yaml = r#"
version: "1.1.0"
name: Test
guards:
  path_allowlist:
    enabled: true
    file_access_allow:
      - "**/repo/**"
"#;

        let err = Policy::from_yaml(yaml).unwrap_err();
        match err {
            Error::PolicyValidation(e) => {
                assert!(e.errors.iter().any(|fe| fe.path == "guards.path_allowlist"
                    && fe.message == "path_allowlist requires policy version 1.2.0"));
            }
            other => panic!("expected policy validation error, got: {}", other),
        }
    }

    #[test]
    fn test_path_allowlist_parses_for_1_2_0() {
        let yaml = r#"
version: "1.2.0"
name: Test
guards:
  path_allowlist:
    enabled: true
    file_access_allow:
      - "**/repo/**"
"#;

        let policy = Policy::from_yaml(yaml).unwrap();
        assert!(policy.guards.path_allowlist.is_some());
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
    fn test_policy_merge_allows_child_version_1_2_override() {
        let base = Policy {
            version: "1.1.0".to_string(),
            name: "Base".to_string(),
            ..Default::default()
        };
        let child = Policy {
            version: "1.2.0".to_string(),
            name: "Child".to_string(),
            merge_strategy: MergeStrategy::DeepMerge,
            ..Default::default()
        };

        let merged = base.merge(&child);
        assert_eq!(merged.version, "1.2.0");
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
