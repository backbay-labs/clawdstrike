//! Policy configuration and rulesets

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{Error, Result};
use crate::guards::{
    EgressAllowlistConfig, EgressAllowlistGuard, ForbiddenPathConfig, ForbiddenPathGuard,
    McpToolConfig, McpToolGuard, PatchIntegrityConfig, PatchIntegrityGuard, SecretLeakConfig,
    SecretLeakGuard,
};

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
    /// Global settings
    #[serde(default)]
    pub settings: PolicySettings,
}

fn default_version() -> String {
    "1.0.0".to_string()
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
            settings: PolicySettings::default(),
        }
    }
}

/// Configuration for all guards
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
}

/// Global policy settings
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicySettings {
    /// Whether to fail fast on first violation
    #[serde(default)]
    pub fail_fast: bool,
    /// Whether to log all actions (not just violations)
    #[serde(default)]
    pub verbose_logging: bool,
    /// Session timeout in seconds
    #[serde(default = "default_timeout")]
    pub session_timeout_secs: u64,
}

fn default_timeout() -> u64 {
    3600 // 1 hour
}

impl Default for PolicySettings {
    fn default() -> Self {
        Self {
            fail_fast: false,
            verbose_logging: false,
            session_timeout_secs: default_timeout(),
        }
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
        serde_yaml::from_str(yaml).map_err(Error::from)
    }

    /// Export to YAML string
    pub fn to_yaml(&self) -> Result<String> {
        serde_yaml::to_string(self).map_err(Error::from)
    }

    /// Create guards from this policy
    pub fn create_guards(&self) -> PolicyGuards {
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
        }
    }
}

/// Guards instantiated from a policy
pub struct PolicyGuards {
    pub forbidden_path: ForbiddenPathGuard,
    pub egress_allowlist: EgressAllowlistGuard,
    pub secret_leak: SecretLeakGuard,
    pub patch_integrity: PatchIntegrityGuard,
    pub mcp_tool: McpToolGuard,
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
    /// Load the "default" ruleset
    pub fn default_ruleset() -> Self {
        Self {
            id: "default".to_string(),
            name: "Default".to_string(),
            description: "Default security rules for AI agent execution".to_string(),
            policy: Policy::default(),
        }
    }

    /// Load the "strict" ruleset
    pub fn strict() -> Self {
        let mut policy = Policy {
            name: "Strict".to_string(),
            description: "Strict security rules with minimal permissions".to_string(),
            ..Default::default()
        };

        // Strict egress - block by default
        policy.guards.egress_allowlist = Some(EgressAllowlistConfig {
            allow: vec![],
            block: vec![],
            default_action: "block".to_string(),
        });

        // Strict MCP tools - block by default
        policy.guards.mcp_tool = Some(McpToolConfig {
            allow: vec![
                "read_file".to_string(),
                "list_directory".to_string(),
                "search".to_string(),
            ],
            block: vec![],
            require_confirmation: vec![],
            default_action: "block".to_string(),
            max_args_size: 1024 * 1024,
        });

        // Strict patch limits
        policy.guards.patch_integrity = Some(PatchIntegrityConfig {
            max_additions: 500,
            max_deletions: 200,
            require_balance: true,
            max_imbalance_ratio: 5.0,
            ..Default::default()
        });

        policy.settings.fail_fast = true;

        Self {
            id: "strict".to_string(),
            name: "Strict".to_string(),
            description: "Strict security rules with minimal permissions".to_string(),
            policy,
        }
    }

    /// Load the "permissive" ruleset (for development)
    pub fn permissive() -> Self {
        let mut policy = Policy {
            name: "Permissive".to_string(),
            description: "Permissive rules for development (use with caution)".to_string(),
            ..Default::default()
        };

        // Allow all egress
        policy.guards.egress_allowlist = Some(EgressAllowlistConfig {
            allow: vec!["*".to_string()],
            block: vec![],
            default_action: "allow".to_string(),
        });

        // Higher patch limits
        policy.guards.patch_integrity = Some(PatchIntegrityConfig {
            max_additions: 10000,
            max_deletions: 5000,
            require_balance: false,
            ..Default::default()
        });

        policy.settings.verbose_logging = true;

        Self {
            id: "permissive".to_string(),
            name: "Permissive".to_string(),
            description: "Permissive rules for development (use with caution)".to_string(),
            policy,
        }
    }

    /// Load a ruleset by name
    pub fn by_name(name: &str) -> Option<Self> {
        match name {
            "default" => Some(Self::default_ruleset()),
            "strict" => Some(Self::strict()),
            "permissive" => Some(Self::permissive()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = Policy::new();
        assert_eq!(policy.version, "1.0.0");
    }

    #[test]
    fn test_policy_yaml_roundtrip() {
        let policy = Policy::new();
        let yaml = policy.to_yaml().unwrap();
        let restored = Policy::from_yaml(&yaml).unwrap();
        assert_eq!(policy.version, restored.version);
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
        let default = RuleSet::default_ruleset();
        assert_eq!(default.id, "default");

        let strict = RuleSet::strict();
        assert!(strict.policy.settings.fail_fast);

        let permissive = RuleSet::permissive();
        assert!(permissive.policy.settings.verbose_logging);
    }

    #[test]
    fn test_ruleset_by_name() {
        assert!(RuleSet::by_name("default").is_some());
        assert!(RuleSet::by_name("strict").is_some());
        assert!(RuleSet::by_name("permissive").is_some());
        assert!(RuleSet::by_name("unknown").is_none());
    }

    #[test]
    fn test_merge_strategy_default() {
        let yaml = r#"
version: "1.0.0"
name: Test
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.merge_strategy, MergeStrategy::DeepMerge);
    }

    #[test]
    fn test_merge_strategy_parse() {
        let yaml = r#"
version: "1.0.0"
name: Test
merge_strategy: replace
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.merge_strategy, MergeStrategy::Replace);
    }

    #[test]
    fn test_extends_field_parse() {
        let yaml = r#"
version: "1.0.0"
name: Test
extends: strict
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.extends, Some("strict".to_string()));
    }

    #[test]
    fn test_extends_field_none_by_default() {
        let yaml = r#"
version: "1.0.0"
name: Test
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert!(policy.extends.is_none());
    }
}
