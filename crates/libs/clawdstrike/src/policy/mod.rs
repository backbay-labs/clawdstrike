//! Policy configuration and rulesets

use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

use crate::error::Result;
use crate::guards::{
    ComputerUseGuard, EgressAllowlistGuard, ForbiddenPathGuard, Guard,
    InputInjectionCapabilityGuard, JailbreakGuard, McpToolGuard, PatchIntegrityGuard,
    PathAllowlistGuard, PromptInjectionGuard, RemoteDesktopSideChannelGuard, SecretLeakGuard,
    ShellCommandGuard,
};

mod async_config;
mod broker;
mod guard_configs;
mod load;
mod merge;
mod origins;
mod resolver;
mod settings;
mod types;
mod validate;

pub use async_config::{
    AsyncCachePolicyConfig, AsyncCircuitBreakerPolicyConfig, AsyncExecutionMode,
    AsyncGuardPolicyConfig, AsyncRateLimitPolicyConfig, AsyncRetryPolicyConfig, TimeoutBehavior,
};
pub use broker::{BrokerConfig, BrokerMethod, BrokerProviderPolicy};
pub use guard_configs::GuardConfigs;
pub use origins::{
    BridgePolicy, BridgeTarget, OriginBudgets, OriginDataPolicy, OriginDefaultBehavior,
    OriginMatch, OriginProfile, OriginsConfig,
};
pub use resolver::{
    LocalPolicyResolver, PolicyCustomGuardSpec, PolicyLocation, PolicyResolver,
    ResolvedPolicySource,
};
pub use settings::{CustomGuardSpec, PolicySettings, VerificationSettings};
pub use types::{MergeStrategy, Policy, PolicyLoadVerificationInput, PolicyValidationOptions};
pub use validate::{policy_version_supports_broker, policy_version_supports_origins};

pub(crate) use settings::merge_verification_settings;

/// Current policy schema version.
///
/// This is a schema compatibility boundary (not the crate version). Runtimes should fail closed on
/// unsupported versions to prevent silent drift.
pub const POLICY_SCHEMA_VERSION: &str = "1.5.0";
pub const POLICY_SUPPORTED_SCHEMA_VERSIONS: &[&str] =
    &["1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0"];

pub(crate) type PolicyLoadVerifier =
    dyn Fn(&PolicyLoadVerificationInput) -> Result<()> + Send + Sync + 'static;

pub(crate) static POLICY_LOAD_VERIFIER: OnceLock<Box<PolicyLoadVerifier>> = OnceLock::new();

pub fn install_policy_load_verifier<F>(verifier: F) -> bool
where
    F: Fn(&PolicyLoadVerificationInput) -> Result<()> + Send + Sync + 'static,
{
    POLICY_LOAD_VERIFIER.set(Box::new(verifier)).is_ok()
}

impl Policy {
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
            shell_command: self
                .guards
                .shell_command
                .clone()
                .map(|cfg| ShellCommandGuard::with_config(cfg, self.guards.forbidden_path.clone()))
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
            computer_use: self
                .guards
                .computer_use
                .clone()
                .map(ComputerUseGuard::with_config)
                .unwrap_or_default(),
            remote_desktop_side_channel: self
                .guards
                .remote_desktop_side_channel
                .clone()
                .map(RemoteDesktopSideChannelGuard::with_config)
                .unwrap_or_default(),
            input_injection_capability: self
                .guards
                .input_injection_capability
                .clone()
                .map(InputInjectionCapabilityGuard::with_config)
                .unwrap_or_default(),
        }
    }
}

/// Guards instantiated from a policy
pub(crate) struct PolicyGuards {
    pub forbidden_path: ForbiddenPathGuard,
    pub path_allowlist: PathAllowlistGuard,
    pub egress_allowlist: EgressAllowlistGuard,
    pub secret_leak: SecretLeakGuard,
    pub patch_integrity: PatchIntegrityGuard,
    pub shell_command: ShellCommandGuard,
    pub mcp_tool: McpToolGuard,
    pub prompt_injection: PromptInjectionGuard,
    pub jailbreak: JailbreakGuard,
    pub computer_use: ComputerUseGuard,
    pub remote_desktop_side_channel: RemoteDesktopSideChannelGuard,
    pub input_injection_capability: InputInjectionCapabilityGuard,
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
            &self.shell_command as &dyn Guard,
            &self.mcp_tool as &dyn Guard,
            &self.prompt_injection as &dyn Guard,
            &self.jailbreak as &dyn Guard,
            &self.computer_use as &dyn Guard,
            &self.remote_desktop_side_channel as &dyn Guard,
            &self.input_injection_capability as &dyn Guard,
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
            "default" => Some(include_str!("../../rulesets/default.yaml")),
            "strict" => Some(include_str!("../../rulesets/strict.yaml")),
            "ai-agent" => Some(include_str!("../../rulesets/ai-agent.yaml")),
            "ai-agent-posture" => Some(include_str!("../../rulesets/ai-agent-posture.yaml")),
            "cicd" => Some(include_str!("../../rulesets/cicd.yaml")),
            "permissive" => Some(include_str!("../../rulesets/permissive.yaml")),
            "remote-desktop" => Some(include_str!("../../rulesets/remote-desktop.yaml")),
            "remote-desktop-strict" => {
                Some(include_str!("../../rulesets/remote-desktop-strict.yaml"))
            }
            "remote-desktop-permissive" => Some(include_str!(
                "../../rulesets/remote-desktop-permissive.yaml"
            )),
            #[cfg(feature = "full")]
            "spider-sense" => Some(include_str!("../../rulesets/spider-sense.yaml")),
            "origin-enclaves-example" => {
                Some(include_str!("../../rulesets/origin-enclaves-example.yaml"))
            }
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
        &[
            "default",
            "strict",
            "ai-agent",
            "ai-agent-posture",
            "cicd",
            "permissive",
            "remote-desktop",
            "remote-desktop-strict",
            "remote-desktop-permissive",
            #[cfg(feature = "full")]
            "spider-sense",
            "origin-enclaves-example",
        ]
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::error::Error;
    use crate::guards::{ForbiddenPathConfig, SecretLeakConfig};
    use crate::origin::{OriginProvider, ProvenanceConfidence, SpaceType, Visibility};
    use std::sync::Mutex;
    use tempfile::tempdir;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    #[test]
    fn test_default_policy() {
        let policy = Policy::new();
        assert_eq!(policy.version, "1.5.0");
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
    fn test_policy_version_accepts_1_3_0() {
        let yaml = r#"
version: "1.3.0"
name: Test
"#;

        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.version, "1.3.0");
    }

    #[test]
    fn test_policy_version_accepts_1_5_0() {
        let yaml = r#"
version: "1.5.0"
name: Test
"#;

        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.version, "1.5.0");
    }

    #[test]
    fn test_broker_version_gating_rejects_1_4_policy() {
        let yaml = r#"
version: "1.4.0"
name: broker-old
broker:
  enabled: true
  providers:
    - name: "openai"
      host: "api.openai.com"
      exact_paths: ["/v1/responses"]
      methods: ["POST"]
      secret_ref: "openai/dev"
"#;

        let err = Policy::from_yaml(yaml).unwrap_err();
        match err {
            Error::PolicyValidation(e) => {
                assert!(e.errors.iter().any(|fe| fe.path == "broker"
                    && fe
                        .message
                        .contains("broker block requires schema version >= 1.5.0")));
            }
            other => panic!("expected policy validation error, got: {}", other),
        }
    }

    #[test]
    fn test_broker_policy_parses_on_1_5() {
        let yaml = r#"
version: "1.5.0"
name: broker-new
broker:
  enabled: true
  providers:
    - name: "openai"
      host: "api.openai.com"
      port: 443
      exact_paths: ["/v1/responses"]
      methods: ["POST"]
      secret_ref: "openai/dev"
      allowed_headers: ["content-type"]
      require_body_sha256: true
"#;

        let policy = Policy::from_yaml(yaml).unwrap();
        let broker = policy.broker.expect("broker config");
        assert!(broker.enabled);
        assert_eq!(broker.providers.len(), 1);
        assert_eq!(broker.providers[0].name, "openai");
        assert_eq!(broker.providers[0].port, Some(443));
        assert_eq!(broker.providers[0].methods, vec![BrokerMethod::POST]);
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_policy_1_3_spider_sense_fields_parse() {
        let yaml = r#"
version: "1.3.0"
name: SpiderSense13
guards:
  spider_sense:
    enabled: true
    embedding_api_url: "https://api.openai.com/v1/embeddings"
    embedding_api_key: "${SPIDER_SENSE_EMBEDDING_KEY}"
    embedding_model: "text-embedding-3-small"
    similarity_threshold: 0.85
    ambiguity_band: 0.10
    top_k: 5
    pattern_db_manifest_path: "/tmp/spider/manifest.json"
    pattern_db_manifest_trust_store_path: "/tmp/spider/manifest-roots.json"
    llm_api_url: "https://api.openai.com/v1/chat/completions"
    llm_api_key: "${SPIDER_SENSE_LLM_KEY}"
    llm_model: "gpt-4.1-mini"
    llm_prompt_template_id: "spider_sense.deep_path.json_classifier"
    llm_prompt_template_version: "1.0.0"
    llm_timeout_ms: 1500
    llm_fail_mode: "warn"
"#;

        let policy = Policy::from_yaml(yaml).expect("1.3 spider-sense config should parse");
        let spider = policy
            .guards
            .spider_sense
            .as_ref()
            .expect("spider_sense should be present");
        assert_eq!(
            spider.pattern_db_manifest_path.as_deref(),
            Some("/tmp/spider/manifest.json")
        );
        assert_eq!(
            spider.llm_prompt_template_id.as_deref(),
            Some("spider_sense.deep_path.json_classifier")
        );
        assert_eq!(spider.llm_prompt_template_version.as_deref(), Some("1.0.0"));
    }

    #[cfg(all(feature = "policy-event", not(feature = "full")))]
    #[test]
    fn test_policy_1_3_spider_sense_fields_parse_policy_event_build() {
        let yaml = r#"
version: "1.3.0"
name: SpiderSense13PolicyEvent
guards:
  spider_sense:
    enabled: true
    embedding_api_url: "https://api.openai.com/v1/embeddings"
    embedding_api_key: "${SPIDER_SENSE_EMBEDDING_KEY}"
    embedding_model: "text-embedding-3-small"
    similarity_threshold: 0.85
    ambiguity_band: 0.10
    top_k: 5
    pattern_db_manifest_path: "/tmp/spider/manifest.json"
    pattern_db_manifest_trust_store_path: "/tmp/spider/manifest-roots.json"
"#;

        let policy = Policy::from_yaml(yaml).expect("1.3 spider-sense policy should parse");
        let spider = policy
            .guards
            .spider_sense
            .as_ref()
            .expect("spider_sense field should be preserved");
        assert_eq!(
            spider
                .pointer("/pattern_db_manifest_path")
                .and_then(|v| v.as_str()),
            Some("/tmp/spider/manifest.json")
        );
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
    fn test_origin_enclaves_example_ruleset_loads() {
        let (yaml, _) = RuleSet::yaml_by_name("origin-enclaves-example").unwrap();
        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.version, "1.4.0");
        assert!(policy.origins.is_some());
        let origins = policy.origins.unwrap();
        assert_eq!(origins.profiles.len(), 4);
        assert_eq!(origins.profiles[0].id, "incident-room");
        assert_eq!(origins.profiles[1].id, "external-chat");
        assert_eq!(origins.profiles[2].id, "code-review");
        assert_eq!(origins.profiles[3].id, "internal-default");
        assert_eq!(origins.default_behavior, Some(OriginDefaultBehavior::Deny));
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

        let rulesets_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../rulesets");
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
version: "1.2.0"
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
version: "1.2.0"
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

    #[test]
    fn test_secret_leak_merge_preserves_base_patterns() {
        let yaml = r#"
version: "1.2.0"
name: CustomDefault
extends: default
guards:
  secret_leak:
    additional_patterns:
      - name: custom_token
        pattern: "CUSTOM_[A-Za-z0-9]{32}"
"#;
        let policy = Policy::from_yaml_with_extends(yaml, None).unwrap();
        let sl = policy.guards.secret_leak.unwrap();
        let effective = sl.effective_patterns();

        // Base patterns should still be present
        assert!(
            effective.iter().any(|p| p.name == "aws_access_key"),
            "base pattern aws_access_key must be preserved"
        );
        assert!(
            effective.iter().any(|p| p.name == "github_token"),
            "base pattern github_token must be preserved"
        );
        // Additional pattern should be present
        assert!(
            effective.iter().any(|p| p.name == "custom_token"),
            "additional pattern custom_token must be present"
        );
    }

    #[test]
    fn test_secret_leak_merge_remove_patterns() {
        let base = SecretLeakConfig::default();
        let child = SecretLeakConfig {
            remove_patterns: vec!["generic_api_key".to_string()],
            ..Default::default()
        };
        let merged = base.merge_with(&child);
        let effective = merged.effective_patterns();

        assert!(
            !effective.iter().any(|p| p.name == "generic_api_key"),
            "removed pattern must not be in effective set"
        );
        assert!(
            effective.iter().any(|p| p.name == "aws_access_key"),
            "other patterns must be preserved"
        );
    }

    #[test]
    fn test_secret_leak_deep_merge_in_guard_configs() {
        let base = GuardConfigs {
            secret_leak: Some(SecretLeakConfig::default()),
            ..Default::default()
        };
        let child = GuardConfigs {
            secret_leak: Some(SecretLeakConfig {
                additional_patterns: vec![crate::guards::SecretPattern {
                    name: "my_custom".to_string(),
                    pattern: r"MY_[A-Z]{10}".to_string(),
                    severity: crate::guards::Severity::Critical,
                    description: None,
                    luhn_check: false,
                    masking: None,
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        let merged = base.merge_with(&child);
        let sl = merged.secret_leak.unwrap();
        let effective = sl.effective_patterns();

        assert!(
            effective.iter().any(|p| p.name == "aws_access_key"),
            "base patterns preserved in deep merge"
        );
        assert!(
            effective.iter().any(|p| p.name == "my_custom"),
            "additional pattern added in deep merge"
        );
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_spider_sense_deep_merge_allows_child_disable_override() {
        let base = GuardConfigs {
            spider_sense: Some(
                serde_json::from_value(serde_json::json!({
                    "enabled": true,
                    "embedding_api_url": "https://example.invalid/v1/embeddings",
                    "embedding_api_key": "base-key",
                    "embedding_model": "text-embedding-3-small",
                    "pattern_db_path": "builtin:s2bench-v1"
                }))
                .unwrap(),
            ),
            ..Default::default()
        };
        let child = GuardConfigs {
            spider_sense: Some(
                serde_json::from_value(serde_json::json!({
                    "enabled": false
                }))
                .unwrap(),
            ),
            spider_sense_present_fields: std::iter::once("enabled".to_string()).collect(),
            ..Default::default()
        };

        let merged = base.merge_with(&child);
        let merged_spider = merged
            .spider_sense
            .expect("child disable override should preserve explicit spider_sense config");
        assert!(!merged_spider.enabled);
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_spider_sense_deep_merge_preserves_base_fields_on_partial_child_override() {
        let base = GuardConfigs {
            spider_sense: Some(
                serde_json::from_value(serde_json::json!({
                    "enabled": false,
                    "embedding_api_url": "https://example.invalid/v1/embeddings",
                    "embedding_api_key": "base-key",
                    "embedding_model": "text-embedding-3-small",
                    "similarity_threshold": 0.82,
                    "pattern_db_path": "builtin:s2bench-v1"
                }))
                .unwrap(),
            ),
            ..Default::default()
        };
        let child = GuardConfigs {
            spider_sense: Some(
                serde_json::from_value(serde_json::json!({
                    "similarity_threshold": 0.91
                }))
                .unwrap(),
            ),
            spider_sense_present_fields: std::iter::once("similarity_threshold".to_string())
                .collect(),
            ..Default::default()
        };

        let merged = base.merge_with(&child);
        let merged_spider = merged
            .spider_sense
            .expect("partial child override should preserve base spider_sense config");
        assert!(!merged_spider.enabled);
        assert_eq!(
            merged_spider.embedding_api_url,
            "https://example.invalid/v1/embeddings"
        );
        assert_eq!(merged_spider.embedding_api_key, "base-key");
        assert_eq!(merged_spider.embedding_model, "text-embedding-3-small");
        assert_eq!(merged_spider.pattern_db_path, "builtin:s2bench-v1");
        assert_eq!(merged_spider.similarity_threshold, 0.91);
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_spider_sense_deep_merge_without_presence_treats_child_as_explicit_replacement() {
        let base = GuardConfigs {
            spider_sense: Some(
                serde_json::from_value(serde_json::json!({
                    "enabled": false,
                    "embedding_api_url": "https://example.invalid/v1/embeddings",
                    "embedding_api_key": "base-key",
                    "embedding_model": "text-embedding-3-small",
                    "similarity_threshold": 0.95,
                    "ambiguity_band": 0.02,
                    "top_k": 9,
                    "pattern_db_path": "builtin:s2bench-v1"
                }))
                .unwrap(),
            ),
            ..Default::default()
        };
        let child = GuardConfigs {
            spider_sense: Some(
                serde_json::from_value(serde_json::json!({
                    "enabled": true,
                    "similarity_threshold": 0.85,
                    "ambiguity_band": 0.10,
                    "top_k": 5
                }))
                .unwrap(),
            ),
            ..Default::default()
        };

        let merged = base.merge_with(&child);
        let ss = merged.spider_sense.expect("merged spider_sense");
        assert!(ss.enabled);
        assert_eq!(ss.similarity_threshold, 0.85);
        assert_eq!(ss.ambiguity_band, 0.10);
        assert_eq!(ss.top_k, 5);
        assert_eq!(ss.embedding_api_key, "");
        assert_eq!(ss.pattern_db_path, "");
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_spider_sense_deep_merge_without_presence_clears_stale_present_fields() {
        let base = GuardConfigs {
            spider_sense: Some(
                serde_json::from_value(serde_json::json!({
                    "enabled": false,
                    "embedding_api_url": "https://example.invalid/v1/embeddings",
                    "embedding_api_key": "base-key",
                    "embedding_model": "text-embedding-3-small",
                    "similarity_threshold": 0.95,
                    "pattern_db_path": "builtin:s2bench-v1"
                }))
                .unwrap(),
            ),
            spider_sense_present_fields: std::iter::once("similarity_threshold".to_string())
                .collect(),
            ..Default::default()
        };
        let child = GuardConfigs {
            spider_sense: Some(
                serde_json::from_value(serde_json::json!({
                    "enabled": true,
                    "similarity_threshold": 0.85,
                    "ambiguity_band": 0.10,
                    "top_k": 5
                }))
                .unwrap(),
            ),
            // Programmatic child replacement has no explicit YAML field metadata.
            spider_sense_present_fields: Default::default(),
            ..Default::default()
        };

        let merged = base.merge_with(&child);
        assert!(
            merged.spider_sense_present_fields.is_empty(),
            "programmatic replacement should not retain stale source present_fields"
        );
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_spider_sense_deep_merge_yaml_presence_preserves_parent_when_field_absent() {
        let base = Policy::from_yaml_unvalidated(
            r#"
version: "1.3.0"
name: "base"
guards:
  spider_sense:
    enabled: false
    embedding_api_url: "https://example.invalid/v1/embeddings"
    embedding_api_key: "base-key"
    embedding_model: "text-embedding-3-small"
    similarity_threshold: 0.82
    ambiguity_band: 0.05
    top_k: 7
    pattern_db_path: "builtin:s2bench-v1"
"#,
        )
        .unwrap();
        let child = Policy::from_yaml_unvalidated(
            r#"
version: "1.3.0"
name: "child"
guards:
  spider_sense:
    similarity_threshold: 0.91
"#,
        )
        .unwrap();

        let merged = base.merge(&child);
        let ss = merged.guards.spider_sense.expect("merged spider_sense");
        assert!(!ss.enabled, "absent child.enabled should preserve parent");
        assert_eq!(ss.similarity_threshold, 0.91);
        assert_eq!(ss.ambiguity_band, 0.05);
        assert_eq!(ss.top_k, 7);
        assert_eq!(
            ss.embedding_api_url,
            "https://example.invalid/v1/embeddings"
        );
    }

    #[cfg(feature = "full")]
    #[test]
    fn test_spider_sense_deep_merge_yaml_presence_honors_explicit_default_overrides() {
        let base = Policy::from_yaml_unvalidated(
            r#"
version: "1.3.0"
name: "base"
guards:
  spider_sense:
    enabled: false
    embedding_api_url: "https://example.invalid/v1/embeddings"
    embedding_api_key: "base-key"
    embedding_model: "text-embedding-3-small"
    similarity_threshold: 0.95
    ambiguity_band: 0.02
    top_k: 9
    pattern_db_path: "builtin:s2bench-v1"
"#,
        )
        .unwrap();
        let child = Policy::from_yaml_unvalidated(
            r#"
version: "1.3.0"
name: "child"
guards:
  spider_sense:
    enabled: true
    similarity_threshold: 0.85
    ambiguity_band: 0.10
    top_k: 5
"#,
        )
        .unwrap();

        let merged = base.merge(&child);
        let ss = merged.guards.spider_sense.expect("merged spider_sense");
        assert!(ss.enabled, "explicit child.enabled should override parent");
        assert_eq!(ss.similarity_threshold, 0.85);
        assert_eq!(ss.ambiguity_band, 0.10);
        assert_eq!(ss.top_k, 5);
        assert_eq!(ss.embedding_api_key, "base-key");
        assert_eq!(ss.pattern_db_path, "builtin:s2bench-v1");
    }

    // -----------------------------------------------------------------------
    // Origin Enclaves (policy schema v1.4.0)
    // -----------------------------------------------------------------------

    #[test]
    fn test_origins_yaml_parse_roundtrip() {
        let yaml = r#"
version: "1.4.0"
name: OriginTest
posture:
  initial: standard
  states:
    standard:
      description: Standard posture
    restricted:
      description: Restricted posture
origins:
  default_behavior: deny
  profiles:
    - id: slack-internal
      match_rules:
        provider: slack
        space_type: channel
        visibility: internal
        tags:
          - hipaa
        provenance_confidence: strong
      posture: restricted
      mcp:
        enabled: true
        allow:
          - "read_*"
      egress:
        enabled: true
        allow:
          - "*.internal.corp"
      data:
        allow_external_sharing: false
        redact_before_send: true
        block_sensitive_outputs: true
      budgets:
        mcp_tool_calls: 100
        egress_calls: 50
        shell_commands: 10
      bridge_policy:
        allow_cross_origin: true
        require_approval: true
        allowed_targets:
          - provider: github
            space_type: issue
            tags:
              - engineering
            visibility: internal
      explanation: "Internal Slack channels with HIPAA data"
"#;

        let policy = Policy::from_yaml(yaml).expect("v1.4.0 origins policy should parse");
        assert_eq!(policy.version, "1.4.0");

        let origins = policy.origins.as_ref().expect("origins must be present");
        assert_eq!(origins.default_behavior, Some(OriginDefaultBehavior::Deny));
        assert_eq!(origins.profiles.len(), 1);

        let profile = &origins.profiles[0];
        assert_eq!(profile.id, "slack-internal");
        assert_eq!(profile.match_rules.provider, Some(OriginProvider::Slack));
        assert_eq!(profile.match_rules.space_type, Some(SpaceType::Channel));
        assert_eq!(profile.match_rules.visibility, Some(Visibility::Internal));
        assert_eq!(profile.match_rules.tags, vec!["hipaa"]);
        assert_eq!(
            profile.match_rules.provenance_confidence,
            Some(ProvenanceConfidence::Strong)
        );
        assert_eq!(profile.posture.as_deref(), Some("restricted"));
        assert!(profile.mcp.is_some());
        assert!(profile.egress.is_some());

        let data = profile.data.as_ref().expect("data policy");
        assert!(!data.allow_external_sharing);
        assert!(data.redact_before_send);
        assert!(data.block_sensitive_outputs);

        let budgets = profile.budgets.as_ref().expect("budgets");
        assert_eq!(budgets.mcp_tool_calls, Some(100));
        assert_eq!(budgets.egress_calls, Some(50));
        assert_eq!(budgets.shell_commands, Some(10));

        let bridge = profile.bridge_policy.as_ref().expect("bridge_policy");
        assert!(bridge.allow_cross_origin);
        assert!(bridge.require_approval);
        assert_eq!(bridge.allowed_targets.len(), 1);
        assert_eq!(
            bridge.allowed_targets[0].provider,
            Some(OriginProvider::GitHub)
        );
        assert_eq!(bridge.allowed_targets[0].space_type, Some(SpaceType::Issue));

        assert_eq!(
            profile.explanation.as_deref(),
            Some("Internal Slack channels with HIPAA data")
        );

        // Roundtrip through YAML serialization
        let yaml_out = policy.to_yaml().expect("to_yaml");
        let restored = Policy::from_yaml(&yaml_out).expect("roundtrip parse");
        let restored_origins = restored.origins.expect("restored origins");
        assert_eq!(restored_origins.profiles.len(), 1);
        assert_eq!(restored_origins.profiles[0].id, "slack-internal");
    }

    #[test]
    fn test_origins_version_gating_rejects_1_3() {
        let yaml = r#"
version: "1.3.0"
name: OriginVersionGated
origins:
  default_behavior: deny
  profiles:
    - id: test
      match_rules:
        provider: slack
"#;

        let err = Policy::from_yaml(yaml).unwrap_err();
        match err {
            Error::PolicyValidation(e) => {
                assert!(
                    e.errors.iter().any(|fe| fe.path == "origins"
                        && fe
                            .message
                            .contains("origins block requires schema version >= 1.4.0")),
                    "expected origins version gating error, got: {:?}",
                    e.errors
                );
            }
            other => panic!("expected policy validation error, got: {}", other),
        }
    }

    #[test]
    fn test_origins_backward_compat_v1_3_without_origins() {
        let yaml = r#"
version: "1.3.0"
name: NoOrigins
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert!(
            policy.origins.is_none(),
            "v1.3.0 policy without origins should load fine"
        );
    }

    #[test]
    fn test_origins_backward_compat_v1_1_without_origins() {
        let yaml = r#"
version: "1.1.0"
name: LegacyPolicy
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert!(policy.origins.is_none());
    }

    #[test]
    fn test_origins_merge_deep_child_overrides_profile_by_id() {
        let base = Policy {
            version: "1.4.0".to_string(),
            name: "Base".to_string(),
            origins: Some(OriginsConfig {
                default_behavior: Some(OriginDefaultBehavior::Deny),
                profiles: vec![
                    OriginProfile {
                        id: "slack-internal".to_string(),
                        match_rules: OriginMatch {
                            provider: Some(OriginProvider::Slack),
                            ..Default::default()
                        },
                        posture: Some("base-posture".to_string()),
                        mcp: None,
                        egress: None,
                        data: None,
                        budgets: None,
                        bridge_policy: None,
                        explanation: Some("base explanation".to_string()),
                    },
                    OriginProfile {
                        id: "github-ci".to_string(),
                        match_rules: OriginMatch {
                            provider: Some(OriginProvider::GitHub),
                            ..Default::default()
                        },
                        posture: None,
                        mcp: None,
                        egress: None,
                        data: None,
                        budgets: None,
                        bridge_policy: None,
                        explanation: Some("base github ci".to_string()),
                    },
                ],
            }),
            ..Default::default()
        };

        let child = Policy {
            version: "1.4.0".to_string(),
            name: "Child".to_string(),
            merge_strategy: MergeStrategy::DeepMerge,
            origins: Some(OriginsConfig {
                default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
                profiles: vec![OriginProfile {
                    id: "slack-internal".to_string(),
                    match_rules: OriginMatch {
                        provider: Some(OriginProvider::Slack),
                        visibility: Some(Visibility::Private),
                        ..Default::default()
                    },
                    posture: Some("child-posture".to_string()),
                    mcp: None,
                    egress: None,
                    data: None,
                    budgets: None,
                    bridge_policy: None,
                    explanation: Some("child explanation".to_string()),
                }],
            }),
            ..Default::default()
        };

        let merged = base.merge(&child);
        let origins = merged.origins.expect("merged origins");

        // Child's default_behavior wins
        assert_eq!(
            origins.default_behavior,
            Some(OriginDefaultBehavior::MinimalProfile)
        );

        // Should have 2 profiles: slack-internal overridden, github-ci preserved
        assert_eq!(origins.profiles.len(), 2);

        let slack = origins
            .profiles
            .iter()
            .find(|p| p.id == "slack-internal")
            .expect("slack-internal profile");
        assert_eq!(
            slack.posture.as_deref(),
            Some("child-posture"),
            "child profile should override base"
        );
        assert_eq!(slack.explanation.as_deref(), Some("child explanation"),);
        assert_eq!(
            slack.match_rules.visibility,
            Some(Visibility::Private),
            "child match_rules should be used"
        );

        let github = origins
            .profiles
            .iter()
            .find(|p| p.id == "github-ci")
            .expect("github-ci profile");
        assert_eq!(
            github.explanation.as_deref(),
            Some("base github ci"),
            "unmatched base profile should be preserved"
        );
    }

    #[test]
    fn test_origins_reject_unknown_fields_in_origin_profile() {
        let yaml = r#"
version: "1.4.0"
name: BadProfile
origins:
  default_behavior: deny
  profiles:
    - id: test
      match_rules:
        provider: slack
      unknown_field: "boom"
"#;

        let err = Policy::from_yaml(yaml).unwrap_err();
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("unknown field"),
            "expected 'unknown field' in error, got: {err_msg}"
        );
    }

    #[test]
    fn test_origins_reject_duplicate_profile_ids() {
        let yaml = r#"
version: "1.4.0"
name: DuplicateIds
origins:
  default_behavior: deny
  profiles:
    - id: same-id
      match_rules:
        provider: slack
    - id: same-id
      match_rules:
        provider: github
"#;

        let err = Policy::from_yaml(yaml).unwrap_err();
        match err {
            Error::PolicyValidation(e) => {
                assert!(
                    e.errors.iter().any(|fe| fe.path == "origins.profiles"
                        && fe.message.contains("duplicate origin profile id: same-id")),
                    "expected duplicate profile id error, got: {:?}",
                    e.errors
                );
            }
            other => panic!("expected policy validation error, got: {}", other),
        }
    }

    #[test]
    fn test_policy_version_accepts_1_4_0() {
        let yaml = r#"
version: "1.4.0"
name: Test
"#;

        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.version, "1.4.0");
        assert!(policy.origins.is_none());
    }

    #[test]
    fn test_policy_version_supports_origins_function() {
        assert!(!policy_version_supports_origins("1.1.0"));
        assert!(!policy_version_supports_origins("1.2.0"));
        assert!(!policy_version_supports_origins("1.3.0"));
        assert!(policy_version_supports_origins("1.4.0"));
    }

    #[test]
    fn test_policy_version_supports_broker_function() {
        assert!(!policy_version_supports_broker("1.1.0"));
        assert!(!policy_version_supports_broker("1.4.0"));
        assert!(policy_version_supports_broker("1.5.0"));
    }

    #[test]
    fn test_extends_depth_terminal_policy_still_fails() {
        let dir = tempdir().expect("tempdir");
        let mut previous: Option<std::path::PathBuf> = None;

        for depth in 0..=crate::core::cycle::MAX_POLICY_EXTENDS_DEPTH + 1 {
            let path = dir.path().join(format!("policy-{depth}.yaml"));
            let yaml = if let Some(previous) = previous.as_ref() {
                format!(
                    "version: \"1.1.0\"\nname: \"policy-{depth}\"\nextends: \"{}\"\n",
                    previous.file_name().expect("filename").to_string_lossy()
                )
            } else {
                format!("version: \"1.1.0\"\nname: \"policy-{depth}\"\n")
            };
            std::fs::write(&path, yaml).expect("write policy");
            previous = Some(path);
        }

        let root = dir.path().join(format!(
            "policy-{}.yaml",
            crate::core::cycle::MAX_POLICY_EXTENDS_DEPTH + 1
        ));
        let root_yaml = std::fs::read_to_string(&root).expect("read root");
        let err = Policy::from_yaml_with_extends(&root_yaml, Some(root.as_path()))
            .expect_err("depth exceeded");
        assert!(
            err.to_string().contains("Policy extends depth exceeded"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_origins_default_behavior_minimal_profile() {
        let yaml = r#"
version: "1.4.0"
name: MinimalProfileDefault
origins:
  default_behavior: minimal_profile
  profiles: []
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        let origins = policy.origins.expect("origins");
        assert_eq!(
            origins.default_behavior,
            Some(OriginDefaultBehavior::MinimalProfile)
        );
    }

    #[test]
    fn test_origins_merge_child_appends_new_profile() {
        let base = Policy {
            version: "1.4.0".to_string(),
            origins: Some(OriginsConfig {
                default_behavior: Some(OriginDefaultBehavior::Deny),
                profiles: vec![OriginProfile {
                    id: "existing".to_string(),
                    match_rules: OriginMatch::default(),
                    posture: None,
                    mcp: None,
                    egress: None,
                    data: None,
                    budgets: None,
                    bridge_policy: None,
                    explanation: None,
                }],
            }),
            ..Default::default()
        };

        let child = Policy {
            version: "1.4.0".to_string(),
            merge_strategy: MergeStrategy::DeepMerge,
            origins: Some(OriginsConfig {
                default_behavior: Some(OriginDefaultBehavior::Deny),
                profiles: vec![OriginProfile {
                    id: "new-profile".to_string(),
                    match_rules: OriginMatch {
                        provider: Some(OriginProvider::Teams),
                        ..Default::default()
                    },
                    posture: None,
                    mcp: None,
                    egress: None,
                    data: None,
                    budgets: None,
                    bridge_policy: None,
                    explanation: None,
                }],
            }),
            ..Default::default()
        };

        let merged = base.merge(&child);
        let origins = merged.origins.expect("merged origins");
        assert_eq!(origins.profiles.len(), 2);
        assert!(origins.profiles.iter().any(|p| p.id == "existing"));
        assert!(origins.profiles.iter().any(|p| p.id == "new-profile"));
    }

    #[test]
    fn strict_verification_without_registered_verifier_fails_closed() {
        let yaml = r#"
version: "1.5.0"
name: strict-verified
settings:
  verification:
    enabled: true
    strict: true
"#;

        let err = Policy::from_yaml(yaml)
            .expect_err("strict verification should fail without a registered verifier");
        assert!(err
            .to_string()
            .contains("no load-time policy verifier is registered"));
    }

    #[test]
    fn non_strict_verification_without_registered_verifier_warns_but_loads() {
        let yaml = r#"
version: "1.5.0"
name: non-strict-verified
settings:
  verification:
    enabled: true
    strict: false
"#;

        let policy = Policy::from_yaml(yaml).expect("non-strict verification should not block");
        assert_eq!(policy.name, "non-strict-verified");
    }

    #[test]
    fn child_inherits_parent_verification_during_extends_load() {
        let parent = Policy::from_yaml_unvalidated(
            r#"
version: "1.5.0"
name: parent
settings:
  verification:
    enabled: true
    strict: true
"#,
        )
        .expect("parse parent");

        let child = Policy::from_yaml_unvalidated(
            r#"
version: "1.5.0"
name: child
extends: "parent.yaml"
settings:
  verification:
    enabled: false
    strict: false
"#,
        )
        .expect("parse child");

        let merged = parent.merge(&child);
        merged.validate().expect("merged policy should validate");
        assert_eq!(merged.name, "child");
        let verification = merged.settings.effective_verification();
        assert!(verification.enabled);
        assert!(verification.strict);
    }

    #[test]
    fn replace_merge_cannot_disable_parent_verification() {
        let parent = Policy::from_yaml_unvalidated(
            r#"
version: "1.5.0"
name: parent
settings:
  verification:
    enabled: true
    strict: true
"#,
        )
        .expect("parse parent");

        let child = Policy::from_yaml_unvalidated(
            r#"
version: "1.5.0"
name: child
merge_strategy: replace
settings:
  verification:
    enabled: false
    strict: false
"#,
        )
        .expect("parse child");

        let merged = parent.merge(&child);
        let verification = merged.settings.effective_verification();
        assert!(verification.enabled);
        assert!(verification.strict);
    }

    #[test]
    fn merge_strategy_merge_keeps_settings_shallow_except_verification_gate() {
        let parent = Policy::from_yaml_unvalidated(
            r#"
version: "1.5.0"
name: parent
settings:
  fail_fast: true
  session_timeout_secs: 42
  verification:
    enabled: true
    strict: true
"#,
        )
        .expect("parse parent");

        let child = Policy::from_yaml_unvalidated(
            r#"
version: "1.5.0"
name: child
merge_strategy: merge
settings:
  verbose_logging: true
"#,
        )
        .expect("parse child");

        let merged = parent.merge(&child);

        assert_eq!(merged.settings.fail_fast, None);
        assert_eq!(merged.settings.session_timeout_secs, None);
        assert_eq!(merged.settings.verbose_logging, Some(true));

        let verification = merged.settings.effective_verification();
        assert!(verification.enabled);
        assert!(verification.strict);
    }

    #[test]
    fn strict_verification_with_extends_defers_until_resolution() {
        let yaml = r#"
version: "1.5.0"
name: child
extends: "parent.yaml"
settings:
  verification:
    enabled: true
    strict: true
"#;

        let policy =
            Policy::from_yaml(yaml).expect("unresolved strict policies should defer verification");
        assert_eq!(policy.extends.as_deref(), Some("parent.yaml"));
    }
}
