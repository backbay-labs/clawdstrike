//! Egress allowlist guard - controls network egress

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use hush_proxy::policy::{DomainPolicy, PolicyAction};

use super::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Configuration for EgressAllowlistGuard
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressAllowlistConfig {
    /// Allowed domain patterns
    #[serde(default)]
    pub allow: Vec<String>,
    /// Blocked domain patterns (takes precedence)
    #[serde(default)]
    pub block: Vec<String>,
    /// Default action when no pattern matches
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_action: Option<PolicyAction>,
    /// Additional allowed domains when merging
    #[serde(default)]
    pub additional_allow: Vec<String>,
    /// Domains to remove from allow list when merging
    #[serde(default)]
    pub remove_allow: Vec<String>,
    /// Additional blocked domains when merging
    #[serde(default)]
    pub additional_block: Vec<String>,
    /// Domains to remove from block list when merging
    #[serde(default)]
    pub remove_block: Vec<String>,
}

impl EgressAllowlistConfig {
    /// Create default config with common allowed domains
    pub fn with_defaults() -> Self {
        Self {
            allow: vec![
                // Common AI/ML APIs
                "*.openai.com".to_string(),
                "*.anthropic.com".to_string(),
                "api.github.com".to_string(),
                // Package registries
                "*.npmjs.org".to_string(),
                "registry.npmjs.org".to_string(),
                "pypi.org".to_string(),
                "files.pythonhosted.org".to_string(),
                "crates.io".to_string(),
                "static.crates.io".to_string(),
            ],
            block: vec![],
            default_action: Some(PolicyAction::Block),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        }
    }

    /// Merge this config with a child config
    pub fn merge_with(&self, child: &Self) -> Self {
        let mut allow = self.allow.clone();
        let mut block = self.block.clone();

        // Add additional domains
        for d in &child.additional_allow {
            if !allow.contains(d) {
                allow.push(d.clone());
            }
        }
        for d in &child.additional_block {
            if !block.contains(d) {
                block.push(d.clone());
            }
        }

        // Remove specified domains
        allow.retain(|d| !child.remove_allow.contains(d));
        block.retain(|d| !child.remove_block.contains(d));

        // Use child's allow/block if non-empty
        if !child.allow.is_empty() {
            allow = child.allow.clone();
        }
        if !child.block.is_empty() {
            block = child.block.clone();
        }

        Self {
            allow,
            block,
            default_action: child
                .default_action
                .clone()
                .or_else(|| self.default_action.clone()),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        }
    }
}

/// Guard that controls network egress via domain allowlist
pub struct EgressAllowlistGuard {
    name: String,
    policy: DomainPolicy,
}

impl EgressAllowlistGuard {
    /// Create with default configuration
    pub fn new() -> Self {
        Self::with_config(EgressAllowlistConfig::with_defaults())
    }

    /// Create with custom configuration
    pub fn with_config(config: EgressAllowlistConfig) -> Self {
        let mut policy = DomainPolicy::new();
        policy.set_default_action(config.default_action.unwrap_or_default());
        policy.extend_allow(config.allow);
        policy.extend_block(config.block);

        Self {
            name: "egress_allowlist".to_string(),
            policy,
        }
    }

    /// Check if a domain is allowed
    pub fn is_allowed(&self, domain: &str) -> bool {
        self.policy.is_allowed(domain)
    }
}

impl Default for EgressAllowlistGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Guard for EgressAllowlistGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(action, GuardAction::NetworkEgress(_, _))
    }

    async fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        let (host, port) = match action {
            GuardAction::NetworkEgress(h, p) => (*h, *p),
            _ => return GuardResult::allow(&self.name),
        };

        let result = self.policy.evaluate_detailed(host);

        match result.action {
            PolicyAction::Allow => GuardResult::allow(&self.name),
            PolicyAction::Block => GuardResult::block(
                &self.name,
                Severity::Error,
                format!("Egress to {} blocked by policy", host),
            )
            .with_details(serde_json::json!({
                "host": host,
                "port": port,
                "matched_pattern": result.matched_pattern,
                "is_default": result.is_default,
            })),
            PolicyAction::Log => {
                GuardResult::warn(&self.name, format!("Egress to {} logged", host)).with_details(
                    serde_json::json!({
                        "host": host,
                        "port": port,
                    }),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_allowlist() {
        let guard = EgressAllowlistGuard::new();

        // Allowed by default
        assert!(guard.is_allowed("api.openai.com"));
        assert!(guard.is_allowed("api.anthropic.com"));
        assert!(guard.is_allowed("registry.npmjs.org"));

        // Not in allowlist
        assert!(!guard.is_allowed("evil.com"));
        assert!(!guard.is_allowed("random-site.org"));
    }

    #[test]
    fn test_custom_config() {
        let config = EgressAllowlistConfig {
            allow: vec!["*.mycompany.com".to_string()],
            block: vec!["blocked.mycompany.com".to_string()],
            default_action: Some(PolicyAction::Block),
            ..Default::default()
        };
        let guard = EgressAllowlistGuard::with_config(config);

        assert!(guard.is_allowed("api.mycompany.com"));
        assert!(!guard.is_allowed("blocked.mycompany.com")); // block takes precedence
        assert!(!guard.is_allowed("other.com"));
    }

    #[tokio::test]
    async fn test_guard_check() {
        let guard = EgressAllowlistGuard::new();
        let context = GuardContext::new();

        let result = guard
            .check(&GuardAction::NetworkEgress("api.openai.com", 443), &context)
            .await;
        assert!(result.allowed);

        let result = guard
            .check(&GuardAction::NetworkEgress("evil.com", 443), &context)
            .await;
        assert!(!result.allowed);
        assert_eq!(result.severity, Severity::Error);
    }
}
