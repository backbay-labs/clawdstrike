//! Egress allowlist guard - controls network egress

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use hush_proxy::policy::{DomainPolicy, PolicyAction};

use super::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Configuration for EgressAllowlistGuard
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressAllowlistConfig {
    /// Enable/disable this guard.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
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

impl Default for EgressAllowlistConfig {
    fn default() -> Self {
        Self::with_defaults()
    }
}

fn default_enabled() -> bool {
    true
}

impl EgressAllowlistConfig {
    /// Create default config with common allowed domains
    pub fn with_defaults() -> Self {
        Self {
            enabled: true,
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
            enabled: child.enabled,
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

    /// Compute the effective intersection of two egress configs.
    ///
    /// The result is the most restrictive combination:
    /// - if both sides define allowlists, only the intersection survives
    /// - blocklists are unioned
    /// - the stricter default action wins (`block` > `log` > `allow`)
    /// - a disabled side contributes no additional restriction
    pub fn intersect_with(&self, other: &Self) -> Self {
        match (self.enabled, other.enabled) {
            (false, false) => {
                return Self {
                    enabled: false,
                    ..Self::default()
                };
            }
            (false, true) => return other.clone(),
            (true, false) => return self.clone(),
            (true, true) => {}
        }

        let allow = match (self.allow.is_empty(), other.allow.is_empty()) {
            (false, false) => self
                .allow
                .iter()
                .filter(|pattern| other.allow.contains(*pattern))
                .cloned()
                .collect(),
            (false, true) => self.allow.clone(),
            (true, false) => other.allow.clone(),
            (true, true) => Vec::new(),
        };

        let mut block = self.block.clone();
        for pattern in &other.block {
            if !block.contains(pattern) {
                block.push(pattern.clone());
            }
        }

        Self {
            enabled: true,
            allow,
            block,
            default_action: Some(stricter_action(
                self.default_action.as_ref(),
                other.default_action.as_ref(),
            )),
            additional_allow: Vec::new(),
            remove_allow: Vec::new(),
            additional_block: Vec::new(),
            remove_block: Vec::new(),
        }
    }
}

fn stricter_action(a: Option<&PolicyAction>, b: Option<&PolicyAction>) -> PolicyAction {
    match (
        a.cloned().unwrap_or_default(),
        b.cloned().unwrap_or_default(),
    ) {
        (PolicyAction::Block, _) | (_, PolicyAction::Block) => PolicyAction::Block,
        (PolicyAction::Log, _) | (_, PolicyAction::Log) => PolicyAction::Log,
        _ => PolicyAction::Allow,
    }
}

fn domain_policy_from_config(config: &EgressAllowlistConfig) -> DomainPolicy {
    let mut policy = DomainPolicy::new();
    policy.set_default_action(config.default_action.clone().unwrap_or_default());
    policy.extend_allow(config.allow.clone());
    policy.extend_block(config.block.clone());
    policy
}

#[cfg(feature = "full")]
fn effective_egress_config(
    base: &EgressAllowlistConfig,
    context: &GuardContext,
) -> EgressAllowlistConfig {
    context
        .enclave
        .as_ref()
        .and_then(|enclave| enclave.egress.as_ref())
        .map(|enclave_config| base.intersect_with(enclave_config))
        .unwrap_or_else(|| base.clone())
}

#[cfg(not(feature = "full"))]
fn effective_egress_config(
    base: &EgressAllowlistConfig,
    _context: &GuardContext,
) -> EgressAllowlistConfig {
    base.clone()
}

/// Guard that controls network egress via domain allowlist
pub struct EgressAllowlistGuard {
    name: String,
    config: EgressAllowlistConfig,
    policy: DomainPolicy,
}

impl EgressAllowlistGuard {
    /// Create with default configuration
    pub fn new() -> Self {
        Self::with_config(EgressAllowlistConfig::with_defaults())
    }

    /// Create with custom configuration
    pub fn with_config(config: EgressAllowlistConfig) -> Self {
        let policy = domain_policy_from_config(&config);

        Self {
            name: "egress_allowlist".to_string(),
            config,
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

    async fn check(&self, action: &GuardAction<'_>, context: &GuardContext) -> GuardResult {
        let effective_config = effective_egress_config(&self.config, context);

        if !effective_config.enabled {
            return GuardResult::allow(&self.name);
        }

        let (host, port) = match action {
            GuardAction::NetworkEgress(h, p) => (*h, *p),
            _ => return GuardResult::allow(&self.name),
        };

        let policy = if effective_config == self.config {
            &self.policy
        } else {
            // Only build a transient policy when an enclave narrows the surface.
            let transient = domain_policy_from_config(&effective_config);
            return evaluate_domain_policy(&self.name, &transient, host, port);
        };

        evaluate_domain_policy(&self.name, policy, host, port)
    }
}

fn evaluate_domain_policy(name: &str, policy: &DomainPolicy, host: &str, port: u16) -> GuardResult {
    let result = policy.evaluate_detailed(host);

    match result.action {
        PolicyAction::Allow => GuardResult::allow(name),
        PolicyAction::Block => GuardResult::block(
            name,
            Severity::Error,
            format!("Egress to {} blocked by policy", host),
        )
        .with_details(serde_json::json!({
            "host": host,
            "port": port,
            "matched_pattern": result.matched_pattern,
            "is_default": result.is_default,
        })),
        PolicyAction::Log => GuardResult::warn(name, format!("Egress to {} logged", host))
            .with_details(serde_json::json!({
                "host": host,
                "port": port,
            })),
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
