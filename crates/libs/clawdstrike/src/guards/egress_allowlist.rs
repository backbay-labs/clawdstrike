//! Egress allowlist guard - controls network egress

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use hush_proxy::policy::{DomainPolicy, PolicyAction, PolicyResult};

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
            (false, false) => intersect_allow_patterns(&self.allow, &other.allow),
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

fn has_glob_metachar(pattern: &str) -> bool {
    pattern.contains('*') || pattern.contains('?') || pattern.contains('[') || pattern.contains('{')
}

fn pattern_matches_domain(pattern: &str, domain: &str) -> bool {
    let mut policy = DomainPolicy::new();
    policy.set_default_action(PolicyAction::Block);
    policy.extend_allow([pattern.to_string()]);
    policy.is_allowed(domain)
}

fn representative_domain(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '*' | '?' => out.push('x'),
            '[' => {
                out.push('x');
                for inner in chars.by_ref() {
                    if inner == ']' {
                        break;
                    }
                }
            }
            '{' => {
                let mut selected = String::new();
                let mut depth = 1usize;
                let mut collecting = true;
                for inner in chars.by_ref() {
                    match inner {
                        '{' => {
                            depth += 1;
                            collecting = false;
                        }
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        ',' if depth == 1 => collecting = false,
                        _ if collecting && depth == 1 => selected.push(inner),
                        _ => {}
                    }
                }
                if selected.is_empty() {
                    out.push('x');
                } else {
                    out.push_str(&selected);
                }
            }
            '\\' => {
                if let Some(escaped) = chars.next() {
                    out.push(escaped);
                }
            }
            _ => out.push(ch),
        }
    }

    out
}

fn pattern_specificity(pattern: &str) -> (usize, usize) {
    let wildcard_count = pattern
        .chars()
        .filter(|ch| matches!(ch, '*' | '?' | '[' | '{'))
        .count();
    let literal_count = pattern.len().saturating_sub(wildcard_count);
    (literal_count, usize::MAX - wildcard_count)
}

fn intersect_domain_patterns(left: &str, right: &str) -> Option<String> {
    if left.eq_ignore_ascii_case(right) {
        return Some(left.to_string());
    }

    let left_is_literal = !has_glob_metachar(left);
    let right_is_literal = !has_glob_metachar(right);

    if left_is_literal && pattern_matches_domain(right, left) {
        return Some(left.to_string());
    }
    if right_is_literal && pattern_matches_domain(left, right) {
        return Some(right.to_string());
    }

    let left_sample = representative_domain(left);
    let right_sample = representative_domain(right);
    let left_matches_right_sample = pattern_matches_domain(left, &right_sample);
    let right_matches_left_sample = pattern_matches_domain(right, &left_sample);

    match (left_matches_right_sample, right_matches_left_sample) {
        (true, false) => Some(right.to_string()),
        (false, true) => Some(left.to_string()),
        (true, true) => match pattern_specificity(left).cmp(&pattern_specificity(right)) {
            std::cmp::Ordering::Greater => Some(left.to_string()),
            std::cmp::Ordering::Less => Some(right.to_string()),
            std::cmp::Ordering::Equal => None,
        },
        (false, false) => None,
    }
}

fn intersect_allow_patterns(left: &[String], right: &[String]) -> Vec<String> {
    let mut out = Vec::new();

    for left_pattern in left {
        for right_pattern in right {
            let Some(intersection) = intersect_domain_patterns(left_pattern, right_pattern) else {
                continue;
            };
            if !out
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(&intersection))
            {
                out.push(intersection);
            }
        }
    }

    out
}

fn domain_policy_from_config(config: &EgressAllowlistConfig) -> DomainPolicy {
    let mut policy = DomainPolicy::new();
    policy.set_default_action(config.default_action.clone().unwrap_or_default());
    policy.extend_allow(config.allow.clone());
    policy.extend_block(config.block.clone());
    policy
}

#[cfg(feature = "full")]
fn enclave_egress_policy(context: &GuardContext) -> Option<DomainPolicy> {
    context
        .enclave
        .as_ref()
        .and_then(|enclave| enclave.egress.as_ref())
        .filter(|config| config.enabled)
        .map(domain_policy_from_config)
}

#[cfg(not(feature = "full"))]
fn enclave_egress_policy(_context: &GuardContext) -> Option<DomainPolicy> {
    None
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
        self.config.enabled && matches!(action, GuardAction::NetworkEgress(_, _))
    }

    async fn check(&self, action: &GuardAction<'_>, context: &GuardContext) -> GuardResult {
        if !self.config.enabled {
            return GuardResult::allow(&self.name);
        }

        let (host, port) = match action {
            GuardAction::NetworkEgress(h, p) => (*h, *p),
            _ => return GuardResult::allow(&self.name),
        };

        let enclave_policy = enclave_egress_policy(context);

        match enclave_policy.as_ref() {
            None => evaluate_domain_policy(&self.name, &self.policy, host, port),
            Some(enclave) => {
                evaluate_combined_domain_policies(&self.name, &self.policy, enclave, host, port)
            }
        }
    }
}

fn evaluate_domain_policy(name: &str, policy: &DomainPolicy, host: &str, port: u16) -> GuardResult {
    let result = policy.evaluate_detailed(host);
    guard_result_from_policy_result(name, host, port, &result)
}

fn evaluate_combined_domain_policies(
    name: &str,
    base: &DomainPolicy,
    enclave: &DomainPolicy,
    host: &str,
    port: u16,
) -> GuardResult {
    let base_result = base.evaluate_detailed(host);
    let enclave_result = enclave.evaluate_detailed(host);
    let combined_action = stricter_action(Some(&base_result.action), Some(&enclave_result.action));

    let combined = PolicyResult {
        domain: host.to_string(),
        action: combined_action,
        matched_pattern: base_result
            .matched_pattern
            .clone()
            .or_else(|| enclave_result.matched_pattern.clone()),
        is_default: base_result.is_default && enclave_result.is_default,
    };

    let mut result = guard_result_from_policy_result(name, host, port, &combined);
    if !matches!(combined.action, PolicyAction::Allow) {
        result.details = Some(serde_json::json!({
            "host": host,
            "port": port,
            "base": {
                "action": base_result.action.clone(),
                "matched_pattern": base_result.matched_pattern.clone(),
                "is_default": base_result.is_default,
            },
            "enclave": {
                "action": enclave_result.action.clone(),
                "matched_pattern": enclave_result.matched_pattern.clone(),
                "is_default": enclave_result.is_default,
            },
        }));
    }

    result
}

fn guard_result_from_policy_result(
    name: &str,
    host: &str,
    port: u16,
    result: &PolicyResult,
) -> GuardResult {
    let matched_pattern = result.matched_pattern.clone();

    match &result.action {
        PolicyAction::Allow => GuardResult::allow(name),
        PolicyAction::Block => GuardResult::block(
            name,
            Severity::Error,
            format!("Egress to {} blocked by policy", host),
        )
        .with_details(serde_json::json!({
            "host": host,
            "port": port,
            "matched_pattern": matched_pattern,
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

    #[test]
    fn test_intersect_with_preserves_literal_overlap() {
        let base = EgressAllowlistConfig {
            allow: vec!["*.openai.com".to_string()],
            default_action: Some(PolicyAction::Block),
            ..Default::default()
        };
        let enclave = EgressAllowlistConfig {
            allow: vec!["api.openai.com".to_string()],
            default_action: Some(PolicyAction::Block),
            ..Default::default()
        };

        let effective = base.intersect_with(&enclave);
        assert_eq!(effective.allow, vec!["api.openai.com".to_string()]);
    }

    #[test]
    fn test_intersect_with_preserves_wildcard_subset_overlap() {
        let base = EgressAllowlistConfig {
            allow: vec!["*.openai.com".to_string()],
            default_action: Some(PolicyAction::Block),
            ..Default::default()
        };
        let enclave = EgressAllowlistConfig {
            allow: vec!["api*.openai.com".to_string()],
            default_action: Some(PolicyAction::Block),
            ..Default::default()
        };

        let effective = base.intersect_with(&enclave);
        assert_eq!(effective.allow, vec!["api*.openai.com".to_string()]);
    }

    #[test]
    fn test_intersect_with_preserves_brace_subset_overlap() {
        let base = EgressAllowlistConfig {
            allow: vec!["*.openai.com".to_string()],
            default_action: Some(PolicyAction::Block),
            ..Default::default()
        };
        let enclave = EgressAllowlistConfig {
            allow: vec!["{api,chat}.openai.com".to_string()],
            default_action: Some(PolicyAction::Block),
            ..Default::default()
        };

        let effective = base.intersect_with(&enclave);
        assert_eq!(effective.allow, vec!["{api,chat}.openai.com".to_string()]);
    }

    #[tokio::test]
    async fn test_guard_check_combines_base_and_enclave_policies() {
        let guard = EgressAllowlistGuard::with_config(EgressAllowlistConfig {
            allow: vec!["*.openai.com".to_string()],
            default_action: Some(PolicyAction::Block),
            ..Default::default()
        });
        let enclave_policy = EgressAllowlistConfig {
            allow: vec!["api.openai.com".to_string()],
            default_action: Some(PolicyAction::Block),
            ..Default::default()
        };
        let context = GuardContext::new().with_enclave(crate::ResolvedEnclave {
            profile_id: Some("strict-openai".to_string()),
            mcp: None,
            posture: None,
            egress: Some(enclave_policy),
            data: None,
            budgets: None,
            bridge_policy: None,
            explanation: None,
            resolution_path: Vec::new(),
        });

        let allowed = guard
            .check(&GuardAction::NetworkEgress("api.openai.com", 443), &context)
            .await;
        assert!(allowed.allowed);

        let blocked = guard
            .check(
                &GuardAction::NetworkEgress("chat.openai.com", 443),
                &context,
            )
            .await;
        assert!(!blocked.allowed);
        assert_eq!(blocked.severity, Severity::Error);
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

    #[tokio::test]
    async fn test_disabled_guard_ignores_enclave_policy() {
        let guard = EgressAllowlistGuard::with_config(EgressAllowlistConfig {
            enabled: false,
            allow: vec!["*.openai.com".to_string()],
            default_action: Some(PolicyAction::Block),
            ..Default::default()
        });
        let context = GuardContext::new().with_enclave(crate::ResolvedEnclave {
            profile_id: Some("strict-openai".to_string()),
            mcp: None,
            posture: None,
            egress: Some(EgressAllowlistConfig {
                allow: vec!["api.openai.com".to_string()],
                default_action: Some(PolicyAction::Block),
                ..Default::default()
            }),
            data: None,
            budgets: None,
            bridge_policy: None,
            explanation: None,
            resolution_path: Vec::new(),
        });

        assert!(!guard.handles(&GuardAction::NetworkEgress("chat.openai.com", 443)));
        let result = guard
            .check(
                &GuardAction::NetworkEgress("chat.openai.com", 443),
                &context,
            )
            .await;
        assert!(result.allowed);
    }
}
