//! Egress policy enforcement
//!
//! Provides domain allowlist/blocklist policy evaluation.

use std::sync::OnceLock;

use globset::{GlobBuilder, GlobMatcher};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
struct DomainPatternError {
    pattern: String,
    error: globset::Error,
}

impl std::fmt::Display for DomainPatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid domain glob {:?}: {}", self.pattern, self.error)
    }
}

#[derive(Debug)]
struct CompiledPattern {
    original: String,
    matcher: GlobMatcher,
}

#[derive(Debug, Default)]
struct CompiledDomainPolicy {
    allow: Vec<CompiledPattern>,
    block: Vec<CompiledPattern>,
}

impl CompiledDomainPolicy {
    fn compile(policy: &DomainPolicy) -> Result<Self, DomainPatternError> {
        Ok(Self {
            allow: compile_patterns(policy.allow_patterns())?,
            block: compile_patterns(policy.block_patterns())?,
        })
    }
}

fn compile_patterns(patterns: &[String]) -> Result<Vec<CompiledPattern>, DomainPatternError> {
    let mut out = Vec::with_capacity(patterns.len());
    for p in patterns {
        let matcher = compile_pattern(p)?;
        out.push(CompiledPattern {
            original: p.clone(),
            matcher,
        });
    }
    Ok(out)
}

fn compile_pattern(pattern: &str) -> Result<GlobMatcher, DomainPatternError> {
    let glob = GlobBuilder::new(pattern)
        .case_insensitive(true)
        .literal_separator(true)
        .build()
        .map_err(|e| DomainPatternError {
            pattern: pattern.to_string(),
            error: e,
        })?;

    Ok(glob.compile_matcher())
}

/// Policy action for a domain
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    /// Allow the connection
    Allow,
    /// Block the connection
    #[serde(alias = "deny")]
    #[default]
    Block,
    /// Log but allow
    Log,
}

/// Domain policy configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct DomainPolicy {
    /// Allowed domain patterns (glob syntax)
    #[serde(default)]
    allow: Vec<String>,
    /// Blocked domain patterns
    #[serde(default)]
    block: Vec<String>,
    /// Default action when no pattern matches
    #[serde(default = "default_action")]
    default_action: PolicyAction,

    #[serde(skip)]
    compiled: OnceLock<Result<CompiledDomainPolicy, DomainPatternError>>,
}

fn default_action() -> PolicyAction {
    PolicyAction::Block
}

impl Default for DomainPolicy {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            block: Vec::new(),
            default_action: default_action(),
            compiled: OnceLock::new(),
        }
    }
}

impl Clone for DomainPolicy {
    fn clone(&self) -> Self {
        Self {
            allow: self.allow.clone(),
            block: self.block.clone(),
            default_action: self.default_action.clone(),
            compiled: OnceLock::new(),
        }
    }
}

impl DomainPolicy {
    /// Create a new policy with default deny
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a permissive policy (default allow)
    pub fn permissive() -> Self {
        Self {
            default_action: PolicyAction::Allow,
            ..Self::default()
        }
    }

    /// Add an allowed domain pattern
    pub fn allow(mut self, pattern: impl Into<String>) -> Self {
        self.allow.push(pattern.into());
        self.compiled = OnceLock::new();
        self
    }

    /// Add a blocked domain pattern
    pub fn block(mut self, pattern: impl Into<String>) -> Self {
        self.block.push(pattern.into());
        self.compiled = OnceLock::new();
        self
    }

    /// Evaluate a domain against the policy
    pub fn evaluate(&self, domain: &str) -> PolicyAction {
        let compiled = match self.compiled() {
            Ok(c) => c,
            Err(_) => return PolicyAction::Block,
        };

        // Check blocklist first (block takes precedence)
        for pattern in &compiled.block {
            if pattern.matcher.is_match(domain) {
                return PolicyAction::Block;
            }
        }

        // Check allowlist
        for pattern in &compiled.allow {
            if pattern.matcher.is_match(domain) {
                return PolicyAction::Allow;
            }
        }

        // Default action
        self.default_action.clone()
    }

    /// Check if a domain is allowed
    pub fn is_allowed(&self, domain: &str) -> bool {
        matches!(self.evaluate(domain), PolicyAction::Allow)
    }
}

/// Policy evaluation result with details
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyResult {
    /// The evaluated domain
    pub domain: String,
    /// The resulting action
    pub action: PolicyAction,
    /// The pattern that matched (if any)
    pub matched_pattern: Option<String>,
    /// Whether this was a default action
    pub is_default: bool,
}

impl DomainPolicy {
    /// Evaluate with detailed result
    pub fn evaluate_detailed(&self, domain: &str) -> PolicyResult {
        let compiled = match self.compiled() {
            Ok(c) => c,
            Err(_) => {
                return PolicyResult {
                    domain: domain.to_string(),
                    action: PolicyAction::Block,
                    matched_pattern: None,
                    is_default: true,
                };
            }
        };

        // Check blocklist first
        for pattern in &compiled.block {
            if pattern.matcher.is_match(domain) {
                return PolicyResult {
                    domain: domain.to_string(),
                    action: PolicyAction::Block,
                    matched_pattern: Some(pattern.original.clone()),
                    is_default: false,
                };
            }
        }

        // Check allowlist
        for pattern in &compiled.allow {
            if pattern.matcher.is_match(domain) {
                return PolicyResult {
                    domain: domain.to_string(),
                    action: PolicyAction::Allow,
                    matched_pattern: Some(pattern.original.clone()),
                    is_default: false,
                };
            }
        }

        // Default action
        PolicyResult {
            domain: domain.to_string(),
            action: self.default_action.clone(),
            matched_pattern: None,
            is_default: true,
        }
    }

    pub fn allow_patterns(&self) -> &[String] {
        &self.allow
    }

    pub fn block_patterns(&self) -> &[String] {
        &self.block
    }

    pub fn set_default_action(&mut self, default_action: PolicyAction) {
        self.default_action = default_action;
        self.compiled = OnceLock::new();
    }

    pub fn extend_allow<I>(&mut self, patterns: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.allow.extend(patterns);
        self.compiled = OnceLock::new();
    }

    pub fn extend_block<I>(&mut self, patterns: I)
    where
        I: IntoIterator<Item = String>,
    {
        self.block.extend(patterns);
        self.compiled = OnceLock::new();
    }

    fn compiled(&self) -> std::result::Result<&CompiledDomainPolicy, &DomainPatternError> {
        match self
            .compiled
            .get_or_init(|| CompiledDomainPolicy::compile(self))
        {
            Ok(c) => Ok(c),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_deny() {
        let policy = DomainPolicy::new();
        assert!(!policy.is_allowed("example.com"));
    }

    #[test]
    fn test_permissive() {
        let policy = DomainPolicy::permissive();
        assert!(policy.is_allowed("example.com"));
    }

    #[test]
    fn test_allowlist() {
        let policy = DomainPolicy::new()
            .allow("example.com")
            .allow("*.allowed.org");

        assert!(policy.is_allowed("example.com"));
        assert!(policy.is_allowed("sub.allowed.org"));
        assert!(!policy.is_allowed("other.com"));
    }

    #[test]
    fn test_blocklist_precedence() {
        let policy = DomainPolicy::permissive().block("bad.example.com");

        assert!(policy.is_allowed("good.example.com"));
        assert!(!policy.is_allowed("bad.example.com"));
    }

    #[test]
    fn test_wildcard_block() {
        let policy = DomainPolicy::permissive()
            .block("*.blocked.com")
            .block("blocked.com");

        assert!(policy.is_allowed("allowed.com"));
        assert!(!policy.is_allowed("sub.blocked.com"));
        assert!(!policy.is_allowed("blocked.com"));
    }

    #[test]
    fn test_evaluate_detailed() {
        let policy = DomainPolicy::new().allow("*.example.com");

        let result = policy.evaluate_detailed("sub.example.com");
        assert_eq!(result.action, PolicyAction::Allow);
        assert_eq!(result.matched_pattern, Some("*.example.com".to_string()));
        assert!(!result.is_default);

        let result = policy.evaluate_detailed("other.com");
        assert_eq!(result.action, PolicyAction::Block);
        assert!(result.matched_pattern.is_none());
        assert!(result.is_default);
    }
}
