//! Forbidden path guard - blocks access to sensitive paths

use async_trait::async_trait;
use glob::Pattern;
use serde::{Deserialize, Serialize};

use super::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Configuration for ForbiddenPathGuard
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ForbiddenPathConfig {
    /// Glob patterns for forbidden paths
    #[serde(default = "default_forbidden_patterns")]
    pub patterns: Vec<String>,
    /// Additional allowed paths (exceptions)
    #[serde(default)]
    pub exceptions: Vec<String>,
    /// Additional patterns to add when merging (for extends)
    #[serde(default)]
    pub additional_patterns: Vec<String>,
    /// Patterns to remove when merging (for extends)
    #[serde(default)]
    pub remove_patterns: Vec<String>,
}

fn default_forbidden_patterns() -> Vec<String> {
    vec![
        // SSH keys
        "**/.ssh/**".to_string(),
        "**/id_rsa*".to_string(),
        "**/id_ed25519*".to_string(),
        "**/id_ecdsa*".to_string(),
        // AWS credentials
        "**/.aws/**".to_string(),
        // Environment files
        "**/.env".to_string(),
        "**/.env.*".to_string(),
        // Git credentials
        "**/.git-credentials".to_string(),
        "**/.gitconfig".to_string(),
        // GPG keys
        "**/.gnupg/**".to_string(),
        // Kubernetes
        "**/.kube/**".to_string(),
        // Docker
        "**/.docker/**".to_string(),
        // NPM tokens
        "**/.npmrc".to_string(),
        // Password stores
        "**/.password-store/**".to_string(),
        "**/pass/**".to_string(),
        // 1Password
        "**/.1password/**".to_string(),
        // System paths
        "/etc/shadow".to_string(),
        "/etc/passwd".to_string(),
        "/etc/sudoers".to_string(),
    ]
}

impl ForbiddenPathConfig {
    /// Create config with default forbidden patterns
    pub fn with_defaults() -> Self {
        Self {
            patterns: default_forbidden_patterns(),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        }
    }

    /// Merge this config with a child config
    ///
    /// - Start with base patterns
    /// - Add child's additional_patterns
    /// - Remove child's remove_patterns
    pub fn merge_with(&self, child: &Self) -> Self {
        let mut patterns: Vec<String> = self.patterns.clone();

        // Add additional patterns
        for p in &child.additional_patterns {
            if !patterns.contains(p) {
                patterns.push(p.clone());
            }
        }

        // Remove specified patterns
        patterns.retain(|p| !child.remove_patterns.contains(p));

        // Merge exceptions
        let mut exceptions = self.exceptions.clone();
        for e in &child.exceptions {
            if !exceptions.contains(e) {
                exceptions.push(e.clone());
            }
        }

        Self {
            patterns,
            exceptions,
            additional_patterns: vec![],
            remove_patterns: vec![],
        }
    }
}

/// Guard that blocks access to sensitive paths
pub struct ForbiddenPathGuard {
    name: String,
    patterns: Vec<Pattern>,
    exceptions: Vec<Pattern>,
}

impl ForbiddenPathGuard {
    /// Create with default configuration
    pub fn new() -> Self {
        Self::with_config(ForbiddenPathConfig::with_defaults())
    }

    /// Create with custom configuration
    pub fn with_config(config: ForbiddenPathConfig) -> Self {
        let patterns = config
            .patterns
            .iter()
            .filter_map(|p| Pattern::new(p).ok())
            .collect();

        let exceptions = config
            .exceptions
            .iter()
            .filter_map(|p| Pattern::new(p).ok())
            .collect();

        Self {
            name: "forbidden_path".to_string(),
            patterns,
            exceptions,
        }
    }

    /// Check if a path is forbidden
    pub fn is_forbidden(&self, path: &str) -> bool {
        // Normalize path
        let path = path.replace('\\', "/");

        // Check exceptions first
        for exception in &self.exceptions {
            if exception.matches(&path) {
                return false;
            }
        }

        // Check forbidden patterns
        for pattern in &self.patterns {
            if pattern.matches(&path) {
                return true;
            }
        }

        false
    }
}

impl Default for ForbiddenPathGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Guard for ForbiddenPathGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(
            action,
            GuardAction::FileAccess(_) | GuardAction::FileWrite(_, _) | GuardAction::Patch(_, _)
        )
    }

    async fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        let path = match action {
            GuardAction::FileAccess(p) => *p,
            GuardAction::FileWrite(p, _) => *p,
            GuardAction::Patch(p, _) => *p,
            _ => return GuardResult::allow(&self.name),
        };

        if self.is_forbidden(path) {
            GuardResult::block(
                &self.name,
                Severity::Critical,
                format!("Access to forbidden path: {}", path),
            )
            .with_details(serde_json::json!({
                "path": path,
                "reason": "matches_forbidden_pattern"
            }))
        } else {
            GuardResult::allow(&self.name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_forbidden_paths() {
        let guard = ForbiddenPathGuard::new();

        // SSH keys
        assert!(guard.is_forbidden("/home/user/.ssh/id_rsa"));
        assert!(guard.is_forbidden("/home/user/.ssh/authorized_keys"));

        // AWS credentials
        assert!(guard.is_forbidden("/home/user/.aws/credentials"));

        // Environment files
        assert!(guard.is_forbidden("/app/.env"));
        assert!(guard.is_forbidden("/app/.env.local"));

        // Normal files should be allowed
        assert!(!guard.is_forbidden("/app/src/main.rs"));
        assert!(!guard.is_forbidden("/home/user/project/README.md"));
    }

    #[test]
    fn test_exceptions() {
        let config = ForbiddenPathConfig {
            patterns: vec!["**/.env".to_string()],
            exceptions: vec!["**/project/.env".to_string()],
            ..Default::default()
        };
        let guard = ForbiddenPathGuard::with_config(config);

        assert!(guard.is_forbidden("/app/.env"));
        assert!(!guard.is_forbidden("/app/project/.env"));
    }

    #[test]
    fn test_additional_patterns_field() {
        let yaml = r#"
patterns:
  - "**/.ssh/**"
additional_patterns:
  - "**/custom/**"
remove_patterns:
  - "**/.ssh/**"
"#;
        let config: ForbiddenPathConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.additional_patterns, vec!["**/custom/**"]);
        assert_eq!(config.remove_patterns, vec!["**/.ssh/**"]);
    }

    #[test]
    fn test_merge_patterns() {
        let base = ForbiddenPathConfig {
            patterns: vec!["**/.ssh/**".to_string(), "**/.env".to_string()],
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        };

        let child = ForbiddenPathConfig {
            patterns: vec![],
            exceptions: vec![],
            additional_patterns: vec!["**/secrets/**".to_string()],
            remove_patterns: vec!["**/.env".to_string()],
        };

        let merged = base.merge_with(&child);

        assert!(merged.patterns.contains(&"**/.ssh/**".to_string()));
        assert!(merged.patterns.contains(&"**/secrets/**".to_string()));
        assert!(!merged.patterns.contains(&"**/.env".to_string()));
    }

    #[tokio::test]
    async fn test_guard_check() {
        let guard = ForbiddenPathGuard::new();
        let context = GuardContext::new();

        let result = guard
            .check(&GuardAction::FileAccess("/home/user/.ssh/id_rsa"), &context)
            .await;
        assert!(!result.allowed);
        assert_eq!(result.severity, Severity::Critical);

        let result = guard
            .check(&GuardAction::FileAccess("/app/src/main.rs"), &context)
            .await;
        assert!(result.allowed);
    }
}
