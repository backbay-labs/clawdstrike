//! Forbidden path guard - blocks access to sensitive paths

use async_trait::async_trait;
use glob::Pattern;
use serde::{Deserialize, Serialize};

use super::path_normalization::{
    normalize_path_for_policy, normalize_path_for_policy_lexical_absolute,
    normalize_path_for_policy_with_fs,
};
use super::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Configuration for ForbiddenPathGuard
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenPathConfig {
    /// Enable/disable this guard.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Glob patterns for forbidden paths
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patterns: Option<Vec<String>>,
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

impl Default for ForbiddenPathConfig {
    fn default() -> Self {
        Self::with_defaults()
    }
}

fn default_enabled() -> bool {
    true
}

fn default_forbidden_patterns() -> Vec<String> {
    let mut patterns = vec![
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
        // System paths (Unix)
        "/etc/shadow".to_string(),
        "/etc/passwd".to_string(),
        "/etc/sudoers".to_string(),
    ];

    // Windows paths are always included for consistency with YAML rulesets
    // (default.yaml, strict.yaml, etc.) which list them unconditionally.
    // On non-Windows these globs simply never match, so no false-positive risk.
    patterns.extend([
        // Windows credential stores
        "**/AppData/Roaming/Microsoft/Credentials/**".to_string(),
        "**/AppData/Local/Microsoft/Credentials/**".to_string(),
        // Windows Credential Manager vault
        "**/AppData/Roaming/Microsoft/Vault/**".to_string(),
        // Windows registry hives
        "**/NTUSER.DAT".to_string(),
        "**/NTUSER.DAT.*".to_string(),
        // Windows SAM / SECURITY / SYSTEM hives
        "**/Windows/System32/config/SAM".to_string(),
        "**/Windows/System32/config/SECURITY".to_string(),
        "**/Windows/System32/config/SYSTEM".to_string(),
        // Registry export files
        "**/*.reg".to_string(),
        // Windows certificate stores
        "**/AppData/Roaming/Microsoft/SystemCertificates/**".to_string(),
        // PowerShell profiles (can contain secrets)
        "**/WindowsPowerShell/profile.ps1".to_string(),
        "**/PowerShell/profile.ps1".to_string(),
    ]);

    patterns
}

impl ForbiddenPathConfig {
    /// Create config with default forbidden patterns
    pub fn with_defaults() -> Self {
        Self {
            enabled: true,
            patterns: None,
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        }
    }

    pub fn effective_patterns(&self) -> Vec<String> {
        let mut patterns = self
            .patterns
            .clone()
            .unwrap_or_else(default_forbidden_patterns);

        for p in &self.additional_patterns {
            if !patterns.contains(p) {
                patterns.push(p.clone());
            }
        }
        patterns.retain(|p| !self.remove_patterns.contains(p));

        patterns
    }

    /// Merge this config with a child config
    ///
    /// - Start with base patterns
    /// - Add child's additional_patterns
    /// - Remove child's remove_patterns
    pub fn merge_with(&self, child: &Self) -> Self {
        let default_patterns = default_forbidden_patterns();
        let mut patterns: Vec<String> = match &child.patterns {
            Some(v) => v.clone(),
            None => self.effective_patterns(),
        };

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

        let patterns = if child.patterns.is_some()
            || self.patterns.is_some()
            || patterns != default_patterns
        {
            Some(patterns)
        } else {
            None
        };

        Self {
            enabled: child.enabled,
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
    enabled: bool,
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
        let enabled = config.enabled;
        let patterns = config
            .effective_patterns()
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
            enabled,
            patterns,
            exceptions,
        }
    }

    /// Check if a path is forbidden
    pub fn is_forbidden(&self, path: &str) -> bool {
        let lexical_path = normalize_path_for_policy(path);
        let resolved_path = normalize_path_for_policy_with_fs(path);
        let lexical_abs_path = normalize_path_for_policy_lexical_absolute(path);
        let resolved_differs_from_lexical_target = lexical_abs_path
            .as_deref()
            .map(|abs| abs != resolved_path.as_str())
            .unwrap_or(resolved_path != lexical_path);

        // Check exceptions first
        for exception in &self.exceptions {
            let lexical_matches = exception.matches(&lexical_path)
                || lexical_abs_path
                    .as_deref()
                    .map(|abs| exception.matches(abs))
                    .unwrap_or(false);
            let resolved_matches = exception.matches(&resolved_path);
            let exception_matches = if resolved_differs_from_lexical_target {
                // If resolution changed the actual target (for example via symlink traversal),
                // require the exception to match the resolved target to prevent lexical bypasses.
                resolved_matches
            } else {
                // If target identity is unchanged (for example relative -> absolute conversion),
                // allow either lexical or resolved exception forms.
                resolved_matches || lexical_matches
            };

            if exception_matches {
                return false;
            }
        }

        // Check forbidden patterns
        for pattern in &self.patterns {
            if pattern.matches(&resolved_path) || pattern.matches(&lexical_path) {
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
        if !self.enabled {
            return false;
        }

        matches!(
            action,
            GuardAction::FileAccess(_) | GuardAction::FileWrite(_, _) | GuardAction::Patch(_, _)
        )
    }

    async fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        if !self.enabled {
            return GuardResult::allow(&self.name);
        }

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
    #![allow(clippy::expect_used, clippy::unwrap_used)]

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
            patterns: Some(vec!["**/.env".to_string()]),
            exceptions: vec!["**/project/.env".to_string()],
            ..Default::default()
        };
        let guard = ForbiddenPathGuard::with_config(config);

        assert!(guard.is_forbidden("/app/.env"));
        assert!(!guard.is_forbidden("/app/project/.env"));
    }

    #[test]
    fn relative_exception_matches_when_target_is_unchanged() {
        let rel_dir = format!("target/forbidden-path-rel-{}", uuid::Uuid::new_v4());
        std::fs::create_dir_all(&rel_dir).expect("create rel dir");
        let rel_file = format!("{rel_dir}/.env");
        std::fs::write(&rel_file, "API_KEY=test\n").expect("write file");

        let guard = ForbiddenPathGuard::with_config(ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec!["**/.env".to_string()]),
            exceptions: vec![rel_file.clone()],
            additional_patterns: vec![],
            remove_patterns: vec![],
        });

        assert!(
            !guard.is_forbidden(&rel_file),
            "relative exception should match even when fs normalization produces absolute path"
        );

        let _ = std::fs::remove_dir_all(&rel_dir);
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
            enabled: true,
            patterns: Some(vec!["**/.ssh/**".to_string(), "**/.env".to_string()]),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        };

        let child = ForbiddenPathConfig {
            enabled: true,
            patterns: None,
            exceptions: vec![],
            additional_patterns: vec!["**/secrets/**".to_string()],
            remove_patterns: vec!["**/.env".to_string()],
        };

        let merged = base.merge_with(&child);

        let patterns = merged.effective_patterns();
        assert!(patterns.contains(&"**/.ssh/**".to_string()));
        assert!(patterns.contains(&"**/secrets/**".to_string()));
        assert!(!patterns.contains(&"**/.env".to_string()));
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

    #[cfg(unix)]
    #[test]
    fn symlink_target_matching_forbidden_pattern_is_forbidden() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("forbidden-path-{}", uuid::Uuid::new_v4()));
        let safe_dir = root.join("safe");
        let forbidden_dir = root.join("forbidden");
        std::fs::create_dir_all(&safe_dir).expect("create safe dir");
        std::fs::create_dir_all(&forbidden_dir).expect("create forbidden dir");

        let target = forbidden_dir.join("secret.txt");
        std::fs::write(&target, "secret").expect("write target");
        let link = safe_dir.join("link.txt");
        symlink(&target, &link).expect("create symlink");

        let guard = ForbiddenPathGuard::with_config(ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec!["**/forbidden/**".to_string()]),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        });

        assert!(
            guard.is_forbidden(link.to_str().expect("utf-8 path")),
            "symlink target that resolves into forbidden path must be blocked"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn test_windows_paths_with_backslash_normalization() {
        // Verify that paths with backslashes are normalized and matched.
        // The **/.ssh/** pattern should match Windows-style paths.
        let guard = ForbiddenPathGuard::new();
        assert!(guard.is_forbidden(r"C:\Users\alice\.ssh\id_rsa"));
        assert!(guard.is_forbidden(r"C:\Users\bob\.aws\credentials"));
        assert!(guard.is_forbidden(r"D:\projects\.env"));
        assert!(!guard.is_forbidden(r"C:\Users\alice\Documents\report.docx"));
    }

    #[test]
    fn test_windows_specific_forbidden_patterns() {
        // Test Windows-specific patterns by explicitly configuring them (so
        // these tests pass on any platform).
        let config = ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec![
                "**/AppData/Roaming/Microsoft/Credentials/**".to_string(),
                "**/AppData/Roaming/Microsoft/Vault/**".to_string(),
                "**/NTUSER.DAT".to_string(),
                "**/Windows/System32/config/SAM".to_string(),
                "**/Windows/System32/config/SECURITY".to_string(),
                "**/*.reg".to_string(),
            ]),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        };
        let guard = ForbiddenPathGuard::with_config(config);

        // Windows credential store
        assert!(
            guard.is_forbidden(r"C:\Users\alice\AppData\Roaming\Microsoft\Credentials\token123")
        );
        // Windows vault
        assert!(guard.is_forbidden(r"C:\Users\bob\AppData\Roaming\Microsoft\Vault\schema.ini"));
        // Registry hive
        assert!(guard.is_forbidden(r"C:\Users\alice\NTUSER.DAT"));
        // SAM file
        assert!(guard.is_forbidden(r"C:\Windows\System32\config\SAM"));
        // SECURITY hive
        assert!(guard.is_forbidden(r"C:\Windows\System32\config\SECURITY"));
        // Registry export
        assert!(guard.is_forbidden(r"C:\temp\export.reg"));
        // Normal file should be allowed
        assert!(!guard.is_forbidden(r"C:\Users\alice\Documents\readme.txt"));
    }

    #[cfg(unix)]
    #[test]
    fn lexical_exception_does_not_bypass_forbidden_resolved_target() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("forbidden-path-{}", uuid::Uuid::new_v4()));
        let safe_dir = root.join("safe");
        let forbidden_dir = root.join("forbidden");
        std::fs::create_dir_all(&safe_dir).expect("create safe dir");
        std::fs::create_dir_all(&forbidden_dir).expect("create forbidden dir");

        let target = forbidden_dir.join("secret.env");
        std::fs::write(&target, "secret").expect("write target");
        let link = safe_dir.join("project.env");
        symlink(&target, &link).expect("create symlink");

        let guard = ForbiddenPathGuard::with_config(ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec!["**/forbidden/**".to_string()]),
            exceptions: vec!["**/safe/project.env".to_string()],
            additional_patterns: vec![],
            remove_patterns: vec![],
        });

        assert!(
            guard.is_forbidden(link.to_str().expect("utf-8 path")),
            "lexical-only exception should not bypass when resolved target is forbidden"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
