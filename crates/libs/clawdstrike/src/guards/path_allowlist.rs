//! Filesystem path allowlist guard (deny by default when enabled).

use async_trait::async_trait;
use glob::Pattern;
use serde::{Deserialize, Serialize};

use super::path_normalization::normalize_path_for_policy;
use super::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Configuration for `PathAllowlistGuard`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathAllowlistConfig {
    /// Enable/disable this guard.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Allowed globs for `GuardAction::FileAccess`.
    #[serde(default)]
    pub file_access_allow: Vec<String>,
    /// Allowed globs for `GuardAction::FileWrite`.
    #[serde(default)]
    pub file_write_allow: Vec<String>,
    /// Allowed globs for `GuardAction::Patch` (falls back to `file_write_allow` when empty).
    #[serde(default)]
    pub patch_allow: Vec<String>,
}

fn default_enabled() -> bool {
    true
}

impl PathAllowlistConfig {
    pub fn merge_with(&self, child: &Self) -> Self {
        Self {
            enabled: child.enabled,
            file_access_allow: if child.file_access_allow.is_empty() {
                self.file_access_allow.clone()
            } else {
                child.file_access_allow.clone()
            },
            file_write_allow: if child.file_write_allow.is_empty() {
                self.file_write_allow.clone()
            } else {
                child.file_write_allow.clone()
            },
            patch_allow: if child.patch_allow.is_empty() {
                self.patch_allow.clone()
            } else {
                child.patch_allow.clone()
            },
        }
    }
}

pub struct PathAllowlistGuard {
    name: String,
    enabled: bool,
    file_access_allow: Vec<Pattern>,
    file_write_allow: Vec<Pattern>,
    patch_allow: Vec<Pattern>,
}

impl PathAllowlistGuard {
    pub fn with_config(config: PathAllowlistConfig) -> Self {
        let file_access_allow = config
            .file_access_allow
            .iter()
            .filter_map(|p| Pattern::new(p).ok())
            .collect::<Vec<_>>();
        let file_write_allow = config
            .file_write_allow
            .iter()
            .filter_map(|p| Pattern::new(p).ok())
            .collect::<Vec<_>>();
        let patch_allow = if config.patch_allow.is_empty() {
            file_write_allow.clone()
        } else {
            config
                .patch_allow
                .iter()
                .filter_map(|p| Pattern::new(p).ok())
                .collect::<Vec<_>>()
        };

        Self {
            name: "path_allowlist".to_string(),
            enabled: config.enabled,
            file_access_allow,
            file_write_allow,
            patch_allow,
        }
    }

    fn matches_any(patterns: &[Pattern], path: &str) -> bool {
        patterns.iter().any(|p| p.matches(path))
    }

    pub fn is_file_access_allowed(&self, path: &str) -> bool {
        if !self.enabled {
            return true;
        }
        let normalized = normalize_path_for_policy(path);
        Self::matches_any(&self.file_access_allow, &normalized)
    }

    pub fn is_file_write_allowed(&self, path: &str) -> bool {
        if !self.enabled {
            return true;
        }
        let normalized = normalize_path_for_policy(path);
        Self::matches_any(&self.file_write_allow, &normalized)
    }

    pub fn is_patch_allowed(&self, path: &str) -> bool {
        if !self.enabled {
            return true;
        }
        let normalized = normalize_path_for_policy(path);
        Self::matches_any(&self.patch_allow, &normalized)
    }
}

impl Default for PathAllowlistGuard {
    fn default() -> Self {
        Self::with_config(PathAllowlistConfig {
            enabled: false,
            file_access_allow: Vec::new(),
            file_write_allow: Vec::new(),
            patch_allow: Vec::new(),
        })
    }
}

#[async_trait]
impl Guard for PathAllowlistGuard {
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

        let (path, allowed) = match action {
            GuardAction::FileAccess(path) => (*path, self.is_file_access_allowed(path)),
            GuardAction::FileWrite(path, _) => (*path, self.is_file_write_allowed(path)),
            GuardAction::Patch(path, _) => (*path, self.is_patch_allowed(path)),
            _ => return GuardResult::allow(&self.name),
        };

        if allowed {
            GuardResult::allow(&self.name)
        } else {
            GuardResult::block(
                &self.name,
                Severity::Error,
                format!("Path not in allowlist: {}", path),
            )
            .with_details(serde_json::json!({
                "path": path,
                "reason": "path_not_allowlisted",
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_allows_paths_inside_scope() {
        let guard = PathAllowlistGuard::with_config(PathAllowlistConfig {
            enabled: true,
            file_access_allow: vec!["**/repo/**".to_string()],
            file_write_allow: vec!["**/repo/**".to_string()],
            patch_allow: vec![],
        });

        assert!(guard.is_file_access_allowed("/tmp/repo/src/main.rs"));
        assert!(guard.is_file_write_allowed("/tmp/repo/src/main.rs"));
        assert!(guard.is_patch_allowed("/tmp/repo/src/main.rs"));
    }

    #[test]
    fn test_denies_paths_outside_scope() {
        let guard = PathAllowlistGuard::with_config(PathAllowlistConfig {
            enabled: true,
            file_access_allow: vec!["**/repo/**".to_string()],
            file_write_allow: vec!["**/repo/**".to_string()],
            patch_allow: vec![],
        });

        assert!(!guard.is_file_access_allowed("/etc/passwd"));
        assert!(!guard.is_file_write_allowed("/etc/passwd"));
        assert!(!guard.is_patch_allowed("/etc/passwd"));
    }

    #[test]
    fn test_patch_allow_falls_back_to_file_write_allow() {
        let guard = PathAllowlistGuard::with_config(PathAllowlistConfig {
            enabled: true,
            file_access_allow: vec![],
            file_write_allow: vec!["**/repo/**".to_string()],
            patch_allow: vec![],
        });
        assert!(guard.is_patch_allowed("/tmp/repo/src/main.rs"));
        assert!(!guard.is_patch_allowed("/tmp/other/src/main.rs"));
    }
}
