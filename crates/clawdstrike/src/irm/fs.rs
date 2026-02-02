//! Filesystem Inline Reference Monitor
//!
//! Monitors filesystem operations and enforces path-based access control.

use async_trait::async_trait;
use tracing::debug;

use crate::policy::Policy;

use super::{Decision, EventType, HostCall, Monitor};

/// Filesystem IRM
pub struct FilesystemIrm {
    name: String,
}

impl FilesystemIrm {
    /// Create a new filesystem IRM
    pub fn new() -> Self {
        Self {
            name: "filesystem_irm".to_string(),
        }
    }

    /// Check if a path is forbidden based on policy
    fn is_forbidden(&self, path: &str, policy: &Policy) -> Option<String> {
        let normalized = self.normalize_path(path);

        // Use forbidden_path guard config if available
        if let Some(config) = &policy.guards.forbidden_path {
            for pattern in &config.patterns {
                // Simple prefix/contains check (full glob matching done by guard)
                if normalized.contains(pattern.trim_start_matches("**/").trim_end_matches("/**"))
                    || self.matches_simple_pattern(&normalized, pattern)
                {
                    return Some(pattern.clone());
                }
            }
        }

        // Default forbidden paths
        let default_forbidden = [
            "/.ssh/",
            "/id_rsa",
            "/id_ed25519",
            "/.aws/",
            "/.env",
            "/etc/shadow",
            "/etc/passwd",
            "/.gnupg/",
            "/.kube/",
        ];

        for forbidden in default_forbidden {
            if normalized.contains(forbidden) {
                return Some(forbidden.to_string());
            }
        }

        None
    }

    /// Check if write is allowed based on policy roots
    fn is_write_allowed(&self, path: &str, _policy: &Policy) -> bool {
        let normalized = self.normalize_path(path);

        // If policy has explicit allowed write roots, check them
        // For now, allow writes to common safe locations
        let safe_prefixes = ["/tmp/", "/workspace/", "/app/", "/home/"];

        for prefix in safe_prefixes {
            if normalized.starts_with(prefix) {
                return true;
            }
        }

        // Check if path is in current working directory (implied safe)
        if !normalized.starts_with('/') {
            return true;
        }

        // Default: deny writes to system paths
        let system_paths = ["/etc/", "/usr/", "/bin/", "/sbin/", "/lib/", "/var/"];
        for sys in system_paths {
            if normalized.starts_with(sys) {
                return false;
            }
        }

        true
    }

    /// Normalize a path for comparison
    fn normalize_path(&self, path: &str) -> String {
        // Expand tilde (simplified - in real code we'd use proper home dir)
        let expanded = if path.starts_with("~/") {
            format!("/home/user{}", &path[1..])
        } else {
            path.to_string()
        };

        // Remove trailing slashes
        let trimmed = expanded.trim_end_matches('/');

        // Resolve .. and . (simple implementation)
        let mut parts: Vec<&str> = Vec::new();
        for part in trimmed.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                other => {
                    parts.push(other);
                }
            }
        }

        if trimmed.starts_with('/') {
            format!("/{}", parts.join("/"))
        } else {
            parts.join("/")
        }
    }

    /// Simple pattern matching (for **/ and /** patterns)
    fn matches_simple_pattern(&self, path: &str, pattern: &str) -> bool {
        let pattern = pattern.replace("**", "");
        let pattern = pattern.trim_matches('/');

        if pattern.is_empty() {
            return false;
        }

        path.contains(pattern)
    }

    /// Extract path from host call arguments
    fn extract_path(&self, call: &HostCall) -> Option<String> {
        for arg in &call.args {
            if let Some(s) = arg.as_str() {
                if s.starts_with('/') || s.starts_with("~/") || s.starts_with("./") {
                    return Some(s.to_string());
                }
            }
        }

        // Check for named path argument
        if let Some(first) = call.args.first() {
            if let Some(obj) = first.as_object() {
                if let Some(path) = obj.get("path") {
                    return path.as_str().map(|s| s.to_string());
                }
            }
        }

        None
    }
}

impl Default for FilesystemIrm {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Monitor for FilesystemIrm {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, event_type: EventType) -> bool {
        matches!(
            event_type,
            EventType::FsRead | EventType::FsWrite | EventType::ArtifactEmit
        )
    }

    async fn evaluate(&self, call: &HostCall, policy: &Policy) -> Decision {
        let path = match self.extract_path(call) {
            Some(p) => p,
            None => {
                debug!("FilesystemIrm: no path found in call {:?}", call.function);
                return Decision::Allow;
            }
        };

        debug!("FilesystemIrm checking path: {}", path);

        // Check forbidden paths
        if let Some(pattern) = self.is_forbidden(&path, policy) {
            return Decision::Deny {
                reason: format!("Path {} matches forbidden pattern: {}", path, pattern),
            };
        }

        // For write operations, check if path is in allowed roots
        let is_write = call.function.contains("write")
            || call.function.contains("create")
            || call.function.contains("unlink")
            || call.function.contains("mkdir")
            || call.function.contains("rename");

        if is_write && !self.is_write_allowed(&path, policy) {
            return Decision::Deny {
                reason: format!("Write to {} not in allowed roots", path),
            };
        }

        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path() {
        let irm = FilesystemIrm::new();

        assert_eq!(irm.normalize_path("/foo/bar"), "/foo/bar");
        assert_eq!(irm.normalize_path("/foo/bar/"), "/foo/bar");
        assert_eq!(irm.normalize_path("/foo/../bar"), "/bar");
        assert_eq!(irm.normalize_path("/foo/./bar"), "/foo/bar");
        assert_eq!(irm.normalize_path("~/test"), "/home/user/test");
    }

    #[test]
    fn test_is_forbidden_default() {
        let irm = FilesystemIrm::new();
        let policy = Policy::default();

        assert!(irm
            .is_forbidden("/home/user/.ssh/id_rsa", &policy)
            .is_some());
        assert!(irm.is_forbidden("/etc/shadow", &policy).is_some());
        assert!(irm
            .is_forbidden("/home/user/.aws/credentials", &policy)
            .is_some());
        assert!(irm.is_forbidden("/app/src/main.rs", &policy).is_none());
    }

    #[test]
    fn test_is_write_allowed() {
        let irm = FilesystemIrm::new();
        let policy = Policy::default();

        assert!(irm.is_write_allowed("/tmp/test.txt", &policy));
        assert!(irm.is_write_allowed("/workspace/output.txt", &policy));
        assert!(!irm.is_write_allowed("/etc/passwd", &policy));
        assert!(!irm.is_write_allowed("/usr/bin/test", &policy));
    }

    #[tokio::test]
    async fn test_forbidden_path_denied() {
        let irm = FilesystemIrm::new();
        let policy = Policy::default();

        let call = HostCall::new("fd_read", vec![serde_json::json!("/etc/shadow")]);
        let decision = irm.evaluate(&call, &policy).await;

        assert!(!decision.is_allowed());
    }

    #[tokio::test]
    async fn test_allowed_read() {
        let irm = FilesystemIrm::new();
        let policy = Policy::default();

        let call = HostCall::new("fd_read", vec![serde_json::json!("/workspace/foo.txt")]);
        let decision = irm.evaluate(&call, &policy).await;

        assert!(decision.is_allowed());
    }

    #[tokio::test]
    async fn test_write_outside_allowed_roots() {
        let irm = FilesystemIrm::new();
        let policy = Policy::default();

        let call = HostCall::new("fd_write", vec![serde_json::json!("/etc/test.conf")]);
        let decision = irm.evaluate(&call, &policy).await;

        assert!(!decision.is_allowed());
    }

    #[tokio::test]
    async fn test_write_in_allowed_roots() {
        let irm = FilesystemIrm::new();
        let policy = Policy::default();

        let call = HostCall::new("fd_write", vec![serde_json::json!("/workspace/output.txt")]);
        let decision = irm.evaluate(&call, &policy).await;

        assert!(decision.is_allowed());
    }

    #[test]
    fn test_extract_path() {
        let irm = FilesystemIrm::new();

        let call = HostCall::new("fd_read", vec![serde_json::json!("/etc/passwd")]);
        assert_eq!(irm.extract_path(&call), Some("/etc/passwd".to_string()));

        let call = HostCall::new("fd_read", vec![serde_json::json!({"path": "/app/main.rs"})]);
        assert_eq!(irm.extract_path(&call), Some("/app/main.rs".to_string()));

        let call = HostCall::new("fd_read", vec![serde_json::json!(123)]);
        assert_eq!(irm.extract_path(&call), None);
    }

    #[test]
    fn test_handles_event_types() {
        let irm = FilesystemIrm::new();

        assert!(irm.handles(EventType::FsRead));
        assert!(irm.handles(EventType::FsWrite));
        assert!(irm.handles(EventType::ArtifactEmit));
        assert!(!irm.handles(EventType::NetConnect));
        assert!(!irm.handles(EventType::CommandExec));
    }
}
