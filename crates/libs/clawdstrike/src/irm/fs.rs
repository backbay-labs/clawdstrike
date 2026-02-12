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
            for pattern in config.effective_patterns() {
                // Simple prefix/contains check (full glob matching done by guard)
                if normalized.contains(pattern.trim_start_matches("**/").trim_end_matches("/**"))
                    || self.matches_simple_pattern(&normalized, &pattern)
                {
                    return Some(pattern);
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

        // Resolve "." but preserve ".." so security checks do not silently change path meaning.
        let mut parts: Vec<&str> = Vec::new();
        for part in trimmed.split('/') {
            match part {
                "" | "." => {}
                ".." => parts.push(".."),
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
        let allow_bare_string_paths = call.function.contains("path");

        for arg in &call.args {
            if let Some(obj) = arg.as_object() {
                for key in ["path", "file_path", "target_path"] {
                    if let Some(path) = obj.get(key).and_then(|value| value.as_str()) {
                        let trimmed = path.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        if self.looks_like_path(trimmed)
                            || self.has_parent_traversal(trimmed)
                            || self.looks_like_bare_filename(trimmed)
                        {
                            return Some(trimmed.to_string());
                        }
                    }
                }
            }
        }

        for arg in &call.args {
            if let Some(s) = arg.as_str() {
                let trimmed = s.trim();
                if self.looks_like_path(trimmed)
                    || (allow_bare_string_paths && self.looks_like_bare_filename(trimmed))
                {
                    return Some(trimmed.to_string());
                }
            }
        }

        None
    }

    fn looks_like_path(&self, value: &str) -> bool {
        if value.is_empty() {
            return false;
        }

        if value.starts_with('/') || value.starts_with("~/") || value.starts_with("./") {
            return true;
        }

        if value == ".." || value.starts_with("../") {
            return true;
        }

        if value.contains('\\') {
            return true;
        }

        value.contains('/') && !value.contains("://") && !self.looks_like_mime_type(value)
    }

    fn looks_like_mime_type(&self, value: &str) -> bool {
        let mut parts = value.split('/');
        let Some(kind) = parts.next() else {
            return false;
        };
        let Some(subtype) = parts.next() else {
            return false;
        };
        if parts.next().is_some() {
            return false;
        }
        if kind.is_empty() || subtype.is_empty() {
            return false;
        }
        // Preserve common relative file paths such as "image/logo.png".
        if subtype.contains('.') {
            return false;
        }

        matches!(
            kind.to_ascii_lowercase().as_str(),
            "application"
                | "audio"
                | "font"
                | "image"
                | "message"
                | "model"
                | "multipart"
                | "text"
                | "video"
        )
    }

    fn looks_like_bare_filename(&self, value: &str) -> bool {
        let value = value.trim();
        if value.is_empty() {
            return false;
        }

        if value.contains("://") {
            return false;
        }

        if value == "." || value == ".." {
            return false;
        }

        if value.contains('/') || value.contains('\\') {
            return false;
        }

        if value.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }

        !value.chars().any(|ch| ch.is_control())
    }

    fn has_parent_traversal(&self, path: &str) -> bool {
        path.replace('\\', "/").split('/').any(|seg| seg == "..")
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
                let reason = format!(
                    "Cannot determine filesystem path for call {}",
                    call.function
                );
                debug!("FilesystemIrm: {}", reason);
                return Decision::Deny { reason };
            }
        };

        debug!("FilesystemIrm checking path: {}", path);

        if self.has_parent_traversal(&path) {
            return Decision::Deny {
                reason: format!("Path contains parent traversal segment: {}", path),
            };
        }

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
        assert_eq!(irm.normalize_path("/foo/../bar"), "/foo/../bar");
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

        let call = HostCall::new("fd_read", vec![serde_json::json!("../../etc/passwd")]);
        assert_eq!(
            irm.extract_path(&call),
            Some("../../etc/passwd".to_string())
        );

        let call = HostCall::new("path_open", vec![serde_json::json!("README.md")]);
        assert_eq!(irm.extract_path(&call), Some("README.md".to_string()));

        let call = HostCall::new("fd_read", vec![serde_json::json!("image/logo.png")]);
        assert_eq!(irm.extract_path(&call), Some("image/logo.png".to_string()));

        let call = HostCall::new(
            "fd_write",
            vec![serde_json::json!({"target_path": "config.json"})],
        );
        assert_eq!(irm.extract_path(&call), Some("config.json".to_string()));

        let call = HostCall::new(
            "fd_read",
            vec![
                serde_json::json!("text/plain"),
                serde_json::json!({"path": "../../etc/passwd"}),
            ],
        );
        assert_eq!(
            irm.extract_path(&call),
            Some("../../etc/passwd".to_string())
        );

        assert!(!irm.looks_like_path("text/plain"));
        assert!(irm.looks_like_path("image/logo.png"));
        assert!(irm.looks_like_path("src/main.rs"));

        let call = HostCall::new("fd_read", vec![serde_json::json!(123)]);
        assert_eq!(irm.extract_path(&call), None);
    }

    #[tokio::test]
    async fn filesystem_irm_allows_bare_filename_for_path_style_calls() {
        let irm = FilesystemIrm::new();
        let policy = Policy::default();
        let call = HostCall::new("path_open", vec![serde_json::json!("README.md")]);
        let decision = irm.evaluate(&call, &policy).await;

        assert!(
            decision.is_allowed(),
            "bare filename should be treated as a valid filesystem path in path-style calls"
        );
    }

    #[tokio::test]
    async fn filesystem_irm_denies_parent_traversal_relative_paths() {
        let irm = FilesystemIrm::new();
        let policy = Policy::default();

        let call = HostCall::new("fd_read", vec![serde_json::json!("../../etc/passwd")]);
        let decision = irm.evaluate(&call, &policy).await;
        assert!(
            !decision.is_allowed(),
            "string traversal path should be denied"
        );

        let call = HostCall::new(
            "fd_write",
            vec![serde_json::json!({"path": "./../..//etc/passwd"})],
        );
        let decision = irm.evaluate(&call, &policy).await;
        assert!(
            !decision.is_allowed(),
            "object traversal path should be denied"
        );

        let call = HostCall::new(
            "fd_read",
            vec![
                serde_json::json!("text/plain"),
                serde_json::json!({"path": "../../etc/passwd"}),
            ],
        );
        let decision = irm.evaluate(&call, &policy).await;
        assert!(
            !decision.is_allowed(),
            "object traversal path must not be bypassed by slash-containing non-path tokens"
        );
    }

    #[tokio::test]
    async fn filesystem_irm_prefers_object_path_over_pathlike_string_arg() {
        let irm = FilesystemIrm::new();
        let policy = Policy::default();
        let call = HostCall::new(
            "fd_read",
            vec![
                serde_json::json!("image/logo.png"),
                serde_json::json!({"path": "../../etc/passwd"}),
            ],
        );

        let decision = irm.evaluate(&call, &policy).await;
        match decision {
            Decision::Deny { reason } => {
                assert!(
                    reason.contains("parent traversal"),
                    "deny reason should use object path traversal, not a slash token: {reason}"
                );
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn filesystem_irm_denies_traversal_when_path_is_in_nonfirst_object_arg() {
        let irm = FilesystemIrm::new();
        let policy = Policy::default();
        let call = HostCall::new(
            "fd_read",
            vec![
                serde_json::json!({"fd": 3}),
                serde_json::json!({"path": "../../etc/passwd"}),
            ],
        );

        let decision = irm.evaluate(&call, &policy).await;
        match decision {
            Decision::Deny { reason } => {
                assert!(
                    reason.contains("parent traversal"),
                    "deny reason should explain traversal rejection: {reason}"
                );
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn filesystem_irm_denies_when_no_path_can_be_extracted() {
        let irm = FilesystemIrm::new();
        let policy = Policy::default();
        let call = HostCall::new("fd_read", vec![serde_json::json!({"fd": 3})]);
        let decision = irm.evaluate(&call, &policy).await;

        assert!(
            !decision.is_allowed(),
            "filesystem calls without extractable paths must fail closed"
        );
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
