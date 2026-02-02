//! Network Inline Reference Monitor
//!
//! Monitors network operations and enforces egress control.

use async_trait::async_trait;
use tracing::debug;

use hush_proxy::dns::domain_matches;
use hush_proxy::policy::PolicyAction;

use crate::policy::Policy;

use super::{Decision, EventType, HostCall, Monitor};

/// Network IRM
pub struct NetworkIrm {
    name: String,
}

impl NetworkIrm {
    /// Create a new network IRM
    pub fn new() -> Self {
        Self {
            name: "network_irm".to_string(),
        }
    }

    /// Extract host from call arguments
    fn extract_host(&self, call: &HostCall) -> Option<String> {
        for arg in &call.args {
            // Check string arguments
            if let Some(s) = arg.as_str() {
                // URL pattern
                if s.starts_with("http://") || s.starts_with("https://") {
                    return self.extract_host_from_url(s);
                }
                // Plain hostname pattern
                if s.contains('.') && !s.contains('/') {
                    return Some(s.to_string());
                }
            }

            // Check object with host field
            if let Some(obj) = arg.as_object() {
                if let Some(host) = obj.get("host").and_then(|h| h.as_str()) {
                    return Some(host.to_string());
                }
                if let Some(url) = obj.get("url").and_then(|u| u.as_str()) {
                    return self.extract_host_from_url(url);
                }
            }
        }

        None
    }

    /// Extract port from call arguments
    #[allow(dead_code)]
    fn extract_port(&self, call: &HostCall) -> Option<u16> {
        for arg in &call.args {
            // Check numeric arguments
            if let Some(n) = arg.as_u64() {
                if n > 0 && n <= 65535 {
                    return Some(n as u16);
                }
            }

            // Check object with port field
            if let Some(obj) = arg.as_object() {
                if let Some(port) = obj.get("port").and_then(|p| p.as_u64()) {
                    if port > 0 && port <= 65535 {
                        return Some(port as u16);
                    }
                }
            }
        }

        // Default ports for known schemes
        for arg in &call.args {
            if let Some(s) = arg.as_str() {
                if s.starts_with("https://") {
                    return Some(443);
                }
                if s.starts_with("http://") {
                    return Some(80);
                }
            }
        }

        None
    }

    /// Extract host from URL
    fn extract_host_from_url(&self, url: &str) -> Option<String> {
        let without_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);

        let host_part = without_scheme.split('/').next()?;
        let host = host_part.split(':').next()?;

        Some(host.to_string())
    }

    /// Check if a host matches a pattern
    fn matches_pattern(&self, host: &str, pattern: &str) -> bool {
        domain_matches(host, pattern)
    }

    /// Check if host is allowed by policy
    fn is_host_allowed(&self, host: &str, policy: &Policy) -> Decision {
        // Check egress_allowlist guard config
        if let Some(config) = &policy.guards.egress_allowlist {
            // Check blocked list first
            for blocked in &config.block {
                if self.matches_pattern(host, blocked) {
                    return Decision::Deny {
                        reason: format!("Host {} matches blocked pattern: {}", host, blocked),
                    };
                }
            }

            // Check allowed list
            let default_action = config.default_action.clone().unwrap_or_default();

            // Check allow patterns
            for allowed in &config.allow {
                if self.matches_pattern(host, allowed) {
                    return Decision::Allow;
                }
            }

            // Apply default action
            match default_action {
                PolicyAction::Allow => return Decision::Allow,
                PolicyAction::Block => {
                    return Decision::Deny {
                        reason: format!("Host {} not in allowlist", host),
                    };
                }
                PolicyAction::Log => {
                    return Decision::Audit {
                        message: format!("Host {} not in allowlist (logged)", host),
                    };
                }
            }
        }

        // Default: check against common allowed hosts
        let default_allowed = [
            "*.github.com",
            "github.com",
            "*.githubusercontent.com",
            "*.openai.com",
            "*.anthropic.com",
            "api.openai.com",
            "api.anthropic.com",
            "pypi.org",
            "*.pypi.org",
            "crates.io",
            "*.crates.io",
            "npmjs.org",
            "*.npmjs.org",
            "registry.npmjs.org",
        ];

        for pattern in default_allowed {
            if self.matches_pattern(host, pattern) {
                return Decision::Allow;
            }
        }

        // Default: deny unknown hosts
        Decision::Deny {
            reason: format!("Host {} not in default allowlist", host),
        }
    }
}

impl Default for NetworkIrm {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Monitor for NetworkIrm {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, event_type: EventType) -> bool {
        matches!(event_type, EventType::NetConnect | EventType::DnsResolve)
    }

    async fn evaluate(&self, call: &HostCall, policy: &Policy) -> Decision {
        let host = match self.extract_host(call) {
            Some(h) => h,
            None => {
                debug!("NetworkIrm: no host found in call {:?}", call.function);
                // If we can't determine the host, deny by default
                return Decision::Deny {
                    reason: "Cannot determine target host for network call".to_string(),
                };
            }
        };

        debug!("NetworkIrm checking host: {}", host);

        self.is_host_allowed(&host, policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_host_from_url() {
        let irm = NetworkIrm::new();

        assert_eq!(
            irm.extract_host_from_url("https://api.github.com/users"),
            Some("api.github.com".to_string())
        );
        assert_eq!(
            irm.extract_host_from_url("http://localhost:8080/api"),
            Some("localhost".to_string())
        );
    }

    #[test]
    fn test_pattern_matching_exact() {
        let irm = NetworkIrm::new();

        assert!(irm.matches_pattern("api.github.com", "api.github.com"));
        assert!(!irm.matches_pattern("evil.github.com", "api.github.com"));
    }

    #[test]
    fn test_pattern_matching_wildcard_subdomain() {
        let irm = NetworkIrm::new();

        assert!(irm.matches_pattern("api.github.com", "*.github.com"));
        assert!(!irm.matches_pattern("github.com", "*.github.com"));
        assert!(!irm.matches_pattern("github.com.evil.com", "*.github.com"));
    }

    #[test]
    fn test_pattern_matching_ip_range() {
        let irm = NetworkIrm::new();

        assert!(irm.matches_pattern("192.168.1.1", "192.168.*.*"));
        assert!(irm.matches_pattern("10.0.0.1", "10.*.*.*"));
        assert!(!irm.matches_pattern("11.0.0.1", "10.*.*.*"));
    }

    #[test]
    fn test_pattern_matching_wildcard_all() {
        let irm = NetworkIrm::new();

        assert!(irm.matches_pattern("any.domain.com", "*"));
        assert!(irm.matches_pattern("localhost", "*"));
    }

    #[tokio::test]
    async fn test_allowed_domain() {
        let irm = NetworkIrm::new();
        let policy = Policy::default();

        let call = HostCall::new(
            "sock_connect",
            vec![serde_json::json!("https://api.github.com/users")],
        );
        let decision = irm.evaluate(&call, &policy).await;

        assert!(decision.is_allowed());
    }

    #[tokio::test]
    async fn test_unknown_domain_denied() {
        let irm = NetworkIrm::new();
        let policy = Policy::default();

        let call = HostCall::new(
            "sock_connect",
            vec![serde_json::json!("https://unknown-evil-site.com/api")],
        );
        let decision = irm.evaluate(&call, &policy).await;

        assert!(!decision.is_allowed());
    }

    #[tokio::test]
    async fn test_no_host_denied() {
        let irm = NetworkIrm::new();
        let policy = Policy::default();

        let call = HostCall::new("sock_connect", vec![serde_json::json!(12345)]);
        let decision = irm.evaluate(&call, &policy).await;

        assert!(!decision.is_allowed());
    }

    #[test]
    fn test_extract_host_from_object() {
        let irm = NetworkIrm::new();

        let call = HostCall::new(
            "connect",
            vec![serde_json::json!({"host": "api.openai.com", "port": 443})],
        );
        assert_eq!(irm.extract_host(&call), Some("api.openai.com".to_string()));
    }

    #[test]
    fn test_extract_port() {
        let irm = NetworkIrm::new();

        let call = HostCall::new(
            "connect",
            vec![serde_json::json!({"host": "example.com", "port": 8080})],
        );
        assert_eq!(irm.extract_port(&call), Some(8080));

        let call = HostCall::new(
            "connect",
            vec![serde_json::json!("https://example.com/path")],
        );
        assert_eq!(irm.extract_port(&call), Some(443));
    }

    #[test]
    fn test_handles_event_types() {
        let irm = NetworkIrm::new();

        assert!(irm.handles(EventType::NetConnect));
        assert!(irm.handles(EventType::DnsResolve));
        assert!(!irm.handles(EventType::FsRead));
        assert!(!irm.handles(EventType::CommandExec));
    }
}
