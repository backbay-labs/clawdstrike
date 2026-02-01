//! Secret leak guard - detects potential secret exposure

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Pattern definition for secret detection
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecretPattern {
    /// Pattern name
    pub name: String,
    /// Regex pattern
    pub pattern: String,
    /// Severity level
    #[serde(default = "default_severity")]
    pub severity: Severity,
}

fn default_severity() -> Severity {
    Severity::Critical
}

/// Configuration for SecretLeakGuard
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SecretLeakConfig {
    /// Secret patterns to detect
    #[serde(default = "default_patterns")]
    pub patterns: Vec<SecretPattern>,
    /// File patterns to skip (e.g., test fixtures)
    #[serde(default)]
    pub skip_paths: Vec<String>,
}

fn default_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "aws_access_key".to_string(),
            pattern: r"AKIA[0-9A-Z]{16}".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "aws_secret_key".to_string(),
            pattern:
                r#"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['"]?\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}"#
                    .to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "github_token".to_string(),
            pattern: r"gh[ps]_[A-Za-z0-9]{36}".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "github_pat".to_string(),
            pattern: r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "openai_key".to_string(),
            pattern: r"sk-[A-Za-z0-9]{48}".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "anthropic_key".to_string(),
            pattern: r"sk-ant-[A-Za-z0-9\-]{95}".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "private_key".to_string(),
            pattern: r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "npm_token".to_string(),
            pattern: r"npm_[A-Za-z0-9]{36}".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "slack_token".to_string(),
            pattern: r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*".to_string(),
            severity: Severity::Critical,
        },
        SecretPattern {
            name: "generic_api_key".to_string(),
            pattern: r#"(?i)(api[_\-]?key|apikey)['"]?\s*[:=]\s*['"]?[A-Za-z0-9]{32,}"#.to_string(),
            severity: Severity::Warning,
        },
        SecretPattern {
            name: "generic_secret".to_string(),
            pattern:
                r#"(?i)(secret|password|passwd|pwd)['"]?\s*[:=]\s*['"]?[A-Za-z0-9!@#$%^&*]{8,}"#
                    .to_string(),
            severity: Severity::Warning,
        },
    ]
}

impl Default for SecretLeakConfig {
    fn default() -> Self {
        Self {
            patterns: default_patterns(),
            skip_paths: vec![
                "**/test/**".to_string(),
                "**/tests/**".to_string(),
                "**/*_test.*".to_string(),
                "**/*.test.*".to_string(),
            ],
        }
    }
}

/// Compiled pattern for matching
struct CompiledPattern {
    name: String,
    regex: Regex,
    severity: Severity,
}

/// Guard that detects potential secret exposure in content
pub struct SecretLeakGuard {
    name: String,
    patterns: Vec<CompiledPattern>,
    skip_paths: Vec<glob::Pattern>,
}

impl SecretLeakGuard {
    /// Create with default configuration
    pub fn new() -> Self {
        Self::with_config(SecretLeakConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: SecretLeakConfig) -> Self {
        let patterns = config
            .patterns
            .into_iter()
            .filter_map(|p| {
                Regex::new(&p.pattern).ok().map(|regex| CompiledPattern {
                    name: p.name,
                    regex,
                    severity: p.severity,
                })
            })
            .collect();

        let skip_paths = config
            .skip_paths
            .iter()
            .filter_map(|p| glob::Pattern::new(p).ok())
            .collect();

        Self {
            name: "secret_leak".to_string(),
            patterns,
            skip_paths,
        }
    }

    /// Check content for secrets
    pub fn scan(&self, content: &[u8]) -> Vec<SecretMatch> {
        let content = match std::str::from_utf8(content) {
            Ok(s) => s,
            Err(_) => return vec![], // Skip binary content
        };

        let mut matches = Vec::new();
        for pattern in &self.patterns {
            for m in pattern.regex.find_iter(content) {
                matches.push(SecretMatch {
                    pattern_name: pattern.name.clone(),
                    severity: pattern.severity.clone(),
                    offset: m.start(),
                    length: m.len(),
                    // Don't include the actual secret in the match!
                    redacted: redact_secret(m.as_str()),
                });
            }
        }
        matches
    }

    /// Check if a path should be skipped
    pub fn should_skip_path(&self, path: &str) -> bool {
        for pattern in &self.skip_paths {
            if pattern.matches(path) {
                return true;
            }
        }
        false
    }
}

impl Default for SecretLeakGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// A secret match (with redacted content)
#[derive(Clone, Debug)]
pub struct SecretMatch {
    pub pattern_name: String,
    pub severity: Severity,
    pub offset: usize,
    pub length: usize,
    pub redacted: String,
}

/// Redact a secret, keeping only first/last chars
fn redact_secret(s: &str) -> String {
    if s.len() <= 8 {
        "*".repeat(s.len())
    } else {
        format!(
            "{}{}{}",
            &s[..4],
            "*".repeat(s.len() - 8),
            &s[s.len() - 4..]
        )
    }
}

#[async_trait]
impl Guard for SecretLeakGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(
            action,
            GuardAction::FileWrite(_, _) | GuardAction::Patch(_, _)
        )
    }

    async fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        let (path, content) = match action {
            GuardAction::FileWrite(p, c) => (*p, *c),
            GuardAction::Patch(p, diff) => (*p, diff.as_bytes()),
            _ => return GuardResult::allow(&self.name),
        };

        // Skip certain paths
        if self.should_skip_path(path) {
            return GuardResult::allow(&self.name);
        }

        let matches = self.scan(content);

        if matches.is_empty() {
            return GuardResult::allow(&self.name);
        }

        // Find the most severe match
        let max_severity = matches
            .iter()
            .map(|m| &m.severity)
            .max_by(|a, b| {
                use Severity::*;
                match (a, b) {
                    (Critical, _) => std::cmp::Ordering::Greater,
                    (_, Critical) => std::cmp::Ordering::Less,
                    (Error, _) => std::cmp::Ordering::Greater,
                    (_, Error) => std::cmp::Ordering::Less,
                    (Warning, _) => std::cmp::Ordering::Greater,
                    (_, Warning) => std::cmp::Ordering::Less,
                    _ => std::cmp::Ordering::Equal,
                }
            })
            .cloned()
            .unwrap_or(Severity::Warning);

        let pattern_names: Vec<_> = matches.iter().map(|m| m.pattern_name.clone()).collect();

        if matches!(max_severity, Severity::Critical | Severity::Error) {
            GuardResult::block(
                &self.name,
                max_severity,
                format!("Potential secrets detected: {}", pattern_names.join(", ")),
            )
            .with_details(serde_json::json!({
                "path": path,
                "matches": matches.iter().map(|m| {
                    serde_json::json!({
                        "pattern": m.pattern_name,
                        "severity": m.severity,
                        "redacted": m.redacted,
                    })
                }).collect::<Vec<_>>(),
            }))
        } else {
            GuardResult::warn(
                &self.name,
                format!(
                    "Potential secrets detected (warning): {}",
                    pattern_names.join(", ")
                ),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aws_access_key() {
        let guard = SecretLeakGuard::new();
        let content = b"aws_key = AKIAIOSFODNN7EXAMPLE";
        let matches = guard.scan(content);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "aws_access_key");
    }

    #[test]
    fn test_github_token() {
        let guard = SecretLeakGuard::new();
        let content = b"token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let matches = guard.scan(content);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "github_token");
    }

    #[test]
    fn test_private_key() {
        let guard = SecretLeakGuard::new();
        let content = b"-----BEGIN RSA PRIVATE KEY-----\nMIIE...";
        let matches = guard.scan(content);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].pattern_name, "private_key");
    }

    #[test]
    fn test_no_secrets() {
        let guard = SecretLeakGuard::new();
        let content = b"This is just normal code\nfn main() { }";
        let matches = guard.scan(content);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_redaction() {
        assert_eq!(redact_secret("short"), "*****");
        assert_eq!(
            redact_secret("AKIAIOSFODNN7EXAMPLE"),
            "AKIA************MPLE"
        );
    }

    #[test]
    fn test_skip_paths() {
        let guard = SecretLeakGuard::new();
        assert!(guard.should_skip_path("/app/tests/fixtures/sample.json"));
        assert!(guard.should_skip_path("/app/src/main_test.rs"));
        assert!(!guard.should_skip_path("/app/src/main.rs"));
    }

    #[tokio::test]
    async fn test_guard_check() {
        let guard = SecretLeakGuard::new();
        let context = GuardContext::new();

        let content = b"api_key = sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
        let result = guard
            .check(&GuardAction::FileWrite("/app/config.py", content), &context)
            .await;
        assert!(!result.allowed);

        let content = b"fn main() { println!(\"Hello\"); }";
        let result = guard
            .check(&GuardAction::FileWrite("/app/main.rs", content), &context)
            .await;
        assert!(result.allowed);
    }
}
