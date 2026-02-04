//! Secret leak guard - detects potential secret exposure

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Pattern definition for secret detection
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPattern {
    /// Pattern name
    pub name: String,
    /// Regex pattern
    pub pattern: String,
    /// Severity level
    #[serde(default = "default_severity")]
    pub severity: Severity,
    /// Optional pattern description (useful for compliance evidence).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional Luhn validation gate (e.g., for card numbers).
    #[serde(default)]
    pub luhn_check: bool,
    /// Optional masking configuration for redaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub masking: Option<SecretMasking>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretMasking {
    pub first: u8,
    pub last: u8,
}

fn default_severity() -> Severity {
    Severity::Critical
}

/// Configuration for SecretLeakGuard
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretLeakConfig {
    /// Enable/disable this guard.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Whether to redact matched secrets in logs/audit details.
    #[serde(default = "default_redact")]
    pub redact: bool,
    /// Block when the highest matched severity is at-or-above this level.
    #[serde(default = "default_severity_threshold")]
    pub severity_threshold: Severity,
    /// Secret patterns to detect
    #[serde(default = "default_patterns")]
    pub patterns: Vec<SecretPattern>,
    /// File patterns to skip (e.g., test fixtures)
    #[serde(default)]
    pub skip_paths: Vec<String>,
}

fn default_enabled() -> bool {
    true
}

fn default_redact() -> bool {
    true
}

fn default_severity_threshold() -> Severity {
    Severity::Error
}

fn default_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "aws_access_key".to_string(),
            pattern: r"AKIA[0-9A-Z]{16}".to_string(),
            severity: Severity::Critical,
            description: None,
            luhn_check: false,
            masking: None,
        },
        SecretPattern {
            name: "aws_secret_key".to_string(),
            pattern:
                r#"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['"]?\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}"#
                    .to_string(),
            severity: Severity::Critical,
            description: None,
            luhn_check: false,
            masking: None,
        },
        SecretPattern {
            name: "github_token".to_string(),
            pattern: r"gh[ps]_[A-Za-z0-9]{36}".to_string(),
            severity: Severity::Critical,
            description: None,
            luhn_check: false,
            masking: None,
        },
        SecretPattern {
            name: "github_pat".to_string(),
            pattern: r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}".to_string(),
            severity: Severity::Critical,
            description: None,
            luhn_check: false,
            masking: None,
        },
        SecretPattern {
            name: "openai_key".to_string(),
            pattern: r"sk-[A-Za-z0-9]{48}".to_string(),
            severity: Severity::Critical,
            description: None,
            luhn_check: false,
            masking: None,
        },
        SecretPattern {
            name: "anthropic_key".to_string(),
            pattern: r"sk-ant-[A-Za-z0-9\-]{95}".to_string(),
            severity: Severity::Critical,
            description: None,
            luhn_check: false,
            masking: None,
        },
        SecretPattern {
            name: "private_key".to_string(),
            pattern: r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----".to_string(),
            severity: Severity::Critical,
            description: None,
            luhn_check: false,
            masking: None,
        },
        SecretPattern {
            name: "npm_token".to_string(),
            pattern: r"npm_[A-Za-z0-9]{36}".to_string(),
            severity: Severity::Critical,
            description: None,
            luhn_check: false,
            masking: None,
        },
        SecretPattern {
            name: "slack_token".to_string(),
            pattern: r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*".to_string(),
            severity: Severity::Critical,
            description: None,
            luhn_check: false,
            masking: None,
        },
        SecretPattern {
            name: "generic_api_key".to_string(),
            pattern: r#"(?i)(api[_\-]?key|apikey)['"]?\s*[:=]\s*['"]?[A-Za-z0-9]{32,}"#.to_string(),
            severity: Severity::Warning,
            description: None,
            luhn_check: false,
            masking: None,
        },
        SecretPattern {
            name: "generic_secret".to_string(),
            pattern:
                r#"(?i)(secret|password|passwd|pwd)['"]?\s*[:=]\s*['"]?[A-Za-z0-9!@#$%^&*]{8,}"#
                    .to_string(),
            severity: Severity::Warning,
            description: None,
            luhn_check: false,
            masking: None,
        },
    ]
}

impl Default for SecretLeakConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            redact: default_redact(),
            severity_threshold: default_severity_threshold(),
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
    description: Option<String>,
    luhn_check: bool,
    masking: Option<SecretMasking>,
}

/// Guard that detects potential secret exposure in content
pub struct SecretLeakGuard {
    name: String,
    enabled: bool,
    redact: bool,
    severity_threshold: Severity,
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
        let enabled = config.enabled;
        let redact = config.redact;
        let severity_threshold = config.severity_threshold.clone();
        let patterns = config
            .patterns
            .into_iter()
            .filter_map(|p| {
                Regex::new(&p.pattern).ok().map(|regex| CompiledPattern {
                    name: p.name,
                    regex,
                    severity: p.severity,
                    description: p.description,
                    luhn_check: p.luhn_check,
                    masking: p.masking,
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
            enabled,
            redact,
            severity_threshold,
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
                let matched = m.as_str();
                if pattern.luhn_check && !is_luhn_valid_card_number(matched) {
                    continue;
                }

                let redacted = if self.redact {
                    mask_value(matched, pattern.masking.as_ref())
                } else {
                    matched.to_string()
                };

                matches.push(SecretMatch {
                    pattern_name: pattern.name.clone(),
                    severity: pattern.severity.clone(),
                    description: pattern.description.clone(),
                    offset: m.start(),
                    length: m.len(),
                    redacted,
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
    pub description: Option<String>,
    pub offset: usize,
    pub length: usize,
    pub redacted: String,
}

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
        Severity::Critical => 3,
    }
}

fn mask_value(s: &str, masking: Option<&SecretMasking>) -> String {
    let first = masking.map(|m| m.first as usize).unwrap_or(4);
    let last = masking.map(|m| m.last as usize).unwrap_or(4);

    if s.is_empty() {
        return String::new();
    }

    let len = s.chars().count();
    if first + last >= len {
        return "*".repeat(len);
    }

    let first_chars: String = s.chars().take(first).collect();
    let last_chars: String = s
        .chars()
        .rev()
        .take(last)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!(
        "{}{}{}",
        first_chars,
        "*".repeat(len - first - last),
        last_chars
    )
}

fn is_luhn_valid_card_number(text: &str) -> bool {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| b.is_ascii_digit())
        .map(|b| b - b'0')
        .collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    if digits.iter().all(|d| *d == digits[0]) {
        return false;
    }

    let mut sum: u32 = 0;
    let mut double = false;
    for d in digits.iter().rev() {
        let mut v = *d as u32;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum = sum.saturating_add(v);
        double = !double;
    }
    sum.is_multiple_of(10)
}

#[async_trait]
impl Guard for SecretLeakGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        if !self.enabled {
            return false;
        }

        matches!(
            action,
            GuardAction::FileWrite(_, _) | GuardAction::Patch(_, _)
        )
    }

    async fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        if !self.enabled {
            return GuardResult::allow(&self.name);
        }

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
            .max_by(|a, b| severity_rank(a).cmp(&severity_rank(b)))
            .cloned()
            .unwrap_or(Severity::Warning);

        let pattern_names: Vec<_> = matches.iter().map(|m| m.pattern_name.clone()).collect();

        let details = serde_json::json!({
            "path": path,
            "matches": matches.iter().map(|m| {
                serde_json::json!({
                    "pattern": m.pattern_name,
                    "severity": m.severity,
                    "description": m.description,
                    "redacted": m.redacted,
                })
            }).collect::<Vec<_>>(),
        });

        if severity_rank(&max_severity) >= severity_rank(&self.severity_threshold) {
            GuardResult::block(
                &self.name,
                max_severity,
                format!("Potential secrets detected: {}", pattern_names.join(", ")),
            )
            .with_details(details)
        } else {
            GuardResult::warn(
                &self.name,
                format!(
                    "Potential secrets detected (warning): {}",
                    pattern_names.join(", ")
                ),
            )
            .with_details(details)
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
        assert_eq!(mask_value("short", None), "*****");
        assert_eq!(
            mask_value("AKIAIOSFODNN7EXAMPLE", None),
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
