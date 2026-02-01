//! Patch integrity guard - validates patch safety

use async_trait::async_trait;
use regex::Regex;
use serde::{Deserialize, Serialize};

use super::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Configuration for PatchIntegrityGuard
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PatchIntegrityConfig {
    /// Maximum lines added in a single patch
    #[serde(default = "default_max_additions")]
    pub max_additions: usize,
    /// Maximum lines deleted in a single patch
    #[serde(default = "default_max_deletions")]
    pub max_deletions: usize,
    /// Patterns that are forbidden in patches
    #[serde(default = "default_forbidden_patterns")]
    pub forbidden_patterns: Vec<String>,
    /// Require patches to have balanced additions/deletions
    #[serde(default)]
    pub require_balance: bool,
    /// Maximum imbalance ratio (additions/deletions)
    #[serde(default = "default_max_imbalance")]
    pub max_imbalance_ratio: f64,
}

fn default_max_additions() -> usize {
    1000
}

fn default_max_deletions() -> usize {
    500
}

fn default_forbidden_patterns() -> Vec<String> {
    vec![
        // Disable security features
        r"(?i)disable[_\-]?(security|auth|ssl|tls)".to_string(),
        r"(?i)skip[_\-]?(verify|validation|check)".to_string(),
        // Dangerous operations
        r"(?i)rm\s+-rf\s+/".to_string(),
        r"(?i)chmod\s+777".to_string(),
        r"(?i)eval\s*\(".to_string(),
        r"(?i)exec\s*\(".to_string(),
        // Backdoor indicators
        r"(?i)reverse[_\-]?shell".to_string(),
        r"(?i)bind[_\-]?shell".to_string(),
        r"base64[_\-]?decode.*exec".to_string(),
    ]
}

fn default_max_imbalance() -> f64 {
    10.0
}

impl Default for PatchIntegrityConfig {
    fn default() -> Self {
        Self {
            max_additions: default_max_additions(),
            max_deletions: default_max_deletions(),
            forbidden_patterns: default_forbidden_patterns(),
            require_balance: false,
            max_imbalance_ratio: default_max_imbalance(),
        }
    }
}

/// Guard that validates patch safety
pub struct PatchIntegrityGuard {
    name: String,
    config: PatchIntegrityConfig,
    forbidden_regexes: Vec<Regex>,
}

impl PatchIntegrityGuard {
    /// Create with default configuration
    pub fn new() -> Self {
        Self::with_config(PatchIntegrityConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: PatchIntegrityConfig) -> Self {
        let forbidden_regexes = config
            .forbidden_patterns
            .iter()
            .filter_map(|p| Regex::new(p).ok())
            .collect();

        Self {
            name: "patch_integrity".to_string(),
            config,
            forbidden_regexes,
        }
    }

    /// Analyze a unified diff
    pub fn analyze(&self, diff: &str) -> PatchAnalysis {
        let mut additions = 0;
        let mut deletions = 0;
        let mut forbidden_matches = Vec::new();

        for line in diff.lines() {
            if line.starts_with('+') && !line.starts_with("+++") {
                additions += 1;

                // Check for forbidden patterns in added lines
                for (idx, regex) in self.forbidden_regexes.iter().enumerate() {
                    if regex.is_match(line) {
                        forbidden_matches.push(ForbiddenMatch {
                            line: line.to_string(),
                            pattern: self.config.forbidden_patterns[idx].clone(),
                        });
                    }
                }
            } else if line.starts_with('-') && !line.starts_with("---") {
                deletions += 1;
            }
        }

        let imbalance_ratio = if deletions > 0 {
            additions as f64 / deletions as f64
        } else if additions > 0 {
            f64::INFINITY
        } else {
            1.0
        };

        PatchAnalysis {
            additions,
            deletions,
            imbalance_ratio,
            forbidden_matches,
            exceeds_max_additions: additions > self.config.max_additions,
            exceeds_max_deletions: deletions > self.config.max_deletions,
            exceeds_imbalance: self.config.require_balance
                && imbalance_ratio > self.config.max_imbalance_ratio,
        }
    }
}

impl Default for PatchIntegrityGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Analysis result for a patch
#[derive(Clone, Debug)]
pub struct PatchAnalysis {
    pub additions: usize,
    pub deletions: usize,
    pub imbalance_ratio: f64,
    pub forbidden_matches: Vec<ForbiddenMatch>,
    pub exceeds_max_additions: bool,
    pub exceeds_max_deletions: bool,
    pub exceeds_imbalance: bool,
}

impl PatchAnalysis {
    /// Check if the patch is safe
    pub fn is_safe(&self) -> bool {
        self.forbidden_matches.is_empty()
            && !self.exceeds_max_additions
            && !self.exceeds_max_deletions
            && !self.exceeds_imbalance
    }
}

/// A forbidden pattern match
#[derive(Clone, Debug)]
pub struct ForbiddenMatch {
    pub line: String,
    pub pattern: String,
}

#[async_trait]
impl Guard for PatchIntegrityGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(action, GuardAction::Patch(_, _))
    }

    async fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        let (path, diff) = match action {
            GuardAction::Patch(p, d) => (*p, *d),
            _ => return GuardResult::allow(&self.name),
        };

        let analysis = self.analyze(diff);

        if analysis.is_safe() {
            return GuardResult::allow(&self.name);
        }

        let mut issues = Vec::new();

        if !analysis.forbidden_matches.is_empty() {
            issues.push(format!(
                "Contains forbidden patterns: {}",
                analysis
                    .forbidden_matches
                    .iter()
                    .map(|m| &m.pattern)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        if analysis.exceeds_max_additions {
            issues.push(format!(
                "Too many additions: {} (max: {})",
                analysis.additions, self.config.max_additions
            ));
        }

        if analysis.exceeds_max_deletions {
            issues.push(format!(
                "Too many deletions: {} (max: {})",
                analysis.deletions, self.config.max_deletions
            ));
        }

        if analysis.exceeds_imbalance {
            issues.push(format!(
                "Imbalanced patch: ratio {:.2} (max: {:.2})",
                analysis.imbalance_ratio, self.config.max_imbalance_ratio
            ));
        }

        let severity = if !analysis.forbidden_matches.is_empty() {
            Severity::Critical
        } else {
            Severity::Error
        };

        GuardResult::block(&self.name, severity, issues.join("; ")).with_details(
            serde_json::json!({
                "path": path,
                "additions": analysis.additions,
                "deletions": analysis.deletions,
                "imbalance_ratio": analysis.imbalance_ratio,
                "forbidden_matches": analysis.forbidden_matches.len(),
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_simple_patch() {
        let guard = PatchIntegrityGuard::new();

        let diff = r#"
--- a/file.txt
+++ b/file.txt
@@ -1,3 +1,4 @@
 unchanged
+added line 1
+added line 2
-deleted line
"#;

        let analysis = guard.analyze(diff);
        assert_eq!(analysis.additions, 2);
        assert_eq!(analysis.deletions, 1);
        assert!(analysis.is_safe());
    }

    #[test]
    fn test_forbidden_pattern() {
        let guard = PatchIntegrityGuard::new();

        let diff = r#"
+disable_security = True
+rm -rf /
"#;

        let analysis = guard.analyze(diff);
        assert!(!analysis.forbidden_matches.is_empty());
        assert!(!analysis.is_safe());
    }

    #[test]
    fn test_max_additions() {
        let config = PatchIntegrityConfig {
            max_additions: 5,
            ..Default::default()
        };
        let guard = PatchIntegrityGuard::with_config(config);

        let diff = "+line1\n+line2\n+line3\n+line4\n+line5\n+line6";
        let analysis = guard.analyze(diff);
        assert!(analysis.exceeds_max_additions);
        assert!(!analysis.is_safe());
    }

    #[tokio::test]
    async fn test_guard_check() {
        let guard = PatchIntegrityGuard::new();
        let context = GuardContext::new();

        let safe_diff = "+added line\n-deleted line";
        let result = guard
            .check(&GuardAction::Patch("file.txt", safe_diff), &context)
            .await;
        assert!(result.allowed);

        let unsafe_diff = "+eval(user_input)";
        let result = guard
            .check(&GuardAction::Patch("file.py", unsafe_diff), &context)
            .await;
        assert!(!result.allowed);
    }
}
