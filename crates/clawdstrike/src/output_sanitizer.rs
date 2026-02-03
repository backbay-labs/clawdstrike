//! Output sanitization and redaction utilities.
//!
//! This module is meant to be used on **model outputs** or **tool outputs** before they are shown
//! to users or written to persistent logs. It is intentionally conservative: it prefers to redact
//! suspicious secrets/PII rather than risk leaking them.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use hush_core::{sha256, Hash};

/// Categories of sensitive data.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveCategory {
    Secret,
    Pii,
    Internal,
    Custom(String),
}

/// Redaction strategies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStrategy {
    /// Replace the entire match with a labeled placeholder.
    Full,
    /// Keep a small prefix/suffix and redact the middle.
    Partial,
    /// Replace with a type-only label (no characters preserved).
    TypeLabel,
    /// Replace with a stable hash of the match (prevents re-identification by content).
    Hash,
    /// Do not redact (for allowlisted / informational findings).
    None,
}

/// Text span in bytes (UTF-8 indices).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// Detector type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorType {
    Pattern,
    Entropy,
    Custom(String),
}

/// A sensitive data finding (no raw match).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SensitiveDataFinding {
    /// Stable finding ID (pattern ID).
    pub id: String,
    pub category: SensitiveCategory,
    pub data_type: String,
    pub confidence: f32,
    pub span: Span,
    /// A redacted preview of the match (never raw).
    pub preview: String,
    pub detector: DetectorType,
    pub recommended_action: RedactionStrategy,
}

/// Applied redaction record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Redaction {
    pub finding_id: String,
    pub strategy: RedactionStrategy,
    pub original_span: Span,
    pub replacement: String,
}

/// Processing statistics.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProcessingStats {
    pub input_length: usize,
    pub output_length: usize,
    pub findings_count: usize,
    pub redactions_count: usize,
    pub processing_time_ms: f64,
}

/// Sanitization output.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SanitizationResult {
    pub sanitized: String,
    pub was_redacted: bool,
    pub findings: Vec<SensitiveDataFinding>,
    pub redactions: Vec<Redaction>,
    pub stats: ProcessingStats,
}

/// Category toggles.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CategoryConfig {
    #[serde(default = "default_true")]
    pub secrets: bool,
    #[serde(default = "default_true")]
    pub pii: bool,
    #[serde(default = "default_true")]
    pub internal: bool,
}

fn default_true() -> bool {
    true
}

impl Default for CategoryConfig {
    fn default() -> Self {
        Self {
            secrets: true,
            pii: true,
            internal: true,
        }
    }
}

/// Entropy configuration for high-entropy token detection.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntropyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_entropy_threshold")]
    pub threshold: f64,
    #[serde(default = "default_min_token_len")]
    pub min_token_len: usize,
}

fn default_entropy_threshold() -> f64 {
    4.5
}

fn default_min_token_len() -> usize {
    32
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: default_entropy_threshold(),
            min_token_len: default_min_token_len(),
        }
    }
}

/// Sanitizer configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputSanitizerConfig {
    #[serde(default)]
    pub categories: CategoryConfig,

    /// Default redaction strategies by category.
    #[serde(default)]
    pub redaction_strategies: HashMap<SensitiveCategory, RedactionStrategy>,

    /// Whether to include findings in the result (always redacted previews).
    #[serde(default = "default_true")]
    pub include_findings: bool,

    /// Entropy-based detection for unknown secrets.
    #[serde(default)]
    pub entropy: EntropyConfig,

    /// Maximum number of bytes to analyze.
    #[serde(default = "default_max_input_bytes")]
    pub max_input_bytes: usize,
}

fn default_max_input_bytes() -> usize {
    1_000_000
}

impl Default for OutputSanitizerConfig {
    fn default() -> Self {
        let mut redaction_strategies = HashMap::new();
        redaction_strategies.insert(SensitiveCategory::Secret, RedactionStrategy::Full);
        redaction_strategies.insert(SensitiveCategory::Pii, RedactionStrategy::Partial);
        redaction_strategies.insert(SensitiveCategory::Internal, RedactionStrategy::TypeLabel);

        Self {
            categories: CategoryConfig::default(),
            redaction_strategies,
            include_findings: true,
            entropy: EntropyConfig::default(),
            max_input_bytes: default_max_input_bytes(),
        }
    }
}

#[derive(Clone)]
struct CompiledPattern {
    id: &'static str,
    category: SensitiveCategory,
    data_type: &'static str,
    confidence: f32,
    strategy: RedactionStrategy,
    regex: Regex,
}

fn compile_patterns() -> &'static [CompiledPattern] {
    static PATTERNS: OnceLock<Vec<CompiledPattern>> = OnceLock::new();

    PATTERNS.get_or_init(|| {
        vec![
            // Secrets (high-confidence known formats)
            CompiledPattern {
                id: "secret_openai_api_key",
                category: SensitiveCategory::Secret,
                data_type: "openai_api_key",
                confidence: 0.99,
                strategy: RedactionStrategy::Full,
                regex: Regex::new(r"sk-[A-Za-z0-9]{48}").unwrap(),
            },
            CompiledPattern {
                id: "secret_github_token",
                category: SensitiveCategory::Secret,
                data_type: "github_token",
                confidence: 0.99,
                strategy: RedactionStrategy::Full,
                regex: Regex::new(r"gh[ps]_[A-Za-z0-9]{36}").unwrap(),
            },
            CompiledPattern {
                id: "secret_aws_access_key_id",
                category: SensitiveCategory::Secret,
                data_type: "aws_access_key_id",
                confidence: 0.99,
                strategy: RedactionStrategy::Full,
                regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            },
            CompiledPattern {
                id: "secret_private_key_block",
                category: SensitiveCategory::Secret,
                data_type: "private_key",
                confidence: 0.99,
                strategy: RedactionStrategy::Full,
                regex: Regex::new(r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----").unwrap(),
            },
            // PII
            CompiledPattern {
                id: "pii_email",
                category: SensitiveCategory::Pii,
                data_type: "email",
                confidence: 0.95,
                strategy: RedactionStrategy::Partial,
                regex: Regex::new(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b").unwrap(),
            },
            CompiledPattern {
                id: "pii_phone",
                category: SensitiveCategory::Pii,
                data_type: "phone",
                confidence: 0.8,
                strategy: RedactionStrategy::Partial,
                // Conservative: US-ish formats with separators.
                regex: Regex::new(
                    r"\b(?:\+?1[\s.-]?)?\(?(?:[2-9][0-9]{2})\)?[\s.-]?[0-9]{3}[\s.-]?[0-9]{4}\b",
                )
                .unwrap(),
            },
            CompiledPattern {
                id: "pii_ssn",
                category: SensitiveCategory::Pii,
                data_type: "ssn",
                confidence: 0.9,
                strategy: RedactionStrategy::Full,
                regex: Regex::new(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b").unwrap(),
            },
            CompiledPattern {
                id: "pii_credit_card",
                category: SensitiveCategory::Pii,
                data_type: "credit_card",
                confidence: 0.7,
                strategy: RedactionStrategy::Full,
                // Very approximate; downstream can add Luhn if needed.
                regex: Regex::new(r"\b(?:[0-9][ -]*?){13,19}\b").unwrap(),
            },
            // Internal
            CompiledPattern {
                id: "internal_localhost_url",
                category: SensitiveCategory::Internal,
                data_type: "internal_url",
                confidence: 0.8,
                strategy: RedactionStrategy::TypeLabel,
                regex: Regex::new(r"(?i)\bhttps?://(?:localhost|127\.0\.0\.1)(?::[0-9]{2,5})?\b")
                    .unwrap(),
            },
            CompiledPattern {
                id: "internal_file_path_sensitive",
                category: SensitiveCategory::Internal,
                data_type: "sensitive_path",
                confidence: 0.7,
                strategy: RedactionStrategy::TypeLabel,
                regex: Regex::new(r"(?i)\b(?:/etc/|/var/secrets/|/home/[^\s]+/\.ssh/)").unwrap(),
            },
        ]
    })
}

fn preview_redacted(s: &str) -> String {
    // Keep this deterministic and safe: never return the raw string.
    let len = s.chars().count();
    if len <= 4 {
        return "*".repeat(len);
    }

    let prefix: String = s.chars().take(2).collect();
    let suffix: String = s
        .chars()
        .rev()
        .take(2)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{prefix}***{suffix}")
}

fn replacement_for(
    strategy: &RedactionStrategy,
    category: &SensitiveCategory,
    data_type: &str,
    raw: &str,
) -> String {
    match strategy {
        RedactionStrategy::None => raw.to_string(),
        RedactionStrategy::Full => format!("[REDACTED:{data_type}]"),
        RedactionStrategy::TypeLabel => match category {
            SensitiveCategory::Secret => "[REDACTED:secret]".to_string(),
            SensitiveCategory::Pii => "[REDACTED:pii]".to_string(),
            SensitiveCategory::Internal => "[REDACTED:internal]".to_string(),
            SensitiveCategory::Custom(label) => format!("[REDACTED:{label}]"),
        },
        RedactionStrategy::Partial => preview_redacted(raw),
        RedactionStrategy::Hash => {
            let h: Hash = sha256(raw.as_bytes());
            format!("[HASH:{}]", h.to_hex())
        }
    }
}

fn shannon_entropy_ascii(token: &str) -> Option<f64> {
    if !token.is_ascii() {
        return None;
    }
    let bytes = token.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] = counts[b as usize].saturating_add(1);
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        entropy -= p * p.log2();
    }
    Some(entropy)
}

fn is_candidate_secret_token(token: &str) -> bool {
    // Common token alphabets (base64/hex/url-safe).
    token
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
}

fn truncate_to_char_boundary(text: &str, max_bytes: usize) -> (&str, bool) {
    if text.len() <= max_bytes {
        return (text, false);
    }

    let mut end = max_bytes.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    (&text[..end], end < text.len())
}

/// Sanitizer for output text.
#[derive(Clone, Debug)]
pub struct OutputSanitizer {
    config: OutputSanitizerConfig,
}

impl OutputSanitizer {
    pub fn new() -> Self {
        Self::with_config(OutputSanitizerConfig::default())
    }

    pub fn with_config(config: OutputSanitizerConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &OutputSanitizerConfig {
        &self.config
    }

    pub fn sanitize_sync(&self, output: &str) -> SanitizationResult {
        let start = std::time::Instant::now();

        let mut stats = ProcessingStats::default();
        stats.input_length = output.len();

        let (limited, truncated) = truncate_to_char_boundary(output, self.config.max_input_bytes);

        let mut findings: Vec<SensitiveDataFinding> = Vec::new();
        let mut redactions: Vec<Redaction> = Vec::new();

        for p in compile_patterns() {
            let enabled = match p.category {
                SensitiveCategory::Secret => self.config.categories.secrets,
                SensitiveCategory::Pii => self.config.categories.pii,
                SensitiveCategory::Internal => self.config.categories.internal,
                SensitiveCategory::Custom(_) => true,
            };
            if !enabled {
                continue;
            }

            for m in p.regex.find_iter(limited) {
                let span = Span {
                    start: m.start(),
                    end: m.end(),
                };
                let preview = preview_redacted(m.as_str());
                findings.push(SensitiveDataFinding {
                    id: p.id.to_string(),
                    category: p.category.clone(),
                    data_type: p.data_type.to_string(),
                    confidence: p.confidence,
                    span,
                    preview,
                    detector: DetectorType::Pattern,
                    recommended_action: p.strategy.clone(),
                });
            }
        }

        if self.config.categories.secrets && self.config.entropy.enabled {
            // A simple scan that finds "word-like" tokens and evaluates entropy.
            static TOKEN_RE: OnceLock<Regex> = OnceLock::new();
            let token_re = TOKEN_RE
                .get_or_init(|| Regex::new(r"[A-Za-z0-9+/=_-]{32,}").expect("hardcoded regex"));
            for m in token_re.find_iter(limited) {
                let token = m.as_str();
                if token.len() < self.config.entropy.min_token_len {
                    continue;
                }
                if !is_candidate_secret_token(token) {
                    continue;
                }
                let ent = match shannon_entropy_ascii(token) {
                    Some(e) => e,
                    None => continue,
                };
                if ent < self.config.entropy.threshold {
                    continue;
                }

                let span = Span {
                    start: m.start(),
                    end: m.end(),
                };
                findings.push(SensitiveDataFinding {
                    id: "secret_high_entropy_token".to_string(),
                    category: SensitiveCategory::Secret,
                    data_type: "high_entropy_token".to_string(),
                    confidence: 0.6,
                    span,
                    preview: preview_redacted(token),
                    detector: DetectorType::Entropy,
                    recommended_action: RedactionStrategy::Full,
                });
            }
        }

        // Apply redactions, preferring "stronger" redaction when multiple findings overlap.
        findings.sort_by_key(|f| (f.span.start, f.span.end));

        let mut spans: Vec<(Span, RedactionStrategy, SensitiveCategory, String, String)> =
            Vec::new();
        for f in &findings {
            let strategy = self
                .config
                .redaction_strategies
                .get(&f.category)
                .cloned()
                .unwrap_or_else(|| f.recommended_action.clone());
            spans.push((
                f.span,
                strategy,
                f.category.clone(),
                f.data_type.clone(),
                f.id.clone(),
            ));
        }

        // Sort by start desc so replacements don't affect earlier spans.
        spans.sort_by(|a, b| {
            b.0.start
                .cmp(&a.0.start)
                .then_with(|| b.0.end.cmp(&a.0.end))
        });

        let mut sanitized = limited.to_string();
        let mut applied_any = false;

        for (span, strategy, category, data_type, finding_id) in spans {
            if span.end > sanitized.len() || span.start >= span.end {
                continue;
            }
            let raw = &sanitized[span.start..span.end];
            let replacement = replacement_for(&strategy, &category, &data_type, raw);
            if replacement == raw {
                continue;
            }
            sanitized.replace_range(span.start..span.end, &replacement);
            applied_any = true;
            redactions.push(Redaction {
                finding_id,
                strategy,
                original_span: span,
                replacement,
            });
        }

        if truncated {
            // If we truncated the input for analysis, we intentionally do NOT append the
            // unscanned suffix. Appending it would risk leaking secrets/PII that were not
            // analyzed/redacted.
            sanitized.push_str("\n[TRUNCATED_UNSCANNED_OUTPUT]");
            applied_any = true;
        }

        if !self.config.include_findings {
            findings.clear();
        }

        stats.output_length = sanitized.len();
        stats.findings_count = findings.len();
        stats.redactions_count = redactions.len();
        stats.processing_time_ms = start.elapsed().as_secs_f64() * 1000.0;

        SanitizationResult {
            was_redacted: applied_any,
            sanitized,
            findings,
            redactions,
            stats,
        }
    }
}

impl Default for OutputSanitizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_known_secrets() {
        let s = OutputSanitizer::new();
        let input = "token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa and sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let r = s.sanitize_sync(input);
        assert!(r.was_redacted);
        assert!(!r.sanitized.contains("ghp_aaaaaaaa"));
        assert!(!r.sanitized.contains("sk-aaaaaaaa"));
        assert!(r.sanitized.contains("[REDACTED:github_token]"));
        assert!(r.sanitized.contains("[REDACTED:openai_api_key]"));
    }

    #[test]
    fn sanitizes_pii_email_partially() {
        let s = OutputSanitizer::new();
        let input = "Contact me at alice@example.com please.";
        let r = s.sanitize_sync(input);
        assert!(r.was_redacted);
        assert!(!r.sanitized.contains("alice@example.com"));
        assert!(r.sanitized.contains("***"));
    }

    #[test]
    fn never_includes_raw_matches_in_findings_preview() {
        let s = OutputSanitizer::new();
        let input = "alice@example.com";
        let r = s.sanitize_sync(input);
        assert!(r.was_redacted);
        assert_eq!(r.findings.len(), 1);
        assert_ne!(r.findings[0].preview, input);
    }

    #[test]
    fn does_not_append_unscanned_suffix_by_default() {
        let mut cfg = OutputSanitizerConfig::default();
        cfg.max_input_bytes = 24;
        let s = OutputSanitizer::with_config(cfg);

        let input =
            "prefix that fits in max bytes then secret: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let r = s.sanitize_sync(input);

        assert!(r.was_redacted);
        assert!(r.sanitized.contains("[TRUNCATED_UNSCANNED_OUTPUT]"));
        assert!(!r.sanitized.contains("ghp_aaaaaaaa"));
        assert!(r.sanitized.starts_with("prefix"));
    }
}
