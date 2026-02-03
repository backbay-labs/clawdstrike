//! Output sanitization and redaction utilities.
//!
//! This module is meant to be used on **model outputs** or **tool outputs** before they are shown
//! to users or written to persistent logs. It is intentionally conservative: it prefers to redact
//! suspicious secrets/PII rather than risk leaking them.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

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
    /// External entity recognizer (NER, etc).
    Entity,
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

/// Entity finding produced by an external recognizer (optional).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntityFinding {
    pub entity_type: String,
    pub confidence: f32,
    pub span: Span,
}

/// Optional entity recognizer hook for richer PII detection.
pub trait EntityRecognizer: Send + Sync {
    fn detect(&self, text: &str) -> Vec<EntityFinding>;
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

/// Allowlist configuration for false-positive reduction.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AllowlistConfig {
    #[serde(default)]
    pub exact: Vec<String>,
    /// Regex strings.
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub allow_test_credentials: bool,
}

/// Denylist configuration: patterns that must be redacted even if not matched by built-ins.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DenylistConfig {
    /// Regex strings.
    #[serde(default)]
    pub patterns: Vec<String>,
}

/// Streaming configuration for incremental sanitization.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StreamingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum bytes to buffer before flushing.
    #[serde(default = "default_stream_buffer_size")]
    pub buffer_size: usize,
    /// Bytes of lookback to retain between writes.
    #[serde(default = "default_stream_carry_bytes")]
    pub carry_bytes: usize,
}

fn default_stream_buffer_size() -> usize {
    50_000
}

fn default_stream_carry_bytes() -> usize {
    512
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            buffer_size: default_stream_buffer_size(),
            carry_bytes: default_stream_carry_bytes(),
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

    /// Allowlisted strings/patterns (skip findings + redaction).
    #[serde(default)]
    pub allowlist: AllowlistConfig,

    /// Denylisted patterns (forced redaction).
    #[serde(default)]
    pub denylist: DenylistConfig,

    /// Streaming configuration.
    #[serde(default)]
    pub streaming: StreamingConfig,

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
            allowlist: AllowlistConfig::default(),
            denylist: DenylistConfig::default(),
            streaming: StreamingConfig::default(),
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
                id: "secret_anthropic_api_key",
                category: SensitiveCategory::Secret,
                data_type: "anthropic_api_key",
                confidence: 0.99,
                strategy: RedactionStrategy::Full,
                regex: Regex::new(r"sk-ant-api03-[A-Za-z0-9_-]{93}").unwrap(),
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
            CompiledPattern {
                id: "secret_jwt",
                category: SensitiveCategory::Secret,
                data_type: "jwt",
                confidence: 0.8,
                strategy: RedactionStrategy::Full,
                regex: Regex::new(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
                    .unwrap(),
            },
            CompiledPattern {
                id: "secret_password_assignment",
                category: SensitiveCategory::Secret,
                data_type: "password",
                confidence: 0.7,
                strategy: RedactionStrategy::Full,
                regex: Regex::new(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*\S{6,}").unwrap(),
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
                id: "internal_private_ip",
                category: SensitiveCategory::Internal,
                data_type: "internal_ip",
                confidence: 0.8,
                strategy: RedactionStrategy::TypeLabel,
                regex: Regex::new(
                    r"\b(?:10|192\.168|172\.(?:1[6-9]|2[0-9]|3[0-1]))\.[0-9]{1,3}\.[0-9]{1,3}\b",
                )
                .unwrap(),
            },
            CompiledPattern {
                id: "internal_windows_path",
                category: SensitiveCategory::Internal,
                data_type: "windows_path",
                confidence: 0.7,
                strategy: RedactionStrategy::TypeLabel,
                regex: Regex::new(r"(?i)\b[A-Z]:\\(?:[^\\\s]+\\)*[^\\\s]+\b").unwrap(),
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

fn compile_regex_list(patterns: &[String]) -> Vec<Regex> {
    patterns
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
}

fn is_obviously_test_credential(value: &str) -> bool {
    // Conservative: only treat obviously placeholder tokens as allowlisted.
    // This is opt-in via `allow_test_credentials`.
    let lower = value.to_ascii_lowercase();

    // Common example markers.
    if lower.contains("example") || lower.contains("dummy") {
        return true;
    }

    // "All one character" bodies for known key prefixes.
    let is_repeated = |s: &str| s.chars().all(|c| Some(c) == s.chars().next());

    if let Some(rest) = lower.strip_prefix("sk-") {
        return rest.len() >= 16 && is_repeated(rest);
    }
    for prefix in ["ghp_", "ghs_", "gho_", "ghu_"] {
        if let Some(rest) = lower.strip_prefix(prefix) {
            return rest.len() >= 16 && is_repeated(rest);
        }
    }
    if let Some(rest) = lower.strip_prefix("akia") {
        return rest.len() >= 8 && is_repeated(rest);
    }

    false
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

fn is_luhn_valid_card_number(text: &str) -> bool {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|b| b.is_ascii_digit())
        .map(|b| (b - b'0') as u8)
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
    sum % 10 == 0
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
#[derive(Clone)]
pub struct OutputSanitizer {
    config: OutputSanitizerConfig,
    allowlist_patterns: Vec<Regex>,
    denylist_patterns: Vec<(String, Regex)>,
    entity_recognizer: Option<Arc<dyn EntityRecognizer>>,
}

impl std::fmt::Debug for OutputSanitizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputSanitizer")
            .field("config", &self.config)
            .field("allowlist_patterns", &self.allowlist_patterns.len())
            .field("denylist_patterns", &self.denylist_patterns.len())
            .field("entity_recognizer", &self.entity_recognizer.is_some())
            .finish()
    }
}

impl OutputSanitizer {
    pub fn new() -> Self {
        Self::with_config(OutputSanitizerConfig::default())
    }

    pub fn with_config(config: OutputSanitizerConfig) -> Self {
        let allowlist_patterns = compile_regex_list(&config.allowlist.patterns);
        let denylist_patterns = config
            .denylist
            .patterns
            .iter()
            .filter_map(|pattern| {
                Regex::new(pattern).ok().map(|re| {
                    let id = format!("denylist_{}", sha256(pattern.as_bytes()).to_hex());
                    (id, re)
                })
            })
            .collect();

        Self {
            config,
            allowlist_patterns,
            denylist_patterns,
            entity_recognizer: None,
        }
    }

    pub fn with_entity_recognizer<R>(mut self, recognizer: R) -> Self
    where
        R: EntityRecognizer + 'static,
    {
        self.entity_recognizer = Some(Arc::new(recognizer));
        self
    }

    pub fn config(&self) -> &OutputSanitizerConfig {
        &self.config
    }

    pub fn create_stream(&self) -> SanitizationStream {
        SanitizationStream::new(self.clone())
    }

    fn is_allowlisted(&self, s: &str) -> bool {
        if self.config.allowlist.exact.iter().any(|x| x == s) {
            return true;
        }
        if self
            .allowlist_patterns
            .iter()
            .any(|re| re.is_match(s))
        {
            return true;
        }
        self.config.allowlist.allow_test_credentials && is_obviously_test_credential(s)
    }

    pub fn sanitize_sync(&self, output: &str) -> SanitizationResult {
        let start = std::time::Instant::now();

        let mut stats = ProcessingStats::default();
        stats.input_length = output.len();

        let (limited, truncated) = truncate_to_char_boundary(output, self.config.max_input_bytes);

        let mut findings: Vec<SensitiveDataFinding> = Vec::new();
        let mut redactions: Vec<Redaction> = Vec::new();

        // Denylist patterns (forced redaction).
        for (id, re) in &self.denylist_patterns {
            for m in re.find_iter(limited) {
                let span = Span {
                    start: m.start(),
                    end: m.end(),
                };
                findings.push(SensitiveDataFinding {
                    id: id.clone(),
                    category: SensitiveCategory::Secret,
                    data_type: "denylist".to_string(),
                    confidence: 0.95,
                    span,
                    preview: preview_redacted(m.as_str()),
                    detector: DetectorType::Custom("denylist".to_string()),
                    recommended_action: RedactionStrategy::Full,
                });
            }
        }

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
                if p.id == "pii_credit_card" && !is_luhn_valid_card_number(m.as_str()) {
                    continue;
                }
                if self.is_allowlisted(m.as_str()) {
                    continue;
                }
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

        // Optional entity recognizer hook for richer PII detection.
        if self.config.categories.pii {
            if let Some(recognizer) = self.entity_recognizer.as_ref() {
                for ent in recognizer.detect(limited) {
                    let span = ent.span;
                    if span.start >= span.end || span.end > limited.len() {
                        continue;
                    }
                    if !limited.is_char_boundary(span.start) || !limited.is_char_boundary(span.end) {
                        continue;
                    }
                    let raw = &limited[span.start..span.end];
                    if self.is_allowlisted(raw) {
                        continue;
                    }
                    findings.push(SensitiveDataFinding {
                        id: format!(
                            "pii_entity_{}",
                            ent.entity_type.to_ascii_lowercase().replace(' ', "_")
                        ),
                        category: SensitiveCategory::Pii,
                        data_type: ent.entity_type,
                        confidence: ent.confidence.clamp(0.0, 1.0),
                        span,
                        preview: preview_redacted(raw),
                        detector: DetectorType::Entity,
                        recommended_action: RedactionStrategy::Partial,
                    });
                }
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
                if self.is_allowlisted(token) {
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

/// Streaming sanitizer for incremental output.
#[derive(Clone)]
pub struct SanitizationStream {
    sanitizer: OutputSanitizer,
    raw_buffer: String,
    findings: Vec<SensitiveDataFinding>,
    redactions: Vec<Redaction>,
    input_bytes: usize,
    output_bytes: usize,
    raw_offset: usize,
    was_redacted: bool,
    started_at: std::time::Instant,
}

impl std::fmt::Debug for SanitizationStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SanitizationStream")
            .field("raw_buffer_len", &self.raw_buffer.len())
            .field("findings_len", &self.findings.len())
            .field("redactions_len", &self.redactions.len())
            .field("input_bytes", &self.input_bytes)
            .field("output_bytes", &self.output_bytes)
            .field("raw_offset", &self.raw_offset)
            .field("was_redacted", &self.was_redacted)
            .finish()
    }
}

impl SanitizationStream {
    fn new(sanitizer: OutputSanitizer) -> Self {
        Self {
            sanitizer,
            raw_buffer: String::new(),
            findings: Vec::new(),
            redactions: Vec::new(),
            input_bytes: 0,
            output_bytes: 0,
            raw_offset: 0,
            was_redacted: false,
            started_at: std::time::Instant::now(),
        }
    }

    /// Write a chunk and return a sanitized prefix that is safe to emit (may be empty).
    pub fn write(&mut self, chunk: &str) -> String {
        self.input_bytes = self.input_bytes.saturating_add(chunk.len());
        if !self.sanitizer.config.streaming.enabled {
            // Streaming disabled: sanitize each chunk independently.
            let r = self.sanitizer.sanitize_sync(chunk);
            let out = self.absorb_result(r, self.raw_offset);
            self.raw_offset = self.raw_offset.saturating_add(chunk.len());
            return out;
        }

        self.raw_buffer.push_str(chunk);

        let max_buffer = self
            .sanitizer
            .config
            .streaming
            .buffer_size
            .min(self.sanitizer.config.max_input_bytes)
            .max(1);

        let mut out = String::new();
        // Ensure the buffer stays bounded. In forced mode, we may flush even if it reduces lookback.
        while self.raw_buffer.len() > max_buffer {
            out.push_str(&self.drain_ready(true));
            if self.raw_buffer.len() <= max_buffer {
                break;
            }
        }
        out.push_str(&self.drain_ready(false));
        out
    }

    /// Flush any remaining buffer and return the final sanitized chunk.
    pub fn flush(&mut self) -> String {
        if self.raw_buffer.is_empty() {
            return String::new();
        }

        let prefix = std::mem::take(&mut self.raw_buffer);
        let r = self.sanitizer.sanitize_sync(&prefix);
        let out = self.absorb_result(r, self.raw_offset);
        self.raw_offset = self.raw_offset.saturating_add(prefix.len());
        out
    }

    pub fn get_findings(&self) -> &[SensitiveDataFinding] {
        &self.findings
    }

    /// End the stream: flush remaining content and return a summary result.
    ///
    /// Note: `sanitized` contains only the final flushed chunk; callers should concatenate the
    /// outputs returned from `write()`/`flush()` to reconstruct the full sanitized stream.
    pub fn end(mut self) -> SanitizationResult {
        let final_chunk = self.flush();
        let findings_count = self.findings.len();
        let redactions_count = self.redactions.len();
        let findings = self.findings;
        let redactions = self.redactions;

        SanitizationResult {
            sanitized: final_chunk,
            was_redacted: self.was_redacted,
            findings,
            redactions,
            stats: ProcessingStats {
                input_length: self.input_bytes,
                output_length: self.output_bytes,
                findings_count,
                redactions_count,
                processing_time_ms: self.started_at.elapsed().as_secs_f64() * 1000.0,
            },
        }
    }

    fn drain_ready(&mut self, force: bool) -> String {
        let carry = self.sanitizer.config.streaming.carry_bytes.max(1);
        if self.raw_buffer.len() <= carry {
            return String::new();
        }

        let mut cutoff = if force {
            self.raw_buffer.len()
        } else {
            self.raw_buffer.len().saturating_sub(carry)
        };
        while cutoff > 0 && !self.raw_buffer.is_char_boundary(cutoff) {
            cutoff = cutoff.saturating_sub(1);
        }

        if cutoff == 0 {
            return String::new();
        }

        // Find redaction spans in the current buffer so we don't cut inside a finding.
        let scan = self.sanitizer.sanitize_sync(&self.raw_buffer);
        let mut spans: Vec<Span> = scan
            .redactions
            .iter()
            .map(|r| r.original_span)
            .collect();
        spans.sort_by_key(|s| (s.start, s.end));

        // Merge overlaps.
        let mut merged: Vec<Span> = Vec::new();
        for s in spans {
            if let Some(last) = merged.last_mut() {
                if s.start <= last.end {
                    last.end = last.end.max(s.end);
                    continue;
                }
            }
            merged.push(s);
        }

        // If the cutoff lands inside a merged span, move it to the start of that span.
        for span in &merged {
            if span.start < cutoff && cutoff < span.end {
                cutoff = span.start;
                while cutoff > 0 && !self.raw_buffer.is_char_boundary(cutoff) {
                    cutoff = cutoff.saturating_sub(1);
                }
                break;
            }
        }

        if cutoff == 0 {
            // Forced mode fallback: emit the full buffer sanitized so we don't stall.
            if force {
                return self.flush();
            }
            return String::new();
        }

        let prefix: String = self.raw_buffer.drain(..cutoff).collect();
        let r = self.sanitizer.sanitize_sync(&prefix);
        let out = self.absorb_result(r, self.raw_offset);
        self.raw_offset = self.raw_offset.saturating_add(prefix.len());
        out
    }

    fn absorb_result(&mut self, mut r: SanitizationResult, offset: usize) -> String {
        self.was_redacted = self.was_redacted || r.was_redacted;

        for f in &mut r.findings {
            f.span.start = f.span.start.saturating_add(offset);
            f.span.end = f.span.end.saturating_add(offset);
        }
        for red in &mut r.redactions {
            red.original_span.start = red.original_span.start.saturating_add(offset);
            red.original_span.end = red.original_span.end.saturating_add(offset);
        }

        self.output_bytes = self.output_bytes.saturating_add(r.sanitized.len());
        self.findings.extend(r.findings);
        self.redactions.extend(r.redactions);
        r.sanitized
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

    #[test]
    fn allowlist_skips_redaction() {
        let mut cfg = OutputSanitizerConfig::default();
        cfg.allowlist.exact = vec!["alice@example.com".to_string()];
        let s = OutputSanitizer::with_config(cfg);

        let input = "alice@example.com";
        let r = s.sanitize_sync(input);
        assert!(!r.was_redacted);
        assert_eq!(r.sanitized, input);
    }

    #[test]
    fn denylist_forces_redaction() {
        let mut cfg = OutputSanitizerConfig::default();
        cfg.denylist.patterns = vec!["SECRET_PHRASE_123".to_string()];
        let s = OutputSanitizer::with_config(cfg);

        let input = "ok SECRET_PHRASE_123 bye";
        let r = s.sanitize_sync(input);
        assert!(r.was_redacted);
        assert!(!r.sanitized.contains("SECRET_PHRASE_123"));
        assert!(r.sanitized.contains("[REDACTED:denylist]"));
    }

    #[test]
    fn streaming_sanitizer_redacts_across_chunks() {
        let s = OutputSanitizer::new();
        let mut stream = s.create_stream();

        let key = format!("sk-{}", "a".repeat(48));
        let chunk1 = &key[..10];
        let chunk2 = &key[10..];

        let out1 = stream.write(chunk1);
        let out2 = stream.write(chunk2);
        let out3 = stream.flush();

        let combined = format!("{out1}{out2}{out3}");
        assert!(!combined.contains(&key));
        assert!(combined.contains("[REDACTED:openai_api_key]"));
    }

    #[test]
    fn streaming_disabled_sanitizes_per_chunk_without_buffering() {
        let mut cfg = OutputSanitizerConfig::default();
        cfg.streaming.enabled = false;
        let s = OutputSanitizer::with_config(cfg);
        let mut stream = s.create_stream();

        let key = format!("sk-{}", "a".repeat(48));
        let out1 = stream.write(&format!("hello {key} bye"));
        let out2 = stream.flush();
        let out3 = stream.end().sanitized;

        assert!(!out1.contains(&key));
        assert!(out1.contains("[REDACTED:openai_api_key]"));
        assert!(out2.is_empty());
        assert!(out3.is_empty());
    }

    #[test]
    fn credit_card_detection_requires_luhn_validity() {
        let s = OutputSanitizer::new();
        let valid = "card=4111 1111 1111 1111";
        let invalid = "card=4111 1111 1111 1112";

        let r_valid = s.sanitize_sync(valid);
        assert!(r_valid.was_redacted);
        assert!(!r_valid.sanitized.contains("4111 1111 1111 1111"));

        let r_invalid = s.sanitize_sync(invalid);
        assert!(!r_invalid.was_redacted);
        assert_eq!(r_invalid.sanitized, invalid);
    }
}
