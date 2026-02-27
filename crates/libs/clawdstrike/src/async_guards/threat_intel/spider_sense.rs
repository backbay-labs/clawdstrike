//! Spider-Sense two-tier screening AsyncGuard.
//!
//! Implements hierarchical threat detection:
//! 1. **Fast path**: Vector similarity against a pattern database
//! 2. **Deep path**: LLM reasoning for ambiguous cases
//!
//! Based on the Spider-Sense paper (Yu et al., Feb 2026) taxonomy:
//! four semantic stages (perception, cognition, action, feedback) ×
//! nine attack types.

use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Method, Url};
use serde::Deserialize;

use hush_core::sha256;

use crate::async_guards::http::{HttpClient, HttpRequestPolicy};
use crate::async_guards::types::{
    AsyncGuard, AsyncGuardConfig, AsyncGuardError, AsyncGuardErrorKind,
};
use crate::guards::{GuardAction, GuardContext, GuardResult, Severity};

// ── Configuration ───────────────────────────────────────────────────────

const DEFAULT_SIMILARITY_THRESHOLD: f64 = 0.85;
const DEFAULT_AMBIGUITY_BAND: f64 = 0.10;
const DEFAULT_TOP_K: usize = 5;

/// Policy-level configuration for the Spider-Sense guard.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpiderSensePolicyConfig {
    /// URL of the embedding API (OpenAI-compatible POST /embeddings).
    pub embedding_api_url: String,
    /// API key for the embedding service.
    pub embedding_api_key: String,
    /// Embedding model name (e.g. `"text-embedding-3-small"`).
    pub embedding_model: String,

    /// Cosine similarity threshold above which a match is considered a threat.
    /// Default: 0.85
    #[serde(default = "default_similarity_threshold")]
    pub similarity_threshold: f64,
    /// Half-width of the ambiguity band around the threshold.
    /// Default: 0.10
    #[serde(default = "default_ambiguity_band")]
    pub ambiguity_band: f64,

    /// Path to the external JSON pattern database file.
    pub pattern_db_path: String,

    /// Optional LLM API URL for the deep reasoning path.
    #[serde(default)]
    pub llm_api_url: Option<String>,
    /// Optional LLM API key.
    #[serde(default)]
    pub llm_api_key: Option<String>,
    /// Optional LLM model name.
    #[serde(default)]
    pub llm_model: Option<String>,
}

fn default_similarity_threshold() -> f64 {
    DEFAULT_SIMILARITY_THRESHOLD
}

fn default_ambiguity_band() -> f64 {
    DEFAULT_AMBIGUITY_BAND
}

// ── Pattern Database ────────────────────────────────────────────────────

/// A single entry in the pattern database.
#[derive(Clone, Debug, Deserialize)]
pub struct PatternEntry {
    /// Unique identifier for this pattern.
    pub id: String,
    /// Attack category (e.g. `"prompt_injection"`, `"data_exfiltration"`).
    pub category: String,
    /// Spider-Sense stage: perception, cognition, action, feedback.
    pub stage: String,
    /// Human-readable label.
    pub label: String,
    /// Pre-computed embedding vector.
    pub embedding: Vec<f32>,
}

/// A scored match from the pattern database.
#[derive(Clone, Debug)]
pub struct PatternMatch {
    pub entry: PatternEntry,
    pub score: f64,
}

/// In-memory pattern database for vector similarity search.
#[derive(Clone, Debug)]
pub struct PatternDb {
    entries: Vec<PatternEntry>,
    expected_dim: Option<usize>,
}

impl PatternDb {
    /// Load from a JSON file. Returns an error if parsing fails or dimensions
    /// are inconsistent.
    pub fn load_from_json(path: &str) -> Result<Self, String> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read pattern DB at {path}: {e}"))?;
        Self::parse_json(&data)
    }

    /// Parse a JSON string containing a pattern array.
    pub fn parse_json(json: &str) -> Result<Self, String> {
        let entries: Vec<PatternEntry> =
            serde_json::from_str(json).map_err(|e| format!("failed to parse pattern DB: {e}"))?;

        if entries.is_empty() {
            return Ok(Self {
                entries,
                expected_dim: None,
            });
        }

        let dim = entries[0].embedding.len();
        if dim == 0 {
            return Err("pattern DB entries must have non-empty embeddings".to_string());
        }

        for (i, entry) in entries.iter().enumerate() {
            if entry.embedding.len() != dim {
                return Err(format!(
                    "pattern DB dimension mismatch at index {i}: expected {dim}, got {}",
                    entry.embedding.len()
                ));
            }
        }

        Ok(Self {
            entries,
            expected_dim: Some(dim),
        })
    }

    /// Brute-force cosine similarity search. Returns the top-k matches sorted
    /// by descending similarity score.
    pub fn search(&self, query: &[f32], top_k: usize) -> Vec<PatternMatch> {
        let mut scored: Vec<PatternMatch> = self
            .entries
            .iter()
            .map(|entry| {
                let score = cosine_similarity_f32(query, &entry.embedding);
                PatternMatch {
                    entry: entry.clone(),
                    score,
                }
            })
            .collect();

        // Sort descending by score.
        scored.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scored.truncate(top_k);
        scored
    }

    /// Number of entries in the database.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Expected embedding dimension, if known.
    pub fn expected_dim(&self) -> Option<usize> {
        self.expected_dim
    }
}

// ── Cosine Similarity ───────────────────────────────────────────────────

/// Compute cosine similarity between two f32 vectors, using f64 precision
/// for the accumulation. Returns 0.0 if either vector has zero norm.
pub fn cosine_similarity_f32(a: &[f32], b: &[f32]) -> f64 {
    if a.len() != b.len() {
        return 0.0;
    }

    let mut dot: f64 = 0.0;
    let mut norm_a: f64 = 0.0;
    let mut norm_b: f64 = 0.0;

    for (x, y) in a.iter().zip(b.iter()) {
        let xd = f64::from(*x);
        let yd = f64::from(*y);
        dot += xd * yd;
        norm_a += xd * xd;
        norm_b += yd * yd;
    }

    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom == 0.0 {
        return 0.0;
    }

    dot / denom
}

// ── Guard Implementation ────────────────────────────────────────────────

/// Spider-Sense AsyncGuard implementing two-tier screening.
pub struct SpiderSenseGuard {
    cfg: SpiderSensePolicyConfig,
    async_cfg: AsyncGuardConfig,
    pattern_db: PatternDb,
    upper_bound: f64,
    lower_bound: f64,
    request_policy: HttpRequestPolicy,
    llm_request_policy: Option<HttpRequestPolicy>,
}

impl SpiderSenseGuard {
    /// Create a new SpiderSenseGuard. Fails if the pattern DB cannot be loaded.
    pub fn new(cfg: SpiderSensePolicyConfig, async_cfg: AsyncGuardConfig) -> Result<Self, String> {
        let pattern_db = PatternDb::load_from_json(&cfg.pattern_db_path)?;

        let upper_bound = cfg.similarity_threshold + cfg.ambiguity_band;
        let lower_bound = cfg.similarity_threshold - cfg.ambiguity_band;

        let request_policy = embedding_request_policy(&cfg.embedding_api_url)?;
        let llm_request_policy = cfg
            .llm_api_url
            .as_deref()
            .map(embedding_request_policy)
            .transpose()?;

        Ok(Self {
            cfg,
            async_cfg,
            pattern_db,
            upper_bound,
            lower_bound,
            request_policy,
            llm_request_policy,
        })
    }

    /// Construct from an already-parsed pattern DB (useful for testing).
    pub fn with_pattern_db(
        cfg: SpiderSensePolicyConfig,
        async_cfg: AsyncGuardConfig,
        pattern_db: PatternDb,
    ) -> Result<Self, String> {
        let upper_bound = cfg.similarity_threshold + cfg.ambiguity_band;
        let lower_bound = cfg.similarity_threshold - cfg.ambiguity_band;

        let request_policy = embedding_request_policy(&cfg.embedding_api_url)?;
        let llm_request_policy = cfg
            .llm_api_url
            .as_deref()
            .map(embedding_request_policy)
            .transpose()?;

        Ok(Self {
            cfg,
            async_cfg,
            pattern_db,
            upper_bound,
            lower_bound,
            request_policy,
            llm_request_policy,
        })
    }

    /// Serialize an action into a text representation for embedding.
    fn action_to_text(action: &GuardAction<'_>, context: &GuardContext) -> String {
        match action {
            GuardAction::Custom(action_type, payload) => {
                format!("[{}] {}", action_type, payload)
            }
            GuardAction::McpTool(name, args) => {
                format!("[mcp_tool:{}] {}", name, args)
            }
            GuardAction::ShellCommand(cmd) => {
                format!("[shell_command] {}", cmd)
            }
            GuardAction::FileWrite(path, content) => {
                let preview = String::from_utf8_lossy(&content[..content.len().min(512)]);
                format!("[file_write:{}] {}", path, preview)
            }
            GuardAction::NetworkEgress(host, port) => {
                let url = context
                    .metadata
                    .as_ref()
                    .and_then(|m| m.pointer("/policy_event/network/url"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(host);
                format!("[network_egress:{}:{}] {}", host, port, url)
            }
            GuardAction::FileAccess(path) => {
                format!("[file_access] {}", path)
            }
            GuardAction::Patch(file, diff) => {
                let preview = truncate_str(diff, 512);
                format!("[patch:{}] {}", file, preview)
            }
        }
    }

    /// Call the embedding API and return the embedding vector.
    async fn get_embedding(
        &self,
        text: &str,
        http: &HttpClient,
    ) -> Result<Vec<f32>, AsyncGuardError> {
        let body = serde_json::json!({
            "input": text,
            "model": self.cfg.embedding_model,
        });

        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {}", self.cfg.embedding_api_key))
                .map_err(|e| AsyncGuardError::new(AsyncGuardErrorKind::Other, e.to_string()))?,
        );

        let resp = http
            .request_json(
                self.name(),
                Method::POST,
                &self.cfg.embedding_api_url,
                headers,
                Some(body),
                &self.request_policy,
            )
            .await?;

        if resp.status != 200 {
            return Err(AsyncGuardError::new(
                AsyncGuardErrorKind::Http,
                format!("embedding API returned status {}", resp.status),
            )
            .with_status(resp.status));
        }

        // Parse OpenAI-compatible response: { data: [{ embedding: [...] }] }
        let embedding = resp
            .json
            .pointer("/data/0/embedding")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                AsyncGuardError::new(
                    AsyncGuardErrorKind::Parse,
                    "embedding API response missing data[0].embedding array",
                )
            })?;

        let vec: Vec<f32> = embedding
            .iter()
            .enumerate()
            .map(|(i, v)| {
                v.as_f64()
                    .map(|f| f as f32)
                    .ok_or_else(|| {
                        AsyncGuardError::new(
                            AsyncGuardErrorKind::Parse,
                            format!("embedding element at index {i} is not a number: {v}"),
                        )
                    })
            })
            .collect::<Result<Vec<f32>, _>>()?;

        if vec.is_empty() {
            return Err(AsyncGuardError::new(
                AsyncGuardErrorKind::Parse,
                "embedding API returned empty vector",
            ));
        }

        Ok(vec)
    }

    /// Call the LLM for deep reasoning on ambiguous inputs.
    async fn deep_reasoning(
        &self,
        text: &str,
        top_matches: &[PatternMatch],
        http: &HttpClient,
    ) -> Result<GuardResult, AsyncGuardError> {
        let llm_url = self.cfg.llm_api_url.as_deref().ok_or_else(|| {
            AsyncGuardError::new(AsyncGuardErrorKind::Other, "LLM not configured")
        })?;
        let llm_key = self.cfg.llm_api_key.as_deref().ok_or_else(|| {
            AsyncGuardError::new(AsyncGuardErrorKind::Other, "LLM API key not configured")
        })?;
        let llm_model = self
            .cfg
            .llm_model
            .as_deref()
            .unwrap_or("claude-haiku-4-5-20251001");

        let policy = self.llm_request_policy.as_ref().ok_or_else(|| {
            AsyncGuardError::new(AsyncGuardErrorKind::Other, "LLM request policy not set")
        })?;

        let match_descriptions: Vec<String> = top_matches
            .iter()
            .map(|m| {
                format!(
                    "- {} (category={}, stage={}, score={:.3})",
                    m.entry.label, m.entry.category, m.entry.stage, m.score
                )
            })
            .collect();

        let prompt = format!(
            "You are a security analyst evaluating whether an AI agent action is malicious.\n\n\
             Action text:\n{text}\n\n\
             Similar known attack patterns:\n{}\n\n\
             Respond with a JSON object:\n\
             - {{ \"verdict\": \"deny\", \"reason\": \"...\" }} if clearly malicious\n\
             - {{ \"verdict\": \"warn\", \"reason\": \"...\" }} if suspicious but uncertain\n\
             - {{ \"verdict\": \"sanitize\", \"reason\": \"...\", \"sanitized_text\": \"...\" }} if safe after removing/replacing dangerous parts\n\
             - {{ \"verdict\": \"allow\", \"reason\": \"...\" }} if clearly benign",
            match_descriptions.join("\n")
        );

        let body = serde_json::json!({
            "model": llm_model,
            "max_tokens": 256,
            "messages": [
                { "role": "user", "content": prompt }
            ]
        });

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-api-key",
            HeaderValue::from_str(llm_key)
                .map_err(|e| AsyncGuardError::new(AsyncGuardErrorKind::Other, e.to_string()))?,
        );
        headers.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));

        let resp = http
            .request_json(
                self.name(),
                Method::POST,
                llm_url,
                headers,
                Some(body),
                policy,
            )
            .await?;

        if resp.status != 200 {
            return Err(AsyncGuardError::new(
                AsyncGuardErrorKind::Http,
                format!("LLM API returned status {}", resp.status),
            )
            .with_status(resp.status));
        }

        // Parse Anthropic messages response.
        let content_text = resp
            .json
            .pointer("/content/0/text")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Try to parse as JSON verdict.
        if let Ok(verdict) = serde_json::from_str::<LlmVerdict>(content_text) {
            return Ok(match verdict.verdict.as_str() {
                "deny" => GuardResult::block(
                    self.name(),
                    Severity::Error,
                    format!(
                        "Spider-Sense deep analysis: threat confirmed — {}",
                        verdict.reason
                    ),
                )
                .with_details(serde_json::json!({
                    "analysis": "deep_path",
                    "verdict": "deny",
                    "reason": verdict.reason,
                    "top_matches": format_matches(top_matches),
                })),
                "warn" => GuardResult::warn(
                    self.name(),
                    format!(
                        "Spider-Sense deep analysis: potential threat — {}",
                        verdict.reason
                    ),
                )
                .with_details(serde_json::json!({
                    "analysis": "deep_path",
                    "verdict": "warn",
                    "reason": verdict.reason,
                    "top_matches": format_matches(top_matches),
                })),
                "sanitize" => GuardResult::sanitize(
                    self.name(),
                    format!(
                        "Spider-Sense deep analysis: safe after sanitization — {}",
                        verdict.reason
                    ),
                    text.to_string(),
                    verdict.sanitized_text.clone().unwrap_or_default(),
                )
                .with_details(serde_json::json!({
                    "action": "sanitized",
                    "original": text,
                    "sanitized": verdict.sanitized_text,
                    "analysis": "deep_path",
                    "verdict": "sanitize",
                    "reason": verdict.reason,
                    "top_matches": format_matches(top_matches),
                })),
                other => GuardResult::warn(
                    self.name(),
                    format!(
                        "Spider-Sense: unknown LLM verdict '{}'; treating as suspicious",
                        other
                    ),
                )
                .with_details(serde_json::json!({
                    "analysis": "deep_path",
                    "verdict": "warn",
                    "original_verdict": other,
                    "reason": verdict.reason,
                    "top_matches": format_matches(top_matches),
                })),
            });
        }

        // Could not parse LLM response — fail closed with a warning.
        Ok(GuardResult::warn(
            self.name(),
            "Spider-Sense: LLM response could not be parsed; treating as ambiguous",
        )
        .with_details(serde_json::json!({
            "analysis": "deep_path",
            "parse_error": true,
            "raw_content": truncate_str(content_text, 200),
            "top_matches": format_matches(top_matches),
        })))
    }
}

#[derive(Deserialize)]
struct LlmVerdict {
    verdict: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    sanitized_text: Option<String>,
}

#[async_trait]
impl AsyncGuard for SpiderSenseGuard {
    fn name(&self) -> &str {
        "clawdstrike-spider-sense"
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        match action {
            GuardAction::Custom(action_type, _) => action_type.starts_with("risk_signal."),
            GuardAction::McpTool(_, _)
            | GuardAction::ShellCommand(_)
            | GuardAction::FileWrite(_, _) => true,
            _ => false,
        }
    }

    fn config(&self) -> &AsyncGuardConfig {
        &self.async_cfg
    }

    fn cache_key(&self, action: &GuardAction<'_>, _context: &GuardContext) -> Option<String> {
        let text = Self::action_to_text(action, _context);
        let hash = sha256(text.as_bytes()).to_hex();
        Some(format!("spider_sense:{}", hash))
    }

    async fn check_uncached(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
        http: &HttpClient,
    ) -> Result<GuardResult, AsyncGuardError> {
        // 1. Serialize action to text.
        let text = Self::action_to_text(action, context);

        // Short-circuit if pattern DB is empty (nothing to compare against).
        if self.pattern_db.is_empty() {
            return Ok(
                GuardResult::allow(self.name()).with_details(serde_json::json!({
                    "analysis": "skip",
                    "reason": "empty_pattern_db",
                })),
            );
        }

        // 2. Get embedding from API.
        let query_embedding = self.get_embedding(&text, http).await?;

        // 2b. Validate embedding dimensions match the pattern DB.
        if let Some(expected_dim) = self.pattern_db.expected_dim() {
            if query_embedding.len() != expected_dim {
                return Err(AsyncGuardError::new(
                    AsyncGuardErrorKind::Parse,
                    format!(
                        "embedding dimension mismatch: API returned {} dims, pattern DB expects {}",
                        query_embedding.len(),
                        expected_dim
                    ),
                ));
            }
        }

        // 3. Search pattern DB.
        let matches = self.pattern_db.search(&query_embedding, DEFAULT_TOP_K);
        let top_score = matches.first().map(|m| m.score).unwrap_or(0.0);

        // 4. Decision based on score bands.
        if top_score >= self.upper_bound {
            // Clear threat — block.
            let top = &matches[0];
            return Ok(GuardResult::block(
                self.name(),
                Severity::Error,
                format!(
                    "Spider-Sense: high similarity ({:.3}) to known attack pattern '{}' (category={}, stage={})",
                    top.score, top.entry.label, top.entry.category, top.entry.stage
                ),
            )
            .with_details(serde_json::json!({
                "analysis": "fast_path",
                "verdict": "deny",
                "top_score": top.score,
                "top_match": {
                    "id": top.entry.id,
                    "category": top.entry.category,
                    "stage": top.entry.stage,
                    "label": top.entry.label,
                },
                "top_matches": format_matches(&matches),
            })));
        }

        if top_score <= self.lower_bound {
            // Clear benign — allow.
            return Ok(
                GuardResult::allow(self.name()).with_details(serde_json::json!({
                    "analysis": "fast_path",
                    "verdict": "allow",
                    "top_score": top_score,
                    "threshold": self.cfg.similarity_threshold,
                    "top_matches": format_matches(&matches),
                })),
            );
        }

        // 5. Ambiguous zone — try deep path if LLM configured.
        if self.cfg.llm_api_url.is_some() {
            return self.deep_reasoning(&text, &matches, http).await;
        }

        // 6. Ambiguous without LLM — warn.
        Ok(GuardResult::warn(
            self.name(),
            format!(
                "Spider-Sense: ambiguous similarity ({:.3}) near threshold {:.2}; no LLM configured for deep analysis",
                top_score, self.cfg.similarity_threshold
            ),
        )
        .with_details(serde_json::json!({
            "analysis": "fast_path",
            "verdict": "warn",
            "top_score": top_score,
            "threshold": self.cfg.similarity_threshold,
            "ambiguity_band": self.cfg.ambiguity_band,
            "top_matches": format_matches(&matches),
        })))
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Truncate a `&str` to at most `max_bytes` without splitting a multi-byte
/// UTF-8 code point (which would panic on `&s[..n]`).
fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn embedding_request_policy(api_url: &str) -> Result<HttpRequestPolicy, String> {
    let parsed =
        Url::parse(api_url).map_err(|e| format!("invalid embedding API URL '{api_url}': {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("embedding API URL '{api_url}' has no host"))?
        .to_string();

    Ok(HttpRequestPolicy {
        allowed_hosts: vec![host],
        allowed_methods: vec![Method::GET, Method::POST],
        allow_insecure_http_for_loopback: true,
        max_request_size_bytes: 1_048_576,   // 1MB
        max_response_size_bytes: 10_485_760, // 10MB
        timeout: Duration::from_secs(30),
    })
}

fn format_matches(matches: &[PatternMatch]) -> serde_json::Value {
    serde_json::json!(matches
        .iter()
        .map(|m| serde_json::json!({
            "id": m.entry.id,
            "category": m.entry.category,
            "stage": m.entry.stage,
            "label": m.entry.label,
            "score": m.score,
        }))
        .collect::<Vec<_>>())
}

// ── Unit Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_identical_vectors() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        let sim = cosine_similarity_f32(&a, &b);
        assert!((sim - 1.0).abs() < 1e-10);
    }

    #[test]
    fn cosine_orthogonal_vectors() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![0.0, 1.0, 0.0];
        let sim = cosine_similarity_f32(&a, &b);
        assert!(sim.abs() < 1e-10);
    }

    #[test]
    fn cosine_opposite_vectors() {
        let a = vec![1.0, 0.0];
        let b = vec![-1.0, 0.0];
        let sim = cosine_similarity_f32(&a, &b);
        assert!((sim - (-1.0)).abs() < 1e-10);
    }

    #[test]
    fn cosine_zero_vector() {
        let a = vec![0.0, 0.0, 0.0];
        let b = vec![1.0, 2.0, 3.0];
        let sim = cosine_similarity_f32(&a, &b);
        assert_eq!(sim, 0.0);
    }

    #[test]
    fn cosine_different_lengths() {
        let a = vec![1.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        let sim = cosine_similarity_f32(&a, &b);
        assert_eq!(sim, 0.0, "Mismatched lengths should return 0");
    }

    #[test]
    fn cosine_f64_precision() {
        // Large vectors where f32 accumulation would lose precision.
        let n = 1000;
        let a: Vec<f32> = (0..n).map(|i| (i as f32) * 0.001).collect();
        let b: Vec<f32> = (0..n).map(|i| ((n - i) as f32) * 0.001).collect();
        let sim = cosine_similarity_f32(&a, &b);
        assert!(sim > 0.0 && sim < 1.0);
    }

    #[test]
    fn pattern_db_parse_valid() {
        let json = r#"[
            {
                "id": "p1",
                "category": "prompt_injection",
                "stage": "perception",
                "label": "ignore previous",
                "embedding": [0.1, 0.2, 0.3]
            },
            {
                "id": "p2",
                "category": "jailbreak",
                "stage": "perception",
                "label": "DAN prompt",
                "embedding": [0.4, 0.5, 0.6]
            }
        ]"#;

        let db = PatternDb::parse_json(json).unwrap();
        assert_eq!(db.len(), 2);
        assert_eq!(db.expected_dim(), Some(3));
    }

    #[test]
    fn pattern_db_parse_empty() {
        let db = PatternDb::parse_json("[]").unwrap();
        assert!(db.is_empty());
        assert_eq!(db.expected_dim(), None);
    }

    #[test]
    fn pattern_db_parse_dimension_mismatch() {
        let json = r#"[
            { "id": "p1", "category": "a", "stage": "b", "label": "c", "embedding": [0.1, 0.2] },
            { "id": "p2", "category": "a", "stage": "b", "label": "d", "embedding": [0.1] }
        ]"#;

        let result = PatternDb::parse_json(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("dimension mismatch"));
    }

    #[test]
    fn pattern_db_search_returns_top_k() {
        let json = r#"[
            { "id": "p1", "category": "a", "stage": "s", "label": "exact", "embedding": [1.0, 0.0, 0.0] },
            { "id": "p2", "category": "b", "stage": "s", "label": "ortho", "embedding": [0.0, 1.0, 0.0] },
            { "id": "p3", "category": "c", "stage": "s", "label": "close", "embedding": [0.9, 0.1, 0.0] }
        ]"#;
        let db = PatternDb::parse_json(json).unwrap();

        let query = vec![1.0, 0.0, 0.0];
        let results = db.search(&query, 2);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].entry.id, "p1"); // exact match first
        assert!((results[0].score - 1.0).abs() < 1e-6);
        assert_eq!(results[1].entry.id, "p3"); // close second
    }
}
