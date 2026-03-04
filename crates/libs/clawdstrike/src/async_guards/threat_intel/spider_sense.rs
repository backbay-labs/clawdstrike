//! Spider-Sense hierarchical screening AsyncGuard.
//!
//! Adapts the hierarchical screening pattern from the Spider-Sense paper
//! (Yu et al., Feb 2026) as a tool-boundary guard:
//!
//! 1. **Fast path**: Cosine similarity against a pre-computed pattern database
//! 2. **Deep path**: Optional external LLM escalation for ambiguous cases
//!
//! Note: the original paper proposes agent-intrinsic risk sensing (IRS) where
//! the agent itself maintains latent vigilance. Our adaptation applies the
//! screening hierarchy as middleware at the tool boundary — architecturally
//! different, but reusing the same fast/deep tiering and the S2Bench
//! taxonomy (four semantic stages × nine attack types).

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Method, Url};
use serde::{Deserialize, Serialize};

use hush_core::{sha256, PublicKey, Signature};

use crate::async_guards::http::{HttpClient, HttpRequestPolicy};
use crate::async_guards::types::{
    AsyncGuard, AsyncGuardConfig, AsyncGuardError, AsyncGuardErrorKind,
};
use crate::guards::{GuardAction, GuardContext, GuardResult, Severity};
use crate::spider_sense::{PatternDb, PatternMatch};
use crate::text_utils;

// ── Configuration ───────────────────────────────────────────────────────

const DEFAULT_SIMILARITY_THRESHOLD: f64 = 0.85;
const DEFAULT_AMBIGUITY_BAND: f64 = 0.10;
const DEFAULT_TOP_K: usize = 5;

/// Built-in S2Bench v1 pattern database (36 demo entries, 3-dim embeddings).
const BUILTIN_S2BENCH_V1: &str = include_str!("../../../rulesets/patterns/s2bench-v1.json");

/// Policy-level configuration for the Spider-Sense guard.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpiderSenseTrustedKeyConfig {
    /// Optional explicit key id. If omitted, SDKs may derive from public key.
    #[serde(default)]
    pub key_id: Option<String>,
    /// Public signing key (hex-encoded).
    pub public_key: String,
    /// Optional key validity start (RFC3339).
    #[serde(default)]
    pub not_before: Option<String>,
    /// Optional key validity end (RFC3339).
    #[serde(default)]
    pub not_after: Option<String>,
    /// Optional key status (`active` / `deprecated` / `revoked`).
    #[serde(default)]
    pub status: Option<String>,
}

/// Policy-level configuration for the Spider-Sense guard.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpiderSensePolicyConfig {
    /// Enable/disable Spider-Sense. Default: true.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// URL of the embedding API (OpenAI-compatible POST /embeddings).
    #[serde(default)]
    pub embedding_api_url: String,
    /// API key for the embedding service.
    #[serde(default)]
    pub embedding_api_key: String,
    /// Embedding model name (e.g. `"text-embedding-3-small"`).
    #[serde(default)]
    pub embedding_model: String,

    /// Cosine similarity threshold above which a match is considered a threat.
    /// Default: 0.85
    #[serde(default = "default_similarity_threshold")]
    pub similarity_threshold: f64,
    /// Half-width of the ambiguity band around the threshold.
    /// Default: 0.10
    #[serde(default = "default_ambiguity_band")]
    pub ambiguity_band: f64,
    /// Number of nearest-neighbor matches returned from the pattern DB.
    /// Default: 5
    #[serde(default = "default_top_k")]
    pub top_k: usize,

    /// Path to the external JSON pattern database file, or `builtin:s2bench-v1`
    /// to use the embedded demo database.
    #[serde(default)]
    pub pattern_db_path: String,
    /// Optional version label for the external pattern DB (metadata only).
    #[serde(default)]
    pub pattern_db_version: Option<String>,
    /// Optional SHA-256 checksum for the external pattern DB (metadata only).
    #[serde(default)]
    pub pattern_db_checksum: Option<String>,
    /// Optional signature over the pattern DB payload.
    #[serde(default)]
    pub pattern_db_signature: Option<String>,
    /// Optional trust-store key id for pattern DB signature verification.
    #[serde(default)]
    pub pattern_db_signature_key_id: Option<String>,
    /// Optional legacy inline public key for signature verification.
    #[serde(default)]
    pub pattern_db_public_key: Option<String>,
    /// Optional trust-store path for pattern DB signature keys.
    #[serde(default)]
    pub pattern_db_trust_store_path: Option<String>,
    /// Optional inline trusted keys for pattern DB signature verification.
    #[serde(default)]
    pub pattern_db_trusted_keys: Vec<SpiderSenseTrustedKeyConfig>,
    /// Optional signed manifest path (can provide DB path/version/checksum/signature chain).
    #[serde(default)]
    pub pattern_db_manifest_path: Option<String>,
    /// Optional trust-store path for manifest signature verification.
    #[serde(default)]
    pub pattern_db_manifest_trust_store_path: Option<String>,
    /// Optional inline trusted keys for manifest signature verification.
    #[serde(default)]
    pub pattern_db_manifest_trusted_keys: Vec<SpiderSenseTrustedKeyConfig>,

    /// Optional LLM API URL for the deep reasoning path.
    #[serde(default)]
    pub llm_api_url: Option<String>,
    /// Optional LLM API key.
    #[serde(default)]
    pub llm_api_key: Option<String>,
    /// Optional LLM model name.
    #[serde(default)]
    pub llm_model: Option<String>,
    /// Optional deep-path prompt template id.
    #[serde(default)]
    pub llm_prompt_template_id: Option<String>,
    /// Optional deep-path prompt template version.
    #[serde(default)]
    pub llm_prompt_template_version: Option<String>,
    /// Optional deep-path timeout override in milliseconds.
    #[serde(default)]
    pub llm_timeout_ms: Option<u64>,
    /// Optional deep-path failure mode (`allow` | `warn` | `deny`).
    #[serde(default)]
    pub llm_fail_mode: Option<String>,

    /// Optional async guard configuration (used when Spider-Sense is configured
    /// as a first-class field in `guards.spider_sense` rather than via
    /// `guards.custom`).
    #[serde(default, rename = "async")]
    pub async_config: Option<crate::policy::AsyncGuardPolicyConfig>,
}

fn default_similarity_threshold() -> f64 {
    DEFAULT_SIMILARITY_THRESHOLD
}

fn default_enabled() -> bool {
    true
}

fn default_ambiguity_band() -> f64 {
    DEFAULT_AMBIGUITY_BAND
}

fn default_top_k() -> usize {
    DEFAULT_TOP_K
}

impl Default for SpiderSensePolicyConfig {
    fn default() -> Self {
        Self {
            // Programmatic defaults should be inert until required fields are set.
            enabled: false,
            embedding_api_url: String::new(),
            embedding_api_key: String::new(),
            embedding_model: String::new(),
            similarity_threshold: default_similarity_threshold(),
            ambiguity_band: default_ambiguity_band(),
            top_k: default_top_k(),
            pattern_db_path: String::new(),
            pattern_db_version: None,
            pattern_db_checksum: None,
            pattern_db_signature: None,
            pattern_db_signature_key_id: None,
            pattern_db_public_key: None,
            pattern_db_trust_store_path: None,
            pattern_db_trusted_keys: vec![],
            pattern_db_manifest_path: None,
            pattern_db_manifest_trust_store_path: None,
            pattern_db_manifest_trusted_keys: vec![],
            llm_api_url: None,
            llm_api_key: None,
            llm_model: None,
            llm_prompt_template_id: None,
            llm_prompt_template_version: None,
            llm_timeout_ms: None,
            llm_fail_mode: None,
            async_config: None,
        }
    }
}

impl SpiderSensePolicyConfig {
    /// Merge a child Spider-Sense config over a base config.
    ///
    /// This public helper performs a heuristic partial merge for programmatic
    /// callers that do not have source-field presence metadata. Empty/default
    /// child values are treated as absent.
    pub fn merge_with(&self, child: &Self) -> Self {
        let mut present_fields = BTreeSet::new();

        if !child.embedding_api_url.trim().is_empty() {
            present_fields.insert("embedding_api_url".to_string());
        }
        if !child.embedding_api_key.trim().is_empty() {
            present_fields.insert("embedding_api_key".to_string());
        }
        if !child.embedding_model.trim().is_empty() {
            present_fields.insert("embedding_model".to_string());
        }
        if child.similarity_threshold != default_similarity_threshold() {
            present_fields.insert("similarity_threshold".to_string());
        }
        if child.ambiguity_band != default_ambiguity_band() {
            present_fields.insert("ambiguity_band".to_string());
        }
        if child.top_k != default_top_k() {
            present_fields.insert("top_k".to_string());
        }
        if !child.pattern_db_path.trim().is_empty() {
            present_fields.insert("pattern_db_path".to_string());
        }
        if child
            .pattern_db_version
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            present_fields.insert("pattern_db_version".to_string());
        }
        if child
            .pattern_db_checksum
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            present_fields.insert("pattern_db_checksum".to_string());
        }
        if child
            .pattern_db_signature
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            present_fields.insert("pattern_db_signature".to_string());
        }
        if child
            .pattern_db_signature_key_id
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            present_fields.insert("pattern_db_signature_key_id".to_string());
        }
        if child
            .pattern_db_public_key
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            present_fields.insert("pattern_db_public_key".to_string());
        }
        if child
            .pattern_db_trust_store_path
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            present_fields.insert("pattern_db_trust_store_path".to_string());
        }
        if !child.pattern_db_trusted_keys.is_empty() {
            present_fields.insert("pattern_db_trusted_keys".to_string());
        }
        if child
            .pattern_db_manifest_path
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            present_fields.insert("pattern_db_manifest_path".to_string());
        }
        if child
            .pattern_db_manifest_trust_store_path
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            present_fields.insert("pattern_db_manifest_trust_store_path".to_string());
        }
        if !child.pattern_db_manifest_trusted_keys.is_empty() {
            present_fields.insert("pattern_db_manifest_trusted_keys".to_string());
        }
        if child
            .llm_api_url
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            present_fields.insert("llm_api_url".to_string());
        }
        if child
            .llm_api_key
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            present_fields.insert("llm_api_key".to_string());
        }
        if child
            .llm_model
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            present_fields.insert("llm_model".to_string());
        }
        if child
            .llm_prompt_template_id
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            present_fields.insert("llm_prompt_template_id".to_string());
        }
        if child
            .llm_prompt_template_version
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            present_fields.insert("llm_prompt_template_version".to_string());
        }
        if child.llm_timeout_ms.is_some() {
            present_fields.insert("llm_timeout_ms".to_string());
        }
        if child
            .llm_fail_mode
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        {
            present_fields.insert("llm_fail_mode".to_string());
        }
        if child.async_config.is_some() {
            present_fields.insert("async".to_string());
        }

        // Heuristic merge without source-presence metadata:
        // - preserve explicit disables (`enabled=false`)
        // - allow explicit programmatic toggle-only enable overrides
        //   (`enabled=true` with all other fields at programmatic defaults)
        let explicit_programmatic_enable_toggle = child.enabled && !self.enabled && {
            let toggle_only = Self {
                enabled: true,
                ..Self::default()
            };
            child == &toggle_only
        };

        if !child.enabled || explicit_programmatic_enable_toggle {
            present_fields.insert("enabled".to_string());
        }

        self.merge_with_present_fields(child, &present_fields)
    }

    /// Merge a child Spider-Sense config over a base config using explicit
    /// field presence extracted from source policy YAML.
    pub fn merge_with_present_fields(
        &self,
        child: &Self,
        present_fields: &BTreeSet<String>,
    ) -> Self {
        if !present_fields.is_empty() {
            let has = |name: &str| present_fields.contains(name);
            return Self {
                enabled: if has("enabled") {
                    child.enabled
                } else {
                    self.enabled
                },
                embedding_api_url: if has("embedding_api_url") {
                    child.embedding_api_url.clone()
                } else {
                    self.embedding_api_url.clone()
                },
                embedding_api_key: if has("embedding_api_key") {
                    child.embedding_api_key.clone()
                } else {
                    self.embedding_api_key.clone()
                },
                embedding_model: if has("embedding_model") {
                    child.embedding_model.clone()
                } else {
                    self.embedding_model.clone()
                },
                similarity_threshold: if has("similarity_threshold") {
                    child.similarity_threshold
                } else {
                    self.similarity_threshold
                },
                ambiguity_band: if has("ambiguity_band") {
                    child.ambiguity_band
                } else {
                    self.ambiguity_band
                },
                top_k: if has("top_k") {
                    child.top_k
                } else {
                    self.top_k
                },
                pattern_db_path: if has("pattern_db_path") {
                    child.pattern_db_path.clone()
                } else {
                    self.pattern_db_path.clone()
                },
                pattern_db_version: if has("pattern_db_version") {
                    child.pattern_db_version.clone()
                } else {
                    self.pattern_db_version.clone()
                },
                pattern_db_checksum: if has("pattern_db_checksum") {
                    child.pattern_db_checksum.clone()
                } else {
                    self.pattern_db_checksum.clone()
                },
                pattern_db_signature: if has("pattern_db_signature") {
                    child.pattern_db_signature.clone()
                } else {
                    self.pattern_db_signature.clone()
                },
                pattern_db_signature_key_id: if has("pattern_db_signature_key_id") {
                    child.pattern_db_signature_key_id.clone()
                } else {
                    self.pattern_db_signature_key_id.clone()
                },
                pattern_db_public_key: if has("pattern_db_public_key") {
                    child.pattern_db_public_key.clone()
                } else {
                    self.pattern_db_public_key.clone()
                },
                pattern_db_trust_store_path: if has("pattern_db_trust_store_path") {
                    child.pattern_db_trust_store_path.clone()
                } else {
                    self.pattern_db_trust_store_path.clone()
                },
                pattern_db_trusted_keys: if has("pattern_db_trusted_keys") {
                    child.pattern_db_trusted_keys.clone()
                } else {
                    self.pattern_db_trusted_keys.clone()
                },
                pattern_db_manifest_path: if has("pattern_db_manifest_path") {
                    child.pattern_db_manifest_path.clone()
                } else {
                    self.pattern_db_manifest_path.clone()
                },
                pattern_db_manifest_trust_store_path: if has("pattern_db_manifest_trust_store_path")
                {
                    child.pattern_db_manifest_trust_store_path.clone()
                } else {
                    self.pattern_db_manifest_trust_store_path.clone()
                },
                pattern_db_manifest_trusted_keys: if has("pattern_db_manifest_trusted_keys") {
                    child.pattern_db_manifest_trusted_keys.clone()
                } else {
                    self.pattern_db_manifest_trusted_keys.clone()
                },
                llm_api_url: if has("llm_api_url") {
                    child.llm_api_url.clone()
                } else {
                    self.llm_api_url.clone()
                },
                llm_api_key: if has("llm_api_key") {
                    child.llm_api_key.clone()
                } else {
                    self.llm_api_key.clone()
                },
                llm_model: if has("llm_model") {
                    child.llm_model.clone()
                } else {
                    self.llm_model.clone()
                },
                llm_prompt_template_id: if has("llm_prompt_template_id") {
                    child.llm_prompt_template_id.clone()
                } else {
                    self.llm_prompt_template_id.clone()
                },
                llm_prompt_template_version: if has("llm_prompt_template_version") {
                    child.llm_prompt_template_version.clone()
                } else {
                    self.llm_prompt_template_version.clone()
                },
                llm_timeout_ms: if has("llm_timeout_ms") {
                    child.llm_timeout_ms
                } else {
                    self.llm_timeout_ms
                },
                llm_fail_mode: if has("llm_fail_mode") {
                    child.llm_fail_mode.clone()
                } else {
                    self.llm_fail_mode.clone()
                },
                async_config: if has("async") {
                    child.async_config.clone()
                } else {
                    self.async_config.clone()
                },
            };
        }

        // No field-presence metadata available: treat as explicit replacement.
        // Policy inheritance paths call this intentionally to avoid hidden
        // heuristics when source-level field presence is unavailable.
        child.clone()
    }
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
        let (upper_bound, lower_bound) = validate_policy_config(&cfg)?;
        let pattern_db_path = resolve_pattern_db_path(&cfg)?;
        let pattern_db = load_pattern_db(&pattern_db_path)?;

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
        let (upper_bound, lower_bound) = validate_policy_config(&cfg)?;

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
                let preview = text_utils::truncate_to_char_boundary(diff, 512).0;
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
                v.as_f64().map(|f| f as f32).ok_or_else(|| {
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
                "sanitize" => {
                    let sanitized_text = verdict
                        .sanitized_text
                        .clone()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                    match sanitized_text {
                        Some(sanitized_text) => GuardResult::sanitize(
                            self.name(),
                            format!(
                                "Spider-Sense deep analysis: safe after sanitization — {}",
                                verdict.reason
                            ),
                            text.to_string(),
                            sanitized_text.clone(),
                        )
                        .with_details(serde_json::json!({
                            "action": "sanitized",
                            "original": text,
                            "sanitized": sanitized_text,
                            "analysis": "deep_path",
                            "verdict": "sanitize",
                            "reason": verdict.reason,
                            "top_matches": format_matches(top_matches),
                        })),
                        None => GuardResult::warn(
                            self.name(),
                            "Spider-Sense: sanitize verdict missing sanitized_text; treating as suspicious",
                        )
                        .with_details(serde_json::json!({
                            "analysis": "deep_path",
                            "verdict": "warn",
                            "original_verdict": "sanitize",
                            "reason": verdict.reason,
                            "missing_sanitized_text": true,
                            "top_matches": format_matches(top_matches),
                        })),
                    }
                }
                "allow" => GuardResult::allow(self.name()).with_details(serde_json::json!({
                    "analysis": "deep_path",
                    "verdict": "allow",
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
            "raw_content": text_utils::truncate_to_char_boundary(content_text, 200).0,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PatternDbManifest {
    #[serde(default)]
    pattern_db_path: Option<String>,
    #[serde(default)]
    pattern_db_version: Option<String>,
    #[serde(default)]
    pattern_db_checksum: Option<String>,
    #[serde(default)]
    pattern_db_signature: Option<String>,
    #[serde(default)]
    pattern_db_public_key: Option<String>,
    #[serde(default)]
    pattern_db_signature_key_id: Option<String>,
    #[serde(default)]
    pattern_db_trust_store_path: Option<String>,
    #[serde(default)]
    pattern_db_trusted_keys: Vec<SpiderSenseTrustedKeyConfig>,
    #[serde(default)]
    manifest_signature: Option<String>,
    #[serde(default)]
    manifest_signature_key_id: Option<String>,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpiderSenseTrustedKeyStatus {
    Active,
    Deprecated,
    Revoked,
}

#[derive(Clone, Debug)]
struct SpiderSenseTrustedKey {
    key_id: String,
    public_key: String,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
    status: SpiderSenseTrustedKeyStatus,
}

#[derive(Default)]
struct SpiderSenseTrustStore {
    keys: HashMap<String, SpiderSenseTrustedKey>,
}

#[derive(Clone, Debug)]
struct PatternDbIntegrity {
    version: String,
    checksum: String,
    signature: String,
    public_key: String,
    signature_key_id: String,
    trust_store_path: String,
    trusted_keys: Vec<SpiderSenseTrustedKeyConfig>,
    use_trust_store: bool,
    use_legacy_key_pair: bool,
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
            | GuardAction::NetworkEgress(_, _)
            | GuardAction::FileAccess(_)
            | GuardAction::FileWrite(_, _)
            | GuardAction::Patch(_, _) => true,
        }
    }

    fn config(&self) -> &AsyncGuardConfig {
        &self.async_cfg
    }

    fn cache_key(&self, action: &GuardAction<'_>, context: &GuardContext) -> Option<String> {
        let text = Self::action_to_text(action, context);
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
        let matches = self.pattern_db.search(&query_embedding, self.cfg.top_k);
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

/// Load the pattern database from a path, supporting `builtin:*` prefixes.
fn load_pattern_db(path: &str) -> Result<PatternDb, String> {
    match path {
        "builtin:s2bench-v1" => PatternDb::parse_json(BUILTIN_S2BENCH_V1),
        _ => PatternDb::load_from_json(path),
    }
}

fn read_pattern_db_bytes(path: &str) -> Result<Vec<u8>, String> {
    match path {
        "builtin:s2bench-v1" => Ok(BUILTIN_S2BENCH_V1.as_bytes().to_vec()),
        _ => {
            std::fs::read(path).map_err(|e| format!("spider_sense: read pattern DB '{path}': {e}"))
        }
    }
}

fn normalize_hex_value(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .trim_start_matches("0x")
        .to_string()
}

fn derive_spider_sense_key_id(public_key_hex: &str) -> String {
    let normalized = normalize_hex_value(public_key_hex);
    sha256(normalized.as_bytes()).to_hex()[..16].to_string()
}

fn resolve_path_relative(base_file: &str, value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.starts_with("builtin:") {
        return trimmed.to_string();
    }
    let path = Path::new(trimmed);
    if path.is_absolute() {
        return trimmed.to_string();
    }
    let base_trimmed = base_file.trim();
    if base_trimmed.is_empty() || base_trimmed.starts_with("builtin:") {
        return trimmed.to_string();
    }
    let base_path = Path::new(base_trimmed);
    let base = if base_path.is_dir() {
        base_path
    } else {
        base_path.parent().unwrap_or_else(|| Path::new("."))
    };
    base.join(path).to_string_lossy().to_string()
}

fn parse_rfc3339(value: &str, label: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| format!("{label}: {e}"))
}

fn normalize_spider_sense_trusted_key(
    entry: &SpiderSenseTrustedKeyConfig,
) -> Result<SpiderSenseTrustedKey, String> {
    let public_key_raw = entry.public_key.trim();
    if public_key_raw.is_empty() {
        return Err("trust store entry is missing public_key".to_string());
    }
    let public_key = normalize_hex_value(public_key_raw);
    PublicKey::from_hex(&public_key).map_err(|e| format!("invalid trusted public_key: {e}"))?;

    let derived_key_id = derive_spider_sense_key_id(&public_key);
    let key_id = entry
        .key_id
        .as_deref()
        .map(normalize_hex_value)
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| derived_key_id.clone());

    let status = match entry
        .status
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "active" => SpiderSenseTrustedKeyStatus::Active,
        "deprecated" => SpiderSenseTrustedKeyStatus::Deprecated,
        "revoked" => SpiderSenseTrustedKeyStatus::Revoked,
        other => return Err(format!("unsupported trusted key status \"{other}\"")),
    };

    let not_before = entry
        .not_before
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| parse_rfc3339(v, &format!("invalid not_before for key_id \"{key_id}\"")))
        .transpose()?;
    let not_after = entry
        .not_after
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| parse_rfc3339(v, &format!("invalid not_after for key_id \"{key_id}\"")))
        .transpose()?;

    if let (Some(start), Some(end)) = (&not_before, &not_after) {
        if end < start {
            return Err(format!(
                "invalid trusted key window for key_id \"{key_id}\""
            ));
        }
    }

    Ok(SpiderSenseTrustedKey {
        key_id,
        public_key,
        not_before,
        not_after,
        status,
    })
}

fn parse_spider_sense_trust_store_file(
    raw: &str,
) -> Result<Vec<SpiderSenseTrustedKeyConfig>, String> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("parse trust store JSON: {e}"))?;
    if let Some(arr) = value.as_array() {
        return arr
            .iter()
            .cloned()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("parse trust store entry: {e}"));
    }
    if let Some(keys) = value.get("keys").and_then(|v| v.as_array()) {
        return keys
            .iter()
            .cloned()
            .map(serde_json::from_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("parse trust store entry: {e}"));
    }
    Err("trust store must be a JSON array or object with keys[]".to_string())
}

fn load_spider_sense_trust_store(
    path: &str,
    inline: &[SpiderSenseTrustedKeyConfig],
) -> Result<SpiderSenseTrustStore, String> {
    let mut store = SpiderSenseTrustStore::default();

    let mut add_entries = |entries: Vec<SpiderSenseTrustedKeyConfig>| -> Result<(), String> {
        for entry in entries {
            let normalized = normalize_spider_sense_trusted_key(&entry)?;
            store.keys.insert(normalized.key_id.clone(), normalized);
        }
        Ok(())
    };

    if !path.trim().is_empty() {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("read trust store \"{path}\": {e}"))?;
        let entries = parse_spider_sense_trust_store_file(&raw)?;
        add_entries(entries)?;
    }

    add_entries(inline.to_vec())?;
    if store.keys.is_empty() {
        return Err("trust store is empty".to_string());
    }
    Ok(store)
}

impl SpiderSenseTrustStore {
    fn select_key(
        &self,
        key_id: &str,
        now: DateTime<Utc>,
    ) -> Result<&SpiderSenseTrustedKey, String> {
        let normalized_id = normalize_hex_value(key_id);
        let key = self.keys.get(&normalized_id).ok_or_else(|| {
            format!("pattern DB signature key_id \"{normalized_id}\" not found in trust store")
        })?;
        if key.status == SpiderSenseTrustedKeyStatus::Revoked {
            return Err(format!(
                "pattern DB signature key_id \"{normalized_id}\" is revoked"
            ));
        }
        if let Some(not_before) = key.not_before.as_ref() {
            if now < *not_before {
                return Err(format!(
                    "pattern DB signature key_id \"{normalized_id}\" is not yet valid"
                ));
            }
        }
        if let Some(not_after) = key.not_after.as_ref() {
            if now > *not_after {
                return Err(format!(
                    "pattern DB signature key_id \"{normalized_id}\" is expired"
                ));
            }
        }
        Ok(key)
    }
}

fn spider_sense_trusted_keys_digest(entries: &[SpiderSenseTrustedKeyConfig]) -> String {
    if entries.is_empty() {
        return sha256(&[]).to_hex();
    }

    let mut parts: Vec<String> = entries
        .iter()
        .map(|entry| {
            format!(
                "{}|{}|{}|{}|{}",
                entry
                    .key_id
                    .as_deref()
                    .map(normalize_hex_value)
                    .unwrap_or_default(),
                normalize_hex_value(&entry.public_key),
                entry
                    .status
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
                entry
                    .not_before
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or_default(),
                entry
                    .not_after
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or_default(),
            )
        })
        .collect();
    parts.sort();
    sha256(parts.join(";").as_bytes()).to_hex()
}

fn spider_sense_manifest_signing_message(manifest: &PatternDbManifest) -> Vec<u8> {
    format!(
        "spider_sense_manifest:v1:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        manifest
            .pattern_db_path
            .as_deref()
            .map(str::trim)
            .unwrap_or_default(),
        manifest
            .pattern_db_version
            .as_deref()
            .map(str::trim)
            .unwrap_or_default(),
        normalize_hex_value(manifest.pattern_db_checksum.as_deref().unwrap_or_default()),
        normalize_hex_value(manifest.pattern_db_signature.as_deref().unwrap_or_default()),
        normalize_hex_value(
            manifest
                .pattern_db_signature_key_id
                .as_deref()
                .unwrap_or_default()
        ),
        normalize_hex_value(
            manifest
                .pattern_db_public_key
                .as_deref()
                .unwrap_or_default()
        ),
        manifest
            .pattern_db_trust_store_path
            .as_deref()
            .map(str::trim)
            .unwrap_or_default(),
        spider_sense_trusted_keys_digest(&manifest.pattern_db_trusted_keys),
        manifest
            .not_before
            .as_deref()
            .map(str::trim)
            .unwrap_or_default(),
        manifest
            .not_after
            .as_deref()
            .map(str::trim)
            .unwrap_or_default(),
    )
    .into_bytes()
}

fn verify_manifest_window(manifest: &PatternDbManifest, now: DateTime<Utc>) -> Result<(), String> {
    if let Some(raw) = manifest
        .not_before
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        let not_before =
            parse_rfc3339(raw, "spider_sense: invalid pattern DB manifest not_before")?;
        if now < not_before {
            return Err("spider_sense: pattern DB manifest not yet valid".to_string());
        }
    }
    if let Some(raw) = manifest
        .not_after
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        let not_after = parse_rfc3339(raw, "spider_sense: invalid pattern DB manifest not_after")?;
        if now > not_after {
            return Err("spider_sense: pattern DB manifest expired".to_string());
        }
    }
    Ok(())
}

fn verify_pattern_manifest_signature(
    manifest: &PatternDbManifest,
    roots_path: &str,
    inline_roots: &[SpiderSenseTrustedKeyConfig],
    now: DateTime<Utc>,
) -> Result<(), String> {
    let manifest_signature = manifest
        .manifest_signature
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    let manifest_signature_key_id = normalize_hex_value(
        manifest
            .manifest_signature_key_id
            .as_deref()
            .unwrap_or_default(),
    );
    if manifest_signature.is_empty() {
        return Err("spider_sense: pattern DB manifest missing manifest_signature".to_string());
    }
    if manifest_signature_key_id.is_empty() {
        return Err(
            "spider_sense: pattern DB manifest missing manifest_signature_key_id".to_string(),
        );
    }

    let store = load_spider_sense_trust_store(roots_path, inline_roots)
        .map_err(|e| format!("spider_sense: load pattern DB manifest trust store: {e}"))?;
    let key = store
        .select_key(&manifest_signature_key_id, now)
        .map_err(|e| format!("spider_sense: {e}"))?;
    let pk = PublicKey::from_hex(&key.public_key).map_err(|e| {
        format!(
            "spider_sense: invalid pattern DB manifest trust key material for key_id \"{}\": {e}",
            key.key_id
        )
    })?;
    let sig = Signature::from_hex(manifest_signature)
        .map_err(|e| format!("spider_sense: invalid pattern DB manifest signature: {e}"))?;
    if !pk.verify(&spider_sense_manifest_signing_message(manifest), &sig) {
        return Err(format!(
            "spider_sense: pattern DB manifest signature verification failed for key_id \"{}\"",
            key.key_id
        ));
    }
    Ok(())
}

fn required_pattern_db_integrity_fields(
    version: &str,
    checksum: &str,
    signature: &str,
    public_key: &str,
    signature_key_id: &str,
    trust_store_path: &str,
    trusted_keys: Vec<SpiderSenseTrustedKeyConfig>,
) -> Result<PatternDbIntegrity, String> {
    let version = version.trim().to_string();
    let checksum = checksum.trim().to_string();
    if version.is_empty() || checksum.is_empty() {
        return Err(
            "spider_sense: pattern_db_version and pattern_db_checksum are required when pattern_db_path is set"
                .to_string(),
        );
    }

    let signature = signature.trim().to_string();
    let public_key = public_key.trim().to_string();
    let signature_key_id = normalize_hex_value(signature_key_id);
    let trust_store_path = trust_store_path.trim().to_string();
    let use_trust_store =
        !signature_key_id.is_empty() || !trust_store_path.is_empty() || !trusted_keys.is_empty();
    let use_legacy_key_pair = !signature.is_empty() && !public_key.is_empty();

    if use_trust_store && !public_key.is_empty() {
        return Err(
            "spider_sense: pattern_db_public_key cannot be combined with trust-store based verification"
                .to_string(),
        );
    }
    if use_trust_store {
        if signature.is_empty() {
            return Err(
                "spider_sense: pattern_db_signature is required when trust-store fields are set"
                    .to_string(),
            );
        }
        if signature_key_id.is_empty() {
            return Err(
                "spider_sense: pattern_db_signature_key_id is required when trust-store fields are set"
                    .to_string(),
            );
        }
    } else if signature.is_empty() != public_key.is_empty() {
        return Err(
            "spider_sense: pattern_db_signature and pattern_db_public_key must either both be set or both be omitted"
                .to_string(),
        );
    }

    Ok(PatternDbIntegrity {
        version,
        checksum,
        signature,
        public_key,
        signature_key_id,
        trust_store_path,
        trusted_keys,
        use_trust_store,
        use_legacy_key_pair,
    })
}

fn verify_pattern_db_integrity(
    data: &[u8],
    integrity: &PatternDbIntegrity,
) -> Result<Option<String>, String> {
    let actual_checksum = sha256(data).to_hex().to_ascii_lowercase();
    let expected_checksum = normalize_hex_value(&integrity.checksum);
    if actual_checksum != expected_checksum {
        return Err(format!(
            "spider_sense: pattern DB checksum mismatch: expected {expected_checksum}, got {actual_checksum}"
        ));
    }

    let message = format!(
        "spider_sense_db:v1:{}:{expected_checksum}",
        integrity.version
    );

    if integrity.use_legacy_key_pair {
        let pk = PublicKey::from_hex(&integrity.public_key)
            .map_err(|e| format!("spider_sense: invalid pattern DB public key: {e}"))?;
        let sig = Signature::from_hex(&integrity.signature)
            .map_err(|e| format!("spider_sense: invalid pattern DB signature: {e}"))?;
        if !pk.verify(message.as_bytes(), &sig) {
            return Err("spider_sense: pattern DB signature verification failed".to_string());
        }
        return Ok(None);
    }

    if integrity.use_trust_store {
        let store =
            load_spider_sense_trust_store(&integrity.trust_store_path, &integrity.trusted_keys)
                .map_err(|e| format!("spider_sense: load trust store: {e}"))?;
        let key = store
            .select_key(&integrity.signature_key_id, Utc::now())
            .map_err(|e| format!("spider_sense: {e}"))?;
        let pk = PublicKey::from_hex(&key.public_key).map_err(|e| {
            format!(
                "spider_sense: invalid trusted key material for key_id \"{}\": {e}",
                key.key_id
            )
        })?;
        let sig = Signature::from_hex(&integrity.signature)
            .map_err(|e| format!("spider_sense: invalid pattern DB signature: {e}"))?;
        if !pk.verify(message.as_bytes(), &sig) {
            return Err(format!(
                "spider_sense: pattern DB signature verification failed for key_id \"{}\"",
                key.key_id
            ));
        }
        return Ok(Some(key.key_id.clone()));
    }

    if !integrity.signature.is_empty() || !integrity.public_key.is_empty() {
        return Err(
            "spider_sense: pattern_db_signature and pattern_db_public_key must either both be set or both be omitted"
                .to_string(),
        );
    }

    Ok(None)
}

fn resolve_pattern_db_path_from_manifest(
    cfg: &SpiderSensePolicyConfig,
    manifest_path: &str,
) -> Result<String, String> {
    let raw = std::fs::read_to_string(manifest_path)
        .map_err(|e| format!("failed to read pattern DB manifest '{manifest_path}': {e}"))?;
    let manifest: PatternDbManifest = serde_json::from_str(&raw)
        .map_err(|e| format!("failed to parse pattern DB manifest '{manifest_path}': {e}"))?;

    let manifest_roots_path = resolve_path_relative(
        manifest_path,
        cfg.pattern_db_manifest_trust_store_path
            .as_deref()
            .unwrap_or_default(),
    );
    let manifest_roots_inline = &cfg.pattern_db_manifest_trusted_keys;
    if manifest_roots_path.is_empty() && manifest_roots_inline.is_empty() {
        return Err(
            "spider_sense: pattern_db_manifest_path requires pattern_db_manifest_trust_store_path or pattern_db_manifest_trusted_keys"
                .to_string(),
        );
    }

    let now = Utc::now();
    verify_manifest_window(&manifest, now)?;
    verify_pattern_manifest_signature(&manifest, &manifest_roots_path, manifest_roots_inline, now)?;

    let db_path = manifest
        .pattern_db_path
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            format!("pattern DB manifest '{manifest_path}' missing non-empty pattern_db_path")
        })?;
    let resolved_db_path = resolve_path_relative(manifest_path, db_path);

    let pattern_trust_store_path = resolve_path_relative(
        manifest_path,
        manifest
            .pattern_db_trust_store_path
            .as_deref()
            .unwrap_or_default(),
    );
    let integrity = required_pattern_db_integrity_fields(
        manifest.pattern_db_version.as_deref().unwrap_or_default(),
        manifest.pattern_db_checksum.as_deref().unwrap_or_default(),
        manifest.pattern_db_signature.as_deref().unwrap_or_default(),
        manifest
            .pattern_db_public_key
            .as_deref()
            .unwrap_or_default(),
        manifest
            .pattern_db_signature_key_id
            .as_deref()
            .unwrap_or_default(),
        &pattern_trust_store_path,
        manifest.pattern_db_trusted_keys.clone(),
    )?;

    let data = read_pattern_db_bytes(&resolved_db_path)?;
    let _ = verify_pattern_db_integrity(&data, &integrity)?;
    Ok(resolved_db_path)
}

fn resolve_pattern_db_path(cfg: &SpiderSensePolicyConfig) -> Result<String, String> {
    let manifest_path = cfg
        .pattern_db_manifest_path
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    if let Some(manifest_path) = manifest_path {
        return resolve_pattern_db_path_from_manifest(cfg, manifest_path);
    }

    let path = cfg.pattern_db_path.trim();
    if path.is_empty() {
        return Err("either pattern_db_path or pattern_db_manifest_path must be set".to_string());
    }

    let has_integrity_fields = cfg
        .pattern_db_version
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        || cfg
            .pattern_db_checksum
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || cfg
            .pattern_db_signature
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || cfg
            .pattern_db_signature_key_id
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || cfg
            .pattern_db_public_key
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || cfg
            .pattern_db_trust_store_path
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || !cfg.pattern_db_trusted_keys.is_empty();

    if has_integrity_fields {
        let trust_store_path = resolve_path_relative(
            "",
            cfg.pattern_db_trust_store_path
                .as_deref()
                .unwrap_or_default(),
        );
        let integrity = required_pattern_db_integrity_fields(
            cfg.pattern_db_version.as_deref().unwrap_or_default(),
            cfg.pattern_db_checksum.as_deref().unwrap_or_default(),
            cfg.pattern_db_signature.as_deref().unwrap_or_default(),
            cfg.pattern_db_public_key.as_deref().unwrap_or_default(),
            cfg.pattern_db_signature_key_id
                .as_deref()
                .unwrap_or_default(),
            &trust_store_path,
            cfg.pattern_db_trusted_keys.clone(),
        )?;
        let data = read_pattern_db_bytes(path)?;
        let _ = verify_pattern_db_integrity(&data, &integrity)?;
    }

    Ok(path.to_string())
}

fn validate_policy_config(cfg: &SpiderSensePolicyConfig) -> Result<(f64, f64), String> {
    if cfg.embedding_api_url.trim().is_empty() {
        return Err("embedding_api_url cannot be empty".to_string());
    }
    if cfg.embedding_api_key.trim().is_empty() {
        return Err("embedding_api_key cannot be empty".to_string());
    }
    if cfg.embedding_model.trim().is_empty() {
        return Err("embedding_model cannot be empty".to_string());
    }

    let has_pattern_db_path = !cfg.pattern_db_path.trim().is_empty();
    let has_manifest_path = cfg
        .pattern_db_manifest_path
        .as_deref()
        .is_some_and(|v| !v.trim().is_empty());
    if has_pattern_db_path && has_manifest_path {
        return Err(
            "pattern_db_path and pattern_db_manifest_path are mutually exclusive".to_string(),
        );
    }
    if !has_pattern_db_path && !has_manifest_path {
        return Err("either pattern_db_path or pattern_db_manifest_path must be set".to_string());
    }

    let has_manifest_trust_store = cfg
        .pattern_db_manifest_trust_store_path
        .as_deref()
        .is_some_and(|v| !v.trim().is_empty());
    let has_manifest_trusted_keys = !cfg.pattern_db_manifest_trusted_keys.is_empty();
    if has_manifest_path {
        let has_db_trust_store = cfg
            .pattern_db_trust_store_path
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty());
        let has_db_trusted_keys = !cfg.pattern_db_trusted_keys.is_empty();
        if has_db_trust_store || has_db_trusted_keys {
            return Err(
                "pattern_db_manifest_path cannot be combined with pattern_db_trust_store_path or pattern_db_trusted_keys"
                    .to_string(),
            );
        }
        if !has_manifest_trust_store && !has_manifest_trusted_keys {
            return Err(
                "pattern_db_manifest_path requires pattern_db_manifest_trust_store_path or pattern_db_manifest_trusted_keys"
                    .to_string(),
            );
        }
    } else if has_manifest_trust_store || has_manifest_trusted_keys {
        return Err(
            "pattern_db_manifest_trust_store_path and pattern_db_manifest_trusted_keys require pattern_db_manifest_path"
                .to_string(),
        );
    }

    if !cfg.similarity_threshold.is_finite() {
        return Err("similarity_threshold must be a finite number".to_string());
    }
    if !(0.0..=1.0).contains(&cfg.similarity_threshold) {
        return Err(format!(
            "similarity_threshold must be in [0.0, 1.0], got {}",
            cfg.similarity_threshold
        ));
    }

    if !cfg.ambiguity_band.is_finite() {
        return Err("ambiguity_band must be a finite number".to_string());
    }
    if !(0.0..=1.0).contains(&cfg.ambiguity_band) {
        return Err(format!(
            "ambiguity_band must be in [0.0, 1.0], got {}",
            cfg.ambiguity_band
        ));
    }
    if cfg.top_k == 0 {
        return Err("top_k must be >= 1".to_string());
    }

    let upper_bound = cfg.similarity_threshold + cfg.ambiguity_band;
    let lower_bound = cfg.similarity_threshold - cfg.ambiguity_band;
    if !(0.0..=1.0).contains(&lower_bound) || !(0.0..=1.0).contains(&upper_bound) {
        return Err(format!(
            "threshold/band produce invalid decision range: lower={lower_bound:.3}, upper={upper_bound:.3}; expected both in [0.0, 1.0]"
        ));
    }

    let has_llm_url = cfg
        .llm_api_url
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let has_llm_key = cfg
        .llm_api_key
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());

    if has_llm_url != has_llm_key {
        return Err(
            "LLM deep path requires both llm_api_url and llm_api_key (or neither)".to_string(),
        );
    }

    if let Some(model) = cfg.llm_model.as_deref() {
        if model.trim().is_empty() {
            return Err("llm_model cannot be empty when provided".to_string());
        }
    }

    let has_template_id = cfg
        .llm_prompt_template_id
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    let has_template_version = cfg
        .llm_prompt_template_version
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty());
    if has_template_id != has_template_version {
        return Err(
            "llm_prompt_template_id and llm_prompt_template_version must be set together"
                .to_string(),
        );
    }

    if has_template_id && !(has_llm_url && has_llm_key) {
        return Err(
            "llm_prompt_template_id/version require both llm_api_url and llm_api_key".to_string(),
        );
    }

    if let Some(timeout_ms) = cfg.llm_timeout_ms {
        if timeout_ms == 0 {
            return Err("llm_timeout_ms must be >= 1 when provided".to_string());
        }
    }

    if let Some(mode) = cfg.llm_fail_mode.as_deref() {
        let normalized = mode.trim().to_ascii_lowercase();
        if !normalized.is_empty()
            && normalized != "allow"
            && normalized != "warn"
            && normalized != "deny"
        {
            return Err("llm_fail_mode must be one of allow|warn|deny".to_string());
        }
    }

    Ok((upper_bound, lower_bound))
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
    use crate::async_guards::types::AsyncGuardConfig;
    use crate::policy::{AsyncExecutionMode, TimeoutBehavior};
    use crate::spider_sense::cosine_similarity_f32;
    use hush_core::Keypair;

    fn test_cfg() -> SpiderSensePolicyConfig {
        SpiderSensePolicyConfig {
            enabled: true,
            embedding_api_url: "http://127.0.0.1:8080/v1/embeddings".to_string(),
            embedding_api_key: "test-key".to_string(),
            embedding_model: "test-model".to_string(),
            similarity_threshold: 0.85,
            ambiguity_band: 0.10,
            top_k: 5,
            pattern_db_path: "/tmp/patterns.json".to_string(),
            pattern_db_version: None,
            pattern_db_checksum: None,
            pattern_db_signature: None,
            pattern_db_signature_key_id: None,
            pattern_db_public_key: None,
            pattern_db_trust_store_path: None,
            pattern_db_trusted_keys: vec![],
            pattern_db_manifest_path: None,
            pattern_db_manifest_trust_store_path: None,
            pattern_db_manifest_trusted_keys: vec![],
            llm_api_url: None,
            llm_api_key: None,
            llm_model: None,
            llm_prompt_template_id: None,
            llm_prompt_template_version: None,
            llm_timeout_ms: None,
            llm_fail_mode: None,
            async_config: None,
        }
    }

    fn test_async_cfg() -> AsyncGuardConfig {
        AsyncGuardConfig {
            timeout: Duration::from_secs(1),
            on_timeout: TimeoutBehavior::Warn,
            execution_mode: AsyncExecutionMode::Parallel,
            cache_enabled: false,
            cache_ttl: Duration::from_secs(1),
            cache_max_size_bytes: 1024,
            rate_limit: None,
            circuit_breaker: None,
            retry: None,
        }
    }

    fn test_pattern_db() -> PatternDb {
        PatternDb::parse_json(
            r#"[
            { "id": "p1", "category": "prompt_injection", "stage": "perception", "label": "x", "embedding": [1.0, 0.0, 0.0] }
        ]"#,
        )
        .expect("test pattern DB should parse")
    }

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
    fn spider_sense_policy_default_is_disabled() {
        let cfg = SpiderSensePolicyConfig::default();
        assert!(!cfg.enabled, "programmatic default should be disabled");
    }

    #[test]
    fn spider_sense_policy_deserialize_missing_enabled_defaults_to_true() {
        let cfg: SpiderSensePolicyConfig = serde_json::from_value(serde_json::json!({
            "embedding_api_url": "https://api.example.test/v1/embeddings",
            "embedding_api_key": "test-key",
            "embedding_model": "test-model",
            "pattern_db_path": "builtin:s2bench-v1"
        }))
        .expect("policy config should deserialize");
        assert!(cfg.enabled, "serialized config should default enabled=true");
    }

    #[test]
    fn spider_sense_policy_merge_with_preserves_base_when_child_values_are_default() {
        let mut base = test_cfg();
        base.similarity_threshold = 0.91;
        base.top_k = 7;

        let child = SpiderSensePolicyConfig {
            enabled: true,
            top_k: 11,
            ..SpiderSensePolicyConfig::default()
        };

        let merged = base.merge_with(&child);
        assert!(merged.enabled);
        assert_eq!(
            merged.embedding_api_url, base.embedding_api_url,
            "default child should preserve base required fields"
        );
        assert_eq!(
            merged.similarity_threshold, 0.91,
            "default threshold should not override base"
        );
        assert_eq!(merged.top_k, 11, "non-default child values should override");
    }

    #[test]
    fn spider_sense_policy_merge_with_present_fields_allows_explicit_enable_override() {
        let mut base = test_cfg();
        base.enabled = false;
        let child = SpiderSensePolicyConfig {
            enabled: true,
            ..SpiderSensePolicyConfig::default()
        };
        let present_fields = std::iter::once("enabled".to_string()).collect();

        let merged = base.merge_with_present_fields(&child, &present_fields);
        assert!(
            merged.enabled,
            "explicit enabled presence should override base"
        );
    }

    #[test]
    fn spider_sense_policy_merge_with_allows_programmatic_disable_override() {
        let mut base = test_cfg();
        base.enabled = true;
        let child = SpiderSensePolicyConfig::default();

        let merged = base.merge_with(&child);
        assert!(!merged.enabled, "child enabled=false should override base");
    }

    #[test]
    fn spider_sense_policy_merge_with_allows_programmatic_enable_toggle_override() {
        let mut base = test_cfg();
        base.enabled = false;
        let child = SpiderSensePolicyConfig {
            enabled: true,
            ..SpiderSensePolicyConfig::default()
        };

        let merged = base.merge_with(&child);
        assert!(
            merged.enabled,
            "toggle-only child enabled=true should override disabled base in heuristic mode"
        );
    }

    #[test]
    fn spider_sense_policy_merge_with_preserves_base_enable_with_other_overrides() {
        let mut base = test_cfg();
        base.enabled = false;
        base.similarity_threshold = 0.84;
        let child = SpiderSensePolicyConfig {
            enabled: true,
            similarity_threshold: 0.91,
            ..SpiderSensePolicyConfig::default()
        };

        let merged = base.merge_with(&child);
        assert!(
            !merged.enabled,
            "heuristic merge should not implicitly enable from default-enabled child plus overrides"
        );
        assert_eq!(merged.similarity_threshold, 0.91);
    }

    #[test]
    fn spider_sense_policy_merge_with_present_fields_preserves_base_when_enabled_absent() {
        let mut base = test_cfg();
        base.enabled = false;
        let child: SpiderSensePolicyConfig = serde_json::from_value(serde_json::json!({
            "embedding_api_url": "https://api.example.test/v1/embeddings",
            "embedding_api_key": "test-key",
            "embedding_model": "test-model",
            "pattern_db_path": "builtin:s2bench-v1"
        }))
        .expect("policy config should deserialize");
        let present_fields = std::iter::once("embedding_api_url".to_string())
            .chain(std::iter::once("embedding_api_key".to_string()))
            .chain(std::iter::once("embedding_model".to_string()))
            .chain(std::iter::once("pattern_db_path".to_string()))
            .collect();

        let merged = base.merge_with_present_fields(&child, &present_fields);
        assert!(
            !merged.enabled,
            "explicit field-presence merge should not auto-enable from serde defaults"
        );
    }

    #[test]
    fn spider_sense_policy_merge_with_preserves_base_when_child_partial_serde_defaults() {
        let mut base = test_cfg();
        base.enabled = false;
        base.similarity_threshold = 0.84;
        let child: SpiderSensePolicyConfig = serde_json::from_value(serde_json::json!({
            "similarity_threshold": 0.91
        }))
        .expect("policy config should deserialize");

        let merged = base.merge_with(&child);
        assert!(
            !merged.enabled,
            "heuristic merge should not auto-enable from serde defaults"
        );
        assert_eq!(
            merged.similarity_threshold, 0.91,
            "non-default child threshold should still override"
        );
    }

    #[test]
    fn spider_sense_policy_merge_with_present_fields_allows_enable_with_other_overrides() {
        let mut base = test_cfg();
        base.enabled = false;
        base.similarity_threshold = 0.84;
        let child = SpiderSensePolicyConfig {
            enabled: true,
            similarity_threshold: 0.91,
            ..SpiderSensePolicyConfig::default()
        };
        let present_fields = std::iter::once("enabled".to_string())
            .chain(std::iter::once("similarity_threshold".to_string()))
            .collect();

        let merged = base.merge_with_present_fields(&child, &present_fields);
        assert!(
            merged.enabled,
            "explicit enabled presence should override base"
        );
        assert_eq!(merged.similarity_threshold, 0.91);
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
        let err = PatternDb::parse_json("[]").expect_err("empty pattern DB must fail closed");
        assert!(err.contains("must contain at least one entry"));
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

    #[test]
    fn guard_config_rejects_invalid_similarity_threshold() {
        let mut cfg = test_cfg();
        cfg.similarity_threshold = 1.1;
        let result = SpiderSenseGuard::with_pattern_db(cfg, test_async_cfg(), test_pattern_db());
        assert!(result.is_err(), "invalid threshold should be rejected");
        let err = result.err().expect("error must be present");
        assert!(err.contains("similarity_threshold"));
    }

    #[test]
    fn guard_config_rejects_non_finite_similarity_threshold() {
        let mut cfg = test_cfg();
        cfg.similarity_threshold = f64::NAN;
        let result = SpiderSenseGuard::with_pattern_db(cfg, test_async_cfg(), test_pattern_db());
        assert!(result.is_err(), "non-finite threshold should be rejected");
        let err = result.err().expect("error must be present");
        assert!(err.contains("finite"));
    }

    #[test]
    fn guard_config_rejects_invalid_ambiguity_band() {
        let mut cfg = test_cfg();
        cfg.ambiguity_band = -0.2;
        let result = SpiderSenseGuard::with_pattern_db(cfg, test_async_cfg(), test_pattern_db());
        assert!(result.is_err(), "invalid ambiguity band should be rejected");
        let err = result.err().expect("error must be present");
        assert!(err.contains("ambiguity_band"));
    }

    #[test]
    fn guard_config_rejects_non_finite_ambiguity_band() {
        let mut cfg = test_cfg();
        cfg.ambiguity_band = f64::INFINITY;
        let result = SpiderSenseGuard::with_pattern_db(cfg, test_async_cfg(), test_pattern_db());
        assert!(
            result.is_err(),
            "non-finite ambiguity band should be rejected"
        );
        let err = result.err().expect("error must be present");
        assert!(err.contains("finite"));
    }

    #[test]
    fn guard_config_rejects_out_of_range_bounds() {
        let mut cfg = test_cfg();
        cfg.similarity_threshold = 0.95;
        cfg.ambiguity_band = 0.10;
        let result = SpiderSenseGuard::with_pattern_db(cfg, test_async_cfg(), test_pattern_db());
        assert!(result.is_err(), "out-of-range bounds should be rejected");
        let err = result.err().expect("error must be present");
        assert!(err.contains("invalid decision range"));
    }

    #[test]
    fn guard_config_rejects_partial_llm_configuration() {
        let mut cfg = test_cfg();
        cfg.llm_api_url = Some("http://127.0.0.1:8081/v1/messages".to_string());
        let result = SpiderSenseGuard::with_pattern_db(cfg, test_async_cfg(), test_pattern_db());
        assert!(result.is_err(), "partial LLM config should be rejected");
        let err = result.err().expect("error must be present");
        assert!(err.contains("requires both llm_api_url and llm_api_key"));
    }

    #[test]
    fn guard_config_rejects_empty_embedding_api_url() {
        let mut cfg = test_cfg();
        cfg.embedding_api_url = "   ".to_string();
        let result = SpiderSenseGuard::with_pattern_db(cfg, test_async_cfg(), test_pattern_db());
        assert!(result.is_err(), "empty embedding url should be rejected");
        let err = result.err().expect("error must be present");
        assert!(err.contains("embedding_api_url"));
    }

    #[test]
    fn guard_config_rejects_empty_llm_model_when_provided() {
        let mut cfg = test_cfg();
        cfg.llm_api_url = Some("http://127.0.0.1:8081/v1/messages".to_string());
        cfg.llm_api_key = Some("llm-test-key".to_string());
        cfg.llm_model = Some("   ".to_string());
        let result = SpiderSenseGuard::with_pattern_db(cfg, test_async_cfg(), test_pattern_db());
        assert!(result.is_err(), "empty llm_model should be rejected");
        let err = result.err().expect("error must be present");
        assert!(err.contains("llm_model"));
    }

    #[test]
    fn guard_config_allows_legacy_llm_without_prompt_template_fields() {
        let mut cfg = test_cfg();
        cfg.llm_api_url = Some("http://127.0.0.1:8081/v1/messages".to_string());
        cfg.llm_api_key = Some("llm-test-key".to_string());
        cfg.llm_model = Some("claude-haiku-4-5-20251001".to_string());

        let result = SpiderSenseGuard::with_pattern_db(cfg, test_async_cfg(), test_pattern_db());
        assert!(
            result.is_ok(),
            "legacy LLM configuration without template fields should remain supported"
        );
    }

    #[test]
    fn guard_config_accepts_manifest_and_prompt_template_fields() {
        let mut cfg = test_cfg();
        cfg.pattern_db_path.clear();
        cfg.pattern_db_manifest_path = Some("/tmp/pattern-db.manifest.json".to_string());
        cfg.pattern_db_manifest_trust_store_path = Some("/tmp/manifest-roots.json".to_string());
        cfg.llm_api_url = Some("http://127.0.0.1:8081/v1/messages".to_string());
        cfg.llm_api_key = Some("llm-test-key".to_string());
        cfg.llm_prompt_template_id = Some("spider_sense.deep_path.json_classifier".to_string());
        cfg.llm_prompt_template_version = Some("1.0.0".to_string());
        cfg.llm_timeout_ms = Some(1500);
        cfg.llm_fail_mode = Some("warn".to_string());

        let result = SpiderSenseGuard::with_pattern_db(cfg, test_async_cfg(), test_pattern_db());
        assert!(
            result.is_ok(),
            "manifest + prompt template schema fields should parse/validate"
        );
    }

    #[test]
    fn resolve_pattern_db_path_accepts_signed_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let patterns_dir = dir.path().join("patterns");
        std::fs::create_dir_all(&patterns_dir).expect("create patterns dir");
        let pattern_db_path = patterns_dir.join("db.json");
        let pattern_db_json = r#"[
  {
    "id": "p1",
    "category": "prompt_injection",
    "stage": "perception",
    "label": "ignore previous",
    "embedding": [1.0, 0.0, 0.0]
  }
]"#;
        std::fs::write(&pattern_db_path, pattern_db_json).expect("write pattern db");

        let checksum = sha256(pattern_db_json.as_bytes()).to_hex();
        let db_keypair = Keypair::generate();
        let db_public_key = db_keypair.public_key().to_hex();
        let db_key_id = derive_spider_sense_key_id(&db_public_key);
        let db_signature = db_keypair
            .sign(format!("spider_sense_db:v1:test-v1:{checksum}").as_bytes())
            .to_hex();

        let manifest_keypair = Keypair::generate();
        let manifest_public_key = manifest_keypair.public_key().to_hex();
        let manifest_key_id = derive_spider_sense_key_id(&manifest_public_key);

        let manifest_path = dir.path().join("pattern_db.manifest.json");
        let mut manifest = serde_json::json!({
          "pattern_db_path": "patterns/db.json",
          "pattern_db_version": "test-v1",
          "pattern_db_checksum": checksum,
          "pattern_db_signature": db_signature,
          "pattern_db_signature_key_id": db_key_id,
          "pattern_db_trusted_keys": [
            {
              "key_id": db_key_id,
              "public_key": db_public_key,
              "status": "active"
            }
          ],
          "manifest_signature_key_id": manifest_key_id,
          "not_before": "1970-01-01T00:00:00Z",
          "not_after": "2999-01-01T00:00:00Z"
        });
        let manifest_for_signing: PatternDbManifest =
            serde_json::from_value(manifest.clone()).expect("deserialize manifest");
        let manifest_signature = manifest_keypair
            .sign(&spider_sense_manifest_signing_message(
                &manifest_for_signing,
            ))
            .to_hex();
        manifest["manifest_signature"] = serde_json::Value::String(manifest_signature);
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).expect("manifest json"),
        )
        .expect("write manifest");

        let mut cfg = test_cfg();
        cfg.pattern_db_path.clear();
        cfg.pattern_db_manifest_path = Some(manifest_path.to_string_lossy().to_string());
        cfg.pattern_db_manifest_trusted_keys = vec![SpiderSenseTrustedKeyConfig {
            key_id: Some(manifest_key_id),
            public_key: manifest_public_key,
            not_before: None,
            not_after: None,
            status: Some("active".to_string()),
        }];

        let resolved = resolve_pattern_db_path(&cfg).expect("resolve manifest path");
        assert!(
            resolved.ends_with("patterns/db.json"),
            "resolved path should preserve manifest-relative DB path"
        );
    }

    #[test]
    fn resolve_pattern_db_path_rejects_signed_manifest_with_unknown_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let patterns_dir = dir.path().join("patterns");
        std::fs::create_dir_all(&patterns_dir).expect("create patterns dir");
        let pattern_db_path = patterns_dir.join("db.json");
        let pattern_db_json = r#"[
  {
    "id": "p1",
    "category": "prompt_injection",
    "stage": "perception",
    "label": "ignore previous",
    "embedding": [1.0, 0.0, 0.0]
  }
]"#;
        std::fs::write(&pattern_db_path, pattern_db_json).expect("write pattern db");

        let checksum = sha256(pattern_db_json.as_bytes()).to_hex();
        let db_keypair = Keypair::generate();
        let db_public_key = db_keypair.public_key().to_hex();
        let db_key_id = derive_spider_sense_key_id(&db_public_key);
        let db_signature = db_keypair
            .sign(format!("spider_sense_db:v1:test-v1:{checksum}").as_bytes())
            .to_hex();

        let manifest_keypair = Keypair::generate();
        let manifest_public_key = manifest_keypair.public_key().to_hex();
        let manifest_key_id = derive_spider_sense_key_id(&manifest_public_key);

        let manifest_path = dir.path().join("pattern_db.manifest.json");
        let mut manifest = serde_json::json!({
          "pattern_db_path": "patterns/db.json",
          "pattern_db_version": "test-v1",
          "pattern_db_checksum": checksum,
          "pattern_db_signature": db_signature,
          "pattern_db_signature_key_id": db_key_id,
          "pattern_db_trusted_keys": [
            {
              "key_id": db_key_id,
              "public_key": db_public_key,
              "status": "active"
            }
          ],
          "manifest_signature_key_id": manifest_key_id,
          "not_before": "1970-01-01T00:00:00Z",
          "not_after": "2999-01-01T00:00:00Z"
        });
        let manifest_for_signing: PatternDbManifest =
            serde_json::from_value(manifest.clone()).expect("deserialize manifest");
        let manifest_signature = manifest_keypair
            .sign(&spider_sense_manifest_signing_message(
                &manifest_for_signing,
            ))
            .to_hex();
        manifest["manifest_signature"] = serde_json::Value::String(manifest_signature);
        manifest["extra_field"] = serde_json::Value::String("unexpected".to_string());
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).expect("manifest json"),
        )
        .expect("write manifest");

        let mut cfg = test_cfg();
        cfg.pattern_db_path.clear();
        cfg.pattern_db_manifest_path = Some(manifest_path.to_string_lossy().to_string());
        cfg.pattern_db_manifest_trusted_keys = vec![SpiderSenseTrustedKeyConfig {
            key_id: Some(manifest_key_id),
            public_key: manifest_public_key,
            not_before: None,
            not_after: None,
            status: Some("active".to_string()),
        }];

        let err =
            resolve_pattern_db_path(&cfg).expect_err("manifest with unknown fields must fail");
        assert!(
            err.contains("unknown field"),
            "expected unknown-field parse error, got: {err}"
        );
    }

    #[test]
    fn resolve_pattern_db_path_rejects_tampered_signed_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let patterns_dir = dir.path().join("patterns");
        std::fs::create_dir_all(&patterns_dir).expect("create patterns dir");
        let pattern_db_path = patterns_dir.join("db.json");
        let pattern_db_json = r#"[
  {
    "id": "p1",
    "category": "prompt_injection",
    "stage": "perception",
    "label": "ignore previous",
    "embedding": [1.0, 0.0, 0.0]
  }
]"#;
        std::fs::write(&pattern_db_path, pattern_db_json).expect("write pattern db");

        let checksum = sha256(pattern_db_json.as_bytes()).to_hex();
        let db_keypair = Keypair::generate();
        let db_public_key = db_keypair.public_key().to_hex();
        let db_key_id = derive_spider_sense_key_id(&db_public_key);
        let db_signature = db_keypair
            .sign(format!("spider_sense_db:v1:test-v1:{checksum}").as_bytes())
            .to_hex();

        let manifest_keypair = Keypair::generate();
        let manifest_public_key = manifest_keypair.public_key().to_hex();
        let manifest_key_id = derive_spider_sense_key_id(&manifest_public_key);

        let manifest_path = dir.path().join("pattern_db.manifest.json");
        let mut manifest = serde_json::json!({
          "pattern_db_path": "patterns/db.json",
          "pattern_db_version": "test-v1",
          "pattern_db_checksum": checksum,
          "pattern_db_signature": db_signature,
          "pattern_db_signature_key_id": db_key_id,
          "pattern_db_trusted_keys": [
            {
              "key_id": db_key_id,
              "public_key": db_public_key,
              "status": "active"
            }
          ],
          "manifest_signature_key_id": manifest_key_id
        });
        let manifest_for_signing: PatternDbManifest =
            serde_json::from_value(manifest.clone()).expect("deserialize manifest");
        let manifest_signature = manifest_keypair
            .sign(&spider_sense_manifest_signing_message(
                &manifest_for_signing,
            ))
            .to_hex();
        manifest["manifest_signature"] = serde_json::Value::String(manifest_signature);
        manifest["pattern_db_version"] = serde_json::Value::String("tampered".to_string());
        std::fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest).expect("manifest json"),
        )
        .expect("write manifest");

        let mut cfg = test_cfg();
        cfg.pattern_db_path.clear();
        cfg.pattern_db_manifest_path = Some(manifest_path.to_string_lossy().to_string());
        cfg.pattern_db_manifest_trusted_keys = vec![SpiderSenseTrustedKeyConfig {
            key_id: Some(manifest_key_id),
            public_key: manifest_public_key,
            not_before: None,
            not_after: None,
            status: Some("active".to_string()),
        }];

        let err = resolve_pattern_db_path(&cfg).expect_err("tampered manifest should fail");
        assert!(
            err.contains("manifest signature verification failed"),
            "expected signature verification failure, got: {err}"
        );
    }

    #[test]
    fn resolve_pattern_db_path_verifies_direct_path_checksum_when_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pattern_db_path = dir.path().join("db.json");
        let pattern_db_json = r#"[
  {
    "id": "p1",
    "category": "prompt_injection",
    "stage": "perception",
    "label": "ignore previous",
    "embedding": [1.0, 0.0, 0.0]
  }
]"#;
        std::fs::write(&pattern_db_path, pattern_db_json).expect("write pattern db");

        let mut cfg = test_cfg();
        cfg.pattern_db_path = pattern_db_path.to_string_lossy().to_string();
        cfg.pattern_db_version = Some("direct-v1".to_string());
        cfg.pattern_db_checksum = Some(sha256(pattern_db_json.as_bytes()).to_hex());

        let resolved = resolve_pattern_db_path(&cfg).expect("resolve direct db path");
        assert_eq!(resolved, cfg.pattern_db_path);
    }

    #[test]
    fn resolve_pattern_db_path_rejects_direct_path_checksum_mismatch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pattern_db_path = dir.path().join("db.json");
        let pattern_db_json = r#"[
  {
    "id": "p1",
    "category": "prompt_injection",
    "stage": "perception",
    "label": "ignore previous",
    "embedding": [1.0, 0.0, 0.0]
  }
]"#;
        std::fs::write(&pattern_db_path, pattern_db_json).expect("write pattern db");

        let mut cfg = test_cfg();
        cfg.pattern_db_path = pattern_db_path.to_string_lossy().to_string();
        cfg.pattern_db_version = Some("direct-v1".to_string());
        cfg.pattern_db_checksum = Some("00".repeat(32));

        let err = resolve_pattern_db_path(&cfg).expect_err("checksum mismatch should fail");
        assert!(
            err.contains("checksum mismatch"),
            "expected checksum mismatch, got: {err}"
        );
    }

    #[test]
    fn resolve_pattern_db_path_verifies_direct_path_trust_store_signature() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pattern_db_path = dir.path().join("db.json");
        let pattern_db_json = r#"[
  {
    "id": "p1",
    "category": "prompt_injection",
    "stage": "perception",
    "label": "ignore previous",
    "embedding": [1.0, 0.0, 0.0]
  }
]"#;
        std::fs::write(&pattern_db_path, pattern_db_json).expect("write pattern db");

        let checksum = sha256(pattern_db_json.as_bytes()).to_hex();
        let keypair = Keypair::generate();
        let key_id = "rotation-key-1";
        let signature = keypair
            .sign(format!("spider_sense_db:v1:direct-v1:{checksum}").as_bytes())
            .to_hex();
        let trust_store_path = dir.path().join("db-trust-store.json");
        std::fs::write(
            &trust_store_path,
            serde_json::json!({
                "keys": [
                    {
                        "key_id": key_id,
                        "public_key": keypair.public_key().to_hex(),
                        "status": "active"
                    }
                ]
            })
            .to_string(),
        )
        .expect("write trust store");

        let mut cfg = test_cfg();
        cfg.pattern_db_path = pattern_db_path.to_string_lossy().to_string();
        cfg.pattern_db_version = Some("direct-v1".to_string());
        cfg.pattern_db_checksum = Some(checksum);
        cfg.pattern_db_signature = Some(signature);
        cfg.pattern_db_signature_key_id = Some(key_id.to_string());
        cfg.pattern_db_trust_store_path = Some(trust_store_path.to_string_lossy().to_string());

        let resolved = resolve_pattern_db_path(&cfg).expect("resolve direct db path");
        assert_eq!(resolved, cfg.pattern_db_path);
    }

    #[test]
    fn resolve_pattern_db_path_direct_relative_trust_store_is_not_anchored_to_db_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pattern_db_path = dir.path().join("db.json");
        let pattern_db_json = r#"[
  {
    "id": "p1",
    "category": "prompt_injection",
    "stage": "perception",
    "label": "ignore previous",
    "embedding": [1.0, 0.0, 0.0]
  }
]"#;
        std::fs::write(&pattern_db_path, pattern_db_json).expect("write pattern db");

        let checksum = sha256(pattern_db_json.as_bytes()).to_hex();
        let keypair = Keypair::generate();
        let key_id = "rotation-key-1";
        let signature = keypair
            .sign(format!("spider_sense_db:v1:direct-v1:{checksum}").as_bytes())
            .to_hex();

        // Place a valid trust store next to the DB file, but configure a
        // relative trust-store path. Direct DB integrity loading should no
        // longer resolve that relative path against `pattern_db_path`.
        let trust_store_path_next_to_db = dir.path().join("relative-db-trust-store.json");
        std::fs::write(
            &trust_store_path_next_to_db,
            serde_json::json!({
                "keys": [
                    {
                        "key_id": key_id,
                        "public_key": keypair.public_key().to_hex(),
                        "status": "active"
                    }
                ]
            })
            .to_string(),
        )
        .expect("write trust store");

        let mut cfg = test_cfg();
        cfg.pattern_db_path = pattern_db_path.to_string_lossy().to_string();
        cfg.pattern_db_version = Some("direct-v1".to_string());
        cfg.pattern_db_checksum = Some(checksum);
        cfg.pattern_db_signature = Some(signature);
        cfg.pattern_db_signature_key_id = Some(key_id.to_string());
        cfg.pattern_db_trust_store_path = Some("relative-db-trust-store.json".to_string());

        let err = resolve_pattern_db_path(&cfg)
            .expect_err("relative trust store should not resolve from DB directory");
        assert!(
            err.contains("load trust store") && err.contains("relative-db-trust-store.json"),
            "expected relative trust-store read failure, got: {err}"
        );
    }

    #[test]
    fn resolve_path_relative_ignores_builtin_base() {
        let resolved = resolve_path_relative("builtin:s2bench-v1", "keys/db-trust-store.json");
        assert_eq!(resolved, "keys/db-trust-store.json");
    }

    #[test]
    fn resolve_path_relative_uses_parent_for_file_base() {
        let resolved = resolve_path_relative(
            "/opt/clawdstrike/patterns/db.json",
            "keys/db-trust-store.json",
        );
        assert_eq!(
            resolved,
            "/opt/clawdstrike/patterns/keys/db-trust-store.json"
        );
    }

    #[test]
    fn trust_store_allows_custom_key_ids() {
        let keypair = Keypair::generate();
        let public_key = keypair.public_key().to_hex();
        let store = load_spider_sense_trust_store(
            "",
            &[SpiderSenseTrustedKeyConfig {
                key_id: Some("external-kid-01".to_string()),
                public_key,
                not_before: None,
                not_after: None,
                status: Some("active".to_string()),
            }],
        )
        .expect("load trust store");

        let selected = store
            .select_key("external-kid-01", Utc::now())
            .expect("select custom key id");
        assert_eq!(selected.key_id, "external-kid-01");
    }
}
