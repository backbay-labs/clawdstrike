//! Spider-Sense detection module (WASM-compatible).
//!
//! Pure, sync screening of embedding vectors against a pre-computed pattern
//! database using cosine similarity. This module is always compiled (no
//! feature gate) and safe for WASM targets.
//!
//! The full async guard (`SpiderSenseGuard`) in `async_guards::threat_intel`
//! delegates its fast-path screening to [`SpiderSenseDetector::screen`].

use serde::{Deserialize, Serialize};

// ── Configuration ───────────────────────────────────────────────────────

const DEFAULT_SIMILARITY_THRESHOLD: f64 = 0.85;
const DEFAULT_AMBIGUITY_BAND: f64 = 0.10;
const DEFAULT_TOP_K: usize = 5;

/// Configuration for the standalone Spider-Sense detector.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpiderSenseDetectorConfig {
    /// Cosine similarity threshold above which a match is a threat.
    /// Default: 0.85
    #[serde(default = "default_similarity_threshold")]
    pub similarity_threshold: f64,
    /// Half-width of the ambiguity band around the threshold.
    /// Default: 0.10
    #[serde(default = "default_ambiguity_band")]
    pub ambiguity_band: f64,
    /// Number of top matches to return.
    /// Default: 5
    #[serde(default = "default_top_k")]
    pub top_k: usize,
}

impl Default for SpiderSenseDetectorConfig {
    fn default() -> Self {
        Self {
            similarity_threshold: DEFAULT_SIMILARITY_THRESHOLD,
            ambiguity_band: DEFAULT_AMBIGUITY_BAND,
            top_k: DEFAULT_TOP_K,
        }
    }
}

fn default_similarity_threshold() -> f64 {
    DEFAULT_SIMILARITY_THRESHOLD
}

fn default_ambiguity_band() -> f64 {
    DEFAULT_AMBIGUITY_BAND
}

fn default_top_k() -> usize {
    DEFAULT_TOP_K
}

// ── Pattern Database ────────────────────────────────────────────────────

/// A single entry in the pattern database.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Serialize)]
pub struct PatternMatch {
    /// The matched entry.
    pub entry: PatternEntry,
    /// Cosine similarity score.
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
    #[cfg(not(target_arch = "wasm32"))]
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
            return Err("pattern DB must contain at least one entry".to_string());
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
            if let Some(j) = entry.embedding.iter().position(|v| !v.is_finite()) {
                return Err(format!(
                    "pattern DB entry {i} has non-finite embedding value at dimension {j}"
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
/// for the accumulation. Returns 0.0 if either vector has zero norm or if
/// any element is non-finite (NaN, Inf). This ensures fail-closed behavior:
/// corrupted embeddings produce a zero score rather than propagating NaN.
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
    if !denom.is_normal() {
        return 0.0;
    }

    let result = dot / denom;
    if result.is_finite() {
        result
    } else {
        0.0
    }
}

// ── Screening ───────────────────────────────────────────────────────────

/// Verdict from the fast-path screening.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreeningVerdict {
    /// Clear threat — above upper bound.
    Deny,
    /// Ambiguous — within the band around the threshold.
    Ambiguous,
    /// Clear benign — below lower bound.
    Allow,
}

/// Result of a [`SpiderSenseDetector::screen`] call.
#[derive(Clone, Debug, Serialize)]
pub struct ScreeningResult {
    /// The screening verdict.
    pub verdict: ScreeningVerdict,
    /// Top similarity score (0.0 if no patterns).
    pub top_score: f64,
    /// Configured similarity threshold.
    pub threshold: f64,
    /// Configured ambiguity band.
    pub ambiguity_band: f64,
    /// Top-k pattern matches.
    pub top_matches: Vec<PatternMatch>,
}

/// Standalone Spider-Sense detector for embedding-based screening.
///
/// Wraps a [`PatternDb`] and screening thresholds. Operates synchronously
/// with no I/O — the caller is responsible for obtaining embeddings.
pub struct SpiderSenseDetector {
    pattern_db: PatternDb,
    upper_bound: f64,
    lower_bound: f64,
    top_k: usize,
    threshold: f64,
    ambiguity_band: f64,
}

impl SpiderSenseDetector {
    /// Create a new detector. Returns an error if the config is invalid.
    pub fn new(pattern_db: PatternDb, config: &SpiderSenseDetectorConfig) -> Result<Self, String> {
        let (upper_bound, lower_bound) = validate_detector_config(config)?;
        Ok(Self {
            pattern_db,
            upper_bound,
            lower_bound,
            top_k: config.top_k,
            threshold: config.similarity_threshold,
            ambiguity_band: config.ambiguity_band,
        })
    }

    /// Screen an embedding vector against the pattern database.
    ///
    /// This is a pure, sync operation with no I/O.
    pub fn screen(&self, embedding: &[f32]) -> ScreeningResult {
        if let Some(expected_dim) = self.pattern_db.expected_dim() {
            if embedding.len() != expected_dim {
                return ScreeningResult {
                    verdict: ScreeningVerdict::Deny,
                    top_score: 0.0,
                    threshold: self.threshold,
                    ambiguity_band: self.ambiguity_band,
                    top_matches: vec![],
                };
            }
        }
        if embedding.iter().any(|v| !v.is_finite()) {
            return ScreeningResult {
                verdict: ScreeningVerdict::Deny,
                top_score: 0.0,
                threshold: self.threshold,
                ambiguity_band: self.ambiguity_band,
                top_matches: vec![],
            };
        }

        let matches = self.pattern_db.search(embedding, self.top_k);
        let top_score = matches.first().map(|m| m.score).unwrap_or(0.0);

        let verdict = if top_score >= self.upper_bound {
            ScreeningVerdict::Deny
        } else if top_score <= self.lower_bound {
            ScreeningVerdict::Allow
        } else {
            ScreeningVerdict::Ambiguous
        };

        ScreeningResult {
            verdict,
            top_score,
            threshold: self.threshold,
            ambiguity_band: self.ambiguity_band,
            top_matches: matches,
        }
    }

    /// Expected embedding dimension from the pattern DB.
    pub fn expected_dim(&self) -> Option<usize> {
        self.pattern_db.expected_dim()
    }

    /// Number of patterns in the database.
    pub fn pattern_count(&self) -> usize {
        self.pattern_db.len()
    }
}

fn validate_detector_config(config: &SpiderSenseDetectorConfig) -> Result<(f64, f64), String> {
    if !config.similarity_threshold.is_finite() {
        return Err("similarity_threshold must be a finite number".to_string());
    }
    if !(0.0..=1.0).contains(&config.similarity_threshold) {
        return Err(format!(
            "similarity_threshold must be in [0.0, 1.0], got {}",
            config.similarity_threshold
        ));
    }

    if !config.ambiguity_band.is_finite() {
        return Err("ambiguity_band must be a finite number".to_string());
    }
    if !(0.0..=1.0).contains(&config.ambiguity_band) {
        return Err(format!(
            "ambiguity_band must be in [0.0, 1.0], got {}",
            config.ambiguity_band
        ));
    }

    let upper_bound = config.similarity_threshold + config.ambiguity_band;
    let lower_bound = config.similarity_threshold - config.ambiguity_band;
    if !(0.0..=1.0).contains(&lower_bound) || !(0.0..=1.0).contains(&upper_bound) {
        return Err(format!(
            "threshold/band produce invalid decision range: lower={lower_bound:.3}, upper={upper_bound:.3}; expected both in [0.0, 1.0]"
        ));
    }

    if config.top_k == 0 {
        return Err("top_k must be at least 1".to_string());
    }

    Ok((upper_bound, lower_bound))
}

// ── Unit Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pattern_db() -> PatternDb {
        PatternDb::parse_json(
            r#"[
            { "id": "p1", "category": "prompt_injection", "stage": "perception", "label": "ignore previous", "embedding": [1.0, 0.0, 0.0] },
            { "id": "p2", "category": "data_exfiltration", "stage": "action", "label": "exfil data", "embedding": [0.0, 1.0, 0.0] },
            { "id": "p3", "category": "privilege_escalation", "stage": "cognition", "label": "escalate", "embedding": [0.0, 0.0, 1.0] }
        ]"#,
        )
        .expect("test pattern DB should parse")
    }

    #[test]
    fn cosine_identical_vectors() {
        let a = vec![1.0, 0.0, 0.0];
        let sim = cosine_similarity_f32(&a, &a);
        assert!((sim - 1.0).abs() < 1e-10);
    }

    #[test]
    fn cosine_orthogonal_vectors() {
        let a = vec![1.0, 0.0, 0.0];
        let b = vec![0.0, 1.0, 0.0];
        assert!(cosine_similarity_f32(&a, &b).abs() < 1e-10);
    }

    #[test]
    fn cosine_opposite_vectors() {
        let a = vec![1.0, 0.0];
        let b = vec![-1.0, 0.0];
        assert!((cosine_similarity_f32(&a, &b) - (-1.0)).abs() < 1e-10);
    }

    #[test]
    fn cosine_zero_vector() {
        let a = vec![0.0, 0.0, 0.0];
        let b = vec![1.0, 2.0, 3.0];
        assert_eq!(cosine_similarity_f32(&a, &b), 0.0);
    }

    #[test]
    fn cosine_different_lengths() {
        let a = vec![1.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert_eq!(cosine_similarity_f32(&a, &b), 0.0);
    }

    #[test]
    fn pattern_db_parse_valid() {
        let db = test_pattern_db();
        assert_eq!(db.len(), 3);
        assert_eq!(db.expected_dim(), Some(3));
    }

    #[test]
    fn pattern_db_parse_allows_extra_metadata_fields() {
        let json = r#"[
            {
                "id": "p1",
                "category": "prompt_injection",
                "stage": "perception",
                "label": "ignore previous instructions",
                "embedding": [0.1, 0.2, 0.3],
                "description": "extra metadata should be ignored",
                "severity": "critical",
                "source": "custom-db",
                "created_at": "2026-03-04T00:00:00Z"
            }
        ]"#;
        let db = PatternDb::parse_json(json).expect("pattern DB with extra metadata should parse");
        assert_eq!(db.len(), 1);
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
        let db = test_pattern_db();
        let query = vec![1.0, 0.0, 0.0];
        let results = db.search(&query, 2);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].entry.id, "p1");
        assert!((results[0].score - 1.0).abs() < 1e-6);
    }

    #[test]
    fn detector_screen_deny() {
        let db = test_pattern_db();
        let config = SpiderSenseDetectorConfig {
            similarity_threshold: 0.85,
            ambiguity_band: 0.10,
            top_k: 5,
        };
        let detector = SpiderSenseDetector::new(db, &config).unwrap();
        // Identical vector → score 1.0, above upper bound 0.95
        let result = detector.screen(&[1.0, 0.0, 0.0]);
        assert_eq!(result.verdict, ScreeningVerdict::Deny);
        assert!((result.top_score - 1.0).abs() < 1e-6);
    }

    #[test]
    fn detector_screen_allow() {
        let db = test_pattern_db();
        let config = SpiderSenseDetectorConfig {
            similarity_threshold: 0.85,
            ambiguity_band: 0.10,
            top_k: 5,
        };
        let detector = SpiderSenseDetector::new(db, &config).unwrap();
        // Orthogonal to all patterns → score ~0.0, below lower bound 0.75
        let result = detector.screen(&[0.577, 0.577, 0.577]);
        assert_eq!(result.verdict, ScreeningVerdict::Allow);
    }

    #[test]
    fn detector_screen_ambiguous() {
        let db = test_pattern_db();
        let config = SpiderSenseDetectorConfig {
            similarity_threshold: 0.50,
            ambiguity_band: 0.10,
            top_k: 5,
        };
        let detector = SpiderSenseDetector::new(db, &config).unwrap();
        // Partially similar → score ~0.577, within band [0.40, 0.60]
        let result = detector.screen(&[0.577, 0.577, 0.577]);
        assert_eq!(result.verdict, ScreeningVerdict::Ambiguous);
    }

    #[test]
    fn detector_screen_dimension_mismatch_denies() {
        let db = test_pattern_db();
        let config = SpiderSenseDetectorConfig::default();
        let detector = SpiderSenseDetector::new(db, &config).unwrap();
        let result = detector.screen(&[1.0, 0.0]);
        assert_eq!(result.verdict, ScreeningVerdict::Deny);
        assert_eq!(result.top_score, 0.0);
        assert!(result.top_matches.is_empty());
    }

    #[test]
    fn detector_screen_non_finite_embedding_denies() {
        let db = test_pattern_db();
        let config = SpiderSenseDetectorConfig::default();
        let detector = SpiderSenseDetector::new(db, &config).unwrap();
        let result = detector.screen(&[f32::NAN, 0.0, 0.0]);
        assert_eq!(result.verdict, ScreeningVerdict::Deny);
        assert_eq!(result.top_score, 0.0);
        assert!(result.top_matches.is_empty());
    }

    #[test]
    fn detector_screen_exact_lower_bound_is_allow() {
        let db = PatternDb::parse_json(
            r#"[
                { "id": "p1", "category": "a", "stage": "s", "label": "x", "embedding": [1.0, 0.0, 0.0] }
            ]"#,
        )
        .unwrap();
        let config = SpiderSenseDetectorConfig {
            similarity_threshold: 0.10,
            ambiguity_band: 0.10,
            top_k: 5,
        };
        let detector = SpiderSenseDetector::new(db, &config).unwrap();
        let lower = config.similarity_threshold - config.ambiguity_band;
        let query = [0.0, 1.0, 0.0];
        let result = detector.screen(&query);
        assert_eq!(result.verdict, ScreeningVerdict::Allow);
        assert!((result.top_score - lower).abs() < 1e-6);
    }

    #[test]
    fn detector_config_rejects_invalid_threshold() {
        let db = test_pattern_db();
        let config = SpiderSenseDetectorConfig {
            similarity_threshold: 1.5,
            ambiguity_band: 0.10,
            top_k: 5,
        };
        assert!(SpiderSenseDetector::new(db, &config).is_err());
    }

    #[test]
    fn detector_config_rejects_zero_top_k() {
        let db = test_pattern_db();
        let config = SpiderSenseDetectorConfig {
            similarity_threshold: 0.85,
            ambiguity_band: 0.10,
            top_k: 0,
        };
        assert!(SpiderSenseDetector::new(db, &config).is_err());
    }

    #[test]
    fn detector_config_rejects_out_of_range_bounds() {
        let db = test_pattern_db();
        let config = SpiderSenseDetectorConfig {
            similarity_threshold: 0.95,
            ambiguity_band: 0.10,
            top_k: 5,
        };
        assert!(SpiderSenseDetector::new(db, &config).is_err());
    }

    #[test]
    fn detector_expected_dim() {
        let db = test_pattern_db();
        let config = SpiderSenseDetectorConfig::default();
        let detector = SpiderSenseDetector::new(db, &config).unwrap();
        assert_eq!(detector.expected_dim(), Some(3));
        assert_eq!(detector.pattern_count(), 3);
    }

    #[test]
    fn screening_result_serializes() {
        let db = test_pattern_db();
        let config = SpiderSenseDetectorConfig::default();
        let detector = SpiderSenseDetector::new(db, &config).unwrap();
        let result = detector.screen(&[1.0, 0.0, 0.0]);
        let json = serde_json::to_string(&result).expect("should serialize");
        assert!(json.contains("\"verdict\""));
        assert!(json.contains("\"top_score\""));
    }

    #[test]
    fn cosine_nan_returns_zero() {
        let a = vec![f32::NAN, 1.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert_eq!(
            cosine_similarity_f32(&a, &b),
            0.0,
            "NaN input must return 0 (fail-closed)"
        );
    }

    #[test]
    fn cosine_infinity_returns_zero() {
        let a = vec![f32::INFINITY, 0.0, 0.0];
        let b = vec![1.0, 0.0, 0.0];
        assert_eq!(
            cosine_similarity_f32(&a, &b),
            0.0,
            "Inf input must return 0 (fail-closed)"
        );
    }

    #[test]
    fn cosine_neg_infinity_returns_zero() {
        let a = vec![f32::NEG_INFINITY, 0.0];
        let b = vec![1.0, 0.0];
        assert_eq!(
            cosine_similarity_f32(&a, &b),
            0.0,
            "negative Inf must return 0 (fail-closed)"
        );
    }

    #[test]
    fn cosine_empty_vectors() {
        let a: Vec<f32> = vec![];
        let b: Vec<f32> = vec![];
        assert_eq!(
            cosine_similarity_f32(&a, &b),
            0.0,
            "empty vectors must return 0"
        );
    }

    #[test]
    fn pattern_db_rejects_nan_embedding() {
        let json = r#"[
            { "id": "p1", "category": "a", "stage": "b", "label": "c", "embedding": [1.0, NaN, 0.0] }
        ]"#;
        // NaN is not valid JSON, so serde_json will reject it at parse time.
        assert!(PatternDb::parse_json(json).is_err());
    }

    #[test]
    fn pattern_db_rejects_infinity_embedding() {
        // Infinity is not valid JSON, so serde_json rejects it.
        let json = r#"[
            { "id": "p1", "category": "a", "stage": "b", "label": "c", "embedding": [1.0, Infinity, 0.0] }
        ]"#;
        assert!(PatternDb::parse_json(json).is_err());
    }

    #[test]
    fn pattern_db_search_with_mismatched_query_dim() {
        let db = test_pattern_db();
        // Query has 2 dims, DB has 3 dims — cosine_similarity returns 0.0 for each
        let results = db.search(&[1.0, 0.0], 3);
        assert_eq!(results.len(), 3);
        for m in &results {
            assert_eq!(m.score, 0.0, "dimension mismatch should produce zero score");
        }
    }

    #[test]
    fn pattern_db_search_top_k_larger_than_db() {
        let db = test_pattern_db();
        let results = db.search(&[1.0, 0.0, 0.0], 100);
        assert_eq!(
            results.len(),
            3,
            "top_k > entries should return all entries"
        );
    }

    #[test]
    fn detector_config_rejects_negative_threshold() {
        let db = test_pattern_db();
        let config = SpiderSenseDetectorConfig {
            similarity_threshold: -0.1,
            ambiguity_band: 0.05,
            top_k: 5,
        };
        assert!(SpiderSenseDetector::new(db, &config).is_err());
    }

    #[test]
    fn detector_config_rejects_nan_ambiguity_band() {
        let db = test_pattern_db();
        let config = SpiderSenseDetectorConfig {
            similarity_threshold: 0.5,
            ambiguity_band: f64::NAN,
            top_k: 5,
        };
        assert!(SpiderSenseDetector::new(db, &config).is_err());
    }

    #[test]
    fn default_config_roundtrips_through_serde() {
        let config = SpiderSenseDetectorConfig::default();
        let json = serde_json::to_string(&config).expect("should serialize");
        let parsed: SpiderSenseDetectorConfig =
            serde_json::from_str(&json).expect("should deserialize");
        assert!((parsed.similarity_threshold - config.similarity_threshold).abs() < f64::EPSILON);
        assert!((parsed.ambiguity_band - config.ambiguity_band).abs() < f64::EPSILON);
        assert_eq!(parsed.top_k, config.top_k);
    }
}
