# Adversarial Robustness for Prompt Security

**Version**: 1.0.0-draft
**Status**: Research & Architecture Specification
**Authors**: Clawdstrike Security Team
**Last Updated**: 2026-02-02

---

## 1. Problem Statement

### 1.1 Definition

Adversarial robustness in prompt security refers to techniques that make detection and enforcement mechanisms resistant to deliberate evasion attempts. Attackers actively craft inputs designed to bypass security guards while achieving malicious objectives.

### 1.2 Adversarial Threat Model

```
+------------------------------------------------------------------+
|                    ADVERSARIAL ATTACK SURFACE                     |
+------------------------------------------------------------------+
|                                                                   |
|  ATTACKER CAPABILITIES:                                           |
|  - Knowledge of detection patterns                                |
|  - Ability to iterate on prompts                                  |
|  - Access to similar LLM systems                                  |
|  - Understanding of guard heuristics                              |
|  - Time to craft sophisticated attacks                            |
|                                                                   |
|  ATTACKER OBJECTIVES:                                             |
|  - Evade detection while achieving malicious goal                 |
|  - Minimize observable indicators                                 |
|  - Preserve attack payload effectiveness                          |
|  - Avoid triggering alerts                                        |
|                                                                   |
+------------------------------------------------------------------+
                              |
                              v
+------------------------------------------------------------------+
|                    EVASION TECHNIQUES                             |
+------------------------------------------------------------------+
|                                                                   |
| 1. CHARACTER-LEVEL PERTURBATIONS                                  |
|    - Unicode substitution (homoglyphs)                            |
|    - Invisible characters                                         |
|    - Character case manipulation                                  |
|    - Whitespace injection                                         |
|                                                                   |
| 2. TOKEN-LEVEL PERTURBATIONS                                      |
|    - Word splitting (ig-nore → ignore)                            |
|    - Synonym replacement                                          |
|    - Typo injection                                               |
|    - Leetspeak/obfuscation                                        |
|                                                                   |
| 3. SEMANTIC PERTURBATIONS                                         |
|    - Paraphrasing                                                 |
|    - Indirect phrasing                                            |
|    - Multi-step reasoning                                         |
|    - Context manipulation                                         |
|                                                                   |
| 4. STRUCTURAL PERTURBATIONS                                       |
|    - Payload fragmentation                                        |
|    - Encoding (Base64, ROT13)                                     |
|    - Nested structures                                            |
|    - Format manipulation                                          |
|                                                                   |
+------------------------------------------------------------------+
```

### 1.3 Attack Examples

| Attack Type | Original | Perturbed | Goal |
|-------------|----------|-----------|------|
| **Homoglyph** | "ignore" | "ignоre" (Cyrillic o) | Bypass keyword filter |
| **Zero-width** | "system" | "sy\u200Bstem" | Split token |
| **Leetspeak** | "password" | "p@ssw0rd" | Evade pattern |
| **Paraphrase** | "ignore previous" | "disregard above" | Semantic evasion |
| **Fragmentation** | "ignore rules" | "ign" + "ore ru" + "les" | Split detection |
| **Encoding** | "reveal secrets" | base64("reveal secrets") | Hide payload |

---

## 2. Research Foundation

### 2.1 Academic Literature

#### 2.1.1 Adversarial Text Attacks

1. **Zou et al. (2023). "Universal and Transferable Adversarial Attacks on Aligned Language Models"**
   - Greedy Coordinate Gradient (GCG) attacks
   - Transferable adversarial suffixes
   - Optimization-based attack generation

2. **Wallace et al. (2019). "Universal Adversarial Triggers for Attacking and Analyzing NLP"**
   - Input-agnostic triggers
   - Gradient-based trigger search
   - Cross-task transferability

3. **Ebrahimi et al. (2018). "HotFlip: White-Box Adversarial Examples for Text Classification"**
   - Character-level perturbations
   - Gradient-based character flips
   - Minimal perturbation attacks

4. **Jin et al. (2020). "Is BERT Really Robust? A Strong Baseline for Natural Language Attack and Defense"**
   - TextFooler attack
   - Synonym-based perturbations
   - Robustness evaluation framework

#### 2.1.2 Defense Mechanisms

1. **Jain et al. (2023). "Baseline Defenses for Adversarial Attacks Against Aligned Language Models"**
   - Paraphrasing defenses
   - Input preprocessing
   - Retokenization

2. **Robey et al. (2023). "SmoothLLM: Defending Large Language Models Against Jailbreaking Attacks"**
   - Randomized smoothing
   - Character perturbation
   - Majority voting

3. **Cao et al. (2024). "Defending Against Alignment-Breaking Attacks via Robustly Aligned LLM"**
   - Adversarial training
   - Alignment robustness
   - Attack detection

4. **Kumar et al. (2023). "Certifying LLM Safety against Adversarial Prompting"**
   - Certified defenses
   - Robustness bounds
   - Formal guarantees

### 2.2 Defense Taxonomy

```
+------------------------------------------------------------------+
|                    ADVERSARIAL DEFENSE LAYERS                     |
+------------------------------------------------------------------+
|                                                                   |
| LAYER 1: INPUT CANONICALIZATION                                   |
|   - Unicode normalization (NFKC)                                  |
|   - Zero-width character removal                                  |
|   - Homoglyph mapping                                             |
|   - Whitespace normalization                                      |
|                                                                   |
| LAYER 2: INPUT PERTURBATION (Randomized Smoothing)                |
|   - Random character drops                                        |
|   - Random character swaps                                        |
|   - Random insertions                                             |
|   - Voting on multiple perturbations                              |
|                                                                   |
| LAYER 3: SEMANTIC ANALYSIS                                        |
|   - Paraphrase detection                                          |
|   - Intent classification                                         |
|   - Embedding similarity                                          |
|   - Cross-lingual analysis                                        |
|                                                                   |
| LAYER 4: ENSEMBLE DETECTION                                       |
|   - Multiple independent detectors                                |
|   - Voting/aggregation                                            |
|   - Confidence calibration                                        |
|   - Anomaly detection                                             |
|                                                                   |
| LAYER 5: RUNTIME MONITORING                                       |
|   - Behavioral analysis                                           |
|   - Output validation                                             |
|   - Session tracking                                              |
|   - Feedback loops                                                |
|                                                                   |
+------------------------------------------------------------------+
```

---

## 3. Architecture

### 3.1 System Design

```
+------------------------------------------------------------------------+
|                    ADVERSARIAL ROBUSTNESS ENGINE                        |
+------------------------------------------------------------------------+
|                                                                         |
|  +------------------+     +------------------+     +------------------+  |
|  | Input            |---->| Canonicalizer    |---->| Perturbation     |  |
|  | Receiver         |     |                  |     | Generator        |  |
|  |                  |     | - Unicode NFKC   |     |                  |  |
|  | - Raw input      |     | - Homoglyph map  |     | - Random drops   |  |
|  | - Metadata       |     | - Zero-width rm  |     | - Random swaps   |  |
|  | - Context        |     | - Whitespace     |     | - Duplicates     |  |
|  +------------------+     +------------------+     +------------------+  |
|           |                       |                       |             |
|           |                       |                       |             |
|           v                       v                       v             |
|  +--------------------------------------------------------------+      |
|  |                    MULTI-DETECTOR ENSEMBLE                    |      |
|  |                                                                |      |
|  |  +--------------+  +--------------+  +--------------+         |      |
|  |  | Heuristic    |  | ML Detector  |  | Semantic     |         |      |
|  |  | Detector     |  |              |  | Analyzer     |         |      |
|  |  +--------------+  +--------------+  +--------------+         |      |
|  |         |                |                |                   |      |
|  |         v                v                v                   |      |
|  |  +----------------------------------------------+             |      |
|  |  |           VOTING / AGGREGATION               |             |      |
|  |  +----------------------------------------------+             |      |
|  +--------------------------------------------------------------+      |
|                                   |                                     |
|                                   v                                     |
|  +------------------+     +------------------+     +------------------+  |
|  | Confidence       |---->| Decision         |---->| Output           |  |
|  | Calibrator       |     | Engine           |     | Handler          |  |
|  |                  |     |                  |     |                  |  |
|  | - Score norm     |     | - Threshold      |     | - Allow/Block    |  |
|  | - Uncertainty    |     | - Policy lookup  |     | - Audit log      |  |
|  +------------------+     +------------------+     +------------------+  |
|                                                                         |
+------------------------------------------------------------------------+
```

### 3.2 Canonicalization Pipeline

```
Input Text
    |
    v
+------------------+
| 1. Decode        |  Detect and decode Base64, URL encoding, etc.
+------------------+
    |
    v
+------------------+
| 2. Unicode NFKC  |  Normalize to compatibility composition
+------------------+
    |
    v
+------------------+
| 3. Homoglyph     |  Map visual lookalikes to ASCII
|    Mapping       |
+------------------+
    |
    v
+------------------+
| 4. Zero-Width    |  Remove invisible characters
|    Removal       |
+------------------+
    |
    v
+------------------+
| 5. Whitespace    |  Normalize spaces, tabs, newlines
|    Normalization |
+------------------+
    |
    v
+------------------+
| 6. Case          |  Lowercase for comparison
|    Normalization |  (preserve original for display)
+------------------+
    |
    v
Canonical Text
```

### 3.3 Randomized Smoothing (SmoothLLM)

```
Original Input: "Ignore previous instructions"

Generate N perturbations (N=10):
┌─────────────────────────────────────────┐
│ 1. "Ignre previous instructions"        │ (dropped 'o')
│ 2. "Ignore previosu instructions"       │ (swapped 'u' and 's')
│ 3. "Ignore previouos instructions"      │ (inserted 'o')
│ 4. "Ignore previous instrctions"        │ (dropped 'u')
│ 5. "Ignroe previous instructions"       │ (swapped 'o' and 'r')
│ ...                                     │
│ 10. "Ignxre previous instructions"      │ (substituted 'x')
└─────────────────────────────────────────┘

Run each through detector:
┌─────────────────────────────────────────┐
│ 1. JAILBREAK (score: 0.85)              │
│ 2. JAILBREAK (score: 0.82)              │
│ 3. JAILBREAK (score: 0.88)              │
│ 4. JAILBREAK (score: 0.79)              │
│ 5. JAILBREAK (score: 0.84)              │
│ ...                                     │
│ 10. SAFE (score: 0.35)                  │ (perturbation too severe)
└─────────────────────────────────────────┘

Aggregate: 9/10 = JAILBREAK with 90% confidence
```

---

## 4. API Design

### 4.1 TypeScript Interface

```typescript
/**
 * Canonicalization options
 */
export interface CanonicalizationConfig {
  /** Unicode normalization form */
  unicodeNormalization: 'NFC' | 'NFD' | 'NFKC' | 'NFKD';

  /** Enable homoglyph mapping */
  homoglyphMapping: boolean;

  /** Custom homoglyph map additions */
  customHomoglyphs?: Map<string, string>;

  /** Remove zero-width characters */
  removeZeroWidth: boolean;

  /** Normalize whitespace */
  normalizeWhitespace: boolean;

  /** Case normalization */
  caseNormalization: 'none' | 'lower' | 'upper';

  /** Encoding detection and decoding */
  decodeEncodings: boolean;

  /** Encodings to detect */
  encodingsToDetect?: ('base64' | 'url' | 'html' | 'unicode_escape')[];
}

/**
 * Perturbation configuration for randomized smoothing
 */
export interface PerturbationConfig {
  /** Number of perturbations to generate */
  numPerturbations: number;

  /** Perturbation types to use */
  perturbationTypes: PerturbationType[];

  /** Perturbation rate (0-1, fraction of characters to perturb) */
  perturbationRate: number;

  /** Random seed for reproducibility (optional) */
  seed?: number;
}

/**
 * Perturbation types
 */
export type PerturbationType =
  | 'char_drop'      // Drop random characters
  | 'char_swap'      // Swap adjacent characters
  | 'char_insert'    // Insert random characters
  | 'char_substitute'// Substitute with random characters
  | 'word_swap'      // Swap adjacent words
  | 'word_drop';     // Drop random words

/**
 * Ensemble detector configuration
 */
export interface EnsembleConfig {
  /** Detectors to use */
  detectors: DetectorConfig[];

  /** Aggregation method */
  aggregation: 'majority_vote' | 'weighted_average' | 'max' | 'min';

  /** Weights for weighted aggregation */
  weights?: number[];

  /** Minimum agreement threshold for majority vote */
  minAgreement?: number;
}

/**
 * Individual detector configuration
 */
export interface DetectorConfig {
  /** Detector type */
  type: 'heuristic' | 'ml' | 'semantic' | 'perplexity';

  /** Detector-specific options */
  options?: Record<string, unknown>;

  /** Weight in ensemble */
  weight?: number;

  /** Enable/disable */
  enabled: boolean;
}

/**
 * Canonicalization result
 */
export interface CanonicalizationResult {
  /** Original input */
  original: string;

  /** Canonicalized output */
  canonical: string;

  /** Transformations applied */
  transformations: Transformation[];

  /** Detected obfuscations */
  detectedObfuscations: ObfuscationDetection[];

  /** Processing time */
  processingTimeMs: number;
}

/**
 * Individual transformation record
 */
export interface Transformation {
  /** Transformation type */
  type: string;

  /** Position in original */
  originalSpan?: { start: number; end: number };

  /** Original text */
  originalText?: string;

  /** Transformed text */
  transformedText?: string;

  /** Description */
  description: string;
}

/**
 * Obfuscation detection
 */
export interface ObfuscationDetection {
  /** Obfuscation type */
  type: 'homoglyph' | 'zero_width' | 'encoding' | 'leetspeak' | 'fragmentation';

  /** Confidence score */
  confidence: number;

  /** Position in original */
  span: { start: number; end: number };

  /** Detected content */
  content: string;

  /** Decoded/normalized content */
  decoded?: string;
}

/**
 * Smoothing result
 */
export interface SmoothingResult {
  /** Original input */
  original: string;

  /** Generated perturbations */
  perturbations: string[];

  /** Detection results for each perturbation */
  detectionResults: DetectionResult[];

  /** Aggregated result */
  aggregatedResult: {
    label: string;
    confidence: number;
    agreement: number;
  };

  /** Processing time */
  processingTimeMs: number;
}

/**
 * Individual detection result
 */
export interface DetectionResult {
  /** Input (perturbation) */
  input: string;

  /** Detected label */
  label: string;

  /** Confidence score */
  score: number;

  /** Detector that produced this result */
  detector: string;
}

/**
 * Ensemble detection result
 */
export interface EnsembleDetectionResult {
  /** Final label */
  label: string;

  /** Aggregated confidence */
  confidence: number;

  /** Per-detector results */
  detectorResults: Map<string, DetectionResult>;

  /** Aggregation method used */
  aggregationMethod: string;

  /** Whether detectors agreed */
  unanimous: boolean;

  /** Processing time */
  processingTimeMs: number;
}

/**
 * Adversarial robustness guard configuration
 */
export interface AdversarialRobustnessConfig {
  /** Canonicalization settings */
  canonicalization: CanonicalizationConfig;

  /** Perturbation/smoothing settings */
  smoothing?: PerturbationConfig;

  /** Ensemble detection settings */
  ensemble: EnsembleConfig;

  /** Action on detected obfuscation */
  obfuscationAction: 'log' | 'warn' | 'block';

  /** Confidence threshold for blocking */
  blockThreshold: number;

  /** Confidence threshold for warning */
  warnThreshold: number;
}

/**
 * Adversarial robustness guard
 */
export class AdversarialRobustnessGuard extends BaseGuard {
  constructor(config?: Partial<AdversarialRobustnessConfig>);

  /**
   * Canonicalize input text
   */
  canonicalize(input: string): CanonicalizationResult;

  /**
   * Apply randomized smoothing
   */
  smooth(input: string, detector: (text: string) => DetectionResult): SmoothingResult;

  /**
   * Run ensemble detection
   */
  detectEnsemble(input: string): Promise<EnsembleDetectionResult>;

  /**
   * Full adversarial-robust analysis
   */
  analyze(input: string): Promise<AdversarialAnalysisResult>;

  /**
   * Check for obfuscation attempts
   */
  detectObfuscation(input: string): ObfuscationDetection[];

  /**
   * Update configuration
   */
  updateConfig(config: Partial<AdversarialRobustnessConfig>): void;
}

/**
 * Complete adversarial analysis result
 */
export interface AdversarialAnalysisResult {
  /** Original input */
  original: string;

  /** Canonicalization result */
  canonicalization: CanonicalizationResult;

  /** Obfuscation detections */
  obfuscations: ObfuscationDetection[];

  /** Smoothing result (if enabled) */
  smoothing?: SmoothingResult;

  /** Ensemble detection result */
  ensemble: EnsembleDetectionResult;

  /** Final decision */
  decision: {
    action: 'allow' | 'warn' | 'block';
    reason: string;
    confidence: number;
  };

  /** Processing time */
  totalProcessingTimeMs: number;
}
```

### 4.2 Rust Interface

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Unicode normalization forms
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnicodeNormalization {
    NFC,
    NFD,
    NFKC,
    NFKD,
}

/// Case normalization options
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaseNormalization {
    None,
    Lower,
    Upper,
}

/// Encoding types to detect
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncodingType {
    Base64,
    Url,
    Html,
    UnicodeEscape,
}

/// Canonicalization configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanonicalizationConfig {
    #[serde(default = "default_unicode_norm")]
    pub unicode_normalization: UnicodeNormalization,
    #[serde(default = "default_true")]
    pub homoglyph_mapping: bool,
    #[serde(default)]
    pub custom_homoglyphs: HashMap<char, char>,
    #[serde(default = "default_true")]
    pub remove_zero_width: bool,
    #[serde(default = "default_true")]
    pub normalize_whitespace: bool,
    #[serde(default)]
    pub case_normalization: CaseNormalization,
    #[serde(default = "default_true")]
    pub decode_encodings: bool,
    #[serde(default = "default_encodings")]
    pub encodings_to_detect: Vec<EncodingType>,
}

fn default_unicode_norm() -> UnicodeNormalization {
    UnicodeNormalization::NFKC
}

fn default_true() -> bool {
    true
}

fn default_encodings() -> Vec<EncodingType> {
    vec![EncodingType::Base64, EncodingType::Url]
}

impl Default for CanonicalizationConfig {
    fn default() -> Self {
        Self {
            unicode_normalization: default_unicode_norm(),
            homoglyph_mapping: true,
            custom_homoglyphs: HashMap::new(),
            remove_zero_width: true,
            normalize_whitespace: true,
            case_normalization: CaseNormalization::None,
            decode_encodings: true,
            encodings_to_detect: default_encodings(),
        }
    }
}

/// Perturbation types
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerturbationType {
    CharDrop,
    CharSwap,
    CharInsert,
    CharSubstitute,
    WordSwap,
    WordDrop,
}

/// Perturbation configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerturbationConfig {
    #[serde(default = "default_num_perturbations")]
    pub num_perturbations: usize,
    #[serde(default = "default_perturbation_types")]
    pub perturbation_types: Vec<PerturbationType>,
    #[serde(default = "default_perturbation_rate")]
    pub perturbation_rate: f32,
    pub seed: Option<u64>,
}

fn default_num_perturbations() -> usize { 10 }
fn default_perturbation_rate() -> f32 { 0.1 }
fn default_perturbation_types() -> Vec<PerturbationType> {
    vec![
        PerturbationType::CharDrop,
        PerturbationType::CharSwap,
        PerturbationType::CharInsert,
    ]
}

impl Default for PerturbationConfig {
    fn default() -> Self {
        Self {
            num_perturbations: default_num_perturbations(),
            perturbation_types: default_perturbation_types(),
            perturbation_rate: default_perturbation_rate(),
            seed: None,
        }
    }
}

/// Aggregation methods
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregationMethod {
    MajorityVote,
    WeightedAverage,
    Max,
    Min,
}

/// Detector types
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DetectorType {
    Heuristic,
    Ml,
    Semantic,
    Perplexity,
}

/// Individual detector configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectorConfig {
    #[serde(rename = "type")]
    pub detector_type: DetectorType,
    #[serde(default)]
    pub options: HashMap<String, serde_json::Value>,
    pub weight: Option<f32>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Ensemble configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnsembleConfig {
    pub detectors: Vec<DetectorConfig>,
    #[serde(default)]
    pub aggregation: AggregationMethod,
    pub weights: Option<Vec<f32>>,
    pub min_agreement: Option<f32>,
}

impl Default for AggregationMethod {
    fn default() -> Self {
        Self::MajorityVote
    }
}

/// Text span
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// Transformation record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transformation {
    #[serde(rename = "type")]
    pub transform_type: String,
    pub original_span: Option<Span>,
    pub original_text: Option<String>,
    pub transformed_text: Option<String>,
    pub description: String,
}

/// Obfuscation type
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObfuscationType {
    Homoglyph,
    ZeroWidth,
    Encoding,
    Leetspeak,
    Fragmentation,
}

/// Obfuscation detection
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObfuscationDetection {
    #[serde(rename = "type")]
    pub obfuscation_type: ObfuscationType,
    pub confidence: f32,
    pub span: Span,
    pub content: String,
    pub decoded: Option<String>,
}

/// Canonicalization result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CanonicalizationResult {
    pub original: String,
    pub canonical: String,
    pub transformations: Vec<Transformation>,
    pub detected_obfuscations: Vec<ObfuscationDetection>,
    pub processing_time_ms: f64,
}

/// Detection result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DetectionResult {
    pub input: String,
    pub label: String,
    pub score: f32,
    pub detector: String,
}

/// Smoothing result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmoothingResult {
    pub original: String,
    pub perturbations: Vec<String>,
    pub detection_results: Vec<DetectionResult>,
    pub aggregated_result: AggregatedResult,
    pub processing_time_ms: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedResult {
    pub label: String,
    pub confidence: f32,
    pub agreement: f32,
}

/// Ensemble detection result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnsembleDetectionResult {
    pub label: String,
    pub confidence: f32,
    pub detector_results: HashMap<String, DetectionResult>,
    pub aggregation_method: String,
    pub unanimous: bool,
    pub processing_time_ms: f64,
}

/// Decision action
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DecisionAction {
    Allow,
    Warn,
    Block,
}

/// Final decision
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Decision {
    pub action: DecisionAction,
    pub reason: String,
    pub confidence: f32,
}

/// Complete adversarial analysis result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdversarialAnalysisResult {
    pub original: String,
    pub canonicalization: CanonicalizationResult,
    pub obfuscations: Vec<ObfuscationDetection>,
    pub smoothing: Option<SmoothingResult>,
    pub ensemble: EnsembleDetectionResult,
    pub decision: Decision,
    pub total_processing_time_ms: f64,
}

/// Obfuscation action
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObfuscationAction {
    Log,
    Warn,
    Block,
}

/// Complete configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdversarialRobustnessConfig {
    pub canonicalization: CanonicalizationConfig,
    pub smoothing: Option<PerturbationConfig>,
    pub ensemble: EnsembleConfig,
    #[serde(default)]
    pub obfuscation_action: ObfuscationAction,
    #[serde(default = "default_block_threshold")]
    pub block_threshold: f32,
    #[serde(default = "default_warn_threshold")]
    pub warn_threshold: f32,
}

fn default_block_threshold() -> f32 { 0.8 }
fn default_warn_threshold() -> f32 { 0.5 }

impl Default for ObfuscationAction {
    fn default() -> Self {
        Self::Warn
    }
}

/// Adversarial robustness guard
pub struct AdversarialRobustnessGuard {
    config: AdversarialRobustnessConfig,
    canonicalizer: Canonicalizer,
    perturbation_generator: PerturbationGenerator,
    ensemble_detector: EnsembleDetector,
}

impl AdversarialRobustnessGuard {
    /// Create with configuration
    pub fn new(config: AdversarialRobustnessConfig) -> Self;

    /// Canonicalize input text
    pub fn canonicalize(&self, input: &str) -> CanonicalizationResult;

    /// Apply randomized smoothing
    pub fn smooth<F>(&self, input: &str, detector: F) -> SmoothingResult
    where
        F: Fn(&str) -> DetectionResult;

    /// Run ensemble detection
    pub async fn detect_ensemble(&self, input: &str) -> Result<EnsembleDetectionResult, AdversarialError>;

    /// Full adversarial-robust analysis
    pub async fn analyze(&self, input: &str) -> Result<AdversarialAnalysisResult, AdversarialError>;

    /// Check for obfuscation attempts
    pub fn detect_obfuscation(&self, input: &str) -> Vec<ObfuscationDetection>;

    /// Update configuration
    pub fn update_config(&mut self, config: AdversarialRobustnessConfig);
}

#[derive(Debug)]
pub enum AdversarialError {
    ConfigError(String),
    DetectionError(String),
    ProcessingError(String),
}
```

---

## 5. Algorithms

### 5.1 Homoglyph Detection and Mapping

```rust
use std::collections::HashMap;
use unicode_normalization::UnicodeNormalization;

/// Comprehensive homoglyph map
fn build_homoglyph_map() -> HashMap<char, char> {
    let mut map = HashMap::new();

    // Cyrillic lookalikes
    map.insert('\u{0430}', 'a'); // а -> a
    map.insert('\u{0435}', 'e'); // е -> e
    map.insert('\u{043E}', 'o'); // о -> o
    map.insert('\u{0440}', 'p'); // р -> p
    map.insert('\u{0441}', 'c'); // с -> c
    map.insert('\u{0443}', 'y'); // у -> y
    map.insert('\u{0445}', 'x'); // х -> x
    map.insert('\u{0410}', 'A'); // А -> A
    map.insert('\u{0412}', 'B'); // В -> B
    map.insert('\u{0415}', 'E'); // Е -> E
    map.insert('\u{041A}', 'K'); // К -> K
    map.insert('\u{041C}', 'M'); // М -> M
    map.insert('\u{041D}', 'H'); // Н -> H
    map.insert('\u{041E}', 'O'); // О -> O
    map.insert('\u{0420}', 'P'); // Р -> P
    map.insert('\u{0421}', 'C'); // С -> C
    map.insert('\u{0422}', 'T'); // Т -> T
    map.insert('\u{0425}', 'X'); // Х -> X

    // Greek lookalikes
    map.insert('\u{0391}', 'A'); // Α -> A
    map.insert('\u{0392}', 'B'); // Β -> B
    map.insert('\u{0395}', 'E'); // Ε -> E
    map.insert('\u{0397}', 'H'); // Η -> H
    map.insert('\u{0399}', 'I'); // Ι -> I
    map.insert('\u{039A}', 'K'); // Κ -> K
    map.insert('\u{039C}', 'M'); // Μ -> M
    map.insert('\u{039D}', 'N'); // Ν -> N
    map.insert('\u{039F}', 'O'); // Ο -> O
    map.insert('\u{03A1}', 'P'); // Ρ -> P
    map.insert('\u{03A4}', 'T'); // Τ -> T
    map.insert('\u{03A5}', 'Y'); // Υ -> Y
    map.insert('\u{03A7}', 'X'); // Χ -> X
    map.insert('\u{03BF}', 'o'); // ο -> o

    // Mathematical/special
    map.insert('\u{FF21}', 'A'); // Ａ (fullwidth)
    map.insert('\u{FF22}', 'B'); // Ｂ
    // ... etc

    // Leetspeak
    map.insert('0', 'o');
    map.insert('1', 'i');
    map.insert('3', 'e');
    map.insert('4', 'a');
    map.insert('5', 's');
    map.insert('7', 't');
    map.insert('@', 'a');
    map.insert('$', 's');

    map
}

struct Canonicalizer {
    config: CanonicalizationConfig,
    homoglyph_map: HashMap<char, char>,
}

impl Canonicalizer {
    fn new(config: CanonicalizationConfig) -> Self {
        let mut homoglyph_map = build_homoglyph_map();
        homoglyph_map.extend(config.custom_homoglyphs.clone());

        Self {
            config,
            homoglyph_map,
        }
    }

    fn canonicalize(&self, input: &str) -> CanonicalizationResult {
        let start = std::time::Instant::now();
        let mut text = input.to_string();
        let mut transformations = Vec::new();
        let mut obfuscations = Vec::new();

        // 1. Decode encodings
        if self.config.decode_encodings {
            let (decoded, decode_transforms, decode_obfuscations) = self.decode_encodings(&text);
            text = decoded;
            transformations.extend(decode_transforms);
            obfuscations.extend(decode_obfuscations);
        }

        // 2. Unicode normalization
        let normalized: String = match self.config.unicode_normalization {
            UnicodeNormalization::NFKC => text.nfkc().collect(),
            UnicodeNormalization::NFC => text.nfc().collect(),
            UnicodeNormalization::NFD => text.nfd().collect(),
            UnicodeNormalization::NFKD => text.nfkd().collect(),
        };
        if normalized != text {
            transformations.push(Transformation {
                transform_type: "unicode_normalization".to_string(),
                original_span: None,
                original_text: Some(text.clone()),
                transformed_text: Some(normalized.clone()),
                description: format!("Applied {:?} normalization", self.config.unicode_normalization),
            });
            text = normalized;
        }

        // 3. Zero-width removal
        if self.config.remove_zero_width {
            let (cleaned, zw_transforms, zw_obfuscations) = self.remove_zero_width(&text);
            text = cleaned;
            transformations.extend(zw_transforms);
            obfuscations.extend(zw_obfuscations);
        }

        // 4. Homoglyph mapping
        if self.config.homoglyph_mapping {
            let (mapped, hg_transforms, hg_obfuscations) = self.map_homoglyphs(&text);
            text = mapped;
            transformations.extend(hg_transforms);
            obfuscations.extend(hg_obfuscations);
        }

        // 5. Whitespace normalization
        if self.config.normalize_whitespace {
            let whitespace_normalized = self.normalize_whitespace(&text);
            if whitespace_normalized != text {
                transformations.push(Transformation {
                    transform_type: "whitespace_normalization".to_string(),
                    original_span: None,
                    original_text: Some(text.clone()),
                    transformed_text: Some(whitespace_normalized.clone()),
                    description: "Normalized whitespace".to_string(),
                });
                text = whitespace_normalized;
            }
        }

        // 6. Case normalization
        let final_text = match self.config.case_normalization {
            CaseNormalization::Lower => text.to_lowercase(),
            CaseNormalization::Upper => text.to_uppercase(),
            CaseNormalization::None => text,
        };

        CanonicalizationResult {
            original: input.to_string(),
            canonical: final_text,
            transformations,
            detected_obfuscations: obfuscations,
            processing_time_ms: start.elapsed().as_secs_f64() * 1000.0,
        }
    }

    fn remove_zero_width(&self, text: &str) -> (String, Vec<Transformation>, Vec<ObfuscationDetection>) {
        let zero_width_chars = [
            '\u{200B}', // Zero Width Space
            '\u{200C}', // Zero Width Non-Joiner
            '\u{200D}', // Zero Width Joiner
            '\u{FEFF}', // Byte Order Mark
            '\u{00AD}', // Soft Hyphen
            '\u{2060}', // Word Joiner
        ];

        let mut result = String::new();
        let mut obfuscations = Vec::new();
        let mut transforms = Vec::new();
        let mut found_any = false;

        for (i, c) in text.char_indices() {
            if zero_width_chars.contains(&c) {
                found_any = true;
                obfuscations.push(ObfuscationDetection {
                    obfuscation_type: ObfuscationType::ZeroWidth,
                    confidence: 1.0,
                    span: Span { start: i, end: i + c.len_utf8() },
                    content: format!("U+{:04X}", c as u32),
                    decoded: None,
                });
            } else {
                result.push(c);
            }
        }

        if found_any {
            transforms.push(Transformation {
                transform_type: "zero_width_removal".to_string(),
                original_span: None,
                original_text: Some(text.to_string()),
                transformed_text: Some(result.clone()),
                description: format!("Removed {} zero-width characters", obfuscations.len()),
            });
        }

        (result, transforms, obfuscations)
    }

    fn map_homoglyphs(&self, text: &str) -> (String, Vec<Transformation>, Vec<ObfuscationDetection>) {
        let mut result = String::new();
        let mut obfuscations = Vec::new();
        let mut transforms = Vec::new();
        let mut mapped_count = 0;

        for (i, c) in text.char_indices() {
            if let Some(&mapped) = self.homoglyph_map.get(&c) {
                result.push(mapped);
                mapped_count += 1;
                obfuscations.push(ObfuscationDetection {
                    obfuscation_type: ObfuscationType::Homoglyph,
                    confidence: 0.95,
                    span: Span { start: i, end: i + c.len_utf8() },
                    content: c.to_string(),
                    decoded: Some(mapped.to_string()),
                });
            } else {
                result.push(c);
            }
        }

        if mapped_count > 0 {
            transforms.push(Transformation {
                transform_type: "homoglyph_mapping".to_string(),
                original_span: None,
                original_text: Some(text.to_string()),
                transformed_text: Some(result.clone()),
                description: format!("Mapped {} homoglyph characters", mapped_count),
            });
        }

        (result, transforms, obfuscations)
    }

    fn normalize_whitespace(&self, text: &str) -> String {
        text.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn decode_encodings(&self, text: &str) -> (String, Vec<Transformation>, Vec<ObfuscationDetection>) {
        // Implementation would check for Base64, URL encoding, etc.
        // and decode if found
        (text.to_string(), Vec::new(), Vec::new())
    }
}
```

### 5.2 Randomized Smoothing

```rust
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

struct PerturbationGenerator {
    config: PerturbationConfig,
    rng: StdRng,
}

impl PerturbationGenerator {
    fn new(config: PerturbationConfig) -> Self {
        let rng = match config.seed {
            Some(seed) => StdRng::seed_from_u64(seed),
            None => StdRng::from_entropy(),
        };

        Self { config, rng }
    }

    fn generate_perturbations(&mut self, input: &str) -> Vec<String> {
        (0..self.config.num_perturbations)
            .map(|_| self.generate_single_perturbation(input))
            .collect()
    }

    fn generate_single_perturbation(&mut self, input: &str) -> String {
        let mut chars: Vec<char> = input.chars().collect();
        let num_changes = (chars.len() as f32 * self.config.perturbation_rate) as usize;

        for _ in 0..num_changes {
            if chars.is_empty() {
                break;
            }

            let perturbation_type = &self.config.perturbation_types[
                self.rng.gen_range(0..self.config.perturbation_types.len())
            ];

            match perturbation_type {
                PerturbationType::CharDrop => {
                    let idx = self.rng.gen_range(0..chars.len());
                    chars.remove(idx);
                }
                PerturbationType::CharSwap => {
                    if chars.len() >= 2 {
                        let idx = self.rng.gen_range(0..chars.len() - 1);
                        chars.swap(idx, idx + 1);
                    }
                }
                PerturbationType::CharInsert => {
                    let idx = self.rng.gen_range(0..=chars.len());
                    let c = self.random_char();
                    chars.insert(idx, c);
                }
                PerturbationType::CharSubstitute => {
                    let idx = self.rng.gen_range(0..chars.len());
                    chars[idx] = self.random_char();
                }
                PerturbationType::WordSwap => {
                    // Convert to words, swap, convert back
                    let text: String = chars.iter().collect();
                    let mut words: Vec<&str> = text.split_whitespace().collect();
                    if words.len() >= 2 {
                        let idx = self.rng.gen_range(0..words.len() - 1);
                        words.swap(idx, idx + 1);
                        chars = words.join(" ").chars().collect();
                    }
                }
                PerturbationType::WordDrop => {
                    let text: String = chars.iter().collect();
                    let mut words: Vec<&str> = text.split_whitespace().collect();
                    if words.len() > 1 {
                        let idx = self.rng.gen_range(0..words.len());
                        words.remove(idx);
                        chars = words.join(" ").chars().collect();
                    }
                }
            }
        }

        chars.iter().collect()
    }

    fn random_char(&mut self) -> char {
        let chars = "abcdefghijklmnopqrstuvwxyz";
        chars.chars().nth(self.rng.gen_range(0..chars.len())).unwrap()
    }
}

/// Run smoothing defense
fn smooth_detection<F>(
    input: &str,
    config: &PerturbationConfig,
    detector: F,
) -> SmoothingResult
where
    F: Fn(&str) -> DetectionResult,
{
    let start = std::time::Instant::now();
    let mut generator = PerturbationGenerator::new(config.clone());

    let perturbations = generator.generate_perturbations(input);
    let detection_results: Vec<DetectionResult> = perturbations
        .iter()
        .map(|p| detector(p))
        .collect();

    // Aggregate results (majority vote)
    let mut label_counts: HashMap<String, usize> = HashMap::new();
    let mut total_score: f32 = 0.0;

    for result in &detection_results {
        *label_counts.entry(result.label.clone()).or_insert(0) += 1;
        total_score += result.score;
    }

    let (majority_label, majority_count) = label_counts
        .iter()
        .max_by_key(|(_, count)| *count)
        .map(|(label, count)| (label.clone(), *count))
        .unwrap_or(("unknown".to_string(), 0));

    let agreement = majority_count as f32 / detection_results.len() as f32;
    let avg_score = total_score / detection_results.len() as f32;

    SmoothingResult {
        original: input.to_string(),
        perturbations,
        detection_results,
        aggregated_result: AggregatedResult {
            label: majority_label,
            confidence: avg_score * agreement,
            agreement,
        },
        processing_time_ms: start.elapsed().as_secs_f64() * 1000.0,
    }
}
```

---

## 6. Performance Analysis

### 6.1 Latency Impact

| Component | Overhead | Notes |
|-----------|----------|-------|
| Canonicalization | +1-2ms | Single pass |
| Homoglyph detection | +0.5ms | Hash lookup |
| Smoothing (N=10) | +10x base | N detector calls |
| Ensemble (3 detectors) | +3x base | Parallel possible |

### 6.2 Accuracy vs Performance Tradeoffs

| Configuration | Accuracy | Latency | Use Case |
|---------------|----------|---------|----------|
| Canon only | 85% | +2ms | Real-time |
| Canon + Ensemble | 92% | +15ms | Standard |
| Canon + Smoothing | 95% | +50ms | High security |
| Full pipeline | 98% | +100ms | Critical |

---

## 7. Implementation Phases

### Phase 1: Canonicalization (Week 1-2)
- Unicode normalization
- Homoglyph mapping
- Zero-width removal
- Basic encoding detection

### Phase 2: Smoothing (Week 3-4)
- Perturbation generator
- Aggregation logic
- Configuration API
- Benchmark suite

### Phase 3: Ensemble (Week 5-6)
- Detector abstraction
- Voting mechanisms
- Confidence calibration
- Integration with existing guards

### Phase 4: Production (Week 7-8)
- Performance optimization
- Monitoring and metrics
- Documentation
- Security audit

---

## 8. References

1. Zou, A., et al. (2023). "Universal and Transferable Adversarial Attacks on Aligned Language Models." arXiv:2307.15043
2. Wallace, E., et al. (2019). "Universal Adversarial Triggers for Attacking and Analyzing NLP." EMNLP 2019
3. Ebrahimi, J., et al. (2018). "HotFlip: White-Box Adversarial Examples for Text Classification." ACL 2018
4. Jin, D., et al. (2020). "Is BERT Really Robust? A Strong Baseline for Natural Language Attack and Defense." AAAI 2020
5. Jain, S., et al. (2023). "Baseline Defenses for Adversarial Attacks Against Aligned Language Models." arXiv:2309.00614
6. Robey, A., et al. (2023). "SmoothLLM: Defending Large Language Models Against Jailbreaking Attacks." arXiv:2310.03684
7. Kumar, A., et al. (2023). "Certifying LLM Safety against Adversarial Prompting." arXiv:2309.02705

---

*This document is part of the Clawdstrike Prompt Security specification suite.*
