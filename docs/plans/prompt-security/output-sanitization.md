# Output Sanitization Guard

**Version**: 1.0.0-draft
**Status**: Research & Architecture Specification
**Authors**: Clawdstrike Security Team
**Last Updated**: 2026-02-02

---

## 1. Problem Statement

### 1.1 Definition

Output sanitization refers to the inspection and modification of LLM-generated content before it reaches end users or downstream systems. The goal is to prevent unintentional leakage of sensitive information including:

- **Secrets**: API keys, tokens, passwords, private keys
- **PII**: Names, addresses, SSNs, phone numbers, emails
- **Internal Data**: System prompts, internal URLs, file paths
- **Sensitive Context**: Confidential business information

### 1.2 Threat Model

```
+------------------------+     +------------------------+     +------------------------+
|     LLM PROCESSING     |     |    OUTPUT STREAM       |     |    EXTERNAL WORLD      |
+------------------------+     +------------------------+     +------------------------+
|                        |     |                        |     |                        |
| System Prompt          |---->| Generated Response     |---->| End User               |
| (contains secrets)     |     | (may leak secrets)     |     | (should not see)       |
|                        |     |                        |     |                        |
| Training Data Memo     |---->| Completion             |---->| API Consumer           |
| (PII residue)          |     | (may echo PII)         |     | (compliance risk)      |
|                        |     |                        |     |                        |
| Context Window         |---->| Tool Call Results      |---->| Audit Log              |
| (user data)            |     | (may expose paths)     |     | (redaction needed)     |
|                        |     |                        |     |                        |
+------------------------+     +------------------------+     +------------------------+

                               SANITIZATION CHECKPOINT
                               ========================
                               Before external delivery
```

### 1.3 Leakage Vectors

| Vector | Description | Example |
|--------|-------------|---------|
| **Direct Echo** | Model repeats secret from context | "Your API key is sk-abc123..." |
| **Partial Reveal** | Model hints at secret structure | "The key starts with AKIA..." |
| **Indirect Reference** | Model describes where secrets are | "Check the .env file for credentials" |
| **Training Leakage** | Model outputs memorized PII | Names, addresses from training data |
| **System Prompt Leak** | Model reveals system instructions | "My instructions say to never..." |
| **Path Disclosure** | Model reveals internal paths | "/var/secrets/api_key.txt" |
| **Error Message Leak** | Stack traces with sensitive info | Connection strings in exceptions |

### 1.4 Regulatory Context

| Regulation | Relevant Requirements |
|------------|----------------------|
| **GDPR** | Data minimization, right to erasure, breach notification |
| **CCPA** | Consumer right to know, delete, opt-out |
| **HIPAA** | PHI protection, minimum necessary standard |
| **PCI-DSS** | Cardholder data protection, masking requirements |
| **SOC 2** | Data classification, access controls |

---

## 2. Research Foundation

### 2.1 Academic Literature

#### 2.1.1 Training Data Extraction

1. **Carlini et al. (2021). "Extracting Training Data from Large Language Models"**
   - Demonstrated extraction of memorized training data
   - ~600 unique memorized sequences from GPT-2
   - Key insight: Larger models memorize more

2. **Carlini et al. (2023). "Quantifying Memorization Across Neural Language Models"**
   - Systematic measurement of memorization
   - Relationship between duplication and memorization
   - Extraction attack methodologies

3. **Lukas et al. (2023). "Analyzing Leakage of Personally Identifiable Information in Language Models"**
   - PII-specific extraction attacks
   - Defense evaluation framework
   - Fine-tuning as leakage vector

#### 2.1.2 Privacy-Preserving Generation

1. **Huang et al. (2022). "Large Language Models Can Be Strong Differentially Private Learners"**
   - Differential privacy for LLM training
   - Privacy-utility tradeoffs
   - Practical deployment considerations

2. **Yu et al. (2023). "Bag of Tricks for Training Data Extraction from Language Models"**
   - Comprehensive extraction techniques
   - Defense evaluation
   - Best practices for mitigation

#### 2.1.3 Output Filtering

1. **Rebedea et al. (2023). "NeMo Guardrails: A Toolkit for Controllable LLM Applications"**
   - Output filtering architectures
   - Programmable guardrails
   - Integration patterns

2. **Inan et al. (2023). "Llama Guard: LLM-based Input-Output Safeguard"**
   - Taxonomy for output safety
   - Multi-class classification approach
   - Benchmark datasets

### 2.2 Industry Standards

- **OWASP Top 10 for LLMs**: LLM06 - Sensitive Information Disclosure
- **NIST SP 800-188**: De-Identification of Personal Information
- **ISO 27701**: Privacy Information Management

---

## 3. Architecture

### 3.1 System Design

```
+------------------------------------------------------------------------+
|                      OUTPUT SANITIZATION PIPELINE                       |
+------------------------------------------------------------------------+
|                                                                         |
|  +------------------+     +------------------+     +------------------+  |
|  | Stream Tokenizer |---->| Pattern Scanner  |---->| Entity Recognizer| |
|  |                  |     |                  |     | (NER)            |  |
|  | - Chunk output   |     | - Regex secrets  |     | - Names          |  |
|  | - Buffer mgmt    |     | - Known formats  |     | - Addresses      |  |
|  | - Position track |     | - High entropy   |     | - SSN/ID         |  |
|  +------------------+     +------------------+     +------------------+  |
|           |                       |                       |             |
|           v                       v                       v             |
|  +--------------------------------------------------------------+      |
|  |                    DETECTION AGGREGATOR                       |      |
|  |  - Combine signals from all detectors                         |      |
|  |  - Score confidence for each finding                          |      |
|  |  - Apply context-specific rules                               |      |
|  +--------------------------------------------------------------+      |
|                                   |                                     |
|                                   v                                     |
|  +------------------+     +------------------+     +------------------+  |
|  | Policy Engine    |---->| Redactor         |---->| Output Emitter  |  |
|  |                  |     |                  |     |                  |  |
|  | - Classification |     | - Full redact    |     | - Sanitized out |  |
|  | - Action rules   |     | - Partial mask   |     | - Audit trail   |  |
|  | - Allowlists     |     | - Placeholder    |     | - Alerts        |  |
|  +------------------+     +------------------+     +------------------+  |
|                                                                         |
+------------------------------------------------------------------------+
```

### 3.2 Detection Categories

#### Category 1: Secrets (High Confidence Patterns)

```
+------------------------------------------------------------------+
|                    SECRET DETECTION PATTERNS                      |
+------------------------------------------------------------------+
| Type                | Pattern                    | Confidence     |
+------------------------------------------------------------------+
| AWS Access Key      | AKIA[0-9A-Z]{16}          | Very High      |
| AWS Secret Key      | [A-Za-z0-9/+=]{40}        | High (context) |
| GitHub Token        | gh[ps]_[A-Za-z0-9]{36}    | Very High      |
| OpenAI Key          | sk-[A-Za-z0-9]{48}        | Very High      |
| Anthropic Key       | sk-ant-api03-[A-Za-z0-9_-]{93} | Very High      |
| Private Key         | -----BEGIN.*PRIVATE KEY   | Very High      |
| JWT Token           | eyJ[A-Za-z0-9_-]*\.eyJ... | High           |
| Generic API Key     | api[_-]?key.*[A-Za-z0-9]+ | Medium         |
| Password Assignment | password\s*[=:]\s*\S+     | Medium         |
| Connection String   | protocol://user:pass@...  | High           |
+------------------------------------------------------------------+
```

#### Category 2: PII (Entity Recognition)

```
+------------------------------------------------------------------+
|                    PII ENTITY CATEGORIES                          |
+------------------------------------------------------------------+
| Entity Type         | Examples                   | Detection      |
+------------------------------------------------------------------+
| Person Name         | "John Smith", "Dr. Jane"  | NER Model      |
| Email Address       | user@domain.com           | Regex + Valid  |
| Phone Number        | (555) 123-4567            | Regex + Format |
| SSN                 | 123-45-6789               | Regex + Luhn   |
| Credit Card         | 4111-1111-1111-1111       | Regex + Luhn   |
| Physical Address    | "123 Main St, City, ST"   | NER + Regex    |
| IP Address          | 192.168.1.1               | Regex          |
| Date of Birth       | "born on 01/15/1990"      | NER + Regex    |
| Medical Record      | MRN, diagnosis codes      | Pattern + NER  |
| Financial Account   | Account numbers           | Pattern        |
+------------------------------------------------------------------+
```

#### Category 3: Internal Information

```
+------------------------------------------------------------------+
|                    INTERNAL INFO PATTERNS                         |
+------------------------------------------------------------------+
| Type                | Indicators                 | Action         |
+------------------------------------------------------------------+
| System Prompt       | "My instructions...",     | Block/Redact   |
|                     | "I was told to..."        |                |
| Internal URLs       | *.internal.*, localhost   | Redact         |
| File Paths          | /var/, /home/, C:\        | Redact         |
| Database Names      | db_production, users_pii  | Redact         |
| Internal IPs        | 10.*, 192.168.*, 172.16.* | Redact         |
| Employee Info       | @company-internal.com     | Redact         |
+------------------------------------------------------------------+
```

### 3.3 Redaction Strategies

| Strategy | Description | Use Case |
|----------|-------------|----------|
| **Full Redaction** | Replace with `[REDACTED]` | High-sensitivity secrets |
| **Partial Masking** | Keep prefix/suffix, mask middle | User verification needs |
| **Type Replacement** | Replace with type label `[API_KEY]` | Debugging clarity |
| **Synthetic Replacement** | Replace with fake but valid-format data | Testing environments |
| **Hash Replacement** | Replace with hash for correlation | Audit trail needs |

---

## 4. API Design

### 4.1 TypeScript Interface

```typescript
/**
 * Sensitive data categories
 */
export type SensitiveCategory =
  | 'secret'           // API keys, tokens, passwords
  | 'pii'              // Personally identifiable information
  | 'phi'              // Protected health information
  | 'pci'              // Payment card information
  | 'internal'         // Internal system information
  | 'custom';          // User-defined categories

/**
 * Redaction strategy
 */
export type RedactionStrategy =
  | 'full'             // Complete redaction: [REDACTED]
  | 'partial'          // Partial masking: sk-****1234
  | 'type_label'       // Type indicator: [API_KEY]
  | 'synthetic'        // Fake replacement: sk-fake123...
  | 'hash'             // Hash for correlation: [SHA:a1b2c3]
  | 'none';            // Log only, don't redact

/**
 * Detection result for a single finding
 */
export interface SensitiveDataFinding {
  /** Unique finding identifier */
  id: string;

  /** Category of sensitive data */
  category: SensitiveCategory;

  /** Specific type within category */
  type: string;

  /** Confidence score [0, 1] */
  confidence: number;

  /** Position in original text */
  span: { start: number; end: number };

  /** Matched text (may be truncated for security) */
  matchPreview: string;

  /** Detection method used */
  detector: 'pattern' | 'ner' | 'entropy' | 'ml' | 'custom';

  /** Recommended action */
  recommendedAction: RedactionStrategy;
}

/**
 * Sanitization result
 */
export interface SanitizationResult {
  /** Sanitized output text */
  sanitized: string;

  /** Whether any redactions were made */
  wasRedacted: boolean;

  /** All findings detected */
  findings: SensitiveDataFinding[];

  /** Redactions applied */
  redactions: Redaction[];

  /** Processing statistics */
  stats: {
    inputLength: number;
    outputLength: number;
    findingsCount: number;
    redactionsCount: number;
    processingTimeMs: number;
  };
}

/**
 * Applied redaction record
 */
export interface Redaction {
  /** Finding that triggered this redaction */
  findingId: string;

  /** Strategy used */
  strategy: RedactionStrategy;

  /** Original span in input */
  originalSpan: { start: number; end: number };

  /** New span in output (after redaction) */
  newSpan: { start: number; end: number };

  /** Replacement text used */
  replacement: string;
}

/**
 * Output sanitizer configuration
 */
export interface OutputSanitizerConfig {
  /** Enable/disable detection categories */
  categories: {
    secrets: boolean;
    pii: boolean;
    phi: boolean;
    pci: boolean;
    internal: boolean;
  };

  /** Default redaction strategy by category */
  redactionStrategies: Record<SensitiveCategory, RedactionStrategy>;

  /** PII detection settings */
  pii: {
    /** Enable NER-based detection */
    nerEnabled: boolean;
    /** NER model to use */
    nerModel: 'spacy' | 'flair' | 'transformers';
    /** Entity types to detect */
    entityTypes: PIIEntityType[];
    /** Minimum confidence for NER */
    minConfidence: number;
  };

  /** Secret detection settings */
  secrets: {
    /** Custom secret patterns */
    customPatterns: SecretPatternDef[];
    /** High-entropy string detection */
    entropyDetection: boolean;
    /** Entropy threshold */
    entropyThreshold: number;
  };

  /** Internal info detection */
  internal: {
    /** Internal domain patterns */
    internalDomains: string[];
    /** Path prefixes to redact */
    sensitivePathPrefixes: string[];
    /** System prompt leak detection */
    systemPromptLeakDetection: boolean;
  };

  /** Allowlist for false positive reduction */
  allowlist: {
    /** Exact strings to allow */
    exact: string[];
    /** Patterns to allow (regex) */
    patterns: RegExp[];
    /** Allow test/example credentials */
    allowTestCredentials: boolean;
  };

  /** Performance settings */
  performance: {
    /** Maximum input length to process */
    maxInputLength: number;
    /** Enable streaming mode */
    streamingEnabled: boolean;
    /** Buffer size for streaming */
    streamBufferSize: number;
  };
}

/**
 * PII entity types
 */
export type PIIEntityType =
  | 'PERSON'
  | 'EMAIL'
  | 'PHONE'
  | 'SSN'
  | 'CREDIT_CARD'
  | 'ADDRESS'
  | 'DATE_OF_BIRTH'
  | 'IP_ADDRESS'
  | 'MEDICAL_RECORD'
  | 'BANK_ACCOUNT';

/**
 * Custom secret pattern definition
 */
export interface SecretPatternDef {
  /** Pattern identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Regex pattern */
  pattern: RegExp;
  /** Confidence when matched */
  confidence: number;
  /** Redaction strategy */
  strategy: RedactionStrategy;
}

/**
 * Output sanitizer guard
 */
export class OutputSanitizer extends BaseGuard {
  constructor(config?: Partial<OutputSanitizerConfig>);

  /** Sanitize output text */
  sanitize(output: string, context?: SanitizationContext): Promise<SanitizationResult>;

  /** Synchronous pattern-only sanitization */
  sanitizeSync(output: string): SanitizationResult;

  /** Detect sensitive data without redacting */
  detect(output: string): Promise<SensitiveDataFinding[]>;

  /** Create a streaming sanitizer */
  createStream(options?: StreamOptions): SanitizationStream;

  /** Add custom detection pattern */
  addPattern(pattern: SecretPatternDef): void;

  /** Update allowlist */
  updateAllowlist(allowlist: Partial<OutputSanitizerConfig['allowlist']>): void;

  /** Get detection statistics */
  getStats(): SanitizerStats;
}

/**
 * Streaming sanitization interface
 */
export interface SanitizationStream {
  /** Write chunk to sanitizer */
  write(chunk: string): string | null;

  /** Flush remaining buffer */
  flush(): string;

  /** Get findings from current stream */
  getFindings(): SensitiveDataFinding[];

  /** End the stream */
  end(): SanitizationResult;
}

/**
 * Sanitization context for policy decisions
 */
export interface SanitizationContext {
  /** User role/permission level */
  userRole?: string;
  /** Whether output is for internal use */
  isInternal?: boolean;
  /** Compliance requirements */
  compliance?: ('gdpr' | 'hipaa' | 'pci' | 'ccpa')[];
  /** Session metadata */
  sessionId?: string;
}

/**
 * Sanitizer statistics
 */
export interface SanitizerStats {
  totalProcessed: number;
  totalRedacted: number;
  findingsByCategory: Record<SensitiveCategory, number>;
  findingsByType: Record<string, number>;
  averageProcessingTimeMs: number;
  falsePositiveRate: number;
}
```

### 4.2 Rust Interface

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Sensitive data categories
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveCategory {
    Secret,
    Pii,
    Phi,
    Pci,
    Internal,
    Custom(String),
}

/// Redaction strategies
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStrategy {
    Full,
    Partial,
    TypeLabel,
    Synthetic,
    Hash,
    None,
}

/// Text span
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// Detection method
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorType {
    Pattern,
    Ner,
    Entropy,
    Ml,
    Custom(String),
}

/// Sensitive data finding
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SensitiveDataFinding {
    pub id: String,
    pub category: SensitiveCategory,
    pub data_type: String,
    pub confidence: f32,
    pub span: Span,
    pub match_preview: String,
    pub detector: DetectorType,
    pub recommended_action: RedactionStrategy,
}

/// Applied redaction
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Redaction {
    pub finding_id: String,
    pub strategy: RedactionStrategy,
    pub original_span: Span,
    pub new_span: Span,
    pub replacement: String,
}

/// Processing statistics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessingStats {
    pub input_length: usize,
    pub output_length: usize,
    pub findings_count: usize,
    pub redactions_count: usize,
    pub processing_time_ms: f64,
}

/// Sanitization result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SanitizationResult {
    pub sanitized: String,
    pub was_redacted: bool,
    pub findings: Vec<SensitiveDataFinding>,
    pub redactions: Vec<Redaction>,
    pub stats: ProcessingStats,
}

/// PII entity types
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PIIEntityType {
    Person,
    Email,
    Phone,
    Ssn,
    CreditCard,
    Address,
    DateOfBirth,
    IpAddress,
    MedicalRecord,
    BankAccount,
}

/// Secret pattern definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretPatternDef {
    pub id: String,
    pub name: String,
    pub pattern: String, // Regex string
    pub confidence: f32,
    pub strategy: RedactionStrategy,
}

/// Category toggles
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CategoryConfig {
    #[serde(default = "default_true")]
    pub secrets: bool,
    #[serde(default = "default_true")]
    pub pii: bool,
    #[serde(default = "default_false")]
    pub phi: bool,
    #[serde(default = "default_false")]
    pub pci: bool,
    #[serde(default = "default_true")]
    pub internal: bool,
}

fn default_true() -> bool { true }
fn default_false() -> bool { false }

impl Default for CategoryConfig {
    fn default() -> Self {
        Self {
            secrets: true,
            pii: true,
            phi: false,
            pci: false,
            internal: true,
        }
    }
}

/// PII detection configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PIIConfig {
    #[serde(default = "default_true")]
    pub ner_enabled: bool,
    #[serde(default)]
    pub entity_types: Vec<PIIEntityType>,
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f32,
}

fn default_min_confidence() -> f32 { 0.8 }

impl Default for PIIConfig {
    fn default() -> Self {
        Self {
            ner_enabled: true,
            entity_types: vec![
                PIIEntityType::Person,
                PIIEntityType::Email,
                PIIEntityType::Phone,
                PIIEntityType::Ssn,
                PIIEntityType::CreditCard,
            ],
            min_confidence: 0.8,
        }
    }
}

/// Secret detection configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretConfig {
    #[serde(default)]
    pub custom_patterns: Vec<SecretPatternDef>,
    #[serde(default = "default_true")]
    pub entropy_detection: bool,
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
}

fn default_entropy_threshold() -> f64 { 4.5 }

impl Default for SecretConfig {
    fn default() -> Self {
        Self {
            custom_patterns: Vec::new(),
            entropy_detection: true,
            entropy_threshold: default_entropy_threshold(),
        }
    }
}

/// Internal information configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InternalConfig {
    #[serde(default)]
    pub internal_domains: Vec<String>,
    #[serde(default)]
    pub sensitive_path_prefixes: Vec<String>,
    #[serde(default = "default_true")]
    pub system_prompt_leak_detection: bool,
}

impl Default for InternalConfig {
    fn default() -> Self {
        Self {
            internal_domains: vec![
                "*.internal".to_string(),
                "*.local".to_string(),
                "localhost".to_string(),
            ],
            sensitive_path_prefixes: vec![
                "/var/secrets".to_string(),
                "/etc/".to_string(),
                "/home/".to_string(),
            ],
            system_prompt_leak_detection: true,
        }
    }
}

/// Allowlist configuration
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AllowlistConfig {
    pub exact: Vec<String>,
    pub patterns: Vec<String>, // Regex strings
    #[serde(default = "default_false")]
    pub allow_test_credentials: bool,
}

/// Performance configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerformanceConfig {
    #[serde(default = "default_max_input_length")]
    pub max_input_length: usize,
    #[serde(default = "default_true")]
    pub streaming_enabled: bool,
    #[serde(default = "default_buffer_size")]
    pub stream_buffer_size: usize,
}

fn default_max_input_length() -> usize { 1_000_000 }
fn default_buffer_size() -> usize { 4096 }

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_input_length: default_max_input_length(),
            streaming_enabled: true,
            stream_buffer_size: default_buffer_size(),
        }
    }
}

/// Complete sanitizer configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputSanitizerConfig {
    #[serde(default)]
    pub categories: CategoryConfig,
    #[serde(default)]
    pub redaction_strategies: HashMap<SensitiveCategory, RedactionStrategy>,
    #[serde(default)]
    pub pii: PIIConfig,
    #[serde(default)]
    pub secrets: SecretConfig,
    #[serde(default)]
    pub internal: InternalConfig,
    #[serde(default)]
    pub allowlist: AllowlistConfig,
    #[serde(default)]
    pub performance: PerformanceConfig,
}

impl Default for OutputSanitizerConfig {
    fn default() -> Self {
        let mut strategies = HashMap::new();
        strategies.insert(SensitiveCategory::Secret, RedactionStrategy::Full);
        strategies.insert(SensitiveCategory::Pii, RedactionStrategy::Partial);
        strategies.insert(SensitiveCategory::Phi, RedactionStrategy::Full);
        strategies.insert(SensitiveCategory::Pci, RedactionStrategy::Partial);
        strategies.insert(SensitiveCategory::Internal, RedactionStrategy::TypeLabel);

        Self {
            categories: CategoryConfig::default(),
            redaction_strategies: strategies,
            pii: PIIConfig::default(),
            secrets: SecretConfig::default(),
            internal: InternalConfig::default(),
            allowlist: AllowlistConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

/// Sanitization context
#[derive(Clone, Debug, Default)]
pub struct SanitizationContext {
    pub user_role: Option<String>,
    pub is_internal: bool,
    pub compliance: Vec<ComplianceFramework>,
    pub session_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComplianceFramework {
    Gdpr,
    Hipaa,
    Pci,
    Ccpa,
}

/// Output sanitizer implementation
pub struct OutputSanitizer {
    config: OutputSanitizerConfig,
    pattern_detector: PatternDetector,
    ner_detector: Option<NERDetector>,
    entropy_detector: EntropyDetector,
    stats: SanitizerStats,
}

impl OutputSanitizer {
    /// Create with default configuration
    pub fn new() -> Self {
        Self::with_config(OutputSanitizerConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(config: OutputSanitizerConfig) -> Self;

    /// Sanitize output text (async for NER)
    pub async fn sanitize(
        &self,
        output: &str,
        context: Option<&SanitizationContext>,
    ) -> Result<SanitizationResult, SanitizationError>;

    /// Synchronous pattern-only sanitization
    pub fn sanitize_sync(&self, output: &str) -> SanitizationResult;

    /// Detect without redacting
    pub async fn detect(&self, output: &str) -> Result<Vec<SensitiveDataFinding>, SanitizationError>;

    /// Create streaming sanitizer
    pub fn create_stream(&self) -> SanitizationStream;

    /// Add custom pattern
    pub fn add_pattern(&mut self, pattern: SecretPatternDef);

    /// Get statistics
    pub fn stats(&self) -> &SanitizerStats;
}

impl Default for OutputSanitizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Streaming sanitizer
pub struct SanitizationStream {
    buffer: String,
    config: OutputSanitizerConfig,
    findings: Vec<SensitiveDataFinding>,
    // ...
}

impl SanitizationStream {
    /// Write chunk, returns sanitized output if safe to emit
    pub fn write(&mut self, chunk: &str) -> Option<String>;

    /// Flush remaining buffer
    pub fn flush(&mut self) -> String;

    /// Get current findings
    pub fn findings(&self) -> &[SensitiveDataFinding];

    /// End stream and get final result
    pub fn end(self) -> SanitizationResult;
}

/// Sanitizer statistics
#[derive(Clone, Debug, Default)]
pub struct SanitizerStats {
    pub total_processed: u64,
    pub total_redacted: u64,
    pub findings_by_category: HashMap<SensitiveCategory, u64>,
    pub findings_by_type: HashMap<String, u64>,
    pub total_processing_time_ms: f64,
}

impl SanitizerStats {
    pub fn average_processing_time_ms(&self) -> f64 {
        if self.total_processed == 0 {
            0.0
        } else {
            self.total_processing_time_ms / self.total_processed as f64
        }
    }
}

#[derive(Debug)]
pub enum SanitizationError {
    ConfigError(String),
    PatternError(String),
    NERError(String),
    InputTooLarge(usize),
}
```

---

## 5. Detection Algorithms

### 5.1 Pattern-Based Secret Detection

```rust
use regex::Regex;
use std::sync::OnceLock;

/// Compiled secret patterns
struct PatternDetector {
    patterns: Vec<CompiledSecretPattern>,
}

struct CompiledSecretPattern {
    id: &'static str,
    name: &'static str,
    category: SensitiveCategory,
    regex: Regex,
    confidence: f32,
    strategy: RedactionStrategy,
}

/// Built-in secret patterns
fn builtin_patterns() -> &'static [CompiledSecretPattern] {
    static PATTERNS: OnceLock<Vec<CompiledSecretPattern>> = OnceLock::new();

    PATTERNS.get_or_init(|| {
        vec![
            // AWS
            CompiledSecretPattern {
                id: "aws_access_key",
                name: "AWS Access Key ID",
                category: SensitiveCategory::Secret,
                regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
                confidence: 0.99,
                strategy: RedactionStrategy::Full,
            },
            CompiledSecretPattern {
                id: "aws_secret_key",
                name: "AWS Secret Access Key",
                category: SensitiveCategory::Secret,
                regex: Regex::new(
                    r#"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['"]?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})"#
                ).unwrap(),
                confidence: 0.95,
                strategy: RedactionStrategy::Full,
            },

            // GitHub
            CompiledSecretPattern {
                id: "github_pat",
                name: "GitHub Personal Access Token",
                category: SensitiveCategory::Secret,
                regex: Regex::new(r"ghp_[A-Za-z0-9]{36}").unwrap(),
                confidence: 0.99,
                strategy: RedactionStrategy::Full,
            },
            CompiledSecretPattern {
                id: "github_fine_grained",
                name: "GitHub Fine-grained PAT",
                category: SensitiveCategory::Secret,
                regex: Regex::new(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}").unwrap(),
                confidence: 0.99,
                strategy: RedactionStrategy::Full,
            },

            // OpenAI / Anthropic
            CompiledSecretPattern {
                id: "openai_key",
                name: "OpenAI API Key",
                category: SensitiveCategory::Secret,
                regex: Regex::new(r"sk-[A-Za-z0-9]{48}").unwrap(),
                confidence: 0.95,
                strategy: RedactionStrategy::Full,
            },
            CompiledSecretPattern {
                id: "anthropic_key",
                name: "Anthropic API Key",
                category: SensitiveCategory::Secret,
                // Anthropic keys follow format: sk-ant-api03-[base62]{93}
                regex: Regex::new(r"sk-ant-[A-Za-z0-9_\-]{90,}").unwrap(),
                confidence: 0.95,
                strategy: RedactionStrategy::Full,
            },

            // Private Keys
            CompiledSecretPattern {
                id: "private_key",
                name: "Private Key",
                category: SensitiveCategory::Secret,
                regex: Regex::new(r"-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----").unwrap(),
                confidence: 0.99,
                strategy: RedactionStrategy::Full,
            },

            // JWT
            CompiledSecretPattern {
                id: "jwt_token",
                name: "JWT Token",
                category: SensitiveCategory::Secret,
                regex: Regex::new(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*").unwrap(),
                confidence: 0.90,
                strategy: RedactionStrategy::Partial,
            },

            // Database URLs
            CompiledSecretPattern {
                id: "database_url",
                name: "Database Connection String",
                category: SensitiveCategory::Secret,
                regex: Regex::new(r"(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@").unwrap(),
                confidence: 0.95,
                strategy: RedactionStrategy::Full,
            },

            // Generic patterns (lower confidence)
            CompiledSecretPattern {
                id: "generic_api_key",
                name: "Generic API Key",
                category: SensitiveCategory::Secret,
                regex: Regex::new(r#"(?i)(api[_\-]?key|apikey)['"]?\s*[:=]\s*['"]?([A-Za-z0-9]{32,})"#).unwrap(),
                confidence: 0.70,
                strategy: RedactionStrategy::Full,
            },
            CompiledSecretPattern {
                id: "generic_password",
                name: "Password Assignment",
                category: SensitiveCategory::Secret,
                regex: Regex::new(r#"(?i)(password|passwd|pwd)['"]?\s*[:=]\s*['"]?([^\s'"]{8,})"#).unwrap(),
                confidence: 0.60,
                strategy: RedactionStrategy::Full,
            },
        ]
    })
}

impl PatternDetector {
    fn detect(&self, text: &str) -> Vec<SensitiveDataFinding> {
        let mut findings = Vec::new();

        for pattern in &self.patterns {
            for m in pattern.regex.find_iter(text) {
                findings.push(SensitiveDataFinding {
                    id: uuid::Uuid::new_v4().to_string(),
                    category: pattern.category.clone(),
                    data_type: pattern.id.to_string(),
                    confidence: pattern.confidence,
                    span: Span {
                        start: m.start(),
                        end: m.end(),
                    },
                    match_preview: truncate_for_preview(m.as_str()),
                    detector: DetectorType::Pattern,
                    recommended_action: pattern.strategy.clone(),
                });
            }
        }

        findings
    }
}

fn truncate_for_preview(s: &str) -> String {
    if s.len() <= 12 {
        "*".repeat(s.len())
    } else {
        format!("{}...{}", &s[..4], &s[s.len()-4..])
    }
}
```

### 5.2 High-Entropy String Detection

```rust
use std::collections::HashMap;

struct EntropyDetector {
    threshold: f64,
    min_length: usize,
    max_length: usize,
}

impl EntropyDetector {
    fn new(threshold: f64) -> Self {
        Self {
            threshold,
            min_length: 20,
            max_length: 200,
        }
    }

    /// Detect high-entropy strings that might be secrets
    fn detect(&self, text: &str) -> Vec<SensitiveDataFinding> {
        let mut findings = Vec::new();

        // Split on whitespace and common delimiters
        for token in self.tokenize(text) {
            if token.text.len() < self.min_length || token.text.len() > self.max_length {
                continue;
            }

            // Skip if it looks like normal text
            if self.looks_like_prose(&token.text) {
                continue;
            }

            let entropy = self.shannon_entropy(&token.text);

            if entropy >= self.threshold {
                findings.push(SensitiveDataFinding {
                    id: uuid::Uuid::new_v4().to_string(),
                    category: SensitiveCategory::Secret,
                    data_type: "high_entropy_string".to_string(),
                    confidence: self.entropy_to_confidence(entropy),
                    span: token.span,
                    match_preview: truncate_for_preview(&token.text),
                    detector: DetectorType::Entropy,
                    recommended_action: RedactionStrategy::Full,
                });
            }
        }

        findings
    }

    fn shannon_entropy(&self, s: &str) -> f64 {
        let mut freq: HashMap<char, f64> = HashMap::new();
        let len = s.len() as f64;

        for c in s.chars() {
            *freq.entry(c).or_insert(0.0) += 1.0;
        }

        freq.values()
            .map(|&count| {
                let p = count / len;
                -p * p.log2()
            })
            .sum()
    }

    fn entropy_to_confidence(&self, entropy: f64) -> f32 {
        // Map entropy to confidence (higher entropy = higher confidence)
        let normalized = (entropy - self.threshold) / (8.0 - self.threshold);
        (0.5 + normalized * 0.4).min(0.95) as f32
    }

    fn looks_like_prose(&self, s: &str) -> bool {
        // Heuristics for normal text
        let lowercase_ratio = s.chars().filter(|c| c.is_lowercase()).count() as f64
            / s.len() as f64;
        let space_ratio = s.chars().filter(|c| *c == ' ').count() as f64
            / s.len() as f64;

        lowercase_ratio > 0.6 && space_ratio > 0.1
    }

    fn tokenize(&self, text: &str) -> Vec<Token> {
        // Simple tokenization on whitespace and delimiters
        let mut tokens = Vec::new();
        let delimiters = [' ', '\n', '\t', '"', '\'', '=', ':', ',', ';'];

        let mut start = 0;
        let mut chars = text.char_indices().peekable();

        while let Some((i, c)) = chars.next() {
            if delimiters.contains(&c) {
                if i > start {
                    tokens.push(Token {
                        text: text[start..i].to_string(),
                        span: Span { start, end: i },
                    });
                }
                start = i + c.len_utf8();
            }
        }

        if start < text.len() {
            tokens.push(Token {
                text: text[start..].to_string(),
                span: Span { start, end: text.len() },
            });
        }

        tokens
    }
}

struct Token {
    text: String,
    span: Span,
}
```

### 5.3 PII Detection with NER

```python
# Python NER integration (conceptual)
import spacy
from typing import List, Dict, Any

class PIIDetector:
    def __init__(self, model_name: str = "en_core_web_trf"):
        self.nlp = spacy.load(model_name)
        self.entity_map = {
            "PERSON": "person_name",
            "GPE": "location",
            "ORG": "organization",
            "DATE": "date",
            "CARDINAL": "number",
            "MONEY": "financial",
        }

    def detect(self, text: str) -> List[Dict[str, Any]]:
        doc = self.nlp(text)
        findings = []

        for ent in doc.ents:
            if ent.label_ in self.entity_map:
                findings.append({
                    "category": "pii",
                    "type": self.entity_map[ent.label_],
                    "confidence": 0.85,  # spaCy doesn't provide confidence
                    "span": {"start": ent.start_char, "end": ent.end_char},
                    "text": ent.text,
                    "detector": "ner",
                })

        # Add regex-based PII detection
        findings.extend(self._detect_structured_pii(text))

        return findings

    def _detect_structured_pii(self, text: str) -> List[Dict[str, Any]]:
        import re
        findings = []

        patterns = [
            ("email", r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 0.95),
            ("phone", r'\b(?:\+?1[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b', 0.85),
            ("ssn", r'\b\d{3}-\d{2}-\d{4}\b', 0.95),
            ("credit_card", r'\b(?:\d{4}[-\s]?){3}\d{4}\b', 0.90),
            ("ip_address", r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 0.80),
        ]

        for pii_type, pattern, confidence in patterns:
            for match in re.finditer(pattern, text):
                # Validate specific formats
                if pii_type == "credit_card" and not self._luhn_check(match.group()):
                    continue
                if pii_type == "ssn" and not self._valid_ssn(match.group()):
                    continue

                findings.append({
                    "category": "pii",
                    "type": pii_type,
                    "confidence": confidence,
                    "span": {"start": match.start(), "end": match.end()},
                    "text": match.group(),
                    "detector": "pattern",
                })

        return findings

    def _luhn_check(self, card_number: str) -> bool:
        """Validate credit card using Luhn algorithm."""
        digits = [int(d) for d in card_number if d.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False

        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d

        return checksum % 10 == 0

    def _valid_ssn(self, ssn: str) -> bool:
        """Basic SSN validation."""
        parts = ssn.split('-')
        if len(parts) != 3:
            return False

        area, group, serial = parts
        # Invalid area numbers
        if area in ['000', '666'] or area.startswith('9'):
            return False

        return True
```

---

## 6. False Positive/Negative Tradeoffs

### 6.1 Sensitivity Configurations

| Configuration | FP Rate | FN Rate | Use Case |
|---------------|---------|---------|----------|
| **High Sensitivity** | ~5% | ~0.1% | Financial, healthcare |
| **Balanced** | ~1% | ~1% | General production |
| **Low Sensitivity** | ~0.1% | ~5% | Internal tools |

### 6.2 Common False Positives

| Type | Example | Mitigation |
|------|---------|------------|
| Test credentials | `sk-test_123...` | Allowlist test patterns |
| Example code | Documentation samples | Context detection |
| Placeholder values | `YOUR_API_KEY_HERE` | Placeholder detection |
| Similar patterns | UUIDs matching key format | Stricter validation |
| Names in quotes | "John said hello" | Context-aware NER |

### 6.3 Common False Negatives

| Type | Description | Mitigation |
|------|-------------|------------|
| Obfuscated secrets | Base64 encoded keys | Encoding detection |
| Novel key formats | New provider patterns | Regular updates |
| Partial reveals | "Key starts with sk-" | Semantic analysis |
| Indirect leakage | "Check the .env file" | Reference detection |

---

## 7. Performance Considerations

### 7.1 Latency Requirements

| Mode | Target (p50) | Target (p99) | Notes |
|------|--------------|--------------|-------|
| Sync (patterns only) | < 2ms | < 10ms | No NER |
| Async (full) | < 20ms | < 100ms | With NER |
| Streaming | < 5ms/chunk | < 20ms/chunk | 4KB chunks |

### 7.2 Streaming Architecture

```
Input Stream --> Buffer --> Pattern Scan --> Safe Emit
                   |
                   +--> Boundary Detection (don't split tokens)
                   |
                   +--> Deferred NER (full sentences)
```

Key considerations:
- Buffer must not split potential matches
- Emit safe content immediately
- Hold back suspicious content for full analysis
- Handle multi-line patterns (private keys)

### 7.3 Memory Requirements

| Component | Memory | Notes |
|-----------|--------|-------|
| Pattern detector | ~5MB | Compiled regex |
| NER model (spaCy) | ~500MB | en_core_web_trf |
| NER model (small) | ~50MB | en_core_web_sm |
| Streaming buffer | ~50KB | Per stream |

---

## 8. Bypass Resistance

### 8.1 Known Evasion Techniques

| Technique | Example | Countermeasure |
|-----------|---------|----------------|
| Character substitution | `sk-abc` -> `sk\u200b-abc` | Unicode normalization |
| Encoding | Base64 secret | Decode before scan |
| Fragmentation | "sk-" + "abc123" | Context window |
| Casing | `SK-ABC123` | Case-insensitive |
| Whitespace | `s k - a b c` | Whitespace normalization |
| Homoglyphs | Cyrillic 'a' for Latin 'a' | Homoglyph normalization |

### 8.2 Defense Updates

- **Daily**: Pattern database sync
- **Weekly**: NER model evaluation
- **Monthly**: Evasion technique analysis

---

## 9. Implementation Phases

### Phase 1: Pattern Foundation (Week 1-2)
- Comprehensive secret patterns
- High-entropy detection
- Basic redaction strategies
- Streaming support

### Phase 2: PII Detection (Week 3-4)
- NER integration
- Structured PII patterns
- Validation (Luhn, etc.)
- Confidence scoring

### Phase 3: Advanced Features (Week 5-6)
- System prompt leak detection
- Internal info protection
- Context-aware redaction
- Allowlist management

### Phase 4: Production Hardening (Week 7-8)
- Performance optimization
- False positive tuning
- Compliance reporting
- Documentation

---

## 10. References

1. Carlini, N., et al. (2021). "Extracting Training Data from Large Language Models." USENIX Security 2021
2. Carlini, N., et al. (2023). "Quantifying Memorization Across Neural Language Models." ICLR 2023
3. Lukas, N., et al. (2023). "Analyzing Leakage of Personally Identifiable Information in Language Models." S&P 2023
4. Huang, Y., et al. (2022). "Large Language Models Can Be Strong Differentially Private Learners." ICLR 2022
5. Rebedea, T., et al. (2023). "NeMo Guardrails: A Toolkit for Controllable LLM Applications." EMNLP 2023
6. Inan, H., et al. (2023). "Llama Guard: LLM-based Input-Output Safeguard." arXiv:2312.06674
7. OWASP. (2024). "OWASP Top 10 for Large Language Model Applications"
8. NIST. (2020). "SP 800-188: De-Identifying Government Datasets"

---

*This document is part of the Clawdstrike Prompt Security specification suite.*
