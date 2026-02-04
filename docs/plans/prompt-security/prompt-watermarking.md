# Prompt Watermarking for Attribution and Tracing

**Version**: 1.0.0-draft
**Status**: Research & Architecture Specification
**Authors**: Clawdstrike Security Team
**Last Updated**: 2026-02-02

---

## 1. Problem Statement

### 1.1 Definition

Prompt watermarking is the process of embedding invisible or minimally visible markers in prompts sent to LLMs, enabling:

1. **Attribution**: Identifying which application/session generated a prompt
2. **Tracing**: Following the lifecycle of prompts through systems
3. **Provenance**: Establishing the origin and chain of custody
4. **Forensics**: Investigating security incidents post-hoc
5. **Compliance**: Meeting audit and regulatory requirements

### 1.2 Motivation

```
+------------------------------------------------------------------+
|                    THE ATTRIBUTION PROBLEM                        |
+------------------------------------------------------------------+
|                                                                   |
| Multiple Applications          Shared LLM API           Incident  |
|      +-----+                   +----------+             Analysis  |
|      |App A|----+              |          |                       |
|      +-----+    |              |   LLM    |           "Which app  |
|                 +------------->|   API    |            caused      |
|      +-----+    |              |          |            this?"      |
|      |App B|----+              +----------+                       |
|      +-----+    |                   |                             |
|                 |                   v                             |
|      +-----+    |              +----------+                       |
|      |App C|----+              |  Logs /  |<------ ???            |
|      +-----+                   |  Audit   |                       |
|                                +----------+                       |
|                                                                   |
+------------------------------------------------------------------+
```

### 1.3 Use Cases

| Use Case | Description | Stakeholder |
|----------|-------------|-------------|
| **Security Forensics** | Trace malicious prompts to origin | Security Team |
| **Compliance Audit** | Prove chain of custody | Compliance |
| **Usage Attribution** | Allocate costs per application | Finance |
| **Quality Control** | Track prompt performance | ML Ops |
| **Incident Response** | Reconstruct attack paths | IR Team |
| **Abuse Detection** | Identify coordinated attacks | Trust & Safety |

### 1.4 Requirements

| Requirement | Priority | Description |
|-------------|----------|-------------|
| **Invisibility** | High | Minimal impact on LLM behavior |
| **Robustness** | High | Survive prompt modifications |
| **Capacity** | Medium | Encode sufficient metadata |
| **Extractability** | High | Reliably extract watermarks |
| **Performance** | High | Minimal latency overhead |
| **Security** | High | Tamper-resistant encoding |

---

## 2. Research Foundation

### 2.1 Academic Literature

#### 2.1.1 Text Watermarking

1. **Kirchenbauer et al. (2023). "A Watermark for Large Language Models"**
   - Output watermarking via token selection
   - Statistical detection methods
   - Robustness analysis

2. **Christ et al. (2023). "Undetectable Watermarks for Language Models"**
   - Cryptographically undetectable watermarks
   - Information-theoretic guarantees
   - Provable security

3. **Zhao et al. (2024). "Provable Robust Watermarking for AI-Generated Text"**
   - Robustness against paraphrasing
   - Semantic preservation
   - Detection under noise

#### 2.1.2 Steganography

1. **Fang et al. (2017). "Generating Steganographic Text with LSTMs"**
   - Neural text steganography
   - Capacity-distortion tradeoffs
   - Encoding techniques

2. **Ziegler et al. (2019). "Neural Linguistic Steganography"**
   - BERT-based steganography
   - Imperceptibility metrics
   - Practical applications

#### 2.1.3 Provenance and Attribution

1. **Abdelnabi & Fritz (2021). "Adversarial Watermarking Transformer"**
   - Watermarking for attribution
   - Adversarial robustness
   - Multi-bit encoding

2. **He et al. (2022). "CATER: Intellectual Property Protection on Text Generation APIs"**
   - API fingerprinting
   - Watermark verification
   - Legal applications

### 2.2 Watermarking Techniques Taxonomy

```
+------------------------------------------------------------------+
|                 PROMPT WATERMARKING TECHNIQUES                    |
+------------------------------------------------------------------+
|                                                                   |
| 1. STRUCTURAL WATERMARKS                                          |
|    - Whitespace encoding (spaces, tabs, zero-width chars)         |
|    - Punctuation variations                                       |
|    - Line break patterns                                          |
|                                                                   |
| 2. LEXICAL WATERMARKS                                             |
|    - Synonym selection                                            |
|    - Word order variations                                        |
|    - Filler word insertion                                        |
|                                                                   |
| 3. SEMANTIC WATERMARKS                                            |
|    - Paraphrase selection                                         |
|    - Sentence reordering (where permissible)                      |
|    - Emphasis variations                                          |
|                                                                   |
| 4. METADATA WATERMARKS                                            |
|    - Hidden XML/JSON tags                                         |
|    - Comment blocks                                               |
|    - Encoded identifiers in natural positions                     |
|                                                                   |
| 5. CRYPTOGRAPHIC WATERMARKS                                       |
|    - Hash-based encoding                                          |
|    - Digital signatures in steganographic form                    |
|    - Verifiable commitments                                       |
|                                                                   |
+------------------------------------------------------------------+
```

---

## 3. Architecture

### 3.1 System Design

```
+------------------------------------------------------------------------+
|                      PROMPT WATERMARKING SYSTEM                         |
+------------------------------------------------------------------------+
|                                                                         |
|  +------------------+     +------------------+     +------------------+  |
|  | Watermark        |---->| Encoder          |---->| Prompt           |  |
|  | Generator        |     |                  |     | Assembler        |  |
|  |                  |     | - Structural     |     |                  |  |
|  | - Session ID     |     | - Lexical        |     | - Merge wmark    |  |
|  | - Timestamp      |     | - Metadata       |     | - Validate       |  |
|  | - App ID         |     | - Cryptographic  |     | - Finalize       |  |
|  +------------------+     +------------------+     +------------------+  |
|           |                       |                       |             |
|           |                       |                       |             |
|           v                       v                       v             |
|  +--------------------------------------------------------------+      |
|  |                    WATERMARKED PROMPT                          |      |
|  |  [Original Content] + [Embedded Watermark]                     |      |
|  +--------------------------------------------------------------+      |
|                                   |                                     |
|                                   v                                     |
|                          +----------------+                             |
|                          |    LLM API     |                             |
|                          +----------------+                             |
|                                   |                                     |
|                                   v                                     |
|  +------------------+     +------------------+     +------------------+  |
|  | Watermark        |<----| Extractor        |<----| Response         |  |
|  | Verifier         |     |                  |     | Handler          |  |
|  |                  |     | - Pattern match  |     |                  |  |
|  | - Validate sig   |     | - Decode         |     | - Parse response |  |
|  | - Check integrity|     | - Extract meta   |     | - Log provenance |  |
|  +------------------+     +------------------+     +------------------+  |
|                                                                         |
+------------------------------------------------------------------------+
```

### 3.2 Watermark Payload

```
+------------------------------------------------------------------+
|                    WATERMARK PAYLOAD STRUCTURE                    |
+------------------------------------------------------------------+
|                                                                   |
| +--------------------------------------------------------------+ |
| |                    HEADER (8 bytes)                           | |
| +--------------------------------------------------------------+ |
| | Version (2) | Flags (2) | Encoding (2) | Reserved (2)        | |
| +--------------------------------------------------------------+ |
|                                                                   |
| +--------------------------------------------------------------+ |
| |                    CORE METADATA (32 bytes)                   | |
| +--------------------------------------------------------------+ |
| | Application ID (16 bytes, UUID)                               | |
| | Session ID (16 bytes, UUID)                                   | |
| +--------------------------------------------------------------+ |
|                                                                   |
| +--------------------------------------------------------------+ |
| |                    TIMESTAMPS (16 bytes)                      | |
| +--------------------------------------------------------------+ |
| | Created (8 bytes, Unix ms) | Expires (8 bytes, Unix ms)      | |
| +--------------------------------------------------------------+ |
|                                                                   |
| +--------------------------------------------------------------+ |
| |                    SEQUENCE (8 bytes)                         | |
| +--------------------------------------------------------------+ |
| | Message Index (4) | Total Messages (4)                        | |
| +--------------------------------------------------------------+ |
|                                                                   |
| +--------------------------------------------------------------+ |
| |                    SIGNATURE (64 bytes)                       | |
| +--------------------------------------------------------------+ |
| | Ed25519 Signature over [Header + Metadata + Timestamps + Seq] | |
| +--------------------------------------------------------------+ |
|                                                                   |
| Total: 128 bytes (1024 bits)                                     |
|                                                                   |
+------------------------------------------------------------------+
```

### 3.3 Encoding Strategies

#### Strategy 1: Zero-Width Character Encoding

```
Encoding: Use zero-width Unicode characters to encode binary data

Characters:
- U+200B (Zero-Width Space) = 0
- U+200C (Zero-Width Non-Joiner) = 1
- U+200D (Zero-Width Joiner) = separator
- U+FEFF (Byte Order Mark) = start marker

Example:
"Hello" + [FEFF][200B][200C][200B][200C]... = "Hello" (appears same, contains data)

Capacity: ~128 bits per word boundary (using pairs)
Invisibility: High (invisible to humans and most displays)
Robustness: Low (stripped by text normalization)
```

#### Strategy 2: Unicode Homoglyph Substitution

```
Encoding: Replace ASCII characters with visually identical Unicode

Substitutions:
- 'a' (U+0061) <-> 'а' (U+0430, Cyrillic)
- 'e' (U+0065) <-> 'е' (U+0435, Cyrillic)
- 'o' (U+006F) <-> 'о' (U+043E, Cyrillic)
- 'p' (U+0070) <-> 'р' (U+0440, Cyrillic)
- 'c' (U+0063) <-> 'с' (U+0441, Cyrillic)

Example:
"Hello" with 'e' as Cyrillic 'е' encodes bit 1 for that position

Capacity: ~1 bit per substitutable character
Invisibility: Medium (appears same visually)
Robustness: Medium (survives copy-paste)
```

#### Strategy 3: Whitespace Pattern Encoding

```
Encoding: Vary whitespace to encode data

Patterns:
- Single space after period = 0
- Double space after period = 1
- Tab vs spaces for indentation
- Trailing whitespace per line

Example:
"Sentence one. Sentence two." (single space = 0)
"Sentence one.  Sentence two." (double space = 1)

Capacity: ~1 bit per sentence/line
Invisibility: High (rarely noticed)
Robustness: Medium (may be normalized)
```

#### Strategy 4: Metadata Embedding

```
Encoding: Embed watermark in natural metadata positions

Positions:
- System prompt headers/footers
- XML/JSON comments
- Instruction block boundaries
- Configuration sections

Example:
<!-- session:a1b2c3d4-e5f6-7890-abcd-ef1234567890 -->
<system_prompt id="wm:base64encodeddata">

Capacity: High (explicit storage)
Invisibility: Low (visible but ignorable)
Robustness: High (explicitly marked)
```

#### Strategy 5: Semantic Paraphrase Selection

```
Encoding: Choose between semantically equivalent phrasings

Paraphrase Sets:
- "Please help me with" / "I need assistance with" = 0/1
- "Can you" / "Would you" = 0/1
- "I want to" / "I'd like to" = 0/1

Example:
Bit 0: "Can you help me write code?"
Bit 1: "Would you assist me with coding?"

Capacity: ~2-4 bits per sentence
Invisibility: High (natural language)
Robustness: High (survives normalization)
```

---

## 4. API Design

### 4.1 TypeScript Interface

```typescript
/**
 * Watermark encoding strategy
 */
export type WatermarkEncoding =
  | 'zero_width'       // Zero-width Unicode characters
  | 'homoglyph'        // Unicode homoglyph substitution
  | 'whitespace'       // Whitespace patterns
  | 'metadata'         // Explicit metadata embedding
  | 'semantic'         // Semantic paraphrase selection
  | 'hybrid';          // Combination of techniques

/**
 * Watermark payload
 */
export interface WatermarkPayload {
  /** Application identifier */
  applicationId: string;

  /** Session identifier */
  sessionId: string;

  /** Timestamp of watermark creation */
  createdAt: Date;

  /** Expiration timestamp (optional) */
  expiresAt?: Date;

  /** Message sequence number */
  sequenceNumber: number;

  /** Total messages in sequence (if known) */
  totalMessages?: number;

  /** Custom metadata */
  metadata?: Record<string, string>;
}

/**
 * Encoded watermark
 */
export interface EncodedWatermark {
  /** Raw payload */
  payload: WatermarkPayload;

  /** Encoding strategy used */
  encoding: WatermarkEncoding;

  /** Encoded binary data */
  encodedData: Uint8Array;

  /** Cryptographic signature */
  signature: Uint8Array;

  /** Public key for verification */
  publicKey: string;
}

/**
 * Watermark extraction result
 */
export interface WatermarkExtractionResult {
  /** Whether a watermark was found */
  found: boolean;

  /** Extracted watermark (if found) */
  watermark?: EncodedWatermark;

  /** Verification status */
  verified: boolean;

  /** Extraction confidence [0, 1] */
  confidence: number;

  /** Any errors encountered */
  errors: string[];

  /** Extraction metadata */
  extractionMetadata: {
    encoding: WatermarkEncoding;
    bitsExtracted: number;
    errorRate: number;
    processingTimeMs: number;
  };
}

/**
 * Watermarking configuration
 */
export interface WatermarkConfig {
  /** Primary encoding strategy */
  encoding: WatermarkEncoding;

  /** Fallback encodings (for hybrid) */
  fallbackEncodings?: WatermarkEncoding[];

  /** Signing key pair */
  keyPair?: {
    privateKey: string;
    publicKey: string;
  };

  /** Generate new key pair if not provided */
  generateKeyPair?: boolean;

  /** Include timestamp in watermark */
  includeTimestamp?: boolean;

  /** Include sequence numbers */
  includeSequence?: boolean;

  /** Custom metadata to include */
  customMetadata?: Record<string, string>;

  /** Encoding-specific options */
  encodingOptions?: {
    zeroWidth?: {
      /** Position: start, end, or distributed */
      position: 'start' | 'end' | 'distributed';
      /** Density for distributed mode */
      density?: number;
    };
    homoglyph?: {
      /** Character set to use */
      charSet: 'cyrillic' | 'greek' | 'mixed';
      /** Maximum substitution ratio */
      maxRatio?: number;
    };
    metadata?: {
      /** Format for metadata embedding */
      format: 'xml_comment' | 'json_comment' | 'custom';
      /** Position in prompt */
      position: 'prepend' | 'append' | 'inline';
    };
  };

  /** Robustness settings */
  robustness?: {
    /** Add error correction */
    errorCorrection: boolean;
    /** Redundancy factor (1-5) */
    redundancy?: number;
  };
}

/**
 * Watermark verifier configuration
 */
export interface WatermarkVerifierConfig {
  /** Trusted public keys */
  trustedPublicKeys: string[];

  /** Allow unverified watermarks */
  allowUnverified?: boolean;

  /** Extraction sensitivity */
  sensitivity?: 'low' | 'medium' | 'high';
}

/**
 * Prompt watermarker
 */
export class PromptWatermarker {
  constructor(config: WatermarkConfig);

  /**
   * Watermark a prompt
   */
  watermark(prompt: string, payload?: Partial<WatermarkPayload>): WatermarkedPrompt;

  /**
   * Generate a new watermark payload
   */
  generatePayload(overrides?: Partial<WatermarkPayload>): WatermarkPayload;

  /**
   * Encode payload to binary
   */
  encodePayload(payload: WatermarkPayload): Uint8Array;

  /**
   * Sign encoded data
   */
  signData(data: Uint8Array): Uint8Array;

  /**
   * Get public key for verification
   */
  getPublicKey(): string;

  /**
   * Update configuration
   */
  updateConfig(config: Partial<WatermarkConfig>): void;
}

/**
 * Watermarked prompt result
 */
export interface WatermarkedPrompt {
  /** Original prompt */
  original: string;

  /** Watermarked prompt */
  watermarked: string;

  /** Embedded watermark */
  watermark: EncodedWatermark;

  /** Encoding used */
  encoding: WatermarkEncoding;

  /** Stats */
  stats: {
    originalLength: number;
    watermarkedLength: number;
    bitsEncoded: number;
    encodingTimeMs: number;
  };
}

/**
 * Watermark extractor
 */
export class WatermarkExtractor {
  constructor(config: WatermarkVerifierConfig);

  /**
   * Extract watermark from text
   */
  extract(text: string): WatermarkExtractionResult;

  /**
   * Extract and verify watermark
   */
  extractAndVerify(text: string): WatermarkExtractionResult;

  /**
   * Verify a watermark signature
   */
  verifySignature(watermark: EncodedWatermark): boolean;

  /**
   * Check if a public key is trusted
   */
  isKeyTrusted(publicKey: string): boolean;

  /**
   * Add a trusted public key
   */
  addTrustedKey(publicKey: string): void;
}

/**
 * Audit trail integration
 */
export interface WatermarkAuditEntry {
  /** Entry ID */
  id: string;

  /** Watermark payload */
  payload: WatermarkPayload;

  /** Event type */
  eventType: 'created' | 'verified' | 'tampered' | 'expired';

  /** Timestamp */
  timestamp: Date;

  /** Associated text hash */
  textHash: string;

  /** Verification result */
  verification?: {
    verified: boolean;
    publicKey?: string;
    errors?: string[];
  };
}

/**
 * Watermark audit logger
 */
export class WatermarkAuditLogger {
  constructor(storage: AuditStorage);

  /**
   * Log watermark creation
   */
  logCreation(watermark: EncodedWatermark, text: string): Promise<void>;

  /**
   * Log watermark verification
   */
  logVerification(result: WatermarkExtractionResult, text: string): Promise<void>;

  /**
   * Query audit trail
   */
  query(filter: AuditQueryFilter): Promise<WatermarkAuditEntry[]>;
}

export interface AuditQueryFilter {
  applicationId?: string;
  sessionId?: string;
  startTime?: Date;
  endTime?: Date;
  eventType?: WatermarkAuditEntry['eventType'];
}

export interface AuditStorage {
  save(entry: WatermarkAuditEntry): Promise<void>;
  query(filter: AuditQueryFilter): Promise<WatermarkAuditEntry[]>;
}
```

### 4.2 Rust Interface

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Watermark encoding strategies
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatermarkEncoding {
    ZeroWidth,
    Homoglyph,
    Whitespace,
    Metadata,
    Semantic,
    Hybrid,
}

/// Watermark payload
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatermarkPayload {
    pub application_id: String,
    pub session_id: String,
    pub created_at: u64, // Unix timestamp ms
    pub expires_at: Option<u64>,
    pub sequence_number: u32,
    pub total_messages: Option<u32>,
    pub metadata: Option<HashMap<String, String>>,
}

impl WatermarkPayload {
    pub fn new(application_id: String, session_id: String) -> Self {
        Self {
            application_id,
            session_id,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            expires_at: None,
            sequence_number: 0,
            total_messages: None,
            metadata: None,
        }
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Failed to serialize payload")
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, WatermarkError> {
        bincode::deserialize(data).map_err(|e| WatermarkError::DeserializationError(e.to_string()))
    }
}

/// Encoded watermark
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncodedWatermark {
    pub payload: WatermarkPayload,
    pub encoding: WatermarkEncoding,
    pub encoded_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub public_key: String,
}

impl EncodedWatermark {
    /// Verify the signature
    pub fn verify(&self) -> bool {
        use ed25519_dalek::{Signature, VerifyingKey};

        let public_key_bytes = hex::decode(&self.public_key).unwrap_or_default();
        if public_key_bytes.len() != 32 {
            return false;
        }

        let verifying_key = match VerifyingKey::from_bytes(
            &public_key_bytes.try_into().unwrap()
        ) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let signature = match Signature::from_slice(&self.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        verifying_key.verify_strict(&self.encoded_data, &signature).is_ok()
    }
}

/// Extraction result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatermarkExtractionResult {
    pub found: bool,
    pub watermark: Option<EncodedWatermark>,
    pub verified: bool,
    pub confidence: f32,
    pub errors: Vec<String>,
    pub extraction_metadata: ExtractionMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExtractionMetadata {
    pub encoding: Option<WatermarkEncoding>,
    pub bits_extracted: usize,
    pub error_rate: f32,
    pub processing_time_ms: f64,
}

/// Zero-width encoding options
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZeroWidthOptions {
    pub position: ZeroWidthPosition,
    pub density: Option<f32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ZeroWidthPosition {
    Start,
    End,
    Distributed,
}

impl Default for ZeroWidthOptions {
    fn default() -> Self {
        Self {
            position: ZeroWidthPosition::End,
            density: Some(0.1),
        }
    }
}

/// Homoglyph encoding options
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HomoglyphOptions {
    pub char_set: HomoglyphCharSet,
    pub max_ratio: Option<f32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HomoglyphCharSet {
    Cyrillic,
    Greek,
    Mixed,
}

impl Default for HomoglyphOptions {
    fn default() -> Self {
        Self {
            char_set: HomoglyphCharSet::Cyrillic,
            max_ratio: Some(0.1),
        }
    }
}

/// Metadata embedding options
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetadataOptions {
    pub format: MetadataFormat,
    pub position: MetadataPosition,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataFormat {
    XmlComment,
    JsonComment,
    Custom,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetadataPosition {
    Prepend,
    Append,
    Inline,
}

impl Default for MetadataOptions {
    fn default() -> Self {
        Self {
            format: MetadataFormat::XmlComment,
            position: MetadataPosition::Prepend,
        }
    }
}

/// Encoding-specific options
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EncodingOptions {
    pub zero_width: Option<ZeroWidthOptions>,
    pub homoglyph: Option<HomoglyphOptions>,
    pub metadata: Option<MetadataOptions>,
}

/// Robustness settings
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RobustnessConfig {
    pub error_correction: bool,
    pub redundancy: Option<u8>,
}

impl Default for RobustnessConfig {
    fn default() -> Self {
        Self {
            error_correction: true,
            redundancy: Some(2),
        }
    }
}

/// Watermarker configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatermarkConfig {
    pub encoding: WatermarkEncoding,
    pub fallback_encodings: Option<Vec<WatermarkEncoding>>,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
    pub generate_key_pair: bool,
    pub include_timestamp: bool,
    pub include_sequence: bool,
    pub custom_metadata: Option<HashMap<String, String>>,
    pub encoding_options: Option<EncodingOptions>,
    pub robustness: Option<RobustnessConfig>,
}

impl Default for WatermarkConfig {
    fn default() -> Self {
        Self {
            encoding: WatermarkEncoding::ZeroWidth,
            fallback_encodings: None,
            private_key: None,
            public_key: None,
            generate_key_pair: true,
            include_timestamp: true,
            include_sequence: true,
            custom_metadata: None,
            encoding_options: None,
            robustness: Some(RobustnessConfig::default()),
        }
    }
}

/// Watermarked prompt result
#[derive(Clone, Debug)]
pub struct WatermarkedPrompt {
    pub original: String,
    pub watermarked: String,
    pub watermark: EncodedWatermark,
    pub encoding: WatermarkEncoding,
    pub stats: WatermarkStats,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatermarkStats {
    pub original_length: usize,
    pub watermarked_length: usize,
    pub bits_encoded: usize,
    pub encoding_time_ms: f64,
}

/// Prompt watermarker
pub struct PromptWatermarker {
    config: WatermarkConfig,
    signing_key: ed25519_dalek::SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
    sequence: std::sync::atomic::AtomicU32,
}

impl PromptWatermarker {
    /// Create with configuration
    pub fn new(config: WatermarkConfig) -> Result<Self, WatermarkError>;

    /// Watermark a prompt
    pub fn watermark(
        &self,
        prompt: &str,
        payload: Option<WatermarkPayload>,
    ) -> Result<WatermarkedPrompt, WatermarkError>;

    /// Generate a new payload
    pub fn generate_payload(
        &self,
        application_id: &str,
        session_id: &str,
    ) -> WatermarkPayload;

    /// Encode payload to binary
    pub fn encode_payload(&self, payload: &WatermarkPayload) -> Vec<u8>;

    /// Sign data
    pub fn sign(&self, data: &[u8]) -> Vec<u8>;

    /// Get public key
    pub fn public_key(&self) -> String;
}

/// Verifier configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WatermarkVerifierConfig {
    pub trusted_public_keys: Vec<String>,
    pub allow_unverified: bool,
    pub sensitivity: VerifierSensitivity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerifierSensitivity {
    Low,
    Medium,
    High,
}

impl Default for WatermarkVerifierConfig {
    fn default() -> Self {
        Self {
            trusted_public_keys: Vec::new(),
            allow_unverified: false,
            sensitivity: VerifierSensitivity::Medium,
        }
    }
}

/// Watermark extractor
pub struct WatermarkExtractor {
    config: WatermarkVerifierConfig,
}

impl WatermarkExtractor {
    pub fn new(config: WatermarkVerifierConfig) -> Self;

    /// Extract watermark from text
    pub fn extract(&self, text: &str) -> WatermarkExtractionResult;

    /// Extract and verify
    pub fn extract_and_verify(&self, text: &str) -> WatermarkExtractionResult;

    /// Verify signature
    pub fn verify_signature(&self, watermark: &EncodedWatermark) -> bool;

    /// Check if key is trusted
    pub fn is_key_trusted(&self, public_key: &str) -> bool;

    /// Add trusted key
    pub fn add_trusted_key(&mut self, public_key: String);
}

#[derive(Debug)]
pub enum WatermarkError {
    ConfigError(String),
    EncodingError(String),
    DeserializationError(String),
    SignatureError(String),
    ExtractionError(String),
    CapacityExceeded,
}
```

---

## 5. Encoding Algorithms

### 5.1 Zero-Width Character Encoder

```rust
/// Zero-width characters for encoding
const ZW_SPACE: char = '\u{200B}';  // Zero Width Space = 0
const ZW_NON_JOINER: char = '\u{200C}';  // Zero Width Non-Joiner = 1
const ZW_JOINER: char = '\u{200D}';  // Zero Width Joiner = separator
const BOM: char = '\u{FEFF}';  // Byte Order Mark = start marker

struct ZeroWidthEncoder {
    options: ZeroWidthOptions,
}

impl ZeroWidthEncoder {
    fn encode(&self, prompt: &str, data: &[u8]) -> String {
        let binary = bytes_to_binary(data);
        let encoded_chars = self.binary_to_zero_width(&binary);

        match self.options.position {
            ZeroWidthPosition::Start => {
                format!("{}{}{}", BOM, encoded_chars, prompt)
            }
            ZeroWidthPosition::End => {
                format!("{}{}{}", prompt, BOM, encoded_chars)
            }
            ZeroWidthPosition::Distributed => {
                self.distribute_encode(prompt, &encoded_chars)
            }
        }
    }

    fn binary_to_zero_width(&self, binary: &str) -> String {
        let mut result = String::new();

        for (i, bit) in binary.chars().enumerate() {
            if bit == '0' {
                result.push(ZW_SPACE);
            } else {
                result.push(ZW_NON_JOINER);
            }

            // Add separator every 8 bits (byte boundary)
            if (i + 1) % 8 == 0 && i + 1 < binary.len() {
                result.push(ZW_JOINER);
            }
        }

        result
    }

    fn distribute_encode(&self, prompt: &str, encoded: &str) -> String {
        let words: Vec<&str> = prompt.split_whitespace().collect();
        let bits_per_word = encoded.len() / words.len().max(1);
        let mut result = String::new();
        let mut bit_index = 0;

        for (i, word) in words.iter().enumerate() {
            result.push_str(word);

            // Embed bits after this word
            let end_index = ((i + 1) * bits_per_word).min(encoded.len());
            let bits_to_embed: String = encoded.chars()
                .skip(bit_index)
                .take(end_index - bit_index)
                .collect();
            result.push_str(&bits_to_embed);
            bit_index = end_index;

            if i < words.len() - 1 {
                result.push(' ');
            }
        }

        // Append any remaining bits
        if bit_index < encoded.len() {
            let remaining: String = encoded.chars().skip(bit_index).collect();
            result.push_str(&remaining);
        }

        result
    }

    fn decode(&self, text: &str) -> Result<Vec<u8>, WatermarkError> {
        // Find start marker
        let start_pos = text.find(BOM).ok_or(
            WatermarkError::ExtractionError("No watermark marker found".into())
        )?;

        let mut binary = String::new();
        let mut found_start = false;

        for c in text[start_pos..].chars() {
            if c == BOM {
                found_start = true;
                continue;
            }

            if !found_start {
                continue;
            }

            match c {
                c if c == ZW_SPACE => binary.push('0'),
                c if c == ZW_NON_JOINER => binary.push('1'),
                c if c == ZW_JOINER => {} // Separator, ignore
                _ => {
                    // Non-zero-width character, check if we should stop
                    if binary.len() > 0 && binary.len() % 8 == 0 {
                        break;
                    }
                }
            }
        }

        binary_to_bytes(&binary)
    }
}

fn bytes_to_binary(data: &[u8]) -> String {
    data.iter()
        .map(|byte| format!("{:08b}", byte))
        .collect()
}

fn binary_to_bytes(binary: &str) -> Result<Vec<u8>, WatermarkError> {
    let mut bytes = Vec::new();

    for chunk in binary.as_bytes().chunks(8) {
        if chunk.len() < 8 {
            break; // Incomplete byte, stop
        }

        let byte_str = std::str::from_utf8(chunk).map_err(|e|
            WatermarkError::DeserializationError(e.to_string())
        )?;

        let byte = u8::from_str_radix(byte_str, 2).map_err(|e|
            WatermarkError::DeserializationError(e.to_string())
        )?;

        bytes.push(byte);
    }

    Ok(bytes)
}
```

### 5.2 Homoglyph Encoder

```rust
use std::collections::HashMap;

/// Homoglyph substitution maps
fn cyrillic_homoglyphs() -> HashMap<char, char> {
    let mut map = HashMap::new();
    map.insert('a', '\u{0430}'); // Cyrillic а
    map.insert('c', '\u{0441}'); // Cyrillic с
    map.insert('e', '\u{0435}'); // Cyrillic е
    map.insert('o', '\u{043E}'); // Cyrillic о
    map.insert('p', '\u{0440}'); // Cyrillic р
    map.insert('x', '\u{0445}'); // Cyrillic х
    map.insert('y', '\u{0443}'); // Cyrillic у
    map.insert('A', '\u{0410}'); // Cyrillic А
    map.insert('B', '\u{0412}'); // Cyrillic В
    map.insert('C', '\u{0421}'); // Cyrillic С
    map.insert('E', '\u{0415}'); // Cyrillic Е
    map.insert('H', '\u{041D}'); // Cyrillic Н
    map.insert('K', '\u{041A}'); // Cyrillic К
    map.insert('M', '\u{041C}'); // Cyrillic М
    map.insert('O', '\u{041E}'); // Cyrillic О
    map.insert('P', '\u{0420}'); // Cyrillic Р
    map.insert('T', '\u{0422}'); // Cyrillic Т
    map.insert('X', '\u{0425}'); // Cyrillic Х
    map
}

struct HomoglyphEncoder {
    options: HomoglyphOptions,
    substitutions: HashMap<char, char>,
    reverse_substitutions: HashMap<char, char>,
}

impl HomoglyphEncoder {
    fn new(options: HomoglyphOptions) -> Self {
        let substitutions = match options.char_set {
            HomoglyphCharSet::Cyrillic => cyrillic_homoglyphs(),
            HomoglyphCharSet::Greek => greek_homoglyphs(),
            HomoglyphCharSet::Mixed => {
                let mut map = cyrillic_homoglyphs();
                map.extend(greek_homoglyphs());
                map
            }
        };

        let reverse_substitutions: HashMap<char, char> = substitutions
            .iter()
            .map(|(&k, &v)| (v, k))
            .collect();

        Self {
            options,
            substitutions,
            reverse_substitutions,
        }
    }

    fn encode(&self, prompt: &str, data: &[u8]) -> String {
        let binary = bytes_to_binary(data);
        let substitutable: Vec<(usize, char)> = prompt
            .char_indices()
            .filter(|(_, c)| self.substitutions.contains_key(c))
            .collect();

        // Check capacity
        if substitutable.len() < binary.len() {
            // Not enough substitutable characters
            // Fall back to partial encoding or error
        }

        let mut result: Vec<char> = prompt.chars().collect();
        let max_ratio = self.options.max_ratio.unwrap_or(1.0);
        let max_substitutions = (substitutable.len() as f32 * max_ratio) as usize;

        for (bit_idx, bit) in binary.chars().enumerate() {
            if bit_idx >= substitutable.len() || bit_idx >= max_substitutions {
                break;
            }

            let (char_idx, original_char) = substitutable[bit_idx];

            if bit == '1' {
                // Substitute with homoglyph
                if let Some(&homoglyph) = self.substitutions.get(&original_char) {
                    result[char_idx] = homoglyph;
                }
            }
            // If bit == '0', leave original (ASCII)
        }

        result.into_iter().collect()
    }

    fn decode(&self, text: &str) -> Result<Vec<u8>, WatermarkError> {
        let mut binary = String::new();

        for c in text.chars() {
            if self.substitutions.contains_key(&c) {
                // ASCII character = 0
                binary.push('0');
            } else if self.reverse_substitutions.contains_key(&c) {
                // Homoglyph = 1
                binary.push('1');
            }
            // Other characters are ignored
        }

        if binary.is_empty() {
            return Err(WatermarkError::ExtractionError("No homoglyph pattern found".into()));
        }

        binary_to_bytes(&binary)
    }
}

fn greek_homoglyphs() -> HashMap<char, char> {
    let mut map = HashMap::new();
    map.insert('A', '\u{0391}'); // Greek Α
    map.insert('B', '\u{0392}'); // Greek Β
    map.insert('E', '\u{0395}'); // Greek Ε
    map.insert('Z', '\u{0396}'); // Greek Ζ
    map.insert('H', '\u{0397}'); // Greek Η
    map.insert('I', '\u{0399}'); // Greek Ι
    map.insert('K', '\u{039A}'); // Greek Κ
    map.insert('M', '\u{039C}'); // Greek Μ
    map.insert('N', '\u{039D}'); // Greek Ν
    map.insert('O', '\u{039F}'); // Greek Ο
    map.insert('P', '\u{03A1}'); // Greek Ρ
    map.insert('T', '\u{03A4}'); // Greek Τ
    map.insert('Y', '\u{03A5}'); // Greek Υ
    map.insert('X', '\u{03A7}'); // Greek Χ
    map.insert('o', '\u{03BF}'); // Greek ο
    map
}
```

---

## 6. False Positive/Negative Analysis

### 6.1 Extraction Reliability

| Encoding | FP Rate | FN Rate | Conditions |
|----------|---------|---------|------------|
| Zero-Width | ~0.1% | ~5% | Text normalization strips |
| Homoglyph | ~0.5% | ~10% | Unicode normalization |
| Whitespace | ~1% | ~15% | Reformatting |
| Metadata | ~0.01% | ~1% | Explicit removal |
| Hybrid | ~0.1% | ~3% | Combined robustness |

### 6.2 Robustness Against Modifications

| Modification | Zero-Width | Homoglyph | Metadata |
|--------------|------------|-----------|----------|
| Copy-paste | Medium | High | High |
| Text editor | Low | Medium | High |
| Unicode norm | Low | Low | High |
| Paraphrasing | N/A | N/A | Low |
| Truncation | Medium | Medium | High |

---

## 7. Performance Considerations

### 7.1 Latency Requirements

| Operation | Target (p50) | Target (p99) | Notes |
|-----------|--------------|--------------|-------|
| Watermark generation | < 1ms | < 5ms | In-memory |
| Encoding (zero-width) | < 0.5ms | < 2ms | Simple insert |
| Encoding (homoglyph) | < 1ms | < 5ms | Character scan |
| Extraction | < 2ms | < 10ms | Pattern search |
| Verification | < 1ms | < 5ms | Ed25519 verify |

### 7.2 Size Overhead

| Encoding | Overhead | Example (1KB prompt) |
|----------|----------|----------------------|
| Zero-Width | ~128 bytes | 1152 bytes |
| Homoglyph | 0 bytes | 1024 bytes |
| Metadata | ~200 bytes | 1224 bytes |
| Hybrid | ~150 bytes | 1174 bytes |

---

## 8. Security Analysis

### 8.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| Watermark removal | Cryptographic signatures detect tampering |
| Watermark forging | Signing key security, key rotation |
| Replay attacks | Timestamps, sequence numbers |
| Denial of service | Rate limiting, validation |

### 8.2 Key Management

- Generate unique key pairs per application
- Rotate keys periodically (recommended: quarterly)
- Store private keys in secure vault
- Distribute public keys for verification

---

## 9. Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)
- Payload structure and serialization
- Zero-width encoder/decoder
- Basic signing and verification
- Configuration API

### Phase 2: Encoding Strategies (Week 3-4)
- Homoglyph encoder
- Metadata encoder
- Whitespace encoder
- Hybrid strategy

### Phase 3: Integration (Week 5-6)
- Guard integration
- Audit logging
- Policy engine hooks
- SDK wrappers

### Phase 4: Production Hardening (Week 7-8)
- Performance optimization
- Key management integration
- Monitoring and alerting
- Documentation

---

## 10. References

1. Kirchenbauer, J., et al. (2023). "A Watermark for Large Language Models." ICML 2023, arXiv:2301.10226
2. Christ, M., et al. (2023). "Undetectable Watermarks for Language Models." arXiv:2306.04634
3. Zhao, X., et al. (2024). "Provable Robust Watermarking for AI-Generated Text." ICLR 2024, arXiv:2401.02874
4. Fang, T., et al. (2017). "Generating Steganographic Text with LSTMs." ACL 2017
5. Ziegler, Z., et al. (2019). "Neural Linguistic Steganography." EMNLP 2019, arXiv:1909.01496
6. Abdelnabi, S., & Fritz, M. (2021). "Adversarial Watermarking Transformer." arXiv:2009.03015
7. He, X., et al. (2022). "CATER: Intellectual Property Protection on Text Generation APIs." EMNLP 2022

---

*This document is part of the Clawdstrike Prompt Security specification suite.*
