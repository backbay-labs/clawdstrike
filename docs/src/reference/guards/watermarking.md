# Prompt Watermarking

Embeds invisible markers in prompts for attribution, tracing, and forensic analysis.

## Overview

Prompt watermarking enables:

- **Attribution** — Identify which application/session generated a prompt
- **Tracing** — Follow prompt lifecycle through distributed systems
- **Provenance** — Establish origin and chain of custody
- **Forensics** — Investigate security incidents post-hoc
- **Compliance** — Meet audit and regulatory requirements

## Use Cases

| Use Case | Description |
|----------|-------------|
| Security Forensics | Trace malicious prompts back to their origin |
| Compliance Audit | Prove chain of custody for regulatory requirements |
| Usage Attribution | Allocate costs per application/tenant |
| Incident Response | Reconstruct attack paths |
| Abuse Detection | Identify coordinated attack patterns |

## Configuration

```yaml
guards:
  watermarking:
    encoding: metadata          # zero_width, homoglyph, whitespace, metadata, hybrid
    include_timestamp: true
    include_sequence: true

    encoding_options:
      metadata:
        format: xml_comment     # xml_comment, json_comment, custom
        position: prepend       # prepend, append, inline

    robustness:
      error_correction: true
      redundancy: 2

    signing:
      enabled: true
      # Key pair generated automatically if not provided
```

## Encoding Strategies

### Metadata Embedding (Recommended)

Embeds watermark in explicit metadata positions. Most robust and debuggable.

```
<!-- clawdstrike:session=a1b2c3d4-e5f6-7890-abcd-ef1234567890 -->
<system_prompt>
Your actual system prompt here...
</system_prompt>
```

**Pros:** High robustness, explicit, easy to debug
**Cons:** Visible (though typically ignored by LLMs)

### Zero-Width Characters

Encodes data using invisible Unicode characters:

- `U+200B` (Zero-Width Space) = 0
- `U+200C` (Zero-Width Non-Joiner) = 1
- `U+FEFF` (BOM) = start marker

```
"Hello" + [invisible watermark] = "Hello" (appears identical)
```

**Pros:** Completely invisible
**Cons:** Stripped by text normalization

### Homoglyph Substitution

Replaces ASCII characters with visually identical Unicode:

- `a` (U+0061) ↔ `а` (U+0430, Cyrillic)
- `e` (U+0065) ↔ `е` (U+0435, Cyrillic)
- `o` (U+006F) ↔ `о` (U+043E, Cyrillic)

**Pros:** Survives copy-paste
**Cons:** Detected by Unicode normalization

### Whitespace Patterns

Varies whitespace to encode data:

- Single vs double space after periods
- Tab vs spaces for indentation
- Trailing whitespace per line

**Pros:** Often survives processing
**Cons:** May be normalized away

### Hybrid

Combines multiple strategies for robustness:

```yaml
encoding: hybrid
fallback_encodings:
  - metadata
  - zero_width
  - homoglyph
```

## Watermark Payload

Each watermark contains:

```typescript
interface WatermarkPayload {
  applicationId: string;    // Which app generated this
  sessionId: string;        // Conversation/task identifier
  createdAt: number;        // Unix timestamp (ms)
  expiresAt?: number;       // Optional expiration
  sequenceNumber: number;   // Message index in session
  totalMessages?: number;   // Total expected messages
  metadata?: Record<string, string>;  // Custom fields
}
```

**Signed payload** (128 bytes total):
- Header: 8 bytes (version, flags, encoding)
- Core metadata: 32 bytes (app ID, session ID)
- Timestamps: 16 bytes
- Sequence: 8 bytes
- Ed25519 signature: 64 bytes

## API

### TypeScript

```typescript
import { PromptWatermarker, WatermarkExtractor } from "@clawdstrike/sdk";

// Create watermarker
const watermarker = new PromptWatermarker({
  encoding: "metadata",
  generateKeyPair: true,
});

// Watermark a prompt
const result = watermarker.watermark(systemPrompt, {
  applicationId: "my-app",
  sessionId: crypto.randomUUID(),
});

console.log(result.watermarked);  // Prompt with embedded watermark
console.log(result.watermark);    // The watermark object
console.log(result.stats.bitsEncoded);

// Extract watermark
const extractor = new WatermarkExtractor({
  trustedPublicKeys: [watermarker.getPublicKey()],
});

const extracted = extractor.extract(suspiciousPrompt);
if (extracted.found && extracted.verified) {
  console.log(`From app: ${extracted.watermark.payload.applicationId}`);
  console.log(`Session: ${extracted.watermark.payload.sessionId}`);
}
```

### Rust

```rust
use clawdstrike::watermark::{PromptWatermarker, WatermarkConfig, WatermarkExtractor};

let config = WatermarkConfig::default();
let watermarker = PromptWatermarker::new(config)?;

let result = watermarker.watermark(prompt, None)?;
println!("Watermarked: {}", result.watermarked);

// Verify later
let extractor = WatermarkExtractor::new(WatermarkVerifierConfig {
    trusted_public_keys: vec![watermarker.public_key()],
    ..Default::default()
});

let extracted = extractor.extract(&suspicious_prompt);
if extracted.found && extracted.verified {
    println!("Verified from: {}", extracted.watermark.payload.application_id);
}
```

## Extraction Result

```typescript
interface WatermarkExtractionResult {
  found: boolean;
  watermark?: EncodedWatermark;
  verified: boolean;              // Signature valid
  confidence: number;             // 0-1

  errors: string[];

  extractionMetadata: {
    encoding: WatermarkEncoding;
    bitsExtracted: number;
    errorRate: number;
    processingTimeMs: number;
  };
}
```

## Robustness Analysis

| Modification | Metadata | Zero-Width | Homoglyph |
|--------------|----------|------------|-----------|
| Copy-paste | High | Medium | High |
| Text editor save | High | Low | Medium |
| Unicode normalization | High | Low | Low |
| Paraphrasing | Low | N/A | N/A |
| Truncation | High | Medium | Medium |
| HTML rendering | High | Low | High |

## Security Considerations

### Tamper Detection

Watermarks are cryptographically signed. Any modification invalidates the signature:

```typescript
const extracted = extractor.extractAndVerify(modifiedPrompt);
if (!extracted.verified) {
  console.log("Watermark was tampered with!");
}
```

### Replay Protection

Timestamps and sequence numbers prevent replay attacks:

```typescript
// Check freshness
const age = Date.now() - extracted.watermark.payload.createdAt;
if (age > 3600000) {  // 1 hour
  console.log("Watermark expired");
}

// Check sequence
if (extracted.watermark.payload.sequenceNumber !== expectedSequence) {
  console.log("Sequence mismatch - possible replay");
}
```

### Key Management

- Generate unique key pairs per application
- Rotate keys periodically (quarterly recommended)
- Store private keys in secure vault
- Distribute public keys for verification

## Audit Integration

```typescript
import { WatermarkAuditLogger } from "@clawdstrike/sdk";

const logger = new WatermarkAuditLogger(storage);

// Log watermark creation
await logger.logCreation(watermark, prompt);

// Log verification
await logger.logVerification(extractionResult, suspiciousPrompt);

// Query audit trail
const entries = await logger.query({
  applicationId: "my-app",
  startTime: new Date("2024-01-01"),
  eventType: "tampered",
});
```

## Performance

| Operation | p50 | p99 | Notes |
|-----------|-----|-----|-------|
| Watermark generation | < 1ms | < 5ms | In-memory |
| Encoding (metadata) | < 0.5ms | < 2ms | String concat |
| Encoding (zero-width) | < 1ms | < 5ms | Character insert |
| Extraction | < 2ms | < 10ms | Pattern search |
| Verification | < 1ms | < 5ms | Ed25519 verify |

## Size Overhead

| Encoding | Overhead | 1KB Prompt |
|----------|----------|------------|
| Metadata | ~200 bytes | 1.2KB |
| Zero-Width | ~128 bytes | 1.1KB |
| Homoglyph | 0 bytes | 1KB |
| Hybrid | ~150 bytes | 1.15KB |
