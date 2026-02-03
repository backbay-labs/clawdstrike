# Output Sanitizer

Inspects and redacts sensitive information from LLM-generated content before it reaches end users or downstream systems.

## Overview

Output sanitization prevents unintentional leakage of:

- **Secrets** — API keys, tokens, passwords, private keys
- **PII** — Names, addresses, SSNs, phone numbers, emails
- **Internal Data** — System prompts, internal URLs, file paths
- **Sensitive Context** — Confidential business information

The sanitizer uses a multi-detector pipeline:

1. **Pattern Detector** — Regex-based secret detection
2. **Entropy Detector** — High-entropy string identification
3. **Entity Recognizer (NER)** — Named entity extraction for PII
4. **Custom Detectors** — User-defined patterns

## Configuration

```yaml
guards:
  output_sanitizer:
    categories:
      secrets: true
      pii: true
      phi: false       # Protected Health Information
      pci: false       # Payment Card Industry
      internal: true

    redaction_strategies:
      secret: full           # [REDACTED]
      pii: partial           # John ***
      internal: type_label   # [INTERNAL_URL]

    secrets:
      entropy_detection: true
      entropy_threshold: 4.5
      custom_patterns:
        - id: company_api_key
          pattern: "MYCO-[A-Z0-9]{32}"
          confidence: 0.95

    pii:
      ner_enabled: true
      min_confidence: 0.8
      entity_types:
        - PERSON
        - EMAIL
        - PHONE
        - SSN
        - CREDIT_CARD

    internal:
      internal_domains:
        - "*.internal.company.com"
        - "localhost"
      sensitive_path_prefixes:
        - "/var/secrets"
        - "/home/"
      system_prompt_leak_detection: true

    allowlist:
      exact:
        - "sk-test-EXAMPLE"
      patterns:
        - "AKIA.*EXAMPLE"
      allow_test_credentials: true

    performance:
      max_input_length: 1000000
      streaming_enabled: true
      stream_buffer_size: 4096
```

## Sensitive Data Categories

### Secrets (High Confidence Patterns)

| Type | Pattern | Confidence |
|------|---------|------------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | 99% |
| GitHub PAT | `ghp_[A-Za-z0-9]{36}` | 99% |
| OpenAI Key | `sk-[A-Za-z0-9]{48}` | 95% |
| Anthropic Key | `sk-ant-api03-...` | 95% |
| Private Key | `-----BEGIN...PRIVATE KEY-----` | 99% |
| JWT Token | `eyJ[A-Za-z0-9_-]*\.eyJ...` | 90% |
| Database URL | `postgres://user:pass@...` | 95% |
| Generic API Key | `api_key=...` | 70% |

### PII (Entity Recognition)

| Entity | Detection Method | Example |
|--------|------------------|---------|
| Person Name | NER model | "John Smith" |
| Email Address | Regex + validation | user@domain.com |
| Phone Number | Regex + format | (555) 123-4567 |
| SSN | Regex + Luhn | 123-45-6789 |
| Credit Card | Regex + Luhn | 4111-1111-1111-1111 |
| Physical Address | NER + regex | "123 Main St, City, ST" |
| IP Address | Regex | 192.168.1.1 |

### Internal Information

| Type | Indicators | Action |
|------|------------|--------|
| System Prompt | "My instructions say...", "I was told to..." | Block/Redact |
| Internal URLs | `*.internal.*`, `localhost` | Redact |
| File Paths | `/var/`, `/home/`, `C:\` | Redact |
| Internal IPs | `10.*`, `192.168.*`, `172.16.*` | Redact |

## Redaction Strategies

| Strategy | Description | Example |
|----------|-------------|---------|
| `full` | Replace entirely | `sk-abc123...` → `[REDACTED]` |
| `partial` | Keep prefix/suffix | `sk-abc123xyz` → `sk-***xyz` |
| `type_label` | Replace with type | `sk-abc123...` → `[API_KEY]` |
| `hash` | Replace with hash | `sk-abc123...` → `[SHA:a1b2c3]` |
| `none` | Log only, don't redact | (for audit without modification) |

## API

### TypeScript

```typescript
import { OutputSanitizer } from "@clawdstrike/sdk";

const sanitizer = new OutputSanitizer({
  categories: { secrets: true, pii: true },
  redactionStrategies: {
    secret: "full",
    pii: "partial",
  },
});

const result = await sanitizer.sanitize(llmOutput);

console.log(result.sanitized);  // Redacted output
console.log(result.wasRedacted);  // true/false
console.log(result.findings);  // Detected sensitive data
```

### Rust

```rust
use clawdstrike::sanitizer::{OutputSanitizer, OutputSanitizerConfig};

let config = OutputSanitizerConfig::default();
let sanitizer = OutputSanitizer::with_config(config);

let result = sanitizer.sanitize(output, None).await?;
println!("Sanitized: {}", result.sanitized);
for finding in &result.findings {
    println!("Found {} at {:?}", finding.data_type, finding.span);
}
```

### Streaming Mode

For real-time sanitization of streaming LLM output:

```typescript
const stream = sanitizer.createStream();

for await (const chunk of llmStream) {
  const safeChunk = stream.write(chunk);
  if (safeChunk) {
    yield safeChunk;  // Emit safe content immediately
  }
}

// Flush remaining buffer
const final = stream.flush();
yield final;

// Get all findings from the stream
const findings = stream.getFindings();
```

## Result Structure

```typescript
interface SanitizationResult {
  sanitized: string;
  wasRedacted: boolean;

  findings: Array<{
    id: string;
    category: "secret" | "pii" | "phi" | "pci" | "internal";
    type: string;              // e.g., "aws_access_key", "email"
    confidence: number;        // 0-1
    span: { start: number; end: number };
    matchPreview: string;      // Truncated, not raw
    detector: "pattern" | "ner" | "entropy" | "custom";
    recommendedAction: RedactionStrategy;
  }>;

  redactions: Array<{
    findingId: string;
    strategy: RedactionStrategy;
    originalSpan: { start: number; end: number };
    newSpan: { start: number; end: number };
    replacement: string;
  }>;

  stats: {
    inputLength: number;
    outputLength: number;
    findingsCount: number;
    redactionsCount: number;
    processingTimeMs: number;
  };
}
```

## High-Entropy Detection

The entropy detector identifies potential secrets that don't match known patterns:

```typescript
// Shannon entropy calculation
function entropy(s: string): number {
  const freq = new Map<string, number>();
  for (const c of s) {
    freq.set(c, (freq.get(c) || 0) + 1);
  }
  return -[...freq.values()].reduce((sum, count) => {
    const p = count / s.length;
    return sum + p * Math.log2(p);
  }, 0);
}

// Strings above threshold (default 4.5) are flagged
if (entropy(token) >= 4.5 && token.length >= 20) {
  // Likely a secret
}
```

## False Positive Mitigation

### Allowlist Configuration

```yaml
allowlist:
  # Exact strings to allow
  exact:
    - "sk-test-EXAMPLEKEY123"
    - "AKIAIOSFODNN7EXAMPLE"

  # Regex patterns to allow
  patterns:
    - "AKIA.*EXAMPLE"
    - "ghp_test.*"

  # Allow test/example credentials
  allow_test_credentials: true
```

### Common False Positives

| Trigger | Example | Mitigation |
|---------|---------|------------|
| Test credentials | `sk-test-123...` | `allow_test_credentials: true` |
| Documentation | Example code blocks | Context detection |
| Placeholder values | `YOUR_API_KEY_HERE` | Placeholder detection |
| UUIDs | `550e8400-e29b-...` | Pattern refinement |

## Compliance Context

The sanitizer can adjust behavior based on compliance requirements:

```typescript
const result = await sanitizer.sanitize(output, {
  compliance: ["gdpr", "hipaa"],  // Stricter PII handling
  isInternal: false,              // External output
  userRole: "customer",           // Not admin
});
```

| Compliance | Effect |
|------------|--------|
| GDPR | Stricter PII detection, full redaction |
| HIPAA | Enable PHI category, full redaction |
| PCI-DSS | Enable PCI category, mask card numbers |
| CCPA | Similar to GDPR for California residents |

## Performance

| Mode | Target p50 | Target p99 | Notes |
|------|------------|------------|-------|
| Sync (patterns only) | < 2ms | < 10ms | No NER |
| Async (full) | < 20ms | < 100ms | With NER |
| Streaming | < 5ms/chunk | < 20ms/chunk | 4KB chunks |

## Privacy Guarantees

- **Never stores raw secrets in findings.** `matchPreview` is always truncated.
- **Hash-based correlation.** Use hash redaction to correlate across logs without exposure.
- **No training data leakage.** Findings don't include enough context to reconstruct secrets.
