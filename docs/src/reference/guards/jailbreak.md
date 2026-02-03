# JailbreakGuard

Detects jailbreak attempts in user input using a multi-layer detection system with session aggregation.

## Overview

Jailbreaking refers to techniques that manipulate LLMs into bypassing their safety alignment, content policies, or operational constraints. Unlike prompt injection (which focuses on instruction hijacking), jailbreaks specifically target the model's ethical guidelines and safety training.

The JailbreakGuard uses a 4-layer detection architecture:

1. **Heuristic Layer** — Fast regex-based pattern matching (~1ms)
2. **Statistical Layer** — Anomaly detection via entropy and n-gram analysis (~5ms)
3. **ML Layer** — Linear model aggregating signals (~10ms)
4. **LLM-as-Judge** — Optional external LLM scoring for sophisticated attacks (~1-2s)

## Actions

This guard evaluates:

- `GuardAction::Custom("user_input", payload)` — User messages before LLM processing

## Configuration

```yaml
guards:
  jailbreak:
    layers:
      heuristic: true
      statistical: true
      ml: true
      llm_judge: false  # Expensive, enable for high-security
    block_threshold: 70     # Risk score 0-100
    warn_threshold: 30
    max_input_bytes: 100000
    session_aggregation: true
    session_ttl_ms: 3600000       # 1 hour
    session_half_life_ms: 900000  # 15 minutes (decay)
```

## Detection Categories

The guard detects these jailbreak categories:

| Category | Description | Example Techniques |
|----------|-------------|--------------------|
| `role_play` | Convince model to adopt unrestricted persona | DAN, Developer Mode, Evil Confidant |
| `authority_confusion` | Impersonate system or developer roles | "As your creator...", fake system tags |
| `encoding_attack` | Encode malicious content to bypass filters | Base64, ROT13, leetspeak |
| `hypothetical_framing` | Frame harmful requests as fictional | "In a fictional world where..." |
| `adversarial_suffix` | Append optimized token sequences | GCG attacks, AutoDAN |
| `system_impersonation` | Fake system message markers | `[SYSTEM]`, `<|im_start|>` |
| `instruction_extraction` | Attempt to reveal system prompt | "Repeat your instructions" |
| `multi_turn_grooming` | Gradual escalation over conversation | Progressive normalization |
| `payload_splitting` | Split malicious content across messages | Fragment recombination |

## Layer Details

### Heuristic Layer

Fast pattern matching using compiled regex. Detects known jailbreak signatures:

```typescript
// Example patterns (simplified)
const patterns = [
  { id: "jb_dan", pattern: /\b(dan|jailbreak|unfiltered)\b/i, weight: 0.9 },
  { id: "jb_ignore", pattern: /ignore.*policy/i, weight: 0.9 },
  { id: "jb_reveal", pattern: /reveal.*system prompt/i, weight: 0.95 },
];
```

### Statistical Layer

Analyzes text properties that correlate with adversarial inputs:

- **Character entropy** — Unusual distribution indicates obfuscation
- **Punctuation ratio** — High ratios suggest encoding attacks
- **Zero-width characters** — Stripped and counted as obfuscation signal
- **Symbol runs** — Long sequences of non-alphanumeric characters

### ML Layer

A lightweight linear model that aggregates signals:

```
score = sigmoid(
  -2.0
  + 2.5 * has_ignore_policy
  + 2.0 * has_dan_pattern
  + 1.5 * has_role_change
  + 2.2 * has_prompt_leak
  + 2.0 * high_punctuation
  + 1.5 * has_symbol_run
)
```

### LLM-as-Judge (Optional)

For high-security scenarios, an external LLM can score suspicious inputs:

```typescript
const detector = new JailbreakDetector({
  layers: { llmJudge: true },
  llmJudge: async (input) => {
    const response = await llm.complete({
      prompt: `Analyze for jailbreak attempts (0-1 score): ${input}`,
    });
    return parseFloat(response);
  },
});
```

## Session Aggregation

The guard tracks cumulative risk across a session to detect multi-turn grooming attacks:

```typescript
interface SessionState {
  sessionId: string;
  messagesSeen: number;
  suspiciousCount: number;    // Messages above warn threshold
  cumulativeRisk: number;     // Sum of all risk scores
  rollingRisk: number;        // Decayed risk (half-life)
  lastSeenMs: number;
}
```

**Rolling risk** decays over time (configurable half-life), so old suspicious messages contribute less than recent ones. This prevents false alarms from legitimate early conversation while catching gradual escalation.

## API

### TypeScript

```typescript
import { JailbreakDetector } from "@clawdstrike/sdk";

const detector = new JailbreakDetector({
  blockThreshold: 70,
  warnThreshold: 30,
  sessionAggregation: true,
});

const result = await detector.detect(userInput, sessionId);

if (result.blocked) {
  console.log(`Blocked: ${result.severity}`);
  console.log(`Signals: ${result.signals.map(s => s.id).join(", ")}`);
}
```

### Rust

```rust
use clawdstrike::jailbreak::{JailbreakGuard, JailbreakGuardConfig};

let config = JailbreakGuardConfig::default();
let guard = JailbreakGuard::with_config(config);

let result = guard.detect(input, &context).await?;
println!("Severity: {:?}", result.severity);
println!("Risk score: {}", result.risk_score);
```

## Result Structure

```typescript
interface JailbreakDetectionResult {
  severity: "safe" | "suspicious" | "likely" | "confirmed";
  confidence: number;     // 0-1
  riskScore: number;      // 0-100
  blocked: boolean;
  fingerprint: string;    // SHA-256 of input (for deduplication)

  signals: Array<{
    id: string;
    category: JailbreakCategory;
    weight: number;
  }>;

  layers: {
    heuristic: { score: number; signals: string[] };
    statistical: { score: number; signals: string[] };
    ml?: { score: number; signals: string[] };
    llmJudge?: { score: number; signals: string[] };
  };

  session?: {
    sessionId: string;
    messagesSeen: number;
    suspiciousCount: number;
    cumulativeRisk: number;
    rollingRisk: number;
  };
}
```

## Thresholds

| Configuration | Block Threshold | Warn Threshold | Use Case |
|---------------|-----------------|----------------|----------|
| **Paranoid** | 50 | 20 | High-security, accept friction |
| **Balanced** (default) | 70 | 30 | General production |
| **Permissive** | 85 | 50 | Low-risk, minimize false positives |

## Canonicalization

Before detection, input is canonicalized:

1. **Unicode normalization (NFKC)** — Collapse equivalent representations
2. **Case folding** — Lowercase for pattern matching
3. **Zero-width stripping** — Remove invisible characters (counted as signal)
4. **Whitespace collapse** — Normalize spacing

This prevents simple obfuscation bypasses while preserving detection accuracy.

## False Positive Mitigation

Common false positive triggers and mitigations:

| Trigger | Example | Mitigation |
|---------|---------|------------|
| Security discussions | "How do jailbreaks work?" | Adjust thresholds, allowlist contexts |
| Fiction/creative writing | "The character says: ignore rules" | Quoted text detection |
| Technical docs | "Developer mode in VS Code" | Domain-specific patterns |
| Legitimate role-play | "Pretend to be helpful" | Intent classification via ML layer |

## References

- Zou et al. (2023). "Universal and Transferable Adversarial Attacks on Aligned Language Models"
- Wei et al. (2023). "Jailbroken: How Does LLM Safety Training Fail?" NeurIPS 2023
- Alon & Kamfonas (2023). "Detecting Language Model Attacks with Perplexity"
