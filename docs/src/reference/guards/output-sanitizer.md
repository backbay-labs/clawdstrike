# Output Sanitizer

`OutputSanitizer` is a prompt-security utility that redacts secrets/PII/internal markers from model output before you show it to users, log it, or feed it back into another model.

It is **not** part of the Rust policy schema (`guards.*`). Instead, it’s configured in integrations (for example `@clawdstrike/vercel-ai` `promptSecurity.outputSanitization`) or used directly.

## TypeScript (`@clawdstrike/sdk`)

```typescript
import { OutputSanitizer } from "@clawdstrike/sdk";

const sanitizer = new OutputSanitizer({
  categories: { secrets: true, pii: true, internal: true },
  allowlist: { allowTestCredentials: true },
  denylist: { patterns: ["MYCO_SECRET_PHRASE_123"] },
  entropy: { enabled: true, threshold: 4.5, minTokenLen: 32 },
});

const r = sanitizer.sanitizeSync(`email=alice@example.com key=sk-${"a".repeat(48)}`);
console.log(r.redacted, r.sanitized);
console.log(r.findings.map((f) => ({ id: f.id, dataType: f.dataType, preview: f.preview })));
```

### Streaming

`createStream()` returns a `SanitizationStream` that buffers a small carry window so it can redact across chunk boundaries.

```typescript
const stream = sanitizer.createStream();

let sanitized = "";
for await (const chunk of llmStream) {
  sanitized += stream.write(chunk);
}
sanitized += stream.flush();

const findings = stream.getFindings();
```

## Rust (`clawdstrike`)

```rust,ignore
use clawdstrike::{OutputSanitizer, OutputSanitizerConfig};

let sanitizer = OutputSanitizer::with_config(OutputSanitizerConfig::default());
let r = sanitizer.sanitize_sync("email=alice@example.com");
println!("{}", r.sanitized);
```

### Streaming

```rust,ignore
use clawdstrike::OutputSanitizer;

let sanitizer = OutputSanitizer::new();
let mut stream = sanitizer.create_stream();

let mut out = String::new();
out.push_str(&stream.write("sk-aaaa"));
out.push_str(&stream.write("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
out.push_str(&stream.flush());

let summary = stream.end();
println!("redacted={} findings={}", summary.redacted, summary.findings.len());
```

## Notes

- Findings never include raw secrets; `preview` is masked.
- If input exceeds `maxInputBytes`, a truncation marker is appended so downstream can treat output as redacted.

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
