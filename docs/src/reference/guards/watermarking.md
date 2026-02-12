# Prompt Watermarking

Prompt watermarking embeds a signed provenance marker into a prompt so you can later attribute content to an application/session without storing raw prompts.

This is a prompt-security utility (used by integrations like `@clawdstrike/vercel-ai`), not part of the Rust policy schema (`guards.*`).

## Encoding

The current implementation supports a single encoding:

- `metadata` — a single metadata comment prepended to the prompt.

Example (prefix only; content is base64url-encoded):

```text
<!--hushclaw.watermark:v1:...-->
You are a helpful assistant.
```

The payload bytes are canonical JSON (RFC 8785 / JCS) and are signed with Ed25519.

## TypeScript (`@clawdstrike/sdk`)

```typescript
import { PromptWatermarker, WatermarkExtractor } from "@clawdstrike/sdk";

const watermarker = await PromptWatermarker.create({ generateKeypair: true });
const payload = watermarker.generatePayload("my-app", crypto.randomUUID());
const { watermarked } = await watermarker.watermark("You are helpful.", payload);

const extractor = new WatermarkExtractor({ trustedPublicKeys: [watermarker.publicKeyHex()] });
const extracted = await extractor.extract(watermarked);

console.log(extracted.found, extracted.verified, extracted.watermark?.payload);
```

## Rust (`clawdstrike`)

```rust,ignore
use clawdstrike::{PromptWatermarker, WatermarkConfig, WatermarkExtractor, WatermarkVerifierConfig};

let watermarker = PromptWatermarker::new(WatermarkConfig::default())?;
let payload = watermarker.generate_payload("my-app", "session-123");
let result = watermarker.watermark("You are helpful.", Some(payload))?;

let extractor = WatermarkExtractor::new(WatermarkVerifierConfig {
    trusted_public_keys: vec![watermarker.public_key()],
    ..Default::default()
});

let extracted = extractor.extract(&result.watermarked);
assert!(extracted.found);
```

## Notes

- If `trustedPublicKeys`/`trusted_public_keys` is empty, the extractor verifies the signature but does not enforce trust (useful for debugging).
- The extractor provides a stable fingerprint (SHA-256 of the canonical payload bytes) for deduplication/correlation.
