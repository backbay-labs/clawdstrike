# Multi-Language & Multi-Framework Support

Clawdstrike provides first-class support across multiple languages and agent frameworks, ensuring you can integrate security enforcement regardless of your stack.

## Language Support

| Language | Package | Status |
|----------|---------|--------|
| **Rust** | `clawdstrike`, `hush-core`, `hush-cli` | Reference implementation |
| **TypeScript** | `@clawdstrike/sdk` | Full parity |
| **Python** | `hush-py` | Full parity (pure Python + optional PyO3) |
| **WebAssembly** | `hush-wasm` | Verification & crypto only |

### Rust

The reference implementation. All guards, policy engine, and cryptographic primitives are implemented here first.

```bash
# Add to Cargo.toml
[dependencies]
clawdstrike = "0.1"
hush-core = "0.1"
```

```rust
use clawdstrike::{HushEngine, GuardContext};

let engine = HushEngine::new();
let ctx = GuardContext::new();
let result = engine.check_file_access("/etc/passwd", &ctx).await?;
```

### TypeScript

Full feature parity with the Rust implementation. Published as `@clawdstrike/sdk`.

```bash
npm install @clawdstrike/sdk
```

```typescript
import { HushEngine, GuardContext } from "@clawdstrike/sdk";

const engine = new HushEngine();
const ctx = new GuardContext();
const result = await engine.checkFileAccess("/etc/passwd", ctx);
```

### Python

Pure Python implementation with optional PyO3 native bindings for performance. Published as `hush-py`.

```bash
pip install hush-py
```

```python
from hush import HushEngine, GuardContext

engine = HushEngine()
ctx = GuardContext()
result = await engine.check_file_access("/etc/passwd", ctx)
```

### WebAssembly

Browser and Node.js compatible bindings for cryptographic verification. Useful for verifying receipts client-side.

```bash
npm install @clawdstrike/wasm
```

```typescript
import { verify_receipt, sha256 } from "@clawdstrike/wasm";

const isValid = verify_receipt(receiptJson, publicKeyHex);
```

---

## Framework Adapters

Clawdstrike integrates with popular agent frameworks through dedicated adapters.

| Framework | Package | Features |
|-----------|---------|----------|
| **OpenClaw** | `@clawdstrike/openclaw` | Plugin architecture, tool interception |
| **Vercel AI SDK** | `@clawdstrike/vercel-ai` | Middleware, React hooks, streaming |
| **LangChain** | `@clawdstrike/langchain` | Tool wrappers, chain callbacks |
| **Claude Code** | `@clawdstrike/claude-code` | CLI integration |
| **Codex** | `@clawdstrike/codex` | Adapter for Codex runtime |
| **OpenCode** | `@clawdstrike/opencode` | Adapter for OpenCode |

### OpenClaw

The primary integration target. Clawdstrike ships as an OpenClaw plugin.

```typescript
// openclaw.config.ts
import { clawdstrike } from "@clawdstrike/openclaw";

export default {
  plugins: [
    clawdstrike({
      ruleset: "ai-agent",
      signing: { enabled: true },
    }),
  ],
};
```

### Vercel AI SDK

Middleware-based integration with React component support for streaming tool guards.

```typescript
import { createClawdstrikeMiddleware } from "@clawdstrike/vercel-ai";

const middleware = createClawdstrikeMiddleware({
  ruleset: "default",
  onViolation: (violation) => console.warn(violation),
});

// Use with Vercel AI SDK
const { messages } = await streamText({
  model: openai("gpt-4"),
  messages: conversation,
  middleware,
});
```

### LangChain

Tool wrappers and chain callbacks for LangChain applications.

```typescript
import { ClawdstrikeToolWrapper } from "@clawdstrike/langchain";

const safeTool = new ClawdstrikeToolWrapper(originalTool, {
  ruleset: "strict",
});

const agent = createReactAgent({
  tools: [safeTool],
});
```

---

## Crates & Packages

### Rust Crates

| Crate | Description |
|-------|-------------|
| `hush-core` | Cryptographic primitives: Ed25519, SHA-256, Keccak-256, Merkle trees, receipts |
| `clawdstrike` | Security guards, policy engine, jailbreak detection, output sanitization |
| `hush-cli` | Command-line interface (`hush` binary) |
| `hush-proxy` | Network utilities: DNS/SNI extraction, domain matching |
| `hush-wasm` | WebAssembly bindings for browser/Node.js |
| `hushd` | Security daemon with HTTP API (WIP) |

### TypeScript Packages

| Package | Description |
|---------|-------------|
| `@clawdstrike/sdk` | Core TypeScript SDK (guards, receipts, crypto) |
| `@clawdstrike/adapter-core` | Framework-agnostic adapter interfaces |
| `@clawdstrike/openclaw` | OpenClaw plugin |
| `@clawdstrike/vercel-ai` | Vercel AI SDK integration |
| `@clawdstrike/langchain` | LangChain integration |
| `@clawdstrike/hush-cli-engine` | Node.js bridge to Rust CLI |

### Python Packages

| Package | Description |
|---------|-------------|
| `hush-py` | Pure Python SDK with optional PyO3 bindings |

---

## Cross-Language Compatibility

All implementations produce compatible outputs:

- **Receipts** signed in Rust can be verified in TypeScript or Python
- **Policies** are YAML and work identically across languages
- **Canonical JSON (RFC 8785)** ensures deterministic serialization
- **Ed25519 signatures** use the same curve parameters

```bash
# Sign a receipt in Rust
hush keygen --output keys
hush sign receipt.json --key keys

# Verify in TypeScript
import { verifyReceipt } from "@clawdstrike/sdk";
const valid = await verifyReceipt(receipt, publicKey);

# Verify in Python
from hush import verify_receipt
valid = verify_receipt(receipt, public_key)
```
