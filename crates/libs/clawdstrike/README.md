# clawdstrike

Security guards and policy engine for AI agent execution.

This is the main Rust library crate for the Clawdstrike system. It provides security guards, the policy engine, receipt signing, jailbreak detection, prompt hygiene, output sanitization, and more.

## Features

- **Security guards** -- ForbiddenPath, PathAllowlist, EgressAllowlist, SecretLeak, PatchIntegrity, McpTool, PromptInjection, Jailbreak
- **Policy engine** -- YAML-based policy configuration (schema v1.2.0) with inheritance via `extends`
- **Receipt signing** -- Ed25519-signed attestations of decisions, policies, and evidence
- **Jailbreak detection** -- Multi-layer detection (heuristic, statistical, ML, optional LLM judge)
- **Prompt hygiene** -- Instruction hierarchy enforcement, prompt injection detection
- **Output sanitization** -- Streaming-capable sensitive data redaction
- **Watermarking** -- Prompt watermark embedding and extraction
- **WASM plugin runtime** -- Execute custom guards as WebAssembly modules (optional feature)
- **IRM** -- Inline reference monitor for filesystem, network, and execution operations

## Quick Start

```rust
use clawdstrike::{ForbiddenPathGuard, SecretLeakGuard, Guard, GuardContext};
use clawdstrike::guards::GuardAction;

// Check if a path is forbidden
let guard = ForbiddenPathGuard::new();
let result = guard.check(&GuardAction::FileAccess("~/.ssh/id_rsa"), &GuardContext::default()).await;
assert!(!result.allowed);

// Scan content for secrets
let secret_guard = SecretLeakGuard::new();
let matches = secret_guard.scan(b"api_key = sk-1234567890abcdef");
```

## Policy Configuration

```rust
use clawdstrike::Policy;

let yaml = r#"
version: "1.2.0"
name: "example"
settings:
  fail_fast: true
"#;

let policy = Policy::from_yaml(yaml).unwrap();
```

## Cargo Features

- `default` -- Core guards and policy engine
- `ipfs` -- IPFS content addressing support
- `llm-judge-openai` -- OpenAI-backed LLM judge for jailbreak detection
- `wasm-plugin-runtime` -- WebAssembly guard plugin execution via Wasmtime

## Documentation

```bash
cargo doc --no-deps --all-features -p clawdstrike --open
```

## License

Apache-2.0
