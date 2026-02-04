# Architecture

Clawdstrike is a guard suite and attestation primitives for agent runtimes.
It is **not** an operating system sandbox: it will not automatically intercept syscalls or "wrap" a process.

The intended integration is at the **tool boundary** (your agent runtime calls Clawdstrike before performing actions).

## System Overview

```text
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                    HushEngine                                        │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐    │
│  │ Forbidden   │ │   Egress    │ │ SecretLeak  │ │   Patch     │ │  MCP Tool   │    │
│  │    Path     │ │  Allowlist  │ │    Guard    │ │  Integrity  │ │    Guard    │    │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘    │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                                    │
│  │  Prompt     │ │  Jailbreak  │ │   Output    │    ┌───────────────────────────┐   │
│  │  Injection  │ │   Guard     │ │  Sanitizer  │    │     Watermarking          │   │
│  └─────────────┘ └─────────────┘ └─────────────┘    └───────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                              Inline Reference Monitors                               │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                                    │
│  │ Filesystem  │ │   Network   │ │  Execution  │                                    │
│  │     IRM     │ │     IRM     │ │     IRM     │                                    │
│  └─────────────┘ └─────────────┘ └─────────────┘                                    │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                Policy Engine (YAML)                                  │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                              Receipt Signing & Attestation                           │
│        Ed25519 │ SHA-256/Keccak │ Merkle Trees │ Canonical JSON (RFC 8785)          │
└─────────────────────────────────────────────────────────────────────────────────────┘
                                          │
┌─────────────────────────────────────────┼───────────────────────────────────────────┐
│                              Framework Adapters                                      │
│  ┌─────────┐ ┌──────────┐ ┌───────────┐ ┌───────────┐ ┌──────┐ ┌──────────┐        │
│  │ OpenClaw│ │ Vercel AI│ │ LangChain │ │Claude Code│ │ Codex│ │ OpenCode │        │
│  └─────────┘ └──────────┘ └───────────┘ └───────────┘ └──────┘ └──────────┘        │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

## Components

### Rust Crates

| Crate | Description |
|-------|-------------|
| `clawdstrike` | Policy type, built-in guards, `HushEngine`, jailbreak detection, output sanitization |
| `hush-core` | Hashing/signing, Merkle trees, `SignedReceipt`, canonical JSON |
| `hush-proxy` | DNS/SNI parsing utilities and domain matching |
| `hush-cli` | `hush` CLI for ad-hoc checks and verification |
| `hush-wasm` | WebAssembly bindings for browser/Node.js |
| `hushd` | HTTP daemon for centralized checks (WIP) |

### TypeScript Packages

| Package | Description |
|---------|-------------|
| `@clawdstrike/sdk` | Crypto/receipts + a subset of guards + prompt-security utilities (no full policy engine) |
| `@clawdstrike/adapter-core` | Framework-agnostic adapter interfaces |
| `@clawdstrike/clawdstrike-security` | OpenClaw plugin (plugin id: `clawdstrike-security`) |
| `@clawdstrike/vercel-ai` | Vercel AI SDK integration |
| `@clawdstrike/langchain` | LangChain integration |
| `@clawdstrike/hush-cli-engine` | Node.js bridge to Rust CLI |

### Python Packages

| Package | Description |
|---------|-------------|
| `hush` | Pure Python SDK (repo: `packages/hush-py`) |

## Data flow (typical integration)

1. Your agent runtime wants to do an action (read a file, call a tool, make a network request).
2. Your runtime constructs a `GuardAction` (e.g. `FileAccess`, `NetworkEgress`, `McpTool`) and a `GuardContext`.
3. Your runtime calls `HushEngine::check_*` (or `check_action_report` for per-guard evidence).
4. Your runtime uses the returned `GuardResult` to allow, warn, or block the action.
5. Optionally, your runtime creates a signed receipt (`create_signed_receipt`) for a content hash that represents the run output/artifacts.

## What Clawdstrike can and cannot enforce

Clawdstrike can enforce only what your runtime routes through it. If an agent has direct access to the filesystem/network without going through your tool layer, Clawdstrike cannot stop it.

## Threat model (explicit)

### Attacker

- Untrusted agent output (LLM-generated tool calls, patches, commands).
- Prompt-injection content that tries to influence tool usage.
- Accidental operator error (overly broad allowlists, unsafe tools enabled).

### Assets to protect

- Local secrets and credentials (SSH keys, `.env`, cloud creds).
- Network egress destinations (exfil to arbitrary hosts).
- Repository integrity (unsafe patches, disabling checks).
- Auditability (what happened, under which policy, with what evidence).

### Enforcement points

- **Tool boundary**: your runtime must call `HushEngine::check_*` before performing an action.
- **Policy validation**: malformed patterns are rejected at policy load time (fail-closed).
- **Receipts**: cryptographically signed artifacts that record results + provenance for later verification.

### Non-goals / limitations

- No syscall interception, sandbox escape prevention, or kernel-level isolation.
- Cannot stop actions that bypass the runtime/tool layer (direct FS/net access).
- Does not guarantee secrecy against a fully compromised host or OS-level attacker.

## Enforced vs attested (don’t conflate these)

- **Enforced**: the action your runtime *chose not to perform* because a guard returned `allowed=false` (or required confirmation).
- **Attested**: what Clawdstrike recorded in a `Receipt`/`SignedReceipt` (policy hash, verdict, violations, timestamps).

Receipts are only as strong as the integration: they prove what Clawdstrike *observed/decided* under a specific policy, not that the underlying OS prevented all side effects.

## Inline Reference Monitors (IRMs)

For deeper integration scenarios, Clawdstrike provides Inline Reference Monitors that intercept operations from sandboxed modules:

| IRM | Operations | Use Case |
|-----|------------|----------|
| **FilesystemIrm** | Read, Write, Delete, List | Sandbox file access |
| **NetworkIrm** | TCP/UDP connect, DNS resolve, Listen | Sandbox network access |
| **ExecutionIrm** | Command execution | Sandbox process spawning |

IRMs integrate with the guard pipeline:

```rust,ignore
use clawdstrike::irm::{HostCall, IrmRouter};
use clawdstrike::RuleSet;

let policy = RuleSet::by_name("default")?.unwrap().policy;
let router = IrmRouter::new(policy);

// Intercept a sandboxed module's file read
let call = HostCall::new(
    "path_open",
    vec![serde_json::json!({ "path": "/etc/passwd" })],
);
let (decision, _monitors) = router.evaluate(&call).await;

if !decision.is_allowed() {
    // Block the operation
}
```

IRMs emit telemetry events for audit logging and can aggregate decisions across multiple operations.
