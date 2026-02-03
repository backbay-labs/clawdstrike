<p align="center">
  <img src=".github/assets/clawdstrike-hero.png" alt="Clawdstrike" width="900" />
</p>

<p align="center">
  <a href="https://github.com/medica/clawdstrike/actions"><img src="https://img.shields.io/github/actions/workflow/status/medica/clawdstrike/ci.yml?branch=main&style=flat-square&logo=github&label=CI" alt="CI Status"></a>
  <a href="https://crates.io/crates/clawdstrike"><img src="https://img.shields.io/crates/v/clawdstrike?style=flat-square&logo=rust" alt="crates.io"></a>
  <a href="https://docs.rs/clawdstrike"><img src="https://img.shields.io/docsrs/clawdstrike?style=flat-square&logo=docs.rs" alt="docs.rs"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/MSRV-1.75-orange?style=flat-square&logo=rust" alt="MSRV: 1.75">
</p>

<p align="center">
  <em>
    The claw strikes back.<br/>
    At the boundary between intent and action,<br/>
    it watches what leaves, what changes, what leaks.<br/>
    Not “visibility.” Not “AI.” Logs are stories—proof is a signature.<br/>
    If the tale diverges, the receipt won’t sign.
  </em>
</p>

<p align="center">
  <img src=".github/assets/divider.png" alt="" width="520" />
</p>

<p align="center">
  <img src=".github/assets/sigils/claw-light.svg#gh-light-mode-only" height="42" alt="" />
  <img src=".github/assets/sigils/claw-dark.svg#gh-dark-mode-only"   height="42" alt="" />
</p>

<h1 align="center">Clawdstrike</h1>

<p align="center">
  <em>Fail closed. Sign the truth.</em>
</p>

<p align="center">
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/sigils/boundary-dark.svg"><img src=".github/assets/sigils/boundary-light.svg" width="16" height="16" alt=""  style="vertical-align:-3px;" ></picture>&nbsp;Tool-boundary enforcement
   <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/sigils/seal-dark.svg"><img src=".github/assets/sigils/seal-light.svg" width="16" height="16" alt=""  style="vertical-align:-3px;" ></picture>&nbsp;Signed receipts
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <picture><source media="(prefers-color-scheme: dark)" srcset=".github/assets/sigils/plugin-dark.svg"><img src=".github/assets/sigils/plugin-light.svg" width="16" height="16" alt=""  style="vertical-align:-3px;" ></picture>&nbsp;OpenClaw plugin
</p>

<p align="center">
  <a href="docs/src/getting-started/quick-start.md">Docs</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="packages/clawdstrike-openclaw/docs/getting-started.md">OpenClaw integration</a>
  <span style="opacity:0.55;">&nbsp;&nbsp;&middot;&nbsp;&nbsp;</span>
  <a href="examples">Examples</a>
</p>

## Overview

Clawdstrike provides runtime security enforcement for agents, designed for developers building EDR solutions and security infrastructure on top of OpenClaw.

Includes:

- <img src=".github/assets/sigils/boundary-light.svg#gh-light-mode-only" width="16" height="16" alt="" style="vertical-align:-3px;" /> <img src=".github/assets/sigils/boundary-dark.svg#gh-dark-mode-only" width="16" height="16" alt="" style="vertical-align:-3px;" /> **Security Guards** — Composable checks for file access, network egress, secret detection, patch validation, and tool invocation
- <img src=".github/assets/sigils/policy-light.svg#gh-light-mode-only" width="16" height="16" alt="" style="vertical-align:-3px;" /> <img src=".github/assets/sigils/policy-dark.svg#gh-dark-mode-only" width="16" height="16" alt="" style="vertical-align:-3px;" /> **Policy Engine** — YAML-based configuration for guard behavior
- <img src=".github/assets/sigils/seal-light.svg#gh-light-mode-only" width="16" height="16" alt="" style="vertical-align:-3px;" /> <img src=".github/assets/sigils/seal-dark.svg#gh-dark-mode-only" width="16" height="16" alt="" style="vertical-align:-3px;" /> **Cryptographic Attestation** — Ed25519 signing, Merkle trees, and receipt generation for verifiable execution
- <img src=".github/assets/sigils/ruleset-light.svg#gh-light-mode-only" width="16" height="16" alt="" style="vertical-align:-3px;" /> <img src=".github/assets/sigils/ruleset-dark.svg#gh-dark-mode-only" width="16" height="16" alt="" style="vertical-align:-3px;" /> **Pre-configured Rulesets** — Ready-to-use security profiles for different environments

### OpenClaw Integration

Clawdstrike ships an OpenClaw plugin in `packages/clawdstrike-openclaw` (published as `@clawdstrike/openclaw`). Get started in under a minute:

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

For full setup and policy schema details, see the [OpenClaw integration guide](packages/clawdstrike-openclaw/docs/getting-started.md).

### Terminology

| Term              | Definition                                                                       |
| ----------------- | -------------------------------------------------------------------------------- |
| **Guard**         | A composable security check (e.g., `ForbiddenPathGuard`, `EgressAllowlistGuard`) |
| **Policy**        | YAML configuration that defines guard behavior and rules                         |
| **Receipt**       | An attestation record capturing tool invocations, verdicts, and provenance       |
| **SignedReceipt** | A `Receipt` cryptographically signed with Ed25519 for tamper-evidence            |

## Threat model & limitations (explicit)

Clawdstrike enforces policy at the **agent/tool boundary**. It is **_NOT_** an OS sandbox and does **_NOT_** intercept syscalls.

The purpose of Clawdstrike is to provide a solid and reliable foundation of tooling for developers building EDR apps and security infrastructure on top of OpenClaw—and to integrate cleanly into existing agent stacks and sandboxes.

- **Enforced**: what your runtime blocks/permits based on `GuardResult` from `HushEngine::check_*`.
- **Attested**: what is recorded in `Receipt`/`SignedReceipt` (verdict + provenance such as policy hash and violations).

If an agent can bypass your tool layer and access the filesystem/network directly, Clawdstrike cannot prevent it.

**Recommended**: Pair Clawdstrike with an OS-level or container sandbox (e.g., seccomp, gVisor, Firecracker) for syscall-level isolation.

## Crates

| Crate         | Description                                                                     |
| ------------- | ------------------------------------------------------------------------------- |
| `hush-core`   | Cryptographic primitives (Ed25519, SHA-256, Keccak-256, Merkle trees, receipts) |
| `hush-proxy`  | Network proxy utilities (DNS/SNI extraction, domain policy)                     |
| `hush-wasm`   | WebAssembly bindings for browser/Node.js verification                           |
| `clawdstrike` | Security guards and policy engine                                               |
| `hush-cli`    | Command-line interface                                                          |
| `hushd`       | Security daemon (WIP)                                                           |

## Quick Start

### Installation

```bash
# From source
cargo install --path crates/hush-cli

# Or build everything
cargo build --release
```

### Offline builds (vendored Rust deps)

This repo vendors Rust dependencies under `vendor/` and configures Cargo to use them via `.cargo/config.toml`.

```bash
CARGO_NET_OFFLINE=true scripts/cargo-offline.sh test --workspace --all-targets
```

If you update `Cargo.lock`, regenerate the vendor directory:

```bash
cargo vendor vendor > /dev/null
```

### Using the CLI

```bash
# Check if a file access is allowed
hush check --action-type file /app/src/main.rs

# Check with strict ruleset
hush check --action-type file --ruleset strict /home/user/.ssh/id_rsa

# Check network egress
hush check --action-type egress api.openai.com:443

# Machine-readable output (JSON)
hush check --json --action-type egress api.openai.com:443

# Generate signing keypair
hush keygen --output my-key

# Verify a receipt
hush verify receipt.json --pubkey my-key.pub

# Machine-readable verify output (JSON)
hush verify --json receipt.json --pubkey my-key.pub

# List available rulesets
hush policy list

# Show a ruleset's policy
hush policy show strict
```

### Using as a Library

```rust
use clawdstrike::{HushEngine, GuardContext};

#[tokio::main]
async fn main() {
    // Create engine with default policy
    let engine = HushEngine::new();
    let context = GuardContext::new();

    // Check file access
    let result = engine.check_file_access("/app/src/main.rs", &context).await.unwrap();
    println!("Allowed: {}", result.allowed);

    // Check network egress
    let result = engine.check_egress("api.openai.com", 443, &context).await.unwrap();
    println!("Allowed: {}", result.allowed);

    // Create a signed receipt
    let engine = HushEngine::new().with_generated_keypair();
    let content_hash = hush_core::sha256(b"task output");
    let signed_receipt = engine.create_signed_receipt(content_hash).await.unwrap();
    println!("{}", signed_receipt.to_json().unwrap());
}
```

## Security Guards

### ForbiddenPathGuard

Blocks access to sensitive paths (SSH keys, credentials, etc.)

```yaml
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env"
    exceptions:
      - "**/.env.example"
```

### EgressAllowlistGuard

Controls network egress via domain allowlist/blocklist.

```yaml
guards:
  egress_allowlist:
    allow:
      - "*.openai.com"
      - "*.anthropic.com"
    block:
      - "*.malware.com"
    default_action: block
```

### SecretLeakGuard

Detects potential secrets in file writes and patches.

```yaml
guards:
  secret_leak:
    patterns:
      - name: aws_access_key
        pattern: "AKIA[0-9A-Z]{16}"
        severity: critical
    skip_paths:
      - "**/tests/**"
```

### PatchIntegrityGuard

Validates patch safety (size limits, forbidden patterns).

```yaml
guards:
  patch_integrity:
    max_additions: 1000
    max_deletions: 500
    forbidden_patterns:
      - "(?i)disable[_\\-]?security"
```

### McpToolGuard

Restricts MCP tool invocations.

```yaml
guards:
  mcp_tool:
    allow:
      - read_file
      - list_directory
    block:
      - shell_exec
    require_confirmation:
      - git_push
    default_action: allow
```

## Rulesets

Pre-configured security profiles in `rulesets/`:

| Ruleset    | Description                               |
| ---------- | ----------------------------------------- |
| `default`  | Balanced security for general use         |
| `strict`   | Maximum security with minimal permissions |
| `ai-agent` | Optimized for AI coding assistants        |
| `cicd`     | Designed for CI/CD pipeline environments  |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                               HushEngine                                │
│  ┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐  │
│  │   ForbiddenPath   │   │      Egress       │   │    SecretLeak     │  │
│  │       Guard       │   │     Allowlist     │   │       Guard       │  │
│  └───────────────────┘   └───────────────────┘   └───────────────────┘  │
│  ┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐  │
│  │  Patch Integrity  │   │     MCP Tool      │   │      Prompt       │  │
│  │       Guard       │   │       Guard       │   │     Injection     │  │
│  └───────────────────┘   └───────────────────┘   └───────────────────┘  │
├─────────────────────────────────────────────────────────────────────────┤
│                              Policy (YAML)                              │
├─────────────────────────────────────────────────────────────────────────┤
│                             Receipt Signing                             │
│        Ed25519 │ SHA-256/Keccak │ Merkle │ Canonical JSON (JCS)         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Development

```bash
# Build
cargo build

# Test
cargo test

# Format
cargo fmt

# Lint
cargo clippy
```

## Security

We take security seriously. If you discover a vulnerability:

- **For sensitive issues**: Email [connor@backbay.io](mailto:connor@backbay.io) with details. We aim to respond within 48 hours.
- **For non-sensitive issues**: Open a [GitHub issue](https://github.com/backbay-labs/clawdstrike/issues) with the `security` label.

Please include steps to reproduce, affected versions, and any relevant context.

## Contributing

Contributions are welcome! To get started:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-improvement`)
3. Make your changes with tests
4. Run `cargo fmt && cargo clippy && cargo test`
5. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on code style, commit messages, and the review process.

## License

MIT License - see [LICENSE](LICENSE) for details.
