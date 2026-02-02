# Clawdstrike

Security guards and attestation primitives for AI agent execution.

## Overview

Clawdstrike provides runtime security enforcement for AI agents, including:

- **Security Guards** - Composable checks for file access, network egress, secret detection, patch validation, and tool invocation
- **Policy Engine** - YAML-based configuration for guard behavior
- **Cryptographic Attestation** - Ed25519 signing, Merkle trees, and receipt generation for verifiable execution
- **Pre-configured Rulesets** - Ready-to-use security profiles for different environments

## Threat model & limitations (explicit)

Clawdstrike enforces policy at the **agent/tool boundary**. It is not an OS sandbox and does not intercept syscalls.

- **Enforced**: what your runtime blocks/permits based on `GuardResult` from `HushEngine::check_*`.
- **Attested**: what is recorded in `Receipt`/`SignedReceipt` (verdict + provenance such as policy hash and violations).

If an agent can bypass your tool layer and access the filesystem/network directly, Clawdstrike cannot prevent it.

## Crates

| Crate | Description |
|-------|-------------|
| `hush-core` | Cryptographic primitives (Ed25519, SHA-256, Keccak-256, Merkle trees, receipts) |
| `hush-proxy` | Network proxy utilities (DNS/SNI extraction, domain policy) |
| `hush-wasm` | WebAssembly bindings for browser/Node.js verification |
| `clawdstrike` | Security guards and policy engine |
| `hush-cli` | Command-line interface |
| `hushd` | Security daemon (WIP) |

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

| Ruleset | Description |
|---------|-------------|
| `default` | Balanced security for general use |
| `strict` | Maximum security with minimal permissions |
| `ai-agent` | Optimized for AI coding assistants |
| `cicd` | Designed for CI/CD pipeline environments |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    HushEngine                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ ForbiddenPath│  │   Egress   │  │ SecretLeak  │ │
│  │    Guard     │  │  Allowlist │  │   Guard     │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │   Patch     │  │  MCP Tool   │  │  Prompt     │ │
│  │ Integrity   │  │   Guard     │  │ Injection   │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────┤
│                 Policy (YAML)                       │
├─────────────────────────────────────────────────────┤
│               Receipt Signing                       │
│  Ed25519 │ SHA-256/Keccak │ Merkle │ Canonical JSON │
└─────────────────────────────────────────────────────┘
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

## License

MIT License - see [LICENSE](LICENSE) for details.
