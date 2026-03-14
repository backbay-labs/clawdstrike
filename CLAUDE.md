# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Clawdstrike is a runtime security enforcement system for AI agents. It provides policy-driven security checks at the tool boundary between agent runtimes and their executed actions. The project is Rust-first with multi-language support (TypeScript, Python, WebAssembly).

**Design Philosophy:** Fail-closed. Invalid policies reject at load time; errors during evaluation deny access.

## Common Commands

```bash
# Build
cargo build --workspace

# Test
cargo test --workspace                    # All tests
cargo test -p clawdstrike                 # Single crate
cargo test test_name                      # Single test

# Lint & Format
cargo fmt --all
cargo clippy --workspace -- -D warnings

# Full CI locally
mise run ci   # or: cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings && cargo test --workspace

# Documentation
cargo doc --no-deps --all-features
mdbook build docs

# TypeScript packages
npm install --workspace=packages/sdk/hush-ts
npm run build --workspace=packages/sdk/hush-ts
npm test --workspace=packages/sdk/hush-ts

# Python
pip install -e packages/sdk/hush-py[dev]
pytest packages/sdk/hush-py/tests

# CLI
cargo install --path crates/services/hush-cli
clawdstrike check --action-type file --ruleset strict ~/.ssh/id_rsa
```

## Architecture

### Monorepo Structure

**Rust Crates (`crates/`):**
- `hush-core` - Cryptographic primitives (Ed25519, SHA-256, Keccak-256, Merkle trees, canonical JSON RFC 8785)
- `clawdstrike` - Main library: guards, policy engine, receipts
- `spine` - Signed envelopes, checkpoints, NATS transport, Merkle proofs
- `hush-cli` - CLI binary (commands: `clawdstrike`, `hush`)
- `spine-cli` - Spine protocol CLI tools
- `hushd` - HTTP daemon for centralized enforcement (broker capability authority)
- `clawdstrike-broker-protocol` - Wire types, capability signing/verification, completion bundles
- `clawdstrike-brokerd` - Local sidecar: capability validation, secret injection, provider execution
- `control-api` - Control API service (early-stage)
- `eas-anchor` - Ethereum Attestation Service anchoring
- `hush-proxy` - Network proxy utilities
- `hush-wasm` - WebAssembly bindings
- `hush-ffi` - C ABI foreign function interface for C#/Go/C bindings
- `hush-certification` - Compliance templates
- `hush-multi-agent` - Multi-agent orchestration
- `hush-native` - Native Python extension (in `packages/sdk/hush-py/hush-native`)
- `tetragon-bridge` - Tetragon gRPC to Spine bridge
- `hubble-bridge` - Cilium Hubble to Spine bridge

**TypeScript Packages (`packages/`):**
- `hush-ts` - Core TypeScript SDK (`@clawdstrike/sdk`)
- `clawdstrike-policy` - Canonical policy engine (TS)
- `clawdstrike-adapter-core` - Base adapter interface
- Framework adapters: `clawdstrike-openclaw`, `clawdstrike-vercel-ai`, `clawdstrike-langchain`, `clawdstrike-claude`, `clawdstrike-openai`, `clawdstrike-opencode`
- `clawdstrike-broker-client` - Typed client for broker capability issuance and proxied execution
- Engine bridges: `clawdstrike-hush-cli-engine`, `clawdstrike-hushd-engine`

**Python:** `packages/sdk/hush-py`

### Core Abstractions

- **Guard** - A security check implementing the `Guard` trait (sync) or `AsyncGuard` trait (async)
- **Policy** - YAML configuration (schema v1.5.0, backward-compatible with v1.1.0) with `extends` for inheritance
- **Receipt** - Ed25519-signed attestation of decision, policy, and evidence
- **HushEngine** - Facade orchestrating guards and signing

### Built-in Guards (13)

1. `ForbiddenPathGuard` - Blocks sensitive filesystem paths
2. `PathAllowlistGuard` - Allowlist-based path access control
3. `EgressAllowlistGuard` - Controls network egress by domain
4. `SecretLeakGuard` - Detects secrets in file writes
5. `PatchIntegrityGuard` - Validates patch safety
6. `ShellCommandGuard` - Blocks dangerous shell commands before execution
7. `McpToolGuard` - Restricts MCP tool invocations
8. `PromptInjectionGuard` - Detects prompt injection
9. `JailbreakGuard` - 4-layer detection (heuristic + statistical + ML + optional LLM-judge)
10. `ComputerUseGuard` - Controls CUA actions for remote desktop sessions
11. `RemoteDesktopSideChannelGuard` - Side-channel controls for clipboard, audio, drive mapping, file transfer
12. `InputInjectionCapabilityGuard` - Restricts input injection capabilities in CUA environments
13. `SpiderSenseGuard` - Hierarchical threat screening (Yu et al. 2026): embedding-based cosine similarity + optional LLM deep path

### Policy System

Policies are YAML files with schema version 1.5.0 (backward-compatible with 1.1.0). They support inheritance via `extends`:
- Built-in rulesets: `permissive`, `default`, `strict`, `ai-agent`, `cicd`, `ai-agent-posture`, `remote-desktop`, `remote-desktop-permissive`, `remote-desktop-strict`, `spider-sense`
- Local file references
- Remote URLs
- Git refs

Location: `rulesets/` directory contains built-in policies.

### Broker Subsystem

The secret broker is a brokered egress tier that interposes between AI agents and external APIs, ensuring agents never touch raw credentials.

**Components:** hushd (capability authority) → clawdstrike-brokerd (local sidecar) → upstream provider APIs

**Policy:** `broker:` block in policy YAML defines per-provider rules with `exact_paths`, `methods`, `secret_ref`, `require_intent_preview`, `max_executions`, and `approval_required_risk_levels`.

**Capability lifecycle:** Issue (hushd signs Ed25519 capability) → Preview/Approve (optional operator gate) → Execute (brokerd injects secret, calls upstream) → Evidence (brokerd reports back to hushd) → Bundle (signed completion proof).

**Security model:** Fail-closed. Capabilities are time-bounded, path-scoped, optionally DPoP sender-constrained. DNS pinning prevents SSRF rebinding. Header deny-list blocks injection. Admin bearer token protects brokerd mutations. Evidence validated against issued capabilities. Delegation tokens checked against shared revocation store.

**Secret backends:** `file` (JSON/YAML on disk), `env` (environment variables), `http` (external vault API).

**Operator surfaces (control-console):** Mission Control (capabilities + previews + approval), Wallet (inventory + replay + freeze), Theater (live event stream).

### Decision Flow

```
Policy Load → Guard Instantiation → Action Check → Per-Guard Evaluation
→ Aggregate Verdict → Receipt Signing → Audit Logging
```

## Conventions

- **Commit messages:** Follow [Conventional Commits](https://www.conventionalcommits.org/) - `feat(scope):`, `fix(scope):`, `docs:`, `test:`, `refactor:`, `perf:`, `chore:`
- **Clippy:** Must pass with `-D warnings` (treat warnings as errors)
- **Property testing:** Use `proptest` for cryptographic and serialization code
- **MSRV:** Rust 1.93

## Key Files

- `Cargo.toml` - Workspace root with all crate definitions
- `mise.toml` - Task runner configuration
- `deny.toml` - cargo-deny license/advisory config
- `rulesets/*.yaml` - Built-in security policies
- `docs/` - mdBook documentation source
