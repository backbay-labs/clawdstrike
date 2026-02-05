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
npm install --workspace=packages/hush-ts
npm run build --workspace=packages/hush-ts
npm test --workspace=packages/hush-ts

# Python
pip install -e packages/hush-py[dev]
pytest packages/hush-py/tests

# CLI
cargo install --path crates/hush-cli
clawdstrike check --action-type file --ruleset strict ~/.ssh/id_rsa
```

## Architecture

### Monorepo Structure

**Rust Crates (`crates/`):**
- `hush-core` - Cryptographic primitives (Ed25519, SHA-256, Keccak-256, Merkle trees, canonical JSON RFC 8785)
- `clawdstrike` - Main library: guards, policy engine, receipts
- `hush-cli` - CLI binary (commands: `clawdstrike`, `hush`)
- `hushd` - HTTP daemon for centralized enforcement (experimental)
- `hush-proxy` - Network proxy utilities
- `hush-wasm` - WebAssembly bindings
- `hush-certification` - Compliance templates
- `hush-multi-agent` - Multi-agent orchestration

**TypeScript Packages (`packages/`):**
- `hush-ts` - Core TypeScript SDK (`@clawdstrike/sdk`)
- `clawdstrike-policy` - Canonical policy engine (TS)
- `clawdstrike-adapter-core` - Base adapter interface
- Framework adapters: `clawdstrike-openclaw`, `clawdstrike-vercel-ai`, `clawdstrike-langchain`, `clawdstrike-claude-code`, `clawdstrike-codex`, `clawdstrike-opencode`

**Python:** `packages/hush-py`

### Core Abstractions

- **Guard** - A security check implementing the `Guard` trait (sync) or `AsyncGuard` trait (async)
- **Policy** - YAML configuration (schema v1.1.0) with `extends` for inheritance
- **Receipt** - Ed25519-signed attestation of decision, policy, and evidence
- **HushEngine** - Facade orchestrating guards and signing

### Built-in Guards (7)

1. `ForbiddenPathGuard` - Blocks sensitive filesystem paths
2. `EgressAllowlistGuard` - Controls network egress by domain
3. `SecretLeakGuard` - Detects secrets in file writes
4. `PatchIntegrityGuard` - Validates patch safety
5. `McpToolGuard` - Restricts MCP tool invocations
6. `PromptInjectionGuard` - Detects prompt injection
7. `JailbreakGuard` - 4-layer detection (heuristic + statistical + ML + optional LLM-judge)

### Policy System

Policies are YAML files with schema version 1.1.0. They support inheritance via `extends`:
- Built-in rulesets: `permissive`, `default`, `strict`, `ai-agent`, `cicd`
- Local file references
- Remote URLs
- Git refs

Location: `rulesets/` directory contains built-in policies.

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
