# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-01

### Added

#### Core Cryptographic Primitives (`hush-core`)

- Ed25519 keypair generation and digital signatures via `ed25519-dalek`
- SHA-256 hashing with optional `0x` prefix
- Keccak-256 hashing for Ethereum-compatible verification
- Merkle tree construction with configurable hash algorithm
- Merkle proof generation and verification
- Canonical JSON serialization for deterministic hashing
- Signed receipt creation with UUID, timestamps, and metadata
- Receipt verification with signer and optional cosigner

#### Security Guards (`clawdstrike`)

- **ForbiddenPathGuard**: Block access to sensitive paths with glob patterns and exceptions
- **EgressAllowlistGuard**: Control network egress via domain allowlist/blocklist with wildcards
- **SecretLeakGuard**: Detect secrets using configurable regex patterns with severity levels
- **PatchIntegrityGuard**: Validate patches with size limits and forbidden pattern detection
- **McpToolGuard**: Restrict MCP tool invocations with allow/block/require_confirmation actions

#### Policy Engine

- YAML-based policy configuration
- Pre-configured rulesets: `default`, `strict`, `ai-agent`, `cicd`
- Policy inheritance and merging
- Runtime policy validation
- `HushEngine` facade for unified guard orchestration

#### CLI (`hush-cli`)

- `hush check` - Check file access, egress, or MCP tool against policy
- `hush verify` - Verify a signed receipt with public key
- `hush keygen` - Generate Ed25519 signing keypair
- `hush policy show` - Display ruleset policy
- `hush policy validate` - Validate a policy YAML file
- `hush policy list` - List available rulesets
- `hush daemon start/stop/status/reload` - Daemon management commands
- `hush completions` - Generate shell completions (bash, zsh, fish, powershell, elvish)

#### Security Daemon (`hushd`)

- HTTP API server on configurable port (default 9876)
- Key-based authentication with scopes (`check`, `read`, `admin`, `*`)
- SQLite-backed audit ledger with structured events
- Server-Sent Events (SSE) endpoint for real-time monitoring
- Policy hot-reload without restart
- Health check and status endpoints
- CORS and request tracing middleware

#### WebAssembly Bindings (`@clawdstrike/wasm`)

- Browser and Node.js compatible WASM module
- `hash_sha256` / `hash_sha256_prefixed` - SHA-256 hashing
- `hash_keccak256` - Keccak-256 hashing
- `verify_ed25519` - Ed25519 signature verification
- `verify_receipt` - Signed receipt verification
- `compute_merkle_root` - Merkle root calculation
- `generate_merkle_proof` / `verify_merkle_proof` - Merkle proof operations
- `get_canonical_json` - Canonical JSON serialization

#### Python SDK (`hush-py`)

- Pure Python implementation of all 5 security guards
- `Policy` class with YAML configuration loading
- `PolicyEngine` for action checking
- `GuardAction` and `GuardContext` for structured requests
- Ed25519 receipt signing and verification
- Optional native bindings via PyO3 (`hush-native`)

#### OpenClaw Integration (`@clawdstrike/openclaw`)

- TypeScript plugin for OpenClaw agent framework
- CLI tool for policy checking in agent workflows
- Bundled rulesets for common use cases
- Plugin manifest (`openclaw.plugin.json`)

#### Distribution

- Homebrew formula (`brew install clawdstrike/tap/hush`)
- Docker image for `hushd` daemon
- npm package `@clawdstrike/wasm` for web verification
- PyPI package `hush` for Python integration

#### Documentation

- mdBook documentation site with:
  - Getting Started guide
  - Concept explanations (Architecture, Guards, Policies)
  - Reference documentation for all guards
  - Recipes for Claude Code, GitHub Actions, self-hosted setups
  - API reference (CLI, Rust, TypeScript)

### Security

- Clippy pedantic and nursery lints enabled
- `unwrap_used` and `expect_used` denied
- Release builds with LTO and single codegen unit
- Dependabot configured for automated security updates

[0.1.0]: https://github.com/backbay-labs/clawdstrike/releases/tag/v0.1.0
