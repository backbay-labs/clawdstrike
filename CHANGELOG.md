# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Initial alpha release. APIs and import paths will change before 1.0.

### Added

#### Core Cryptographic Primitives (`hush-core`)

- Ed25519 keypair generation and digital signatures via `ed25519-dalek`
- SHA-256 and Keccak-256 hashing
- Merkle tree construction with configurable hash algorithm
- Merkle proof generation and verification
- Canonical JSON serialization (RFC 8785) for deterministic cross-language hashing
- Signed receipt creation with UUID, timestamps, and metadata
- Receipt verification with signer and optional cosigner

#### Security Guards (`clawdstrike`)

- **ForbiddenPathGuard**: Block access to sensitive paths with glob patterns and exceptions
- **EgressAllowlistGuard**: Control network egress via domain allowlist/blocklist with wildcards
- **SecretLeakGuard**: Detect secrets using configurable regex patterns with severity levels
- **PatchIntegrityGuard**: Validate patches with size limits and forbidden pattern detection
- **McpToolGuard**: Restrict MCP tool invocations with allow/block/require_confirmation actions
- **PromptInjectionGuard**: Detect prompt injection attempts in untrusted text
- **JailbreakGuard**: 4-layer jailbreak detection (heuristic → statistical → ML → optional LLM-as-judge)

#### Prompt Security Features (`clawdstrike`)

- **Jailbreak Detection**: Multi-layer analysis with 9 attack categories (role_play, authority_confusion, encoding_attack, context_manipulation, instruction_override, system_prompt_extraction, multi_turn_attack, hypothetical_framing, emotional_manipulation)
- **Session Aggregation**: Rolling risk tracking with configurable decay for multi-turn attacks
- **Output Sanitization**: Redact secrets, PII, PHI, PCI data from LLM output with streaming support
- **Redaction Strategies**: full, partial, type_label, hash, none
- **Prompt Watermarking**: Embed signed provenance markers using zero-width, homoglyph, whitespace, or metadata encoding

#### Policy Engine

- YAML-based policy configuration (`version: "1.0.0"` for Rust)
- Pre-configured rulesets: `default`, `strict`, `ai-agent`, `cicd`, `permissive`
- Policy inheritance and merging
- Runtime policy validation with fail-closed semantics
- `HushEngine` facade for unified guard orchestration

#### CLI (`hush-cli`)

- `hush check` - Check file access, egress, or MCP tool against policy
- `hush verify` - Verify a signed receipt with public key
- `hush keygen` - Generate Ed25519 signing keypair
- `hush policy show` - Display ruleset policy
- `hush policy validate` - Validate a policy YAML file
- `hush policy list` - List available rulesets
- `hush completions` - Generate shell completions (bash, zsh, fish, powershell, elvish)

#### TypeScript SDK (`@clawdstrike/sdk`, `hush-ts`)

- Crypto: `sha256`, `keccak256`, Ed25519 signing/verification
- Canonical JSON (RFC 8785): `canonicalize`, `canonicalHash`
- Merkle trees and receipt verification
- **JailbreakDetector**: Multi-layer detection with session aggregation
- **OutputSanitizer**: Streaming-compatible sanitization with multiple redaction strategies
- **PromptWatermarker** / **WatermarkExtractor**: Embed and extract signed provenance markers

#### Framework Adapters

- `@clawdstrike/adapter-core` - Framework-agnostic primitives (PolicyEventFactory, SecurityContext, BaseToolInterceptor)
- `@clawdstrike/hush-cli-engine` - Node.js bridge to Rust CLI for policy evaluation
- `@clawdstrike/vercel-ai` - Middleware and stream guarding for Vercel AI SDK
- `@clawdstrike/langchain` - Tool wrappers and callback handlers for LangChain

#### OpenClaw Integration (`@clawdstrike/clawdstrike-security`)

- OpenClaw plugin with `policy_check` tool for preflight security checks
- CLI commands via `openclaw clawdstrike status|check`
- Tool-boundary enforcement with `tool_result_persist` hook
- Bundled rulesets: `clawdstrike:ai-agent-minimal`, `clawdstrike:ai-agent`
- Separate policy schema (`version: "clawdstrike-v1.0"`) for OpenClaw context

#### Inline Reference Monitors (IRMs)

- **FilesystemIrm**: Intercept file read/write/delete/list operations
- **NetworkIrm**: Intercept TCP/UDP connect, DNS resolve, listen operations
- **ExecutionIrm**: Intercept command execution from sandboxed modules

#### WebAssembly Bindings (`@clawdstrike/wasm`)

- Browser and Node.js compatible WASM module
- SHA-256 and Keccak-256 hashing
- Ed25519 signature verification
- Signed receipt verification
- Merkle root calculation and proof operations
- Canonical JSON serialization

#### Python SDK (`hush-py`)

- Pure Python implementation of security guards
- `Policy` class with YAML configuration loading
- `HushEngine` for action checking
- Ed25519 receipt signing and verification
- Async and sync APIs

#### Documentation

- mdBook documentation site
- Getting Started guides (Rust, TypeScript, Python)
- Guard reference documentation (all 9 guards + output sanitizer + watermarking)
- Framework integration guides (OpenClaw, Vercel AI, LangChain)
- Architecture and design philosophy docs
- Terminology glossary

### Security

- Fail-closed design: invalid policies reject at load time, errors deny access
- Clippy pedantic lints enabled
- Release builds with LTO
- Dependabot configured for automated security updates

[Unreleased]: https://github.com/backbay-labs/clawdstrike/compare/main...HEAD
