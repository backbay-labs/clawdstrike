# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Agent Identity + Liveness Operations

- Added endpoint/runtime liveness telemetry in `hushd`:
  - `POST /api/v1/agent/heartbeat`
  - `GET /api/v1/agents/status`
  - persistent `endpoint_liveness`, `runtime_liveness`, and `heartbeat_history` control DB tables.
- Added runtime-aware audit ingestion and query controls:
  - `POST /api/v1/audit/batch` for queued replay uploads from agents
  - cursor pagination fields (`next_cursor`, `has_more`)
  - runtime filters (`runtime_agent_id`, `runtime_agent_kind`) for audit queries.
- Added agent-side runtime registration and identity propagation across policy checks for Claude Code, OpenClaw, and MCP integrations.
- Added desktop-agent diagnostics bundle generation (redacted settings, connectivity checks, version matrix, queue state, log tails) with local API route and tray action.
- Added scheduled local API token rotation with grace-window auth fallback and configurable local API security settings.
- Added control-console stream backpressure controls (pause/resume, buffer caps, dropped-event counters, clear buffer) and event-table virtualization for long sessions.
- Added control-console liveness surfacing in Agent Explorer (online/offline heartbeat age) and server-driven runtime filters in Audit Log.

#### Desktop Policy Workbench Rollout (Forensics River)

- Forensics River now supports an integrated Policy Workbench with in-place policy editing, validation, save/revert flow, and canonical `PolicyEvent` test execution.
- Desktop now supports policy bridge commands for `load policy`, `validate policy`, `evaluate test event`, and `save policy` against `hushd`.
- Added desktop rollout controls for the Policy Workbench: `VITE_POLICY_WORKBENCH`/`VITE_ENABLE_POLICY_WORKBENCH` plus local override key `sdr:feature:policy-workbench`.

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

- YAML-based policy configuration (`version: "1.1.0"` for Rust)
- Pre-configured rulesets: `default`, `strict`, `ai-agent`, `cicd`, `permissive`
- Policy inheritance and merging
- Runtime policy validation with fail-closed semantics
- `HushEngine` facade for unified guard orchestration

#### CLI (`hush-cli`)

- `hush check` - Check file access, egress, or MCP tool against policy
- `hush verify` - Verify a signed receipt with public key
- `hush keygen` - Generate Ed25519 signing keypair (hex seed + `.pub`)
- `hush keygen --tpm-seal` - Generate a TPM2-sealed Ed25519 seed (best-effort, requires `tpm2-tools`)
- `hush policy show` - Display ruleset policy
- `hush policy validate` - Validate a policy YAML file
- `hush policy list` - List available rulesets
- `hush guard inspect|validate` - Inspect and validate plugin manifests/load plans
- `hush policy rego compile|eval` - Embedded Rego compile/eval with optional trace output
- `hush policy test generate` - Generate baseline policy test suites from policy + observed events
- `hush policy test` enhancements - `--min-coverage`, `--format` (`text|json|html|junit`), `--output`, `--snapshots`, `--update-snapshots`, `--mutation`
- `hush run` - Best-effort process wrapper (CONNECT proxy egress enforcement + audit log + signed receipt)
- `hush completions` - Generate shell completions (bash, zsh, fish, powershell, elvish)

#### Daemon (`hushd`)

- Central policy enforcement with HTTP API
- Native TLS support (optional)
- Prometheus `/metrics` endpoint
- Canonical PolicyEvent evaluation (`POST /api/v1/eval`)
- SQLite audit ledger with optional at-rest encryption for metadata
- Certification badge PNG rendering (`format=png`, `size=1x|2x`)

#### TypeScript SDK (`@clawdstrike/sdk`, `hush-ts`)

- Crypto: `sha256`, `keccak256`, Ed25519 signing/verification
- Canonical JSON (RFC 8785): `canonicalize`, `canonicalHash`
- Merkle trees and receipt verification
- **JailbreakDetector**: Multi-layer detection with session aggregation
- **OutputSanitizer**: Streaming-compatible sanitization with multiple redaction strategies
- **PromptWatermarker** / **WatermarkExtractor**: Embed and extract signed provenance markers
- Built-in prompt security guards in policy path: `prompt_injection`, `jailbreak_detection`

#### Framework Adapters

- `@clawdstrike/adapter-core` - Framework-agnostic primitives (PolicyEventFactory, SecurityContext, BaseToolInterceptor)
- `@clawdstrike/engine-local` - Node.js bridge to Rust CLI for policy evaluation
- `@clawdstrike/engine-remote` - Node.js engine that evaluates events via `hushd` (`POST /api/v1/eval`)
- `@clawdstrike/vercel-ai` - Middleware and stream guarding for Vercel AI SDK
- `@clawdstrike/langchain` - Tool wrappers and callback handlers for LangChain

### Changed

- Agent identity validation is now strict across check/eval paths: runtime attribution must provide `runtime_agent_id` and `runtime_agent_kind` as a complete pair.
- Agent audit outbox durability now enforces stable event IDs and dedupes by event ID before replay.
- Local API settings now expose hardening controls (`token_rotation_interval_hours`, `token_grace_minutes`, mTLS configuration) through the authenticated settings API.
- Canonical-first policy handling across SDKs: canonical `version: "1.1.0"/"1.2.0"` is primary, with legacy `clawdstrike-v1.0` accepted via translation and deprecation warning.
- WASM plugin runtime now executes via Rust Wasmtime path with capability checks and resource ceilings; TS `executionMode: wasm` uses the CLI bridge path instead of a stub failure.
- `hushd` auth pepper is now instance-bound (resolved at store creation) to eliminate global env race conditions in parallel test/runtime paths.
- Local TS file-dependency workflows are now clean-install safe via `@clawdstrike/adapter-core` `prepare` build and CI smoke coverage.

#### OpenClaw Integration (`@clawdstrike/openclaw`)

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
- Guard reference documentation (all 12 guards + output sanitizer + watermarking)
- Framework integration guides (OpenClaw, Vercel AI, LangChain)
- Architecture and design philosophy docs
- Terminology glossary

### Security

- Fail-closed design: invalid policies reject at load time, errors deny access
- Clippy pedantic lints enabled
- Release builds with LTO
- Dependabot configured for automated security updates
- Added hushd eval-surface regression coverage for path traversal targets, userinfo-spoofed egress host inputs, and private-IP egress attempts.

## [0.1.2] - 2026-02-26

### Added

- **CUA Gateway** — `ComputerUseGuard`, `ShellCommandGuard`, `PathAllowlistGuard`, `RemoteDesktopSideChannelGuard`, `InputInjectionCapabilityGuard` guards; 3 remote-desktop rulesets and `ai-agent-posture` ruleset (#88)
- **Desktop Agent Overhaul** — OTA updates, session/agent tracing, Open Web UI integration, local dashboard MVP (#86)
- **Enterprise Desktop Agent** — hardened agent deployment with productionized OpenClaw ownership (#80)
- **FFI** — `hush-ffi` C ABI crate with C# SDK and Go SDK bindings (#83)
- **OpenClaw Launch Readiness** — security fixes, adapter-core alignment, PR review resolutions (#101)
- **Agent fail-closed POC** — smoke test suite for fail-closed enforcement (#63)
- **Helm confidence pipeline** — EKS smoke/resilience workflows (#65)
- **Policy Workbench** — river-based policy workbench with hushd eval hardening (#64)

### Changed

- Guard count expanded from 7 to 12 with CUA Gateway guards
- `@clawdstrike/` npm scope finalized for all public packages
- Ruleset count expanded from 5 to 9 (added `ai-agent-posture`, `remote-desktop`, `remote-desktop-permissive`, `remote-desktop-strict`)

### Fixed

- `hushd`: replace `expect(format!)` with `unwrap_or_else(panic!)` (#98)
- SDK: `host:port` network parsing and docs refresh (#81)
- SDK: resolve 44 review findings across all packages (#67)
- Helm: all-on profile with bridge/ingress contract fixes (#66)
- CI: Artifact Hub ORAS media type and badge alignment (#73, #74, #75, #78)

### Security

- Removed 22 unused Python imports flagged by CodeQL (#97)
- Updated lockfiles and acknowledged remaining advisories (#96)
- Dependency bumps: minimatch, Cargo workspace, Rust minor (#72, #85, #89, #90)

## [0.1.1] - 2026-02-10

### Added

- **npm scope migration** — packages published under `@clawdstrike/` scope (#59)
- **Helm chart** — Artifact Hub integration, chart icon, ORAS publishing
- **Argo CD** — dev deploy verification workflow (#68)
- **CI** — tag-driven publishing pipeline for Rust and npm

### Fixed

- Release pipeline: protoc installation, npm publish race conditions, crate ordering
- Adapters: bump `adapter-core` minimum to `^0.1.1` and sync lock files

[Unreleased]: https://github.com/backbay-labs/clawdstrike/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/backbay-labs/clawdstrike/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/backbay-labs/clawdstrike/compare/v0.1.0...v0.1.1
