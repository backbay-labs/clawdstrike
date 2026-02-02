# Clawdstrike Repo Deep Dive (v3)

Goal: a real, content-driven deep dive of the Rust workspace (code + docs drift), with concrete refactor options.

Constraints:
- Network access is unavailable in this environment (DNS fails).
- `cargo test` / `cargo clippy` cannot run because crates.io index cannot be fetched.
- This review is therefore static (source-based) plus design reasoning.

This document is intentionally dense and actionable. It includes:
- Architecture summary and invariants
- Public API inventory (heuristic extraction)
- File-by-file notes and hotspots
- Doc/code mismatch audit (mdBook + README vs current implementation)
- Concrete refactor proposals with tradeoffs

## 0. Workspace map

### hush-core (crates/hush-core)
- Dependencies: chrono, ed25519-dalek, hex, rand, serde, serde_json, sha2, sha3, thiserror, uuid
- Dev-dependencies: proptest, tokio
- Rust files: 0

### hush-proxy (crates/hush-proxy)
- Dependencies: serde, thiserror, tokio
- Dev-dependencies: tokio
- Rust files: 0

### clawdstrike (crates/clawdstrike)
- Dependencies: async-trait, chrono, glob, globset, hush-core, hush-proxy, ipnet, regex, serde, serde_json, serde_yaml, thiserror, tokio, tracing, uuid
- Dev-dependencies: proptest, tokio, tokio-test
- Rust files: 0

### hush-cli (crates/hush-cli)
- Dependencies: anyhow, chrono, clap, clap_complete, hex, hush-core, clawdstrike, rand, reqwest, serde_json, sha2, tokio, tracing, tracing-subscriber
- Dev-dependencies: (none)
- Rust files: 0

### hushd (crates/hushd)
- Dependencies: anyhow, axum, chrono, clap, dirs, futures, hex, hush-core, hush-proxy, clawdstrike, reqwest, rusqlite, serde, serde_json, serde_yaml, sha2, thiserror, tokio, tokio-stream, toml, tower, tower-http, tracing, tracing-subscriber, uuid
- Dev-dependencies: reqwest
- Rust files: 0

### hush-wasm (crates/hush-wasm)
- Dependencies: console_error_panic_hook, getrandom, hex, hush-core, js-sys, serde, serde-wasm-bindgen, serde_json, wasm-bindgen, web-sys
- Dev-dependencies: wasm-bindgen-test
- Rust files: 0

### hush-native (packages/hush-py/hush-native)
- Dependencies: hex, hush-core, pyo3, serde_json
- Dev-dependencies: (none)
- Rust files: 0

## 1. Architectural intent (as implemented today)

### 1.1 Components
- `hush-core`: cryptographic primitives (hashing, signing, canonical JSON, Merkle trees, receipt model).
- `hush-proxy`: DNS/SNI extraction + domain policy evaluation (allow/block/log).
- `clawdstrike`: guard framework + policy config + engine orchestration + receipt emission.
- `hush-cli`: a small CLI that calls into `clawdstrike` and `hush-core`.
- `hushd`: a daemon skeleton that will eventually expose a server API.

### 1.2 Core invariants you should treat as “security boundaries”
- Canonical JSON: signature correctness depends on canonicalization being stable and spec-aligned.
- Receipt schema: any consumer verifying receipts must share the same schema and canonicalization rules.
- Guard correctness: “silent misconfiguration” is a security bug (e.g., invalid regex dropped).
- Egress matching semantics: operators will assume wildcard/glob semantics; mismatch is a policy bypass risk.

### 1.3 Engine flow (happy path)
- A caller constructs `HushEngine` with a `Policy` (direct or via `RuleSet`).
- Caller submits a `GuardAction` (file access/write, egress, MCP tool, patch, shell).
- Engine iterates guards, recording violations, and returns a `GuardResult`.
- Engine can then produce a `Receipt` / `SignedReceipt` summarizing the session.

## 2. Public API inventory (heuristic)

Notes:
- This is a regex-based inventory (not a full Rust parser).
- It is meant to help you see public surface area and drift risks.

### crates/hush-cli/src/tests.rs
- Module doc: CLI unit tests for hush command-line interface  Tests cover: - Command parsing for all subcommands - Argument validation and defaults - Help and version flags - Invalid command han...
- tests: #[test]=24  #[tokio::test]=0

### crates/hush-core/src/canonical.rs
- Module doc: Canonical JSON for hashing/signatures (RFC 8785 JCS)  Clawdstrike needs byte-for-byte identical canonical JSON across Rust/Python/TS. We adopt RFC 8785 (JCS) and match ECMAScript `JSO...
- pub fn: canonicalize
- tests: #[test]=7  #[tokio::test]=0

### crates/hush-core/src/error.rs
- Module doc: Error types for hush-core operations
- pub enum: Error
- pub type: Result

### crates/hush-core/src/hashing.rs
- Module doc: Cryptographic hashing (SHA-256 and Keccak-256)
- pub struct: Hash
- pub fn: as_bytes, concat_hashes, deserialize, from_bytes, from_hex, keccak256, keccak256_hex, serialize, sha256, sha256_hex, to_hex, to_hex_prefixed, zero
- tests: #[test]=6  #[tokio::test]=0

### crates/hush-core/src/merkle.rs
- Module doc: RFC 6962-compatible Merkle tree (Certificate Transparency style).  This tree is required for transparency log checkpoints: - `LeafHash(leaf_bytes) = SHA256(0x00 || leaf_bytes)` - `...
- pub struct: MerkleProof, MerkleTree
- pub fn: compute_root, compute_root_from_hash, from_hashes, from_leaves, inclusion_proof, leaf_count, leaf_hash, node_hash, root, verify, verify_hash
- tests: #[test]=7  #[tokio::test]=0

### crates/hush-core/src/receipt.rs
- Module doc: Receipt types and signing for attestation
- pub struct: Provenance, PublicKeySet, Receipt, Signatures, SignedReceipt, Verdict, VerificationResult, ViolationRef
- pub fn: add_cosigner, fail, fail_with_gate, from_json, hash_keccak256, hash_sha256, new, pass, pass_with_gate, sign, to_canonical_json, to_json, verify, with_cosigner, with_id, with_metadata, with_provenance
- tests: #[test]=8  #[tokio::test]=0

### crates/hush-core/src/signing.rs
- Module doc: Ed25519 signing and verification
- pub struct: Keypair, PublicKey, Signature
- pub fn: as_bytes, deserialize, from_bytes, from_hex, from_seed, generate, public_key, serialize, sign, to_bytes, to_hex, to_hex_prefixed, verify, verify_signature
- tests: #[test]=6  #[tokio::test]=0

### crates/hush-core/tests/proptest_crypto.rs
- Module doc: Property-based tests for cryptographic primitives
- tests: #[test]=10  #[tokio::test]=0

### crates/hush-core/tests/proptest_merkle.rs
- Module doc: Property-based tests for Merkle tree operations
- tests: #[test]=7  #[tokio::test]=0

### crates/hush-proxy/src/dns.rs
- Module doc: DNS packet parsing and domain extraction  Provides utilities for extracting domain names from DNS queries for egress filtering.
- pub fn: domain_matches, extract_domain_from_query
- tests: #[test]=3  #[tokio::test]=0

### crates/hush-proxy/src/error.rs
- Module doc: Error types for hush-proxy
- pub enum: Error
- pub type: Result

### crates/hush-proxy/src/policy.rs
- Module doc: Egress policy enforcement  Provides domain allowlist/blocklist policy evaluation.
- pub struct: DomainPolicy, PolicyResult
- pub enum: PolicyAction
- pub fn: allow, block, evaluate, evaluate_detailed, is_allowed, new, permissive
- tests: #[test]=6  #[tokio::test]=0

### crates/hush-proxy/src/sni.rs
- Module doc: TLS SNI (Server Name Indication) extraction  Provides utilities for extracting the server name from TLS ClientHello messages for HTTPS egress filtering.
- pub fn: extract_sni
- tests: #[test]=8  #[tokio::test]=0

### crates/hush-wasm/src/lib.rs
- Module doc: WebAssembly bindings for hush-core cryptographic primitives  This crate provides browser-side verification of clawdstrike attestations.
- pub fn: compute_merkle_root, generate_merkle_proof, get_canonical_json, hash_keccak256, hash_receipt, hash_sha256, hash_sha256_prefixed, init, verify_ed25519, verify_merkle_proof, verify_receipt, version

### crates/hush-wasm/tests/integration.rs
- Module doc: Integration tests for hush-wasm These run as regular Rust tests (not WASM)
- tests: #[test]=4  #[tokio::test]=0

### crates/clawdstrike/src/engine.rs
- Module doc: HushEngine - Main entry point for security enforcement
- pub struct: EngineStats, HushEngine
- pub fn: check_action, check_egress, check_file_access, check_file_write, check_mcp_tool, check_patch, check_shell, create_receipt, create_signed_receipt, from_ruleset, new, policy_hash, reset, stats, with_generated_keypair, with_keypair, with_policy
- tests: #[test]=0  #[tokio::test]=8

### crates/clawdstrike/src/error.rs
- Module doc: Error types for clawdstrike
- pub enum: Error
- pub type: Result

### crates/clawdstrike/src/guards/egress_allowlist.rs
- Module doc: Egress allowlist guard - controls network egress
- pub struct: EgressAllowlistConfig, EgressAllowlistGuard
- pub fn: is_allowed, new, with_config
- tests: #[test]=2  #[tokio::test]=1

### crates/clawdstrike/src/guards/forbidden_path.rs
- Module doc: Forbidden path guard - blocks access to sensitive paths
- pub struct: ForbiddenPathConfig, ForbiddenPathGuard
- pub fn: is_forbidden, new, with_config
- tests: #[test]=2  #[tokio::test]=1

### crates/clawdstrike/src/guards/mcp_tool.rs
- Module doc: MCP tool guard - restricts tool invocations
- pub struct: McpToolConfig, McpToolGuard
- pub enum: ToolDecision
- pub fn: is_allowed, new, with_config
- tests: #[test]=4  #[tokio::test]=2

### crates/clawdstrike/src/guards/mod.rs
- Module doc: Security guards for AI agent execution.  Guards implement async checks that can allow, block, or log actions.  # Example  ```rust use clawdstrike::guards::{ForbiddenPathGuard, GuardAc...
- pub struct: GuardContext, GuardResult
- pub enum: GuardAction, Severity
- pub trait: Guard
- pub fn: allow, block, new, warn, with_agent_id, with_cwd, with_details, with_session_id

### crates/clawdstrike/src/guards/patch_integrity.rs
- Module doc: Patch integrity guard - validates patch safety
- pub struct: ForbiddenMatch, PatchAnalysis, PatchIntegrityConfig, PatchIntegrityGuard
- pub fn: analyze, is_safe, new, with_config
- tests: #[test]=3  #[tokio::test]=1

### crates/clawdstrike/src/guards/secret_leak.rs
- Module doc: Secret leak guard - detects potential secret exposure
- pub struct: SecretLeakConfig, SecretLeakGuard, SecretMatch, SecretPattern
- pub fn: new, scan, should_skip_path, with_config
- tests: #[test]=6  #[tokio::test]=1

### crates/clawdstrike/src/irm/exec.rs
- Module doc: Execution Inline Reference Monitor  Enforces execution policy (allowed commands + denied patterns) for command execution.
- pub struct: ExecutionIrm
- pub fn: new
- tests: #[test]=4  #[tokio::test]=6

### crates/clawdstrike/src/irm/fs.rs
- Module doc: Filesystem Inline Reference Monitor  Monitors filesystem operations and enforces path-based access control.
- pub struct: FilesystemIrm
- pub fn: new
- tests: #[test]=5  #[tokio::test]=4

### crates/clawdstrike/src/irm/mod.rs
- Module doc: Inline Reference Monitors (IRM)  IRMs intercept host calls from sandboxed modules and enforce policy at runtime.  # Architecture  ```text ┌─────────────────────────────────────────...
- pub struct: HostCall, HostCallMetadata, IrmEvent, IrmRouter
- pub enum: Decision, EventType, ExecOperation, FsOperation, NetOperation
- pub trait: Monitor
- pub fn: audit, create_event, deny, evaluate, from_function, is_allowed, new, now, policy, with_metadata, with_monitors
- tests: #[test]=9  #[tokio::test]=5

### crates/clawdstrike/src/irm/net.rs
- Module doc: Network Inline Reference Monitor  Monitors network operations and enforces egress control.
- pub struct: NetworkIrm
- pub fn: new
- tests: #[test]=8  #[tokio::test]=3

### crates/clawdstrike/src/irm/sandbox.rs
- Module doc: Sandbox orchestration for IRM  Provides a unified interface for managing all IRMs in a session.
- pub struct: Sandbox, SandboxConfig, SandboxStats
- pub fn: check_call, check_exec, check_fs, check_net, cleanup, events, init, new, policy, run_id, stats, with_config, with_monitors
- tests: #[test]=0  #[tokio::test]=9

### crates/clawdstrike/src/policy.rs
- Module doc: Policy configuration and rulesets
- pub struct: GuardConfigs, Policy, PolicyGuards, PolicySettings, RuleSet
- pub fn: by_name, create_guards, default_ruleset, from_yaml, from_yaml_file, new, permissive, strict, to_yaml
- tests: #[test]=5  #[tokio::test]=0

### crates/clawdstrike/tests/proptest_guards.rs
- Module doc: Property-based tests for security guards
- tests: #[test]=10  #[tokio::test]=0

### crates/hushd/src/api/audit.rs
- Module doc: Audit log endpoints
- pub struct: AuditQuery, AuditResponse, AuditStatsResponse
- pub fn: audit_stats, query_audit

### crates/hushd/src/api/check.rs
- Module doc: Action checking endpoint
- pub struct: CheckRequest, CheckResponse
- pub fn: check_action

### crates/hushd/src/api/events.rs
- Module doc: Server-Sent Events (SSE) streaming endpoint
- pub fn: stream_events

### crates/hushd/src/api/health.rs
- Module doc: Health check endpoint
- pub struct: HealthResponse
- pub fn: health

### crates/hushd/src/api/mod.rs
- Module doc: HTTP API for hushd daemon
- pub fn: create_router

### crates/hushd/src/api/policy.rs
- Module doc: Policy management endpoints
- pub struct: PolicyResponse, UpdatePolicyRequest, UpdatePolicyResponse
- pub fn: get_policy, reload_policy, update_policy

### crates/hushd/src/audit/mod.rs
- Module doc: SQLite-backed audit ledger for security events
- pub struct: AuditEvent, AuditFilter, AuditLedger, SessionStats
- pub enum: AuditError, ExportFormat
- pub type: Result
- pub fn: count, export, from_guard_result, in_memory, new, query, record, session_end, session_start, with_max_entries
- tests: #[test]=4  #[tokio::test]=0

### crates/hushd/src/audit/schema.rs
- Module doc: Database schema for audit ledger
- pub const: COUNT_EVENTS, CREATE_TABLES, DELETE_OLD_EVENTS, INSERT_EVENT, SELECT_EVENTS

### crates/hushd/src/auth/middleware.rs
- Module doc: Authentication middleware for axum
- pub struct: AuthenticatedKey
- pub fn: require_auth, require_scope, scope_layer
- tests: #[test]=6  #[tokio::test]=0

### crates/hushd/src/auth/store.rs
- Module doc: API key storage and validation
- pub struct: AuthStore
- pub enum: AuthError
- pub fn: add_key, hash_key, key_count, list_keys, new, remove_key, validate_key
- tests: #[test]=2  #[tokio::test]=5

### crates/hushd/src/auth/types.rs
- Module doc: API key types and scope definitions
- pub struct: ApiKey
- pub enum: Scope
- pub fn: as_str, from_str, has_scope, is_expired
- tests: #[test]=7  #[tokio::test]=0

### crates/hushd/src/config.rs
- Module doc: Configuration for hushd daemon
- pub struct: ApiKeyConfig, AuthConfig, Config, TlsConfig
- pub fn: from_file, load_auth_store, load_default, tracing_level
- tests: #[test]=5  #[tokio::test]=2

### crates/hushd/src/state.rs
- Module doc: Shared application state for the daemon
- pub struct: AppState, DaemonEvent
- pub fn: auth_enabled, broadcast, new, reload_policy, uptime_secs

### crates/hushd/tests/integration.rs
- Module doc: Integration tests for hushd HTTP API
- tests: #[test]=2  #[tokio::test]=13

## 3. High-impact issues (with evidence and concrete fixes)

### 3.1 Example/API drift: `examples/rust/basic-verification` is from a different world
- The example references `verify_receipt`, `VerificationResult`, and receipt fields that do not exist in the current `hush-core` receipt model.
- Fix options:
  - Option A (preferred): update the example to verify `SignedReceipt` using `hush_core::receipt::PublicKeySet` and `SignedReceipt::verify`.
  - Option B: reintroduce a legacy receipt schema + verifier behind a feature flag and move the example under `examples/legacy/`.
  - Option C: delete or clearly mark the example as outdated to avoid trust erosion.

### 3.2 Ruleset drift: YAML rulesets exist but `RuleSet::by_name` is hard-coded
- Evidence: `crates/clawdstrike/src/policy.rs` has a `by_name` match that only supports `default|strict|permissive`.
- But `rulesets/ai-agent.yaml` and `rulesets/cicd.yaml` exist (and README mentions them).
- Fix options:
  - Option A (file-driven): implement a `RuleSetRegistry` that loads `rulesets/*.yaml` at runtime and exposes `by_name` and CLI `policy list/show` against that registry.
  - Option B (compile-time embed): embed YAML rulesets as `include_str!()` constants and keep `by_name` as a match, but include all shipped rulesets and keep docs in sync.
  - Option C (hard-coded only): delete `rulesets/*.yaml` and rewrite docs/README to reflect only programmatic rulesets.

### 3.3 Silent weakening: invalid regex/glob patterns are dropped via `filter_map`
- Evidence:
  - ForbiddenPathGuard: `filter_map(|p| Pattern::new(p).ok())`
  - PatchIntegrityGuard: `filter_map(|p| Regex::new(p).ok())`
  - SecretLeakGuard: `Regex::new(...).ok().map(...)`
- Why this is serious: a typo in policy can silently disable a protection.
- Fix options:
  - Return `Result<Self>` from `with_config` and surface an explicit config error containing the invalid pattern(s).
  - Add `Policy::validate()` which compiles all patterns and returns a structured error report.

### 3.4 Warning semantics are effectively “best effort” (warnings can be lost)
- Evidence: engine’s “keep most severe result” logic only compares severity for blocking results.
- Example failure mode: if guard A returns allow and guard B returns warn, the final result can remain allow.
- Fix options:
  - Return a composite `GuardReport` containing per-guard results, plus a computed overall verdict.
  - Or: compute max severity regardless of allowed/block and prefer warning when no block exists.

### 3.5 Docs drift: mdBook documents a different product surface than the code
- `docs/src/reference/policy-schema.md` describes a schema with `extends`, `egress/filesystem/execution/tools`, resource limits, and `on_violation` actions.
- Current Rust `Policy` is a different shape: `guards.<guard_name>` configs and `settings`.
- `docs/src/reference/api/cli.md` describes `hush run` and `hush policy lint`, which are not present in `crates/hush-cli`.
- Recommendation: decide whether docs are aspirational (future roadmap) or contract (current behavior) and label them accordingly.

## 4. Medium-impact issues (correctness, ergonomics, maintainability)

### 4.1 Stringly-typed config actions
- `EgressAllowlistConfig.default_action` and `McpToolConfig.default_action` are strings.
- Prefer typed enums with serde rename to prevent silent typos.

### 4.2 Unused dependencies (signal of drift)
- `hush-core`: `uuid` appears unused.
- `clawdstrike`: `ipnet` and `globset` appear unused.
- `hush-proxy`: `tokio` appears unused.
- Recommendation: remove unused deps or add the missing features they were intended for (CIDR support, richer globbing, async IO).

### 4.3 Domain matching semantics are narrower than documentation implies
- `domain_matches` only supports `*.` prefix patterns.
- Docs mention more complex wildcards like `*.*.example.com` which will not work today.

## 5. Testing posture (what exists vs what is missing)

What exists:
- There are solid unit tests for hashing, signing, canonical JSON, Merkle trees, receipt signing/verification, and each guard.

What is missing (high value):
- Canonical JSON: official RFC 8785 test vectors (especially float/edge cases) and cross-language compatibility tests.
- DNS/SNI parsing: property tests or fuzz tests for malformed inputs (parsers are security boundaries).
- Ruleset loading: tests ensuring CLI lists the same rulesets as the engine and YAML schema is validated.
- Warning aggregation: tests for expected semantics when warnings occur but no blocks occur.

## 6. Concrete refactor proposals (opinionated)

### Proposal A: treat policy parsing as a security boundary
- Add `Policy::validate()` that compiles all regex/glob patterns and returns a structured error report.
- Make `from_yaml_file` call validate by default (or provide `from_yaml_file_unchecked`).
- Add CLI `hush policy validate` to run validation and show errors with pattern locations.

### Proposal B: unify “rulesets” into one authoritative mechanism
- Make YAML rulesets the source of truth, and ensure `RuleSet::by_name` loads them.
- Optionally embed them at compile time to avoid runtime file dependencies.
- Update README + mdBook to match the chosen mechanism.

### Proposal C: introduce an engine-level report type
- Replace `GuardResult` return value with `GuardReport { overall: GuardDecision, results: Vec<GuardResult>, stats }`.
- This makes warnings first-class and makes debugging far easier.

### Proposal D: align docs with implementation (or label docs as roadmap)
- If mdBook describes the target system, add a banner: “Roadmap / Not yet implemented” and link to tracking issues.
- If mdBook is meant to be accurate now, implement missing CLI and policy schema or rewrite docs.

## Bibliography (stable references)
- Rust API Guidelines: https://rust-lang.github.io/api-guidelines/
- Rustdoc Book: https://doc.rust-lang.org/stable/rustdoc/
- Clippy Book: https://doc.rust-lang.org/stable/clippy/
- Cargo features: https://doc.rust-lang.org/cargo/reference/features.html
- RFC 8785 (JCS): https://www.rfc-editor.org/rfc/rfc8785
- RFC 6962 (Merkle trees): https://www.rfc-editor.org/rfc/rfc6962
- ed25519-dalek: https://docs.rs/ed25519-dalek/

## Appendix A: Doc drift evidence (mdBook vs current code)

This is a raw inventory of places where docs describe features/schemas/commands not present in the Rust implementation.
Use it to drive either a docs rewrite or an implementation roadmap.

### A.1 CLI commands referenced in docs
- Pattern: `extends:`
  - docs/src/reference/rulesets/strict.md:20:extends: clawdstrike:default
  - docs/src/reference/rulesets/strict.md:137:extends: clawdstrike:strict
  - docs/src/reference/rulesets/strict.md:157:extends: clawdstrike:strict
  - docs/src/reference/rulesets/README.md:27:extends: clawdstrike:default
  - docs/src/reference/rulesets/README.md:73:extends: file://./company-ruleset.yaml
  - docs/src/reference/rulesets/README.md:81:extends: https://policies.company.com/standard.yaml
  - docs/src/reference/rulesets/README.md:87:extends: git://github.com/company/policies.git#main:security/base.yaml
  - docs/src/reference/rulesets/ai-agent.md:20:extends: clawdstrike:default
  - docs/src/reference/rulesets/ai-agent.md:188:extends: clawdstrike:ai-agent
  - docs/src/reference/rulesets/ai-agent.md:208:extends: clawdstrike:ai-agent
  - docs/src/reference/rulesets/default.md:144:extends: clawdstrike:default
  - docs/src/reference/policy-schema.md:17:extends: clawdstrike:default  # Optional base policy
  - docs/src/concepts/policies.md:11:extends: clawdstrike:default     # Optional base policy
  - docs/src/concepts/policies.md:41:extends: clawdstrike:ai-agent
  - docs/src/concepts/policies.md:70:extends: base
  - docs/src/concepts/policies.md:176:1. **Start with a base policy** - Use `extends:` instead of from scratch
  - docs/src/concepts/architecture.md:58:- **Inheritance** - Extend built-in policies with `extends:`
  - docs/src/guides/policy-inheritance.md:19:extends: clawdstrike:ai-agent
  - docs/src/guides/policy-inheritance.md:48:extends: base
  - docs/src/guides/policy-inheritance.md:68:extends: base
  - docs/src/guides/policy-inheritance.md:85:extends: base
  - docs/src/guides/policy-inheritance.md:106:extends: clawdstrike:strict
  - docs/src/guides/policy-inheritance.md:114:extends: file://company-base.yaml
  - docs/src/guides/policy-inheritance.md:122:extends: file://team-policy.yaml
  - docs/src/guides/policy-inheritance.md:134:extends: clawdstrike:default
  - docs/src/guides/policy-inheritance.md:145:extends: clawdstrike:default
  - docs/src/guides/policy-inheritance.md:158:extends: clawdstrike:default
  - docs/src/guides/policy-inheritance.md:169:extends: https://policies.company.com/base-policy.yaml
  - docs/src/guides/policy-inheritance.md:175:extends: git://github.com/company/policies.git#main:security/base.yaml
  - docs/src/guides/policy-inheritance.md:182:extends: file://./base-policy.yaml
  - docs/src/guides/policy-inheritance.md:185:extends: file:///etc/hush/company-policy.yaml
  - docs/src/guides/policy-inheritance.md:223:extends: clawdstrike:ai-agent  # Not from scratch
  - docs/src/guides/policy-inheritance.md:232:extends: clawdstrike:ai-agent
  - docs/src/guides/policy-inheritance.md:256:extends: clawdstrike:ai-agent
  - docs/src/guides/policy-inheritance.md:272:extends: clawdstrike:strict
  - docs/src/guides/policy-inheritance.md:286:extends: file://./team-policy.yaml
  - docs/src/guides/openclaw-integration.md:190:extends: clawdstrike:ai-agent
  - docs/src/recipes/github-actions.md:17:extends: clawdstrike:cicd
  - docs/src/recipes/self-hosted.md:206:    extends: clawdstrike:strict
  - docs/src/recipes/claude-code.md:27:extends: clawdstrike:ai-agent
  - docs/src/recipes/claude-code.md:58:extends: clawdstrike:ai-agent
  - docs/src/getting-started/quick-start.md:20:extends: clawdstrike:ai-agent-minimal
  - docs/src/getting-started/first-policy.md:31:extends: clawdstrike:ai-agent-minimal
  - docs/src/getting-started/first-policy.md:184:extends: clawdstrike:ai-agent
  - docs/src/README.md:21:extends: clawdstrike:ai-agent
- Pattern: `on_violation:`
  - docs/src/reference/rulesets/strict.md:101:on_violation: isolate
  - docs/src/reference/rulesets/strict.md:167:on_violation: cancel  # Fail fast
  - docs/src/reference/rulesets/README.md:67:on_violation: cancel
  - docs/src/reference/rulesets/ai-agent.md:102:on_violation: escalate
  - docs/src/reference/rulesets/ai-agent.md:148:on_violation: escalate
  - docs/src/reference/rulesets/default.md:123:on_violation: cancel
  - docs/src/reference/policy-schema.md:88:on_violation: cancel  # cancel | warn | isolate | escalate
  - docs/src/concepts/policies.md:31:on_violation: cancel           # What to do on violation
  - docs/src/guides/policy-inheritance.md:291:on_violation: cancel  # Fail fast
  - docs/src/recipes/github-actions.md:34:on_violation: cancel
  - docs/src/recipes/github-actions.md:172:on_violation: cancel
  - docs/src/recipes/claude-code.md:97:on_violation: cancel
  - docs/src/getting-started/first-policy.md:22:on_violation: cancel
  - docs/src/getting-started/first-policy.md:126:on_violation: cancel  # Options: cancel, warn, isolate, escalate
  - docs/src/getting-started/first-policy.md:207:on_violation: cancel
- Pattern: `CLAWDSTRIKE_MODE=`
  - docs/src/concepts/policies.md:133:CLAWDSTRIKE_MODE=advisory hush run --policy policy.yaml -- command
  - docs/src/guides/openclaw-integration.md:149:CLAWDSTRIKE_MODE=advisory openclaw start
  - docs/src/guides/openclaw-integration.md:233:CLAWDSTRIKE_MODE=advisory openclaw start

### A.2 Policy schema mismatch summary

- Docs policy schema includes: `extends`, `egress/filesystem/execution/tools`, `limits`, `on_violation`.
- Rust policy schema includes: `guards.<guard_name>` configs and `settings`.
- Decide contract: implement docs schema or rewrite docs to match Rust.

## Appendix B: Known build/test blockers in restricted environments

- `cargo test --workspace` fails because crates.io cannot be reached (DNS/network restriction).
- If offline builds matter, add a vendoring strategy (`cargo vendor`) and document it.

## Appendix C: `unwrap`/`expect` inventory (quality signal)

This is not “bad” by itself (many are in tests), but it helps locate where library code might panic.
- crates/hushd/src/main.rs:154:                .expect("Failed to install Ctrl+C handler");
- crates/hushd/src/main.rs:160:                .expect("Failed to install SIGTERM handler")
- crates/hushd/tests/integration.rs:14:        .expect("Failed to connect to daemon");
- crates/hushd/tests/integration.rs:18:    let health: serde_json::Value = resp.json().await.unwrap();
- crates/hushd/tests/integration.rs:36:        .expect("Failed to connect to daemon");
- crates/hushd/tests/integration.rs:40:    let result: serde_json::Value = resp.json().await.unwrap();
- crates/hushd/tests/integration.rs:56:        .expect("Failed to connect to daemon");
- crates/hushd/tests/integration.rs:60:    let result: serde_json::Value = resp.json().await.unwrap();
- crates/hushd/tests/integration.rs:76:        .expect("Failed to connect to daemon");
- crates/hushd/tests/integration.rs:80:    let result: serde_json::Value = resp.json().await.unwrap();
- crates/hushd/tests/integration.rs:92:        .expect("Failed to connect to daemon");
- crates/hushd/tests/integration.rs:96:    let policy: serde_json::Value = resp.json().await.unwrap();
- crates/hushd/tests/integration.rs:116:        .expect("Failed to check action");
- crates/hushd/tests/integration.rs:123:        .expect("Failed to query audit");
- crates/hushd/tests/integration.rs:127:    let audit: serde_json::Value = resp.json().await.unwrap();
- crates/hushd/tests/integration.rs:140:        .expect("Failed to get audit stats");
- crates/hushd/tests/integration.rs:144:    let stats: serde_json::Value = resp.json().await.unwrap();
- crates/hushd/tests/integration.rs:160:        .expect("Failed to connect to events");
- crates/hushd/tests/integration.rs:201:        .expect("Failed to connect to daemon");
- crates/hushd/tests/integration.rs:210:    let api_key = std::env::var("HUSHD_API_KEY").expect("HUSHD_API_KEY not set");
- crates/hushd/tests/integration.rs:221:        .expect("Failed to connect to daemon");
- crates/hushd/tests/integration.rs:240:        .expect("Failed to connect to daemon");
- crates/hushd/tests/integration.rs:250:    let api_key = std::env::var("HUSHD_API_KEY").expect("HUSHD_API_KEY not set");
- crates/hushd/tests/integration.rs:257:        .expect("Failed to connect to daemon");
- crates/hushd/tests/integration.rs:276:        .expect("Failed to connect to daemon");
- crates/clawdstrike/src/engine.rs:311:            .unwrap();
- crates/clawdstrike/src/engine.rs:318:            .unwrap();
- crates/clawdstrike/src/engine.rs:331:            .unwrap();
- crates/clawdstrike/src/engine.rs:338:            .unwrap();
- crates/clawdstrike/src/engine.rs:351:            .unwrap();
- crates/clawdstrike/src/engine.rs:367:            .unwrap();
- crates/clawdstrike/src/engine.rs:370:        let receipt = engine.create_receipt(content_hash).await.unwrap();
- crates/clawdstrike/src/engine.rs:384:            .unwrap();
- crates/clawdstrike/src/engine.rs:387:        let signed = engine.create_signed_receipt(content_hash).await.unwrap();
- crates/clawdstrike/src/engine.rs:394:        let engine = HushEngine::from_ruleset("strict").unwrap();
- crates/clawdstrike/src/engine.rs:401:            .unwrap();
- crates/clawdstrike/src/engine.rs:413:            .unwrap();
- crates/hushd/src/config.rs:256:        let config: Config = toml::from_str(toml).unwrap();
- crates/hushd/src/config.rs:302:        let config: Config = toml::from_str(toml).unwrap();
- crates/hushd/src/config.rs:324:        let config: Config = toml::from_str(toml).unwrap();
- crates/hushd/src/config.rs:330:        let key = result.unwrap();
- crates/hushd/src/config.rs:349:        let config: Config = toml::from_str(toml).unwrap();
- crates/hushd/src/config.rs:352:        let key = store.validate_key("my-key").await.unwrap();
- crates/clawdstrike/src/lib.rs:38://! let policy = Policy::from_yaml(yaml).unwrap();
- crates/hush-cli/src/tests.rs:351:        let script = String::from_utf8(output).expect("valid UTF-8");
- crates/hush-cli/src/tests.rs:363:        let script = String::from_utf8(output).expect("valid UTF-8");
- crates/hush-cli/src/tests.rs:374:        let script = String::from_utf8(output).expect("valid UTF-8");
- crates/hushd/src/audit/mod.rs:213:        let conn = self.conn.lock().unwrap();
- crates/hushd/src/audit/mod.rs:246:        let conn = self.conn.lock().unwrap();
- crates/hushd/src/audit/mod.rs:321:        let conn = self.conn.lock().unwrap();
- crates/hushd/src/audit/mod.rs:372:        let ledger = AuditLedger::in_memory().unwrap();
- crates/hushd/src/audit/mod.rs:389:        ledger.record(&event).unwrap();
- crates/hushd/src/audit/mod.rs:392:        let events = ledger.query(&filter).unwrap();
- crates/hushd/src/audit/mod.rs:401:        let ledger = AuditLedger::in_memory().unwrap();
- crates/hushd/src/audit/mod.rs:419:            ledger.record(&event).unwrap();
- crates/hushd/src/audit/mod.rs:427:        let events = ledger.query(&filter).unwrap();
- crates/hushd/src/audit/mod.rs:435:        let events = ledger.query(&filter).unwrap();
- crates/hushd/src/audit/mod.rs:441:        let ledger = AuditLedger::in_memory().unwrap();
- crates/hushd/src/audit/mod.rs:457:        ledger.record(&event).unwrap();
- crates/hushd/src/audit/mod.rs:460:        let json = ledger.export(&filter, ExportFormat::Json).unwrap();
- crates/hushd/src/audit/mod.rs:462:        let parsed: Vec<AuditEvent> = serde_json::from_slice(&json).unwrap();
- crates/hushd/src/audit/mod.rs:469:        let ledger = AuditLedger::in_memory().unwrap();
- crates/hushd/src/audit/mod.rs:470:        assert_eq!(ledger.count().unwrap(), 0);
- crates/hushd/src/audit/mod.rs:487:            ledger.record(&event).unwrap();
- crates/hushd/src/audit/mod.rs:490:        assert_eq!(ledger.count().unwrap(), 3);
- crates/hushd/src/auth/middleware.rs:125:            .unwrap()
- crates/hushd/src/auth/middleware.rs:129:        Request::builder().body(Body::empty()).unwrap()
- crates/hush-core/src/receipt.rs:335:        let signed = SignedReceipt::sign(receipt, &keypair).unwrap();
- crates/hush-core/src/receipt.rs:350:        let mut signed = SignedReceipt::sign(receipt, &signer_kp).unwrap();
- crates/hush-core/src/receipt.rs:351:        signed.add_cosigner(&cosigner_kp).unwrap();
- crates/hush-core/src/receipt.rs:369:        let signed = SignedReceipt::sign(receipt, &signer_kp).unwrap();
- crates/hush-core/src/receipt.rs:384:        let json1 = receipt.to_canonical_json().unwrap();
- crates/hush-core/src/receipt.rs:385:        let json2 = receipt.to_canonical_json().unwrap();
- crates/hush-core/src/receipt.rs:392:        let json = receipt.to_canonical_json().unwrap();
- crates/hush-core/src/receipt.rs:396:        let content_pos = json.find("\"content_hash\"").unwrap();
- crates/hush-core/src/receipt.rs:397:        let verdict_pos = json.find("\"verdict\"").unwrap();
- crates/hush-core/src/receipt.rs:405:        let signed = SignedReceipt::sign(receipt, &keypair).unwrap();
- crates/hush-core/src/receipt.rs:407:        let json = signed.to_json().unwrap();
- crates/hush-core/src/receipt.rs:408:        let restored = SignedReceipt::from_json(&json).unwrap();
- crates/clawdstrike/src/policy.rs:293:        let yaml = policy.to_yaml().unwrap();
- crates/clawdstrike/src/policy.rs:294:        let restored = Policy::from_yaml(&yaml).unwrap();
- crates/hush-cli/src/main.rs:264:                    let rs = RuleSet::by_name(name).unwrap();
- crates/hushd/src/auth/store.rs:130:        assert_eq!(result.unwrap().name, "test");
- crates/hush-proxy/src/sni.rs:168:        assert_eq!(extract_sni(&[0; 5]).unwrap(), None);
- crates/hush-proxy/src/sni.rs:174:        assert_eq!(extract_sni(&data).unwrap(), None);
- crates/hush-proxy/src/sni.rs:181:        let result = extract_sni(client_hello).unwrap();
- crates/hush-proxy/src/sni.rs:189:        let result = extract_sni(client_hello).unwrap();
- crates/hush-proxy/src/sni.rs:197:        assert_eq!(extract_sni(http).unwrap(), None);
- crates/hush-proxy/src/sni.rs:204:        assert_eq!(extract_sni(&data).unwrap(), None);
- crates/hush-proxy/src/sni.rs:209:        assert_eq!(extract_sni(&[]).unwrap(), None);
- crates/hush-core/src/canonical.rs:237:        let canonical = canonicalize(&value).unwrap();
- crates/hush-core/src/canonical.rs:255:        let canonical = canonicalize(&value).unwrap();
- crates/hush-core/src/canonical.rs:275:        let canonical = canonicalize(&value).unwrap();
- crates/hush-core/src/canonical.rs:290:        let canonical = canonicalize(&value).unwrap();
- crates/hush-core/src/canonical.rs:302:        let canonical = canonicalize(&value).unwrap();
- crates/hush-core/src/canonical.rs:314:        let canonical = canonicalize(&value).unwrap();
- crates/hush-core/src/canonical.rs:321:        let canonical = canonicalize(&value).unwrap();
- crates/hush-core/tests/proptest_crypto.rs:88:        let restored = Hash::from_hex(&hex_str).expect("valid hex");
- crates/hush-core/tests/proptest_crypto.rs:97:        let restored = Hash::from_hex(&hex_str).expect("valid hex");
- crates/hush-core/src/hashing.rs:201:        let from_hex = Hash::from_hex(&original.to_hex()).unwrap();
- crates/hush-core/src/hashing.rs:202:        let from_hex_prefixed = Hash::from_hex(&original.to_hex_prefixed()).unwrap();
- crates/hush-core/src/hashing.rs:211:        let json = serde_json::to_string(&hash).unwrap();
- crates/hush-core/src/hashing.rs:212:        let restored: Hash = serde_json::from_str(&json).unwrap();
- crates/hush-core/tests/proptest_merkle.rs:12:        let tree1 = MerkleTree::from_leaves(&leaves).expect("valid tree");
- crates/hush-core/tests/proptest_merkle.rs:13:        let tree2 = MerkleTree::from_leaves(&leaves).expect("valid tree");
- crates/hush-core/tests/proptest_merkle.rs:23:        let tree = MerkleTree::from_leaves(&leaves).expect("valid tree");
- crates/hush-core/tests/proptest_merkle.rs:27:        let proof = tree.inclusion_proof(index).expect("valid proof");
- crates/hush-core/tests/proptest_merkle.rs:35:        let tree = MerkleTree::from_leaves(&[&leaf]).expect("valid tree");
- crates/hush-core/tests/proptest_merkle.rs:42:        let tree = MerkleTree::from_leaves(&[&leaf]).expect("valid tree");
- crates/hush-core/tests/proptest_merkle.rs:43:        let proof = tree.inclusion_proof(0).expect("valid proof");
- crates/hush-core/tests/proptest_merkle.rs:53:        let tree = MerkleTree::from_leaves(&leaves).expect("valid tree");
- crates/hush-core/tests/proptest_merkle.rs:54:        let proof = tree.inclusion_proof(0).expect("valid proof");
- crates/hush-core/tests/proptest_merkle.rs:68:        let tree = MerkleTree::from_leaves(&leaves).expect("valid tree");
- crates/hush-core/tests/proptest_merkle.rs:79:        let tree1 = MerkleTree::from_leaves(&leaves1).expect("valid tree");
- crates/hush-core/tests/proptest_merkle.rs:80:        let tree2 = MerkleTree::from_leaves(&leaves2).expect("valid tree");
- crates/clawdstrike/src/irm/sandbox.rs:255:        sandbox.init().await.unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:260:        sandbox.cleanup().await.unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:269:        sandbox.init().await.unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:275:            .unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:282:            .unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:290:        sandbox.init().await.unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:293:        let decision = sandbox.check_net("api.github.com", 443).await.unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:297:        let decision = sandbox.check_net("evil-site.com", 443).await.unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:305:        sandbox.init().await.unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:311:            .unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:321:            .unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:329:        sandbox.init().await.unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:334:            .unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:335:        sandbox.check_fs("/etc/shadow", false).await.unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:346:        sandbox.init().await.unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:351:            .unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:373:        sandbox.init().await.unwrap();
- crates/clawdstrike/src/irm/sandbox.rs:387:        sandbox.init().await.unwrap();
- crates/hush-core/src/lib.rs:38://! let tree = MerkleTree::from_leaves(&leaves).unwrap();
- crates/hush-core/src/lib.rs:41://! let proof = tree.inclusion_proof(1).unwrap();
- crates/hush-core/src/merkle.rs:57:    /// let tree = MerkleTree::from_leaves(&leaves).unwrap();
- crates/hush-core/src/merkle.rs:138:    /// let tree = MerkleTree::from_leaves(&leaves).unwrap();
- crates/hush-core/src/merkle.rs:139:    /// let proof = tree.inclusion_proof(0).unwrap();
- crates/hush-core/src/merkle.rs:273:            let tree = MerkleTree::from_leaves(&leaves).unwrap();
- crates/hush-core/src/merkle.rs:286:        let tree = MerkleTree::from_leaves(&leaves).unwrap();
- crates/hush-core/src/merkle.rs:290:            let proof = tree.inclusion_proof(idx).unwrap();
- crates/hush-core/src/merkle.rs:300:        let tree = MerkleTree::from_leaves(&leaves).unwrap();
- crates/hush-core/src/merkle.rs:303:        let proof = tree.inclusion_proof(3).unwrap();
- crates/hush-core/src/merkle.rs:309:        let tree = MerkleTree::from_leaves(&[b"single"]).unwrap();
- crates/hush-core/src/merkle.rs:313:        let proof = tree.inclusion_proof(0).unwrap();
- crates/hush-core/src/merkle.rs:321:        let tree = MerkleTree::from_leaves(&leaves).unwrap();
- crates/hush-core/src/merkle.rs:340:        let tree = MerkleTree::from_leaves(&leaves).unwrap();
- crates/hush-core/src/merkle.rs:341:        let proof = tree.inclusion_proof(2).unwrap();
- crates/hush-core/src/merkle.rs:343:        let json = serde_json::to_string(&proof).unwrap();
- crates/hush-core/src/merkle.rs:344:        let restored: MerkleProof = serde_json::from_str(&json).unwrap();
- crates/hush-core/src/signing.rs:282:        let restored = PublicKey::from_hex(&pubkey_hex).unwrap();
- crates/hush-core/src/signing.rs:292:        let restored = Signature::from_hex(&sig_hex).unwrap();
- crates/hush-core/src/signing.rs:303:        let pubkey_json = serde_json::to_string(&pubkey).unwrap();
- crates/hush-core/src/signing.rs:304:        let sig_json = serde_json::to_string(&signature).unwrap();
- crates/hush-core/src/signing.rs:306:        let pubkey_restored: PublicKey = serde_json::from_str(&pubkey_json).unwrap();
- crates/hush-core/src/signing.rs:307:        let sig_restored: Signature = serde_json::from_str(&sig_json).unwrap();
- crates/hush-wasm/tests/integration.rs:14:    let signed = SignedReceipt::sign(receipt, &keypair).unwrap();
- crates/hush-wasm/tests/integration.rs:17:    let json = signed.to_json().unwrap();
- crates/hush-wasm/tests/integration.rs:20:    let restored = SignedReceipt::from_json(&json).unwrap();
- crates/hush-wasm/tests/integration.rs:36:    let tree = MerkleTree::from_leaves(&leaves).unwrap();
- crates/hush-wasm/tests/integration.rs:40:    let proof = tree.inclusion_proof(2).unwrap();
- crates/hush-wasm/tests/integration.rs:46:    let proof_json = serde_json::to_string(&proof).unwrap();
- crates/hush-wasm/tests/integration.rs:47:    let restored: hush_core::MerkleProof = serde_json::from_str(&proof_json).unwrap();
- crates/clawdstrike/src/irm/mod.rs:360:        let json = serde_json::to_string(&op).unwrap();
- crates/clawdstrike/src/irm/mod.rs:371:        let json = serde_json::to_string(&op).unwrap();
- crates/clawdstrike/src/irm/mod.rs:382:        let json = serde_json::to_string(&op).unwrap();
- crates/clawdstrike/src/irm/mod.rs:521:        sandbox.init().await.unwrap();
- crates/clawdstrike/src/irm/mod.rs:539:        sandbox.cleanup().await.unwrap();
- crates/clawdstrike/src/irm/exec.rs:164:        let (cmd, args) = irm.extract_command_and_args(&call).unwrap();
- crates/clawdstrike/src/irm/exec.rs:174:        let (cmd, args) = irm.extract_command_and_args(&call).unwrap();
- crates/hush-wasm/tests/web.rs:45:    assert!(result.unwrap());
- crates/hush-wasm/tests/web.rs:56:    assert!(!result.unwrap()); // Should be false for wrong message
- crates/hush-wasm/tests/web.rs:112:    let hash = hash.unwrap();
- crates/hush-wasm/tests/web.rs:128:    let canonical = canonical.unwrap();
- crates/hush-wasm/tests/web.rs:131:    let canonical2 = get_canonical_json(receipt_json).unwrap();
- crates/hush-wasm/tests/web.rs:149:    let root = result.unwrap();
- crates/hush-wasm/tests/web.rs:180:    let proof_json = proof.unwrap();
- crates/hush-wasm/tests/web.rs:194:    let root = compute_merkle_root(leaves_json).unwrap();
- crates/hush-wasm/tests/web.rs:195:    let proof_json = generate_merkle_proof(leaves_json, 0).unwrap();
- crates/hush-wasm/tests/web.rs:201:    assert!(valid.unwrap());
- crates/hush-wasm/tests/web.rs:211:    let root = compute_merkle_root(leaves_json).unwrap();
- crates/hush-wasm/tests/web.rs:212:    let proof_json = generate_merkle_proof(leaves_json, 0).unwrap();
- crates/hush-wasm/tests/web.rs:218:    assert!(!valid.unwrap());
- crates/hush-wasm/tests/web.rs:250:    let root = root.unwrap();
- crates/hush-wasm/tests/web.rs:256:    let proof_json = proof.unwrap();
- crates/hush-wasm/tests/web.rs:261:    assert!(valid.unwrap());
- crates/hush-wasm/tests/web.rs:268:    assert!(sig_valid.unwrap());
