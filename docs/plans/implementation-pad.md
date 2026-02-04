# Implementation Pad (Working Plan / Scratchpad)

Last updated: 2026-02-04

This file is the execution scratchpad for implementing the `docs/plans/**` roadmap in this repo.
Keep it ruthlessly up to date as work ships: check boxes, add links to PRs/issues, and record decisions.

---

## TL;DR Priorities (from the roadmap)

Tier 1: Foundation (build first)

| Priority | Area | Why |
|---|---|---|
| P0 | Custom Guards | Core extensibility. Everything depends on the guard abstraction + plugin system. |
| P0 | Agent Frameworks | Adoption driver (LangChain / Vercel AI / etc). No integrations = no users. |
| P0 | Policy-as-Code | Usability at scale: validation, testing, CI/CD, OPA integration. |

Tier 2: Differentiation (unique value)

| Priority | Area | Why |
|---|---|---|
| P1 | Prompt Security | Moat: jailbreak/injection detection, instruction hierarchy, output sanitization. |
| P1 | Multi-Agent | Future-proofing: orchestration security is the strategic wedge. |

Tier 3: Enterprise readiness (close deals)

| Priority | Area | Why |
|---|---|---|
| P2 | Human-in-Loop | Approval flows + breakglass for high-stakes actions. |
| P2 | Identity & Access | SSO/RBAC/policy scoping by team. |
| P2 | SIEM/SOAR | Visibility for security teams (Splunk/Datadog/etc). |

---

## Repo Reality Check (what exists today)

### Rust (workspace)
- `crates/clawdstrike`: guard suite + `HushEngine` policy enforcement at the tool boundary.
- `crates/hush-core`: cryptographic primitives + receipts (Ed25519, Merkle, canonicalization).
- `crates/hush-cli`: `hush` CLI (`hush check`, `hush policy show|validate|list`, receipts, merkle).
- `crates/hushd`: WIP HTTP daemon for centralized checks.
- `crates/hush-wasm`: WASM bindings (verification-oriented today).

### TypeScript (packages)
- `packages/clawdstrike-openclaw` (`@clawdstrike/openclaw`): OpenClaw plugin + TS policy engine + TS CLI (`clawdstrike policy lint|show|test|diff`, `clawdstrike audit ...`).
- `packages/hush-ts` (`@clawdstrike/sdk`): hashing/receipts utilities (not the policy engine).

### Known mismatches / gaps to resolve early
- Policy schema mismatch:
  - Rust policy schema is `version: "1.0.0"` and config lives under `guards.*`.
  - TS OpenClaw policy schema is `version: "clawdstrike-v1.0"` and config lives under `egress/filesystem/execution/...`.
  - The new P0/P1 specs (custom guards, PaC, composition) assume a guard-centric schema.
- Guard parity mismatch (built-ins differ between Rust and TS; prompt-injection exists in Rust, not in TS).
- Engine architecture gap (still): plugins/composition need a dynamic registry + policy representation. **Progress:** `HushEngine` now supports runtime appended guards (built-ins first, extras last).
- CLI naming mismatch (resolved): `hush` is canonical; `clawdstrike` is TS/OpenClaw-specific + planned wrapper/alias to forward to `hush` (ADR 0001).

---

## Feb 2026 progress (merged to `main`)

- Decisions + conventions:
  - ADR 0001 (`hush` vs `clawdstrike`): `docs/plans/decisions/0001-cli-command-surface.md`
  - ADR 0002 (policy schema convergence): `docs/plans/decisions/0002-policy-schema-convergence.md`
  - ADR 0003 (canonical `PolicyEvent` + severity): `docs/plans/decisions/0003-policy-event-and-severity.md`
- Fixture corpus (parity scaffolding):
  - Canonical policy events: `fixtures/policy-events/v1/events.jsonl`
  - Validator: `tools/scripts/validate-policy-events`
- Rust engine extensibility:
  - `HushEngine` supports runtime `extra_guards` (built-ins first, extras last) and records extras in receipt metadata.
- Rust CLI (PaC baseline):
  - Added policy-as-code commands: `hush policy lint|test|eval|simulate|diff|impact|version` (see `docs/src/reference/api/cli.md`).
- TypeScript adapter foundation:
  - Added `packages/clawdstrike-adapter-core/` (`@clawdstrike/adapter-core`) with `BaseToolInterceptor`, `DefaultOutputSanitizer`, `PolicyEventFactory`, and `InMemoryAuditLogger` + unit tests.
- Agent framework integrations (P0):
  - `@clawdstrike/vercel-ai`: middleware, tool/model wrappers, streaming support, optional prompt-security (tests included): `packages/clawdstrike-vercel-ai/`.
  - `@clawdstrike/langchain`: tool wrappers + callback handler + LangGraph nodes (tests included): `packages/clawdstrike-langchain/`.
- Prompt Security (P1 baseline + wiring):
  - Watermark payload bytes are RFC 8785 (JCS) canonical in Rust + TS (portable signatures/fingerprints).
  - Jailbreak detection: added session TTL + half-life decay + optional persistence hooks; linear model weights are configurable.
  - Output sanitization: allow/deny lists + streaming-safe sanitizer + optional entity/NER hook; improved patterns (Anthropic key, JWT, internal IPs, etc) and Luhn validation for CC.
  - Vercel AI: `createClawdstrikeMiddleware` supports `config.promptSecurity` to apply hierarchy, jailbreak detection, output sanitization, and watermarking to model calls; stream sanitization is supported for `text-delta`.
  - Tool-boundary runtime convenience: Codex/OpenCode/Claude Code packages now ship `wrap*ToolDispatcher(...)` helpers for drop-in wiring into a tool dispatcher.
- CI/tooling hardening:
  - Offline vendored build fixed by narrowing `.gitignore` patterns so vendored crate sources aren’t accidentally ignored.
  - WASM build fixed by enabling `getrandom`'s `js` feature for wasm32 in `hush-core`.

---

## Guiding principles (non-negotiables)

- Tool-boundary enforcement only (explicitly not an OS sandbox).
- Fail-closed semantics for malformed config, ambiguous security state, or missing dependencies.
- Observable by default: every deny/warn has a structured audit event (with correlation IDs).
- Low overhead: policy evaluation should be “cheap enough” for per-tool-call use (target <10ms p99 in common cases).
- Extensibility without weakening: plugins must not bypass core invariants; sandbox/capabilities are mandatory for untrusted code.
- Cross-SDK parity where it matters: same policy file should behave the same across Rust + TS integrations (or we clearly document compatibility boundaries).

---

## Parallel worktrees (M0 / Feb 2026)

These are intended to run in parallel; avoid cross-editing across worktrees:

- `hushclaw-p0-integ` *(this worktree)*: decisions + coordination artifacts (`docs/plans/**`, `fixtures/**`, lightweight validators).
- `hushclaw-p0-rust`: Rust runtime work (`crates/**`) — schema, engine/guards, adapters.
- `hushclaw-p0-ts`: TypeScript runtime work (`packages/**`) — OpenClaw policy engine + schema compatibility.
- `hushclaw-p0-cli`: CLI UX work (command surface, aliases/wrappers, help text), plus doc updates once naming is confirmed.

---

## Working structure (suggested owners)

Fill these in with real people/handles once assigned; keep one DRI per workstream.

- [ ] DRI: P0 / overall tech lead: @__________
- [ ] DRI: Rust core (engine/policy/guards/sandbox): @__________
- [ ] DRI: TypeScript SDK + adapters (policy engine, adapter-core, framework integrations): @__________
- [ ] DRI: DevEx (CLI/CI/docs/examples/templates): @__________
- [ ] DRI: Security research (prompt-security eval, red-team corpus): @__________
- [ ] DRI: Enterprise plumbing (hushd, audit sinks, IAM/approvals): @__________

---

## “Decisions We Must Make” (blockers)

### Decision records (ACCEPTED 2026-02-03)

- ADR 0001: CLI surface (`hush` vs `clawdstrike`): `decisions/0001-cli-command-surface.md`
- ADR 0002: Policy schema convergence: `decisions/0002-policy-schema-convergence.md`
- ADR 0003: Canonical `PolicyEvent` + severity: `decisions/0003-policy-event-and-severity.md`

### Naming / UX
- [x] Decide canonical CLI surface: `hush` canonical; `clawdstrike` wrapper/alias forwards to `hush`. (See `decisions/0001-cli-command-surface.md`)
- [x] Decide canonical docs/examples command naming; update docs accordingly (`hush` canonical, `clawdstrike` only when TS/OpenClaw-specific).

### Policy schema
- [x] Decide canonical policy schema for v1 going forward: guard-centric `version: "1.0.0"`; legacy `clawdstrike-v1.0` supported via migration/translation. (See `decisions/0002-policy-schema-convergence.md`)
- [x] Confirm compatibility stance + migration plan. (See `decisions/0002-policy-schema-convergence.md`)
- [x] Define a single canonical `PolicyEvent` schema across SDKs (TypeScript + Rust). (See `decisions/0003-policy-event-and-severity.md`)

### Plugin execution model
- [ ] Decide Node plugin loading strategy: native TS guards vs WASM-only for “untrusted”.
- [ ] Decide Rust plugin loading strategy: WASM-only initially vs native (`dlopen`) for trusted tiers.
- [ ] Decide sandbox trust tiers + default restrictions (untrusted/community/verified/certified/first-party).

### Where evaluation runs
- [ ] Decide if Node integrations evaluate policies in-process (TS engine) vs call out to `hushd` (HTTP).
  - In-process is lower latency + easier adoption.
  - `hushd` centralizes policy + audit + enterprise features.

### Audit storage
- [ ] Decide audit store contract: local file, sqlite, stdout, OTLP, or pluggable sinks (and which is P0 vs P2).

---

## Milestones (ship slices, not a big bang)

### M0: Baseline convergence (P0 prerequisite)
- [x] Policy schema convergence plan written (decision + migration path). (See `decisions/0002-policy-schema-convergence.md`)
- [x] Canonical event model documented + fixture corpus created. (See `decisions/0003-policy-event-and-severity.md` and `../../fixtures/policy-events/v1/`)
- [ ] Cross-SDK parity tests scaffolded (same events, same expected decisions).

### M1: P0 Foundation shipped (Custom Guards + Agent Frameworks + Policy-as-Code)
- [ ] Custom guards plugin system (dev-mode first; production hardening later).
- [x] `@clawdstrike/adapter-core` + at least 2 “real” integrations (Vercel AI + LangChain). (See `packages/clawdstrike-adapter-core/`, `packages/clawdstrike-vercel-ai/`, `packages/clawdstrike-langchain/`.)
- [x] Policy-as-code CLI: lint + test (YAML test suite) + diff + simulate. (See `crates/hush-cli/src/policy_lint.rs`, `crates/hush-cli/src/policy_test.rs`, `crates/hush-cli/src/policy_pac.rs`, `crates/hush-cli/src/policy_diff.rs`.)

### M2: P1 Differentiation shipped (Prompt Security + Multi-Agent primitives)
- [x] Prompt security baseline: stronger injection/jailbreak detection + output sanitization. (See `docs/src/reference/guards/README.md`, `crates/clawdstrike/src/jailbreak.rs`, `crates/clawdstrike/src/output_sanitizer.rs`.)
- [ ] Multi-agent baseline: identities + delegation tokens + audit correlation.

### M3: P2 Enterprise readiness shipped
- [ ] Human-in-loop approvals + breakglass.
- [ ] Identity & access (RBAC/SSO hooks, policy scoping).
- [ ] SIEM/SOAR sinks (Splunk/Datadog/etc), plus compliance export formats.

---

## Workstream A — Custom Guards (P0)

Primary specs: `docs/plans/custom-guards/*`

### A0. Core refactors (enables everything else)
- [ ] Refactor Rust `HushEngine` to use a dynamic guard registry (vector/graph), not a fixed `[Guard; 6]`. *(Partial: runtime `extra_guards` supported; full plugin registry TBD.)*
- [ ] Extend Rust policy model to represent “custom guards” and “compositions” without breaking existing policies.
- [ ] Add structured “per-guard evidence” to all SDKs (Rust already has `GuardReport`; ensure TS parity).

### A1. Stable Guard API (Rust + TS parity)
- [ ] Freeze a minimal cross-language guard interface:
  - name, handles(event/action), validate(config), check(event, context) → result.
- [ ] Define shared enums/strings (event types, severities, decision statuses) and publish them as a single source of truth.
- [ ] Define guard config schemas and how they are validated (JSON Schema + runtime checks).

### A2. Plugin manifest + validation
- [ ] Implement `clawdstrike.plugin.json` (npm) and `clawdstrike.plugin.toml` (Rust) parsing + validation.
- [ ] Publish JSON Schema(s) for manifests + policy schema(s) (versioned URLs + local copies for offline use).
- [ ] Add CLI commands for plugin validation (dev ergonomics): `guard validate`, `guard inspect`.

### A3. TS plugin loader (Node)
- [ ] Package resolution (local path + npm).
- [ ] Dynamic import loader with explicit entrypoints per guard.
- [ ] Guard instance manager: lifecycle, caching, hot reload (dev only).
- [ ] Capability gate stubs wired through (even before WASM sandbox lands).

### A4. Rust plugin loader (native)
- [ ] WASM runtime integration (Wasmtime) as the default for “untrusted/community” plugins.
- [ ] Host function surface + capability enforcement (network/fs/secrets/subprocess).
- [ ] Resource limits (cpu/memory/wall clock) enforced per plugin call.
- [ ] (Optional later) Native `dlopen` path for certified/first-party plugins.

### A5. Capability system (security boundary)
- [ ] Define capability model and enforcement points (pre-host-call checks).
- [ ] Add audit events for capability denials, timeouts, sandbox faults.
- [ ] Define safe defaults for untrusted plugins (no subprocess, no fs write, limited net).

### A6. Composition DSL (policy-level)
- [ ] Implement composition rule parsing + evaluation semantics (AND/OR/NOT/IF_THEN/N_OF/SCORE).
- [ ] Implement expression language for context-based conditions (strictly bounded; no arbitrary eval).
- [ ] Add cycle detection, max depth/operands limits, and deterministic short-circuit rules.
- [ ] Add tooling: explain/trace output for why a composition allowed/blocked.

### A7. Async guards (external services)
- [ ] Define async execution model (timeouts, retries, caching).
- [ ] Implement rate limiting + circuit breakers.
- [ ] Provide 1–2 reference guards (VirusTotal/Snyk/Webhook) behind explicit capabilities.

### A8. Versioning + lockfile
- [ ] Implement semver constraints for plugins and policy schema.
- [ ] Implement `clawdstrike.lock.json` generation/validation for reproducible installs.
- [ ] Add “compat matrix” checks at load time (fail closed).

### A9. Acceptance / tests
- [ ] Golden test corpus: (policy, events) → expected decisions across Rust + TS.
- [ ] Fuzz policy parsing + composition expression parser.
- [ ] Sandbox escape regression suite (capability denial, resource exhaustion, malformed inputs).

---

## Workstream B — Agent Framework Integrations (P0)

Primary specs: `docs/plans/agent-frameworks/*`

### B0. Adapter core (shared)
- [x] Create `@clawdstrike/adapter-core` package (interfaces + base implementations): `packages/clawdstrike-adapter-core/`.
- [x] Define the “interception contract” (captured in exported types + base interceptor):
  - Pre-call: build `PolicyEvent` + evaluate + block/warn/allow.
  - Post-call: sanitize output + audit + optional block persistence.
  - Bootstrap: inject security prompt + load policy.
  - Error: convert failures to safe denies, never silent-allow.
- [x] Provide “default” implementations: tool interceptor, output sanitizer, event factory, in-memory audit logger.

### B1. Policy engine packaging strategy (TS)
- [ ] Decide: keep policy engine in `@clawdstrike/openclaw` and depend on it, OR extract to `@clawdstrike/policy` for reuse.
- [ ] Align policy schema with the canonical decision from M0 (migration shim if needed).
- [ ] Bring built-in guard parity with Rust where feasible (mcp_tool, prompt_injection, etc.).

### B2. Vercel AI SDK integration (P0)
- [x] Create `@clawdstrike/vercel-ai` with middleware + streaming support. (See `packages/clawdstrike-vercel-ai/`.)
- [x] Tool wrapping (pre/post) + model wrapping (bootstrap + prompt injection defenses). (See `packages/clawdstrike-vercel-ai/src/middleware.ts`.)
- [x] React helpers (`useSecureChat`, etc.) if they don’t materially expand scope. (See `packages/clawdstrike-vercel-ai/src/react/use-secure-chat.ts`.)
- [x] Examples + integration tests with mocked model/tools. (See `packages/clawdstrike-vercel-ai/src/*.test.ts` and `packages/clawdstrike-vercel-ai/src/react/use-secure-chat.test.tsx`.)

### B3. LangChain / LangGraph integration (P0)
- [x] Create `@clawdstrike/langchain` using callbacks + tool wrappers. (See `packages/clawdstrike-langchain/`.)
- [x] LangGraph nodes: “security checkpoint node”, tool-node wrapper, conditional edges. (See `packages/clawdstrike-langchain/src/langgraph.ts`.)
- [x] Ensure correct trace/correlation propagation for audit. (See `packages/clawdstrike-langchain/src/callback-handler.ts`.)

### B4. Generic adapter “bring your own framework” (P0)
- [ ] Document and ship a minimal “generic tool runner” wrapper that any framework can plug into.
- [ ] Provide examples (one TS sample app, one server-side handler).

### B5. P1/P2 frameworks (later)
- [ ] P1: `@clawdstrike/crewai` (Python bridge strategy TBD).
- [ ] P1: `@clawdstrike/autogpt` (higher complexity).
- [ ] P2: `@clawdstrike/autogen`.

---

## Workstream C — Policy-as-Code (P0)

Primary specs: `docs/plans/policy-as-code/*`

### C0. CLI surface (Rust + TS)
- [ ] Decide what’s “source of truth”:
  - Rust: extend `hush` CLI (`hush policy lint|test|diff|simulate|migrate|version`).
  - TS: keep `clawdstrike policy ...` for OpenClaw users, but ensure semantics match.
- [ ] Ensure machine-readable output formats (JSON + optional SARIF for CI).

### C1. Validation (lint)
- [x] Implement layered validation:
  - Syntax (YAML parsing), schema (unknown fields), semantics (regex/glob validity), security warnings.
- [ ] Implement regex ReDoS checks (static heuristics + optional “safe regex” mode).
- [ ] Add policy “style” hints (sorted patterns, missing descriptions) behind non-blocking level.

### C2. Testing framework (YAML test suites)
- [x] Implement `policy.test.yaml` runner with fixtures, contexts, parameterization. (See `crates/hush-cli/src/policy_test.rs`.)
- [x] Add coverage model (which guards/rules were exercised). (See `hush policy test --coverage`.)
- [ ] Add snapshot testing for decisions + mutation testing (later, likely P1).

### C3. Diff + migration tooling
- [x] M0 baseline: `hush policy diff <left> <right> [--resolve] [--json]` (rulesets or files; optional extends resolution).
- [x] Breaking-change detector (configurable rules; CI `--fail-on-breaking`). (See `hush policy impact --fail-on-breaking`.)
- [ ] Migration transforms for schema upgrades (and a “dry-run” mode).

### C4. Simulation / replay
- [x] Batch simulation mode (`events.jsonl` / audit replay) producing a report (counts, top denials). (See `hush policy simulate`.)
- [x] Policy A vs Policy B comparison mode. (See `hush policy impact`.)
- [ ] “Shadow mode” concept captured (likely P1/P2 with `hushd`).

### C5. OPA/Rego integration (likely P1 unless enterprise asks)
- [ ] Embed OPA/Rego engine (Rust/WASM).
- [ ] Hybrid YAML+Rego combination modes and “replaces guard” migration story.
- [ ] Rego tooling: compile, eval, trace/explain.

---

## Workstream D — Prompt Security (P1)

Primary specs: `docs/plans/prompt-security/*`

### D0. Baseline parity + wiring
- [ ] Decide how prompt-security events are represented in the canonical event model.
- [ ] Ensure prompt-security decisions are surfaced consistently to integrations (block/warn + evidence).
- [x] Add prompt-security audit events (including fingerprints/hashes for dedupe without storing raw prompts). (See `packages/clawdstrike-vercel-ai/src/middleware.ts` and `crates/clawdstrike/src/hygiene.rs`.)

### D1. Jailbreak detection (tiered)
- [x] Heuristics + normalization (fast). (See `crates/clawdstrike/src/jailbreak.rs`.)
- [x] Statistical layer (entropy/n-grams/perplexity proxies). (See `crates/clawdstrike/src/jailbreak.rs`.)
- [ ] Optional ML classifier path (ONNX) with clear deployment requirements.
- [x] Optional LLM-as-judge path with caching + cost controls. (See `crates/clawdstrike/src/jailbreak.rs` + `llm-judge-openai` feature.)

### D2. Output sanitization
- [x] Secret patterns + high-entropy detection improvements. (See `crates/clawdstrike/src/output_sanitizer.rs` and `packages/hush-ts/src/output-sanitizer.ts`.)
- [x] PII detection (NER optional; provide “small/fast” and “large/accurate” modes). (See `crates/clawdstrike/src/output_sanitizer.rs`.)
- [x] Streaming-safe sanitizer (don’t split tokens; bounded buffering). (See `crates/clawdstrike/src/output_sanitizer.rs` and `packages/hush-ts/src/output-sanitizer.ts`.)

### D3. Instruction hierarchy enforcement
- [x] Standard “message tagging” and override detection strategy. (See `crates/clawdstrike/src/instruction_hierarchy.rs`.)
- [x] Enforce system > developer > user > tool instruction priority in adapters. (See `packages/clawdstrike-vercel-ai/src/middleware.ts`.)
- [x] Audit “override attempts” (blocked/warned). (See `packages/clawdstrike-vercel-ai/src/middleware.ts`.)

### D4. Watermarking + provenance (P1/P2 depending on scope)
- [x] Define watermark payload + encoding (zero-width/homoglyph/metadata/hybrid). (See `crates/clawdstrike/src/watermarking.rs` and `packages/hush-ts/src/watermarking.ts`.)
- [ ] Key management story (rotation, verification, audit).

### D5. Adversarial robustness
- [ ] Canonicalization pipeline (unicode, homoglyphs, zero-width).
- [ ] Randomized smoothing / ensemble detectors with explicit latency tradeoffs.

---

## Workstream E — Multi-Agent (P1)

Primary specs: `docs/plans/multi-agent/*`

### E0. Foundations (types + audit)
- [ ] Define `AgentIdentity` and registration APIs (TS + Rust).
- [ ] Define trace/correlation propagation (W3C trace context recommended).
- [ ] Define “cross-agent event” schema additions (delegation, channel open/close, cross-agent access).

### E1. Delegation tokens
- [ ] Token format + signing (COSE Sign1 / EdDSA suggested).
- [ ] Verification middleware + revocation registry interface.
- [ ] Attenuation enforcement (capability ceiling, chain tracking).

### E2. Cross-agent policy enforcement
- [ ] Cross-agent guard to prevent confused deputy (sender+receiver checks).
- [ ] Policy syntax for allow/deny between agent patterns + required delegation + approval hooks.

### E3. Identity attestation
- [ ] Key management + certificate issuance flow (local dev vs prod).
- [ ] Optional hardware attestation integrations (TPM/SGX) as P2+.

### E4. Isolation boundaries (P2-ish in practice)
- [ ] Process/container isolation strategy (Docker/seccomp/AppArmor).
- [ ] Per-agent filesystem roots + network namespaces (if runtime controls exist).

### E5. Coordination protocols
- [ ] Secure channels (mTLS + optional E2E encryption) + message framing.
- [ ] Evidence collection + audit correlation for task handoff.

---

## Workstream F — Enterprise readiness (P2)

These items don’t have full specs in `docs/plans/**` yet; treat as placeholders until written.

### F1. Human-in-the-loop approvals + breakglass
- [ ] Define approval request/response schema (who, what, why, expiry).
- [ ] Add engine-level “requires approval” decision type (not just allow/deny/warn).
- [ ] Implement at least one approval backend (local CLI + webhook) before adding Slack/Jira/etc.
- [ ] Breakglass flow: audited, time-limited, with explicit reason capture.

### F2. Identity & access (RBAC/SSO)
- [ ] Policy scoping by org/team/project/environment.
- [ ] RBAC model for who can change policies, approve actions, view audit logs.
- [ ] SSO integration points (Auth0/Okta) — likely via `hushd` or a control plane.

### F3. SIEM/SOAR + audit exports
- [ ] Define audit sink interface (stdout/jsonl, webhook, OTLP, Splunk HEC, Datadog logs).
- [ ] Ensure tamper-evident audit storage options (hash chaining, signed checkpoints).
- [ ] Add export formats (JSONL + optional CEF/LEEF).

---

## Cross-cutting checklists

### For every PR
- [ ] Adds/updates tests (unit + parity fixtures where applicable).
- [ ] Updates docs (`docs/src/**` and/or relevant `docs/plans/**`), plus examples if user-facing.
- [ ] Updates changelog if behavior changes.
- [ ] Includes “fail closed” behavior for invalid/missing config.
- [ ] Emits structured audit events for deny/warn paths (no silent drops).

### Security review gates (before calling something “production ready”)
- [ ] Threat model written/updated for the component.
- [ ] Fuzzing/regression tests for parsers (policy, manifests, composition).
- [ ] Dependency review for sandboxing/runtime code.
- [ ] Clear capability defaults for untrusted plugins.
- [ ] Red-team style test cases for prompt injection/jailbreak bypass attempts.

### Release checklist
- [ ] Version bumps consistent across Rust crates + npm packages.
- [ ] Compatibility notes updated (policy schema version, supported Node/Rust versions).
- [ ] Migration notes included when schema/behavior changes.
- [ ] CI green (including offline build/test).

---

## Links (spec index)

### P0
- Custom guards: `docs/plans/custom-guards/overview.md`
- Plugin system: `docs/plans/custom-guards/plugin-system.md`
- Guard SDK: `docs/plans/custom-guards/guard-sdk.md`
- Composition DSL: `docs/plans/custom-guards/composition-dsl.md`
- Async guards: `docs/plans/custom-guards/async-guards.md`
- Agent frameworks: `docs/plans/agent-frameworks/overview.md`
- Generic adapter: `docs/plans/agent-frameworks/generic-adapter.md`
- Policy-as-code: `docs/plans/policy-as-code/overview.md`
- PaC validation/testing/diff/simulation: `docs/plans/policy-as-code/validation.md`, `docs/plans/policy-as-code/testing-framework.md`, `docs/plans/policy-as-code/diff-migration.md`, `docs/plans/policy-as-code/simulation.md`

### P1
- Prompt security: `docs/plans/prompt-security/overview.md`
- Multi-agent: `docs/plans/multi-agent/overview.md`
