# ClawdStrike v1.2.0 — Implementation Task Tracker

**Status:** ACTIVE
**Date:** 2026-02-06
**Branch:** `feat/spider-sense-integration`
**Last audit:** 2026-02-06 (code-audit team verified all tasks against `main`)

This document tracks **only genuinely new work** for v1.2.0. Existing infrastructure is listed in the [Existing Infrastructure](#existing-infrastructure-do-not-rebuild) section — these are extension points, not tasks.

**Roadmap documents:**
- [Spider-Sense Integration](./spider-sense-integration.md) — agent defense via hierarchical adaptive screening
- [Next-Gen Dynamic Policies](./nextgen-policy-roadmap.md) — session posture, budgets, transitions, observe/synth

---

## Existing Infrastructure (DO NOT REBUILD)

These systems are **production-grade and already exist on `main`**. Spider-Sense and Dynamic Policies extend them — they don't replace them.

### Guard Pipeline (fully operational)
- **7 built-in sync guards** in `crates/clawdstrike/src/guards/`: `ForbiddenPathGuard`, `EgressAllowlistGuard`, `SecretLeakGuard`, `PatchIntegrityGuard`, `McpToolGuard`, `PromptInjectionGuard`, `JailbreakGuard`
- **`CustomGuardRegistry`** + **`CustomGuardFactory` trait** in `guards/custom.rs` — register new guards by ID, instantiate from policy YAML config. **This is the primary extension point for Spider-Sense stage guards.**
- **`GuardAction::Custom(&str, &Value)`** in `guards/mod.rs` — extensible action type for arbitrary payloads. Already used by `PromptInjectionGuard` and `JailbreakGuard`. **This is the hook for `risk_signal.*` actions.**
- **Engine pipeline** in `engine.rs`: BuiltIn → Custom (via registry) → Extra (runtime) → Async, with `fail_fast`, `#[must_use]` on `GuardResult`, fail-closed on config error

### Async Guard Runtime (fully operational)
- **`AsyncGuard` trait** in `async_guards/types.rs:87` — `name()`, `handles()`, `config()`, `cache_key()`, `check_uncached()`
- **`AsyncGuardRuntime`** in `async_guards/runtime.rs` — automatic caching, rate limiting, circuit breaker, retry with exponential backoff
- **`AsyncGuardConfig`** — timeout, on_timeout behavior, execution mode (parallel/sequential/background), cache TTL, rate limit, circuit breaker, retry config
- **3 existing async guard packages** in `async_guards/threat_intel/`: VirusTotal, SafeBrowsing, Snyk — **follow this pattern for `clawdstrike-spider-sense`**
- **Registry** in `async_guards/registry.rs` — closed set of 3 packages via `match` on `spec.package`; adding a new one = one match arm + one `validate_custom_guards` entry

### Session Management (fully operational)
- **`SessionManager`** in `crates/hushd/src/session/mod.rs` (725 lines) — `SessionStore` trait, `InMemorySessionStore`, `SqliteSessionStore`
- **`SessionUpdates.state: Option<HashMap<String, serde_json::Value>>`** — generic key/value state map. **Posture and Spider-Sense session state go here.**
- REST API: `POST /session`, `GET /session/{id}`, `DELETE /session/{id}`, session binding, rotation, RBAC
- SQLite persistence with atomic operations

### Receipts (fully operational)
- **`Receipt`** in `crates/hush-core/src/receipt.rs` — `metadata: Option<JsonValue>` generic field. **Posture snapshots go under `metadata.clawdstrike.posture`.**
- Signing (`SignedReceipt`), cosigning, verification, canonical JSON (JCS)
- Receipt schema v1.0.0 with strict validation

### SSE Events (fully operational)
- **`GET /api/v1/events`** in `crates/hushd/src/api/events.rs` — SSE endpoint with auth/RBAC gating
- **`DaemonEvent { event_type: String, data: Value }`** broadcast via `tokio::sync::broadcast` (capacity 1024)
- Already emits events from check, eval, webhooks, SAML, policy scoping
- **Adding Spider-Sense events = calling `state.broadcast(DaemonEvent { event_type: "spider_sense.*", ... })`**

### SIEM Exporters (fully operational, comprehensive)
- **24 files** in `crates/hushd/src/siem/` — `SecurityEvent` type, `Exporter` trait, `ExporterManager` with fanout
- **6 exporters**: Splunk, Elastic, Datadog, Sumo Logic, Webhooks, Alerting
- **3 schema transforms**: CEF, ECS, OCSF
- **Threat intel**: STIX format, TAXII protocol, config, guard, service
- Dead letter queue, retry with backoff, rate limiting, batching
- **Spider-Sense events flow through automatically once emitted as `SecurityEvent`**

### Multi-Agent (fully operational)
- `crates/hush-multi-agent/src/` — `AgentIdentity`, `TrustLevel` (5 levels), `AgentRole` (7 variants), `AgentCapability` (9 variants incl. `Custom { name, params }`)
- **Delegation tokens** (`SignedDelegationToken`) — JWS-like claims with capability ceiling, attenuation-only, Ed25519 signing over JCS
- **Signed messages** (`SignedMessage`) — integrity, replay protection via nonce, delegation chain verification
- **`RevocationStore`** trait + `InMemoryRevocationStore`
- **`DelegationClaims.ctx`** and **`MessageClaims.ctx`** — open `Value` fields for carrying Spider-Sense metadata

### TS SDK (partial — SIEM fully mirrors Rust)
- `packages/clawdstrike-policy/src/policy/schema.ts` — `Policy`, `GuardConfigs`, `CustomGuardSpec`, `PolicySettings`
- `packages/hush-ts/src/siem/` (10 files) — full Rust SIEM parity: types, event bus, manager, filter, exporters, transforms, threat intel

### CLI (simulate exists, observe/synth do not)
- **`hush policy simulate`** in `crates/hush-cli/src/policy_pac.rs` — JSONL input, interactive mode, benchmarking. No posture awareness yet.

---

## Legend

- `[ ]` Not started
- `[~]` In progress
- `[x]` Complete
- **Ref** links to roadmap section with full design
- **Deps** lists task IDs that must complete first
- **Extends** names the existing infrastructure being wired into

---

## Milestone 0: Prerequisite Decisions

| ID | Decision | Status | Ref |
|----|----------|--------|-----|
| D-1 | Embedding model: ONNX local vs API vs both | `[ ]` | [SS §10 Q1](./spider-sense-integration.md#10-risks-and-open-questions) |
| D-2 | Vector DB format: `hnsw` crate vs sqlite-vss vs custom | `[ ]` | [SS §10 Q2](./spider-sense-integration.md#10-risks-and-open-questions) |
| D-3 | IRS signal source: agent SDK, proxy heuristic, or hybrid | `[ ]` | [SS §10 Q4](./spider-sense-integration.md#10-risks-and-open-questions) |
| D-4 | Pattern DB distribution: compiled-in vs external files | `[ ]` | [SS §10 Q5](./spider-sense-integration.md#10-risks-and-open-questions) |
| D-5 | Spider-Sense + existing PromptInjection/Jailbreak: complement or replace | `[ ]` | [SS §10 Q7](./spider-sense-integration.md#10-risks-and-open-questions) |
| D-6 | Confirm S2Bench MIT license compatibility | `[ ]` | [SS §10 Q6](./spider-sense-integration.md#10-risks-and-open-questions) |

---

## Milestone 1: Spider-Sense Crate + Stage Guards

New crate with vector DB and four stage guards. Registers into the **existing `CustomGuardRegistry`**.

| ID | Task | Status | Deps | Extends | Ref |
|----|------|--------|------|---------|-----|
| SS-1 | **Create `crates/clawdstrike-spider-sense/` crate** | `[ ]` | — | — | [SS §9 P1](./spider-sense-integration.md#phase-1-foundation-23-weeks) |
| | Scaffold workspace crate. Match existing lint config (`unwrap_used = "deny"`, `deny_unknown_fields`). | | | | |
| SS-2 | **`VectorStore` trait + implementations** | `[ ]` | D-2, SS-1 | — | [SS App C.2](./spider-sense-integration.md#c2-has-vectorfeedbacksandbox-implementation) |
| | `fn query(&self, embedding: &[f32], top_k: usize) -> Result<Vec<Match>>`. In-memory (tests) + file-backed (prod). Cosine similarity. | | | | |
| SS-3 | **Embedding abstraction** | `[ ]` | D-1, SS-1 | — | [SS App C.2](./spider-sense-integration.md#c2-has-vectorfeedbacksandbox-implementation) |
| | `fn embed(&self, text: &str) -> Result<Vec<f32>>`. Feature-gated backends: ONNX (`ort`), API-based. | | | | |
| SS-4 | **Port S2Bench attack patterns** | `[ ]` | D-4, D-6, SS-2, SS-3 | — | [SS §9 P1](./spider-sense-integration.md#phase-1-foundation-23-weeks) |
| | Convert `HAS_db/` ChromaDB → Rust format. Separate DBs per stage. Migration tool. | | | | |
| SS-5 | **`QuerySenseGuard`** | `[ ]` | SS-4 | `CustomGuardFactory` | [SS §5.1](./spider-sense-integration.md#51-querysenseguard) |
| | Handles `Custom("risk_signal.query", ...)`. Cosine similarity vs query DB. Impl `CustomGuardFactory`. | | | | |
| SS-6 | **`PlanSenseGuard`** | `[ ]` | SS-4 | `CustomGuardFactory` | [SS §5.2](./spider-sense-integration.md#52-plansenseguard) |
| | Handles `Custom("risk_signal.plan", ...)`. Plan-stage blind spot coverage. Lower threshold (0.80). | | | | |
| SS-7 | **`ActionSenseGuard`** | `[ ]` | SS-4 | `CustomGuardFactory` | [SS §5.3](./spider-sense-integration.md#53-actionsenseguard) |
| | Handles `Custom("risk_signal.action", ...)` + inspects `McpTool`/`ShellCommand`. | | | | |
| SS-8 | **`ObservationSenseGuard`** | `[ ]` | SS-4 | `CustomGuardFactory` | [SS §5.4](./spider-sense-integration.md#54-observationsenseguard) |
| | Handles `Custom("risk_signal.observation", ...)`. IPI + tool-return injection. | | | | |
| SS-9 | **Register all 4 guards + `spider-sense` ruleset** | `[ ]` | SS-5..8 | `CustomGuardRegistry` | [SS §4.1](./spider-sense-integration.md#411-custom-guard-factories-for-stage-specific-sensing) |
| | `register_spider_sense_guards(registry)` helper. Ship `rulesets/spider-sense.yaml` for `extends`. | | | | |
| SS-10 | **S2Bench integration tests** | `[ ]` | SS-9 | — | [SS §8](./spider-sense-integration.md#8-s2bench-as-test-harness) |
| | 9 attack types + 153 hard benign samples. Coverage matrix from §8.2. | | | | |

**Deliverable:** `extends: ["spider-sense"]` enables fast-path vector defense. Zero schema changes.

---

## Milestone 2: Spider-Sense Deep Analysis

Async LLM guard for ambiguous cases. Plugs into the **existing `AsyncGuard` runtime** (gets free caching, rate limiting, circuit breaker).

| ID | Task | Status | Deps | Extends | Ref |
|----|------|--------|------|---------|-----|
| SS-11 | **Escalation protocol** | `[ ]` | SS-9 | `GuardContext.metadata` | [SS §9 P2](./spider-sense-integration.md#phase-2-deep-analysis-23-weeks) |
| | Sync guards set `metadata["spider_sense.escalated"]` when ambiguous. Async guard reads it. | | | | |
| SS-12 | **Port judge prompts** | `[ ]` | SS-1 | — | [SS App C.2](./spider-sense-integration.md#c2-has-vectorfeedbacksandbox-implementation) |
| | Port `sandbox_judge_*.txt` (4 stage-specific) from Spider-Sense `template/`. | | | | |
| SS-13 | **`SpiderSenseDeepAnalysis` async guard** | `[ ]` | SS-11, SS-12, SS-2 | `AsyncGuard` trait | [SS §5.5](./spider-sense-integration.md#55-spidersensedeepanalysis-async) |
| | Top-K retrieval + LLM reasoning. Configurable endpoint. Implements `AsyncGuard`. | | | | |
| SS-14 | **Add to async guard registry** | `[ ]` | SS-13 | `async_guards/registry.rs` | [SS §4.2](./spider-sense-integration.md#42-tier-2--async-guard-package) |
| | Add `"clawdstrike-spider-sense"` match arm in `build_guard()` + entry in `validate_custom_guards()`. | | | | |
| SS-15 | **Emit Spider-Sense SSE events** | `[ ]` | SS-13 | `DaemonEvent` broadcast | [SS §4.1.4](./spider-sense-integration.md#414-sse-event-broadcasting) |
| | `spider_sense.threat_detected`, `.deep_analysis`, `.escalated` via existing `event_tx`. | | | | |
| SS-16 | **TS SDK: Spider-Sense guard config types** | `[ ]` | SS-9, SS-14 | `clawdstrike-policy` TS schema | [SS §9 P2](./spider-sense-integration.md#phase-2-deep-analysis-23-weeks) |
| | Mirror custom guard config + `risk_signal.*` action kinds in TypeScript. | | | | |

**Deliverable:** Full two-tier HAS pipeline — fast vector match + LLM deep analysis.

---

## Milestone 3: Schema v1.2.0

Shared schema bump for both Spider-Sense (Tier 3) and Dynamic Policies.

| ID | Task | Status | Deps | Extends | Ref |
|----|------|--------|------|---------|-----|
| SC-1 | **Multi-version schema support** | `[ ]` | — | `policy.rs:validate_policy_version()` | [NGP §4.1.1](./nextgen-policy-roadmap.md#411-version-validation-change-required) |
| | Change strict `==` to `SUPPORTED_VERSIONS` set. Feature-gate: 1.1.0 → no new fields; 1.2.0 → posture + spider_sense allowed. | | | | |
| SC-2 | **Posture types + validation** | `[ ]` | SC-1 | `Policy` struct | [NGP §10 PR 1-2](./nextgen-policy-roadmap.md#pr-1-schema-foundation) |
| | `PostureConfig`, `PostureState`, `PostureTransition`. Optional `posture` field on `Policy`. Validation (unique states, valid refs, reachability). | | | | |
| SC-3 | **`SpiderSenseConfig` in `GuardConfigs`** | `[ ]` | SC-1 | `GuardConfigs` struct | [SS §6.2](./spider-sense-integration.md#62-schema-v120-tier-3) |
| | `SpiderSenseConfig`, `SpiderSenseMode`, `SpiderSenseStages`, `StageConfig`, `DeepAnalysisConfig`, `SessionRiskConfig`. All `deny_unknown_fields`. | | | | |
| SC-4 | **`Decision::Sanitize` variant** | `[ ]` | SC-1 | `Decision` enum in `irm/mod.rs` | [SS §4.3](./spider-sense-integration.md#43-tier-3--first-class-schema-support-v120) |
| | `Sanitize { original, sanitized, reason }`. Update receipt, audit, aggregation. Cross-language design (TS). | | | | |
| SC-5 | **`PathAllowlistGuard`** | `[ ]` | SC-1 | `guards/forbidden_path.rs` | [NGP §10 PR 3](./nextgen-policy-roadmap.md#pr-3-filesystem-allowlist-guard) |
| | Deny-by-default scoping. Shared `normalize_path_for_policy()` with `ForbiddenPathGuard`. | | | | |
| SC-6 | **TS SDK: posture + spider_sense + Sanitize types** | `[ ]` | SC-2, SC-3, SC-4 | `clawdstrike-policy` TS schema | [NGP §10 PR 1](./nextgen-policy-roadmap.md#pr-1-schema-foundation) |
| | Mirror all new Rust types in TypeScript. | | | | |

**Deliverable:** Schema v1.2.0 parses, validates, backward compat preserved.

---

## Milestone 4: Dynamic Policies Engine

Posture-aware evaluation. Wires into **existing engine pipeline and session state**.

| ID | Task | Status | Deps | Extends | Ref |
|----|------|--------|------|---------|-----|
| DP-1 | **Posture precheck** | `[ ]` | SC-2 | `engine.rs:check_action_report()` | [NGP §10 PR 4](./nextgen-policy-roadmap.md#pr-4-engine-posture-precheck) |
| | Compile `PostureConfig` → `PostureProgram`. Early deny if capability missing. No posture = all allowed. | | | | |
| DP-2 | **Budget enforcement** | `[ ]` | DP-1 | `SessionContext.state["posture"]` | [NGP §10 PR 5](./nextgen-policy-roadmap.md#pr-5-budget-enforcement) |
| | Track counters in `PostureRuntimeState`. Consume on allow, deny on exhaustion, reset on transition. | | | | |
| DP-3 | **Posture transitions** | `[ ]` | DP-2 | `engine.rs` | [NGP §10 PR 6](./nextgen-policy-roadmap.md#pr-6-transitions) |
| | `posture_postcheck()`. Violation triggers, budget exhaustion, wildcard `from: "*"`, timeouts, history. | | | | |

**Deliverable:** Engine enforces posture capabilities, budgets, and transitions.

---

## Milestone 5: Spider-Sense First-Class + Posture Integration

Promote Spider-Sense from custom guards to schema-driven. Wire risk score into posture transitions.

| ID | Task | Status | Deps | Extends | Ref |
|----|------|--------|------|---------|-----|
| SS-17 | **Wire `SpiderSenseConfig` into engine** | `[ ]` | SC-3, SS-9 | `engine.rs` | [SS §6.2](./spider-sense-integration.md#62-schema-v120-tier-3) |
| | Auto-register stage guards + async guard when `guards.spider_sense` present. Respect `mode`. | | | | |
| SS-18 | **Session risk tracking** | `[ ]` | SS-17, DP-2 | `SessionContext.state` | [SS §6.2](./spider-sense-integration.md#62-schema-v120-tier-3) |
| | Cumulative score, decay, escalation threshold, quarantine threshold. Store in `state["spider_sense"]`. | | | | |
| SS-19 | **Risk score → posture transitions** | `[ ]` | SS-18, DP-3 | posture transition triggers | [SS §6.3](./spider-sense-integration.md#63-interaction-with-dynamic-policies-roadmap) |
| | `risk_score >= quarantine_threshold` → `PostureTransition::EventDriven("spider_sense.quarantine")`. | | | | |
| SS-20 | **Trust-level-gated defense mode** | `[ ]` | SS-17 | `AgentIdentity.trust_level` | [SS §7.2](./spider-sense-integration.md#72-trust-level-gated-defense-mode) |
| | System/High → adaptive; Medium/Low/Untrusted → mandatory. Uses existing `TrustLevel` enum. | | | | |
| SS-21 | **Inter-agent threat propagation** | `[ ]` | SS-17 | `SignedMessage`, `AgentCapability::Custom` | [SS §7.3](./spider-sense-integration.md#73-inter-agent-threat-propagation) |
| | Threat alerts via existing signed messages. Gate with `Custom { name: "spider_sense.*" }` capability. | | | | |

**Deliverable:** Spider-Sense as first-class schema feature with session risk and multi-agent integration.

---

## Milestone 6: hushd + CLI

Wire posture and Spider-Sense into **existing daemon and CLI infrastructure**.

| ID | Task | Status | Deps | Extends | Ref |
|----|------|--------|------|---------|-----|
| HC-1 | **Session posture endpoints** | `[ ]` | DP-3 | `hushd/src/session/`, `hushd/src/api/` | [NGP §10 PR 7](./nextgen-policy-roadmap.md#pr-7-hushd-integration) |
| | Add `/session/{id}/transition` + `/session/{id}/posture`. Posture info in `CheckResponse`. Atomic SQLite updates. **Session infra already handles persistence.** | | | | |
| HC-2 | **Receipt posture metadata** | `[ ]` | DP-3 | `receipt.metadata` field | [NGP §10 PR 8](./nextgen-policy-roadmap.md#pr-8-receiptaudit-metadata-enrichment) |
| | Posture/budget/transition snapshots under `receipt.metadata.clawdstrike.posture`. JSON merge helper. **Receipt signing infra untouched.** | | | | |
| HC-3 | **`hush policy observe`** | `[ ]` | HC-2 | hush-cli | [NGP §10 PR 9](./nextgen-policy-roadmap.md#pr-9-cli-policy-observe) |
| | New command. Event recording to JSONL. Works with local engine or hushd. | | | | |
| HC-4 | **`hush policy synth`** | `[ ]` | HC-3 | hush-cli | [NGP §10 PR 10](./nextgen-policy-roadmap.md#pr-10-cli-policy-synth) |
| | New command. Event analysis → policy generation. Safety defaults. Diff/patch output. | | | | |
| HC-5 | **Extend simulate/test/migrate for posture** | `[ ]` | DP-3 | `policy_pac.rs` (existing simulate) | [NGP §10 PR 11](./nextgen-policy-roadmap.md#pr-11-cli-extensions) |
| | `--track-posture` flag, posture assertions, `hush policy migrate 1.1.0 → 1.2.0`. | | | | |
| HC-6 | **Spider-Sense CLI commands** | `[ ]` | SS-17 | hush-cli | [SS §9 P3](./spider-sense-integration.md#phase-3-first-class-feature-23-weeks) |
| | `hush spider-sense status`, `hush spider-sense db update`. | | | | |

---

## Milestone 7: Documentation

| ID | Task | Status | Deps | Ref |
|----|------|--------|------|-----|
| DOC-1 | Posture concept docs + tutorials | `[ ]` | DP-3 | [NGP §10 PR 12](./nextgen-policy-roadmap.md#pr-12-documentation) |
| DOC-2 | Observe/synth workflow guide | `[ ]` | HC-4 | [NGP §10 PR 12](./nextgen-policy-roadmap.md#pr-12-documentation) |
| DOC-3 | Spider-Sense integration guide | `[ ]` | SS-17 | [SS §9 P3](./spider-sense-integration.md#phase-3-first-class-feature-23-weeks) |
| DOC-4 | Schema v1.2.0 reference | `[ ]` | SC-2, SC-3 | [NGP §10 PR 12](./nextgen-policy-roadmap.md#pr-12-documentation) |
| DOC-5 | Example policies (posture + spider-sense) | `[ ]` | SS-9, SC-2 | [NGP §10 PR 12](./nextgen-policy-roadmap.md#pr-12-documentation) |
| DOC-6 | Migration guide 1.1.0 → 1.2.0 | `[ ]` | HC-5 | [SS §9 P3](./spider-sense-integration.md#phase-3-first-class-feature-23-weeks) |

---

## Milestone 8: Hardening (Ongoing)

| ID | Task | Status | Deps | Ref |
|----|------|--------|------|-----|
| H-1 | Pattern DB curation (ongoing) | `[ ]` | SS-4 | [SS §9 P4](./spider-sense-integration.md#phase-4-hardening-ongoing) |
| H-2 | S2Bench CI regression testing | `[ ]` | SS-10 | [SS §9 P4](./spider-sense-integration.md#phase-4-hardening-ongoing) |
| H-3 | Adaptive threshold learning | `[ ]` | SS-18 | [SS §9 P4](./spider-sense-integration.md#phase-4-hardening-ongoing) |
| H-4 | Multi-agent scenario tests | `[ ]` | SS-21 | [SS §9 P4](./spider-sense-integration.md#phase-4-hardening-ongoing) |
| H-5 | SIMD cosine similarity optimization | `[ ]` | SS-2 | [SS §9 P4](./spider-sense-integration.md#phase-4-hardening-ongoing) |

---

## Critical Path

```
D-1/D-2 → SS-1 → SS-2/SS-3 → SS-4 → SS-5..8 → SS-9 → SS-10
                                                    │
                                                    ├→ SS-11..14 (deep analysis)
                                                    │
SC-1 → SC-2 → DP-1 → DP-2 → DP-3 ──→ HC-1 → HC-2 → HC-3 → HC-4
  │                                │
  ├→ SC-3 → SS-17 → SS-18 → SS-19 │
  │            │                   │
  ├→ SC-4      ├→ SS-20, SS-21    └→ HC-5
  └→ SC-5
```

Milestones 1–2 (Spider-Sense guards) and Milestone 3 (schema bump) can proceed **in parallel**.

---

## Summary

| Category | New Tasks | Extends Existing |
|----------|-----------|-----------------|
| Spider-Sense crate + guards | 10 | `CustomGuardRegistry`, `CustomGuardFactory` |
| Spider-Sense deep analysis | 6 | `AsyncGuard`, `AsyncGuardRuntime`, SSE broadcast |
| Schema v1.2.0 | 6 | `Policy`, `GuardConfigs`, `Decision`, TS schema |
| Dynamic Policies engine | 3 | `engine.rs`, `SessionContext.state` |
| Spider-Sense first-class | 5 | Engine, `TrustLevel`, `SignedMessage` |
| hushd + CLI | 6 | Session API, receipt metadata, `hush-cli` |
| Documentation | 6 | — |
| Hardening | 5 | — |
| **Total** | **47** | |

Down from 62 → **47 tasks** after removing infrastructure that already exists. The existing `CustomGuardRegistry`, `AsyncGuard` runtime, session management, SIEM, SSE, multi-agent, and receipt systems are extension points — not rebuild targets.
