# Next-Gen Dynamic Policies Roadmap

**Status:** DRAFT
**Author:** Claude (Planner Mode)
**Date:** 2026-02-05
**Target:** Clawdstrike v1.2.0+

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Current-State Architecture Map](#2-current-state-architecture-map)
3. [Target Architecture Overview](#3-target-architecture-overview)
4. [Schema Plan](#4-schema-plan)
5. [Engine Plan](#5-engine-plan)
6. [hushd Plan](#6-hushd-plan)
7. [CLI Plan](#7-cli-plan)
8. [Test Plan](#8-test-plan)
9. [Doc Plan](#9-doc-plan)
10. [PR Series Roadmap](#10-pr-series-roadmap)
11. [Open Questions](#11-open-questions--decisions-needed)
- [Appendix A: Capability Mapping](#appendix-a-capability-mapping)
- [Appendix B: Transition Trigger Mapping](#appendix-b-transition-trigger-mapping)
- [Appendix C: Event Schema](#appendix-c-event-schema-for-observesynth)
- [Appendix D: Related Files](#appendix-d-related-roadmap-files)
- [Appendix E: Glossary](#appendix-e-glossary)

---

## Naming Convention

| Name | Usage |
|------|-------|
| **clawdstrike** | Core library crate, product name, TypeScript packages |
| **hush** | CLI binary (`hush policy ...`, `hush run ...`) |
| **hushd** | Daemon binary and crate |
| **hush-*** | Supporting Rust crates (hush-core, hush-cli, hush-proxy, etc.) |

---

## 1. Executive Summary

This roadmap describes how to evolve Clawdstrike's policy system from **static YAML rules** to **dynamic session-aware policies** that support:

- **Session Posture/States**: Named security states (e.g., `observe`, `work`, `elevated`, `quarantine`) with different capability sets
- **Capability Budgets**: Numeric limits on actions (file writes, network calls, tool invocations) that deplete over a session
- **State Transitions**: Event-driven or time-based transitions between postures (violation → quarantine, approval → elevated)
- **Observe → Synthesize → Tighten**: A workflow to record agent activity, then generate least-privilege policy candidates
- **Internal DAG Evaluation**: Fast-path/deep-path guard pipelines (hidden from users)

### What Ships (Backwards Compatible)

| Feature | Compatibility | Notes |
|---------|---------------|-------|
| Existing 1.1.0 policies | ✅ Unchanged | No posture = "default" state with all capabilities |
| `extends` / `merge_strategy` | ✅ Unchanged | Posture blocks merge via `deep_merge` |
| Built-in guards | ✅ Unchanged | Guards unaware of posture (engine orchestrates) |
| Async guards | ✅ Unchanged | Gated by posture capabilities |
| CLI commands | ✅ Unchanged | New `observe`/`synth` commands added |
| Receipt/audit format | ✅ Extended* | Posture/budget/transition data embedded under `receipt.metadata.clawdstrike.posture` (no schema bump) |

\* **Receipt compatibility note:** receipts are currently schema/version locked and parsed with `deny_unknown_fields` in hush-core. Adding new *top-level* receipt fields requires a receipt schema bump + multi-language updates, or you can keep the receipt schema stable by placing new posture fields under `receipt.metadata.clawdstrike.posture`.

### What's New (Opt-In)

- Schema version `1.2.0` with optional `posture` block
- `PostureRuntimeState` stored in existing `SessionContext.state["posture"]`
- `hush policy observe` / `hush policy synth` commands
- Posture snapshots in `receipt.metadata.clawdstrike.posture` and `AuditEvent.metadata.clawdstrike.posture`

---

## 2. Current-State Architecture Map

### 2.1 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              POLICY LOADING                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│  YAML File/Ruleset                                                          │
│       │                                                                     │
│       ▼                                                                     │
│  Policy::from_yaml_with_extends_resolver()                                  │
│       │                                                                     │
│       ├─→ LocalPolicyResolver::resolve()                                    │
│       │       ├─→ RuleSet::by_name() (builtin: default, strict, ...)       │
│       │       └─→ File system lookup (relative paths)                       │
│       │                                                                     │
│       ├─→ Cycle detection (visited HashSet<key>)                           │
│       │                                                                     │
│       └─→ Policy::merge() with MergeStrategy                               │
│               ├─→ Replace: child wins                                       │
│               ├─→ Merge: shallow, replace whole top-level blocks           │
│               └─→ DeepMerge: recursive GuardConfigs merge                  │
│                                                                             │
│       ▼                                                                     │
│  Policy::validate()                                                         │
│       ├─→ Version check (must be "1.1.0")                                  │
│       ├─→ Glob/regex pattern compilation                                   │
│       ├─→ Placeholder validation (${env}, ${secrets.x})                    │
│       └─→ Custom guard config validation                                   │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ENGINE COMPILATION                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  HushEngine::with_policy(policy)                                            │
│       │                                                                     │
│       ├─→ policy.create_guards() → PolicyGuards                             │
│       │       ForbiddenPath, EgressAllowlist, SecretLeak,                  │
│       │       PatchIntegrity, McpTool, PromptInjection, Jailbreak          │
│       │                                                                     │
│       ├─→ build_async_guards() → Vec<Arc<dyn AsyncGuard>>                  │
│       │       VirusTotal, SafeBrowsing, Snyk (from guards.custom[])        │
│       │                                                                     │
│       ├─→ build_custom_guards_from_policy() → Vec<Box<dyn Guard>>          │
│       │       (via CustomGuardRegistry)                                     │
│       │                                                                     │
│       └─→ AsyncGuardRuntime::new()                                         │
│               (cache, rate limiter, circuit breaker per guard)             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          HUSHD POLICY RESOLUTION                            │
├─────────────────────────────────────────────────────────────────────────────┤
│  CheckRequest arrives with:                                                 │
│       session_id, action_type, target, content, args                       │
│                                                                             │
│       ▼                                                                     │
│  PolicyResolver::resolve_policy(GuardContext)                               │
│       │                                                                     │
│       ├─→ List scoped policies from DB                                     │
│       ├─→ Filter by scope (Global, Org, Team, Project, Role, User)         │
│       ├─→ Evaluate scope conditions (identity, request, time)              │
│       ├─→ Sort by priority                                                 │
│       └─→ Merge matching policies → ResolvedPolicy                         │
│                                                                             │
│       ▼                                                                     │
│  PolicyEngineCache::get_or_insert_with()                                    │
│       Key: SHA256(resolved_policy_yaml)                                    │
│       Value: CachedEngine { engine: Arc<HushEngine>, inserted_at }         │
│       TTL: configurable, eviction on max_entries                           │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ACTION CHECKING                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│  engine.check_action_report(action, context)                                │
│       │                                                                     │
│       ├─→ [1] Built-in guards (stable order):                              │
│       │       forbidden_path → egress_allowlist → secret_leak →            │
│       │       patch_integrity → mcp_tool → prompt_injection → jailbreak   │
│       │                                                                     │
│       ├─→ [2] Custom guards (policy.custom_guards[])                       │
│       │                                                                     │
│       ├─→ [3] Extra guards (appended at runtime)                           │
│       │                                                                     │
│       ├─→ [4] Fail-fast check (if enabled, break on first deny)            │
│       │                                                                     │
│       └─→ [5] Async guards (only if all prior allowed)                     │
│               execution_mode: parallel | sequential | background           │
│               timeout → on_timeout behavior (allow/deny/warn/defer)        │
│                                                                             │
│       ▼                                                                     │
│  aggregate_overall(per_guard_results) → GuardResult                         │
│       Rule: denials > allows; within same status, highest severity wins    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          DECISION & RECEIPT                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  GuardReport { overall: GuardResult, per_guard: Vec<GuardResult> }         │
│       │                                                                     │
│       ├─→ Decision { status, guard, severity, message, reason, details }   │
│       │                                                                     │
│       ├─→ AuditEvent (recorded to SQLite ledger)                           │
│       │       action_type, target, decision, guard, severity, message,     │
│       │       session_id, policy_hash, contributing_policies               │
│       │                                                                     │
│       ├─→ AuditEventV2 (hash-chained for integrity)                        │
│       │       previous_hash, content_hash, signature                       │
│       │                                                                     │
│       └─→ Receipt (signed with Ed25519)                                    │
│               verdict, provenance.violations[], policy_hash                │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Key Files and Symbols

> **Note:** Line numbers are approximate and may drift as the codebase evolves.

| Component | File | Key Symbols | Lines (approx) |
|-----------|------|-------------|----------------|
| **Policy Schema** | `crates/clawdstrike/src/policy.rs` | `Policy`, `GuardConfigs`, `PolicySettings`, `MergeStrategy`, `POLICY_SCHEMA_VERSION` | 21, 136-174, 383-393 |
| **Policy Validation** | `crates/clawdstrike/src/policy.rs` | `Policy::validate()`, `validate_policy_version()` | 444-663, 913-925 |
| **Policy Merge** | `crates/clawdstrike/src/policy.rs` | `Policy::merge()`, `GuardConfigs::merge_with()` | 690-760, 228-272 |
| **Policy Resolver** | `crates/clawdstrike/src/policy.rs` | `PolicyResolver` trait, `LocalPolicyResolver`, `from_yaml_with_extends_resolver()` | 78-131, 775-826 |
| **Engine** | `crates/clawdstrike/src/engine.rs` | `HushEngine`, `check_action_report()`, `aggregate_overall()` | 25-57, 274-393, 552-574 |
| **Guard Trait** | `crates/clawdstrike/src/guards/mod.rs` | `Guard` trait, `GuardResult`, `GuardAction` (line 210), `GuardContext` | 228-238, 64-120, 210-225, 123-145 |
| **Async Guards** | `crates/clawdstrike/src/async_guards/` | `AsyncGuard` trait, `AsyncGuardRuntime`, `AsyncGuardConfig` | types.rs:86-106, runtime.rs |
| **Identity & Session** | `crates/clawdstrike/src/identity.rs` | `SessionContext` (line 156), `IdentityPrincipal`, `RequestContext` | 156-174, 28-80, 116-138 |
| **hushd Check API** | `crates/hushd/src/api/check.rs` | `CheckRequest` (line 65), `CheckResponse` (line 85) | 64-92 |
| **hushd Session** | `crates/hushd/src/session/mod.rs` | `SessionManager` (line 272), `SessionStore` trait, `StoredSession` | 272-320, 45-50, 31-34 |
| **Policy Scoping** | `crates/hushd/src/policy_scoping/mod.rs` | `PolicyResolver::resolve_policy()`, `ResolvedPolicy` | 596-676, 177 |
| **Engine Cache** | `crates/hushd/src/policy_engine_cache.rs` | `PolicyEngineCache`, `CachedEngine` | 1-78 |
| **Receipt** | `crates/hush-core/src/receipt.rs` | `Receipt`, `SignedReceipt`, `Verdict`, `ViolationRef` | 154-175, 245-253, 59-74, 118-131 |
| **CLI Policy Cmds** | `crates/hush-cli/src/*.rs` | `cmd_policy_migrate()`, `cmd_policy_eval()`, `cmd_policy_simulate()`, `cmd_policy_impact()` + helpers in `policy_diff.rs` | Various |
| **TS Policy Schema** | `packages/clawdstrike-policy/src/policy/schema.ts` | `Policy`, `GuardConfigs`, `PolicySettings` | 70-79, 52-62 |
| **TS Engine** | `packages/clawdstrike-policy/src/engine.ts` | `createPolicyEngineFromPolicy()`, `aggregateOverall()` | 27-68, 177-200 |

> **MergeStrategy detail:** In the current Rust implementation, `merge_strategy: merge` is *not* a per-guard/per-field merge. It replaces entire top-level blocks (`guards`, `settings`, `custom_guards`) when the child provides any non-default values. Use `deep_merge` for compositional policy authoring.

### 2.3 Existing Session State Field

**Key discovery:** `SessionContext` (in `crates/clawdstrike/src/identity.rs:156`) already has a flexible state field:

```rust
pub struct SessionContext {
    pub session_id: String,
    pub identity: IdentityPrincipal,
    // ... other fields ...

    /// Arbitrary session state - CAN BE LEVERAGED FOR POSTURE
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<HashMap<String, serde_json::Value>>,
}
```

This existing `state` field can store posture runtime state without schema changes to `SessionContext`. The posture state would be stored as:

```json
{
  "posture": {
    "current_state": "work",
    "entered_at": "2026-02-05T10:00:00Z",
    "budgets": {
      "file_writes": { "used": 5, "limit": 50 }
    }
  }
}
```

---

## 3. Target Architecture Overview

### 3.1 Core Concepts

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         POSTURE-AWARE POLICY                                │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Policy                                                                     │
│  ├── version: "1.2.0"                                                      │
│  ├── guards: { ... }         ← Existing, unchanged                         │
│  ├── settings: { ... }       ← Existing, unchanged                         │
│  │                                                                          │
│  └── posture:                ← NEW, optional                               │
│       ├── initial: "observe"                                               │
│       ├── states:                                                          │
│       │    ├── observe:      { capabilities: [...], budgets: {...} }       │
│       │    ├── work:         { capabilities: [...], budgets: {...} }       │
│       │    ├── elevated:     { capabilities: [...], budgets: {...} }       │
│       │    └── quarantine:   { capabilities: [], budgets: {} }             │
│       └── transitions:                                                      │
│            ├── { from: observe, to: work, on: user_approval }              │
│            ├── { from: *, to: quarantine, on: critical_violation }         │
│            └── { from: quarantine, to: observe, on: timeout, after: 5m }   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SESSION CONTEXT (Runtime)                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  SessionCtx                                                                 │
│  ├── session_id: String                                                    │
│  ├── policy_hash: String                                                   │
│  │                                                                          │
│  ├── posture:                ← NEW                                         │
│  │    ├── current_state: "work"                                            │
│  │    ├── entered_at: "2026-02-05T10:00:00Z"                               │
│  │    └── transition_history: Vec<TransitionRecord>                        │
│  │                                                                          │
│  ├── budgets:                ← NEW                                         │
│  │    ├── file_writes: { used: 5, limit: 50 }                              │
│  │    ├── egress_calls: { used: 3, limit: 20 }                             │
│  │    └── mcp_tool_calls: { used: 10, limit: 100 }                         │
│  │                                                                          │
│  └── event_ring: RingBuffer<RecentEvent>  ← NEW (for pattern detection)    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         EVALUATION FLOW (Enhanced)                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. POSTURE PRE-CHECK                                                       │
│     ├── Is action_type in current_state.capabilities?                      │
│     ├── Is relevant budget available?                                      │
│     └── If no → DENY early (no guard evaluation needed)                    │
│                                                                             │
│  2. GUARD EVALUATION (existing pipeline)                                    │
│     ├── Built-in guards                                                    │
│     ├── Custom guards                                                      │
│     ├── Async guards (gated by capabilities)                               │
│     └── Aggregation                                                        │
│                                                                             │
│  3. POSTURE POST-CHECK                                                      │
│     ├── If violation → check transition triggers (→ quarantine?)           │
│     ├── If allowed → consume budget, check transition triggers             │
│     ├── Check time-based transitions (timeout → downgrade?)                │
│     └── Update SessionCtx posture state                                    │
│                                                                             │
│  4. AUDIT / RECEIPT (metadata)                                              │
│     ├── receipt.metadata.clawdstrike.posture: {...}                        │
│     ├── audit_event.metadata.clawdstrike.posture: {...}                    │
│     └── explanation_tree: { ... }                                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Internal DAG Pipelines (Hidden from Users)

Users author **states + capabilities + transitions**. Internally, the engine can optimize:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    INTERNAL GUARD DAG (Not User-Facing)                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Capability: file_write                                                     │
│  ┌────────────┐                                                            │
│  │ fast_path  │ ─── quick checks (forbidden_path, in-memory) ──┐           │
│  └────────────┘                                                 │           │
│        │                                                        │           │
│        ▼ (if pass)                                              │           │
│  ┌────────────┐                                                 │           │
│  │ std_path   │ ─── content guards (secret_leak, patch) ───────┤           │
│  └────────────┘                                                 │           │
│        │                                                        │           │
│        ▼ (if suspicious)                                        ▼           │
│  ┌────────────┐                                           ┌──────────┐     │
│  │ deep_path  │ ─── async guards (virustotal, model) ───▶│ DECISION │     │
│  └────────────┘                                           └──────────┘     │
│                                                                             │
│  Receipt includes: "evaluation_path: fast_path → std_path"                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

This is an **internal optimization**. Users don't author DAGs; they get fast evaluations + explainable receipts.

### 3.3 Enforcement Completeness (Mediation Model)

Posture budgets and capability gates only matter if **all relevant action paths are mediated** by clawdstrike/hushd. If an agent/runtime can perform an operation without first calling the policy engine, then:

- budgets can be bypassed,
- observe logs become incomplete (synth underfits),
- “least privilege” degrades into “best effort”.

**Rule:** treat posture budgets as **strict** only for action kinds that are fully mediated.

#### Current Mediation Reality (today)

| Action kind | Where it is mediated today | Notes |
|------------|----------------------------|-------|
| `egress` | `hush run` CONNECT proxy and `/api/v1/check` | Proxy is the most “complete” enforcement path available today. |
| `patch` | Only if patch application code calls `check_patch`/`/api/v1/check` | Not OS-level; must be routed through the enforcer. |
| `mcp_tool` | Only if tool runner calls `check_mcp_tool`/`/api/v1/check` | Requires adapter completeness. |
| `file_access`, `file_write` | Only if the runtime calls `check_file_*`/`/api/v1/check` | No automatic interception; without wrappers this is audit-only. |
| `shell` | `/api/v1/check` supports it; `hush run` currently emits `command_exec` as audit-only | Enforcing shell commands requires the runtime/tool runner to mediate. |

#### Required Strategy (executor-ready)

1. **Single enforcement gateway:** in each runtime/integration, route privileged operations through one function (e.g., `enforce(action, context)`), which calls local engine or `/api/v1/check`.
2. **No bypass paths:** ensure every tool/action implementation uses the gateway (MCP adapters, patch application, file IO helpers, shell exec wrappers, network proxy).
3. **Fail-closed defaults:** if the gateway cannot reach hushd or persist posture updates, treat posture-enabled checks as denied or error (never “allow and hope”).
4. **Observe completeness:** `hush policy observe` should record the same mediated actions the executor will later enforce; otherwise synth will not produce safe least-privilege candidates.

---

## 4. Schema Plan

### 4.1 Schema Evolution Strategy

**Recommendation:** Single schema bump to `1.2.0` with an optional `posture` block.

| Approach | Pros | Cons |
|----------|------|------|
| **Option A: 1.2.0 + `posture` block** | Clean opt-in, existing policies unchanged, version signals feature support | Requires bumping version constant |
| Option B: `extensions` map | No version bump needed | More complex validation, unclear semantics |
| Option C: Fit into existing fields | No schema change | Hacky, unclear intent, validation issues |

**Decision: Option A** — bump to `1.2.0`, add optional `posture` block.

### 4.1.1 Version Validation Change Required

The current version check in `policy.rs:920` uses strict equality:

```rust
if version != POLICY_SCHEMA_VERSION {
    return Err(Error::UnsupportedPolicyVersion { ... });
}
```

This must change to a "supported versions" check:

```rust
const SUPPORTED_VERSIONS: &[&str] = &["1.1.0", "1.2.0"];

fn validate_policy_version(version: &str) -> Result<(), Error> {
    // ... semver parsing ...
    if !SUPPORTED_VERSIONS.contains(&version) {
        return Err(Error::UnsupportedPolicyVersion { ... });
    }
    Ok(())
}
```

#### Feature Gating by Version (recommended)

To keep intent explicit and avoid “1.1.0 file that accidentally uses 1.2.0 features”, validation should enforce:

- `version: "1.1.0"` → **no** `posture:` block and **no** `guards.path_allowlist` config.
- `version: "1.2.0"` → posture + path allowlist allowed (both optional).

### 4.2 New YAML Shape

```yaml
# Schema 1.2.0 additions
posture:
  # Which state to start in (required if posture block exists)
  initial: observe

  # State definitions
  states:
    observe:
      description: "Monitoring mode - read-only, learning"
      capabilities:
        - file_access
      budgets: {}  # No budget limits in observe

    work:
      description: "Normal working mode"
      capabilities:
        - file_access
        - file_write
        - egress
        - mcp_tool
      budgets:
        file_writes: 50
        egress_calls: 20
        mcp_tool_calls: 100

    elevated:
      description: "Elevated privileges after approval"
      capabilities:
        - file_access
        - file_write
        - egress
        - mcp_tool
        - shell  # Only in elevated
      budgets:
        file_writes: 200
        egress_calls: 50
        shell_commands: 10

    quarantine:
      description: "Locked down after violation"
      capabilities: []  # No capabilities
      budgets: {}

  # Transition rules
  transitions:
    - from: observe
      to: work
      on: user_approval

    - from: work
      to: elevated
      on: user_approval
      requires:
        - no_violations_in: 5m

    - from: "*"  # Wildcard: any state
      to: quarantine
      on: critical_violation

    - from: quarantine
      to: observe
      on: timeout
      after: 5m

    - from: elevated
      to: work
      on: timeout
      after: 30m

    - from: "*"
      to: quarantine
      on: budget_exhausted
```

### 4.3 Capability Types

Based on `GuardAction` enum in `crates/clawdstrike/src/guards/mod.rs:210`:

| Capability | Maps to GuardAction | Budget Key | Notes |
|------------|---------------------|------------|-------|
| `file_access` | `FileAccess(&str)` | - | Read-ish file operations (no budget by default) |
| `file_write` | `FileWrite(&str, &[u8])` | `file_writes` | |
| `egress` | `NetworkEgress(&str, u16)` | `egress_calls` | |
| `shell` | `ShellCommand(&str)` | `shell_commands` | High-risk, often excluded |
| `mcp_tool` | `McpTool(&str, &Value)` | `mcp_tool_calls` | |
| `patch` | `Patch(&str, &str)` | `patches` | |
| `custom` | `Custom(&str, &Value)` | `custom_calls` | For custom guard actions |

**Important:** Capabilities map 1:1 with `GuardAction` variants and hushd `action_type` strings. The YAML uses lowercase snake_case names.

### 4.3.1 PolicyEvent → ActionType Mapping (Recommended)

To avoid naming confusion:

- **PolicyEvent** uses higher-level `eventType` strings (e.g., `file_read`, `network_egress`).
- **Enforcement** in clawdstrike/hushd ultimately happens on `GuardAction` / hushd `action_type`.
- Posture `capabilities` should gate **those** action kinds.

| PolicyEvent `eventType` | hushd `action_type` | GuardAction | Capability |
|-------------------------|---------------------|-------------|------------|
| `file_read` | `file_access` | `FileAccess` | `file_access` |
| `file_write` | `file_write` | `FileWrite` | `file_write` |
| `network_egress` | `egress` | `NetworkEgress` | `egress` |
| `command_exec` | `shell` | `ShellCommand` | `shell` |
| `patch_apply` | `patch` | `Patch` | `patch` |
| `tool_call` (MCP) | `mcp_tool` | `McpTool` | `mcp_tool` |
| `tool_call` (non-MCP) | `custom` | `Custom("tool_call", ...)` | `custom` |

### 4.3.2 Filesystem Least-Privilege Requires an Allowlist Guard

`forbidden_path` is a **denylist**: it can block known-sensitive patterns, but it cannot express “the agent may only touch *these* paths”. For true least-privilege file access, we need an allowlist-style guard.

**Decision:** add a new built-in guard `path_allowlist` (deny-by-default when enabled).

#### Proposed YAML

```yaml
guards:
  # Deny-by-default filesystem scoping
  path_allowlist:
    enabled: true

    # Applies to GuardAction::FileAccess targets
    file_access_allow:
      - "**/my-repo/**"
      - "/tmp/**"

    # Applies to GuardAction::FileWrite targets
    file_write_allow:
      - "**/my-repo/**"
      - "/tmp/**"

    # Applies to GuardAction::Patch targets (optional; default = file_write_allow)
    patch_allow:
      - "**/my-repo/**"
```

#### Matching & Normalization (important)

The current `forbidden_path` guard only normalizes path separators (`\\` → `/`). For allowlist correctness, `path_allowlist` must apply **the same normalization** and should additionally do **lexical path normalization** (no filesystem calls required):

- collapse multiple separators,
- remove `.` segments,
- resolve `..` segments where possible.

Recommendation: introduce a shared helper (e.g., `normalize_path_for_policy(&str) -> String`) and use it in both `forbidden_path` and `path_allowlist`.

#### How Observe/Synth Should Use This

When synthesizing least-privilege policies from observed events:

- Prefer generating `guards.path_allowlist.*_allow` patterns from observed file paths.
- Do **not** auto-generate `forbidden_path.exceptions` as a default edit. If observed workload conflicts with an existing forbidden pattern, emit it as a **review-only risk note**.

### 4.4 Transition Triggers

| Trigger | Description | Parameters |
|---------|-------------|------------|
| `user_approval` | Explicit user/system approval | - |
| `user_denial` | Explicit user/system denial | - |
| `critical_violation` | Guard returned critical severity deny | - |
| `any_violation` | Guard returned any deny | - |
| `timeout` | Time elapsed in current state | `after: <duration>` |
| `budget_exhausted` | Any budget exhausted (`used >= limit`) | - |
| `pattern_match` | Event pattern detected (future) | `pattern: <name>` |

### 4.5 Unknown Fields Behavior

```rust
// Serde config for Policy (unchanged)
#[serde(deny_unknown_fields)]
pub struct Policy { ... }

// New: Posture also strict
#[serde(deny_unknown_fields)]
pub struct PostureConfig { ... }

#[serde(deny_unknown_fields)]
pub struct PostureState { ... }

#[serde(deny_unknown_fields)]
pub struct PostureTransition { ... }
```

**Rationale:** Fail-closed on unknown fields prevents typos from being silently ignored.

### 4.6 Example Policies

#### Example 1: Minimal Observe/Work/Quarantine

```yaml
version: "1.2.0"
name: Minimal Posture
extends: clawdstrike:default

posture:
  initial: observe

  states:
    observe:
      capabilities: [file_access]

    work:
      capabilities: [file_access, file_write, egress, mcp_tool]
      budgets:
        file_writes: 50

    quarantine:
      capabilities: []

  transitions:
    - { from: observe, to: work, on: user_approval }
    - { from: "*", to: quarantine, on: critical_violation }
    - { from: quarantine, to: observe, on: timeout, after: 5m }
```

#### Example 2: No Posture (Backwards Compatible)

```yaml
version: "1.2.0"  # Or "1.1.0" - both work
name: Classic Policy
extends: clawdstrike:default

guards:
  forbidden_path:
    additional_patterns:
      - "**/secrets/**"

settings:
  fail_fast: true
```

When no `posture` block exists, engine uses implicit "default" state with all capabilities and no budgets.

#### Example 3: Posture + Budgets + Transitions

```yaml
version: "1.2.0"
name: Enterprise Agent Policy
description: Production policy with observe-work-elevated flow

extends: clawdstrike:strict

posture:
  initial: observe

  states:
    observe:
      description: Learning mode - read only
      capabilities:
        - file_access
      budgets: {}

    work:
      description: Standard working mode
      capabilities:
        - file_access
        - file_write
        - egress
        - mcp_tool
      budgets:
        file_writes: 100
        egress_calls: 50
        mcp_tool_calls: 200

    elevated:
      description: Admin mode with shell access
      capabilities:
        - file_access
        - file_write
        - egress
        - mcp_tool
        - shell
      budgets:
        file_writes: 500
        egress_calls: 100
        shell_commands: 20

    quarantine:
      description: Violation lockdown
      capabilities: []

  transitions:
    # Normal progression
    - from: observe
      to: work
      on: user_approval

    - from: work
      to: elevated
      on: user_approval
      requires:
        - no_violations_in: 10m

    # Security responses
    - from: "*"
      to: quarantine
      on: critical_violation

    - from: "*"
      to: quarantine
      on: budget_exhausted

    # Recovery
    - from: quarantine
      to: observe
      on: user_approval

    # Timeouts
    - from: elevated
      to: work
      on: timeout
      after: 30m

guards:
  egress_allowlist:
    additional_allow:
      - "internal.corp.example.com"

settings:
  fail_fast: false
  verbose_logging: true
```

### 4.7 Migration Strategy

| Phase | Action | CLI Command |
|-------|--------|-------------|
| M0 | 1.1.0 policies continue working | N/A |
| M0 | 1.2.0 policies with no `posture` work identically | N/A |
| M1 | Migration command upgrades version field | `hush policy migrate --to 1.2.0` |
| M1 | No functional change for policies without posture | Auto |
| M2 | Lint warns if old version without posture | `hush policy lint --suggest-posture` |

### 4.8 Validation Rules

| Rule | Error Message |
|------|---------------|
| `version: "1.1.0"` cannot include `posture` | `posture requires policy version 1.2.0` |
| `version: "1.1.0"` cannot include `guards.path_allowlist` | `path_allowlist requires policy version 1.2.0` |
| `posture.initial` must name an existing state | `posture.initial 'foo' not found in states` |
| State names must be unique | `duplicate state name: 'work'` |
| Capabilities must be known types | `unknown capability: 'foo'` |
| Budget names must be known types | `unknown budget type: 'bar'` |
| Budget values must be non-negative | `budget 'file_writes' cannot be negative` |
| `guards.path_allowlist.*` patterns must be valid globs | `invalid glob in guards.path_allowlist.file_access_allow[0]` |
| Transitions must reference existing states | `transition references unknown state: 'foo'` |
| Wildcard `*` only valid in `from` | `wildcard in 'to' not allowed` |
| Timeout transitions require `after` | `timeout transition missing 'after' duration` |
| Duration format: `<n>s`, `<n>m`, `<n>h` | `invalid duration format: '5'` |
| No unreachable states (warning) | `state 'foo' has no incoming transitions (unreachable)` |
| No terminal states without timeout (warning) | `state 'quarantine' has no outgoing transitions` |

---

## 5. Engine Plan

### 5.1 New Data Structures

#### Rust: `crates/clawdstrike/src/posture.rs` (new file)

```rust
/// Compiled posture configuration (derived from YAML)
pub struct PostureProgram {
    pub initial_state: String,
    pub states: HashMap<String, CompiledState>,
    pub transitions: Vec<CompiledTransition>,
}

pub struct CompiledState {
    pub name: String,
    pub description: Option<String>,
    pub capabilities: HashSet<Capability>,
    pub budgets: HashMap<BudgetType, u64>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    FileAccess,
    FileWrite,
    Egress,
    Shell,
    McpTool,
    Patch,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetType {
    FileWrites,
    EgressCalls,
    ShellCommands,
    McpToolCalls,
    Patches,
}

pub struct CompiledTransition {
    pub from: TransitionSource,  // Specific(state) | Wildcard
    pub to: String,
    pub trigger: TransitionTrigger,
    pub requires: Vec<TransitionRequirement>,
}

pub enum TransitionTrigger {
    UserApproval,
    UserDenial,
    CriticalViolation,
    AnyViolation,
    Timeout(Duration),
    BudgetExhausted,
}

pub enum TransitionRequirement {
    NoViolationsIn(Duration),
}
```

#### Rust: `crates/clawdstrike/src/posture/runtime.rs` (new file)

These types are serialized to/from `SessionContext.state["posture"]`:

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Runtime posture state (stored in SessionContext.state["posture"])
/// Uses String timestamps for JSON serialization (not Instant)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostureRuntimeState {
    pub current_state: String,
    pub entered_at: String,  // ISO-8601
    pub transition_history: Vec<TransitionRecord>,
    pub budgets: HashMap<String, BudgetCounter>,
}

impl PostureRuntimeState {
    pub fn new(initial_state: &str, budgets: HashMap<String, BudgetCounter>) -> Self {
        Self {
            current_state: initial_state.to_string(),
            entered_at: chrono::Utc::now().to_rfc3339(),
            transition_history: Vec::new(),
            budgets,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransitionRecord {
    pub from: String,
    pub to: String,
    pub trigger: String,
    pub at: String,  // ISO-8601
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BudgetCounter {
    pub used: u64,
    pub limit: u64,
}

impl BudgetCounter {
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    pub fn is_exhausted(&self) -> bool {
        self.used >= self.limit
    }

    pub fn try_consume(&mut self) -> bool {
        if self.used < self.limit {
            self.used += 1;
            true
        } else {
            false
        }
    }
}

/// Helper to extract/update posture state from SessionContext.state
pub fn get_posture_state(session_state: &Option<HashMap<String, serde_json::Value>>)
    -> Option<PostureRuntimeState>
{
    session_state.as_ref()
        .and_then(|s| s.get("posture"))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
}

pub fn set_posture_state(
    session_state: &mut Option<HashMap<String, serde_json::Value>>,
    posture: &PostureRuntimeState,
) {
    let map = session_state.get_or_insert_with(HashMap::new);
    map.insert("posture".to_string(), serde_json::to_value(posture).unwrap());
}
```

#### Future: Event Ring Buffer (for pattern detection)

```rust
/// Ring buffer for recent events (pattern detection) - FUTURE FEATURE
pub struct EventRing {
    events: VecDeque<RecentEvent>,
    capacity: usize,
}

pub struct RecentEvent {
    pub action_type: String,
    pub target: String,
    pub result: bool,
    pub at: String,  // ISO-8601
}
```

### 5.2 Engine Modifications

#### File: `crates/clawdstrike/src/engine.rs`

The engine gains a new `posture_program: Option<PostureProgram>` field compiled from policy, and new methods for posture-aware evaluation.

```rust
use crate::posture::{PostureProgram, PostureRuntimeState, Capability, BudgetType, TransitionTrigger};

impl HushEngine {
    /// New method: posture-aware check that works with SessionContext.state
    pub async fn check_action_with_posture(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
        posture_state: &mut Option<PostureRuntimeState>,  // Extracted from SessionContext.state
    ) -> PostureAwareReport {
        let posture_enabled = self.posture_program.is_some();

        // IMPORTANT: if posture is configured, missing runtime state MUST initialize to posture.initial.
        if posture_enabled {
            self.ensure_posture_initialized(posture_state);
            self.apply_timeout_transitions(posture_state.as_mut().unwrap());
        }

        let posture_before = posture_state
            .as_ref()
            .map(|p| p.current_state.clone())
            .unwrap_or_else(|| "default".to_string());

        // 1. PRE-CHECK: Is action allowed in current posture?
        if posture_enabled {
            let precheck_result = self.posture_precheck(action, posture_state.as_ref().unwrap());
            if !precheck_result.allowed {
                return PostureAwareReport {
                    guard_report: GuardReport::from_precheck(precheck_result),
                    posture_before,
                    posture_after: posture_before.clone(),
                    budget_deltas: HashMap::new(),
                    transition: None,
                };
            }
        }

        // 2. GUARD EVALUATION (existing pipeline - unchanged)
        let guard_report = self.check_action_report(action, context).await;

        // 3. POST-CHECK: Transitions and budget updates
        let (transition, posture_after, budget_deltas) = if posture_enabled {
            self.posture_postcheck(action, &guard_report, posture_state)
        } else {
            (None, posture_before.clone(), HashMap::new())
        };

        PostureAwareReport {
            guard_report,
            posture_before,
            posture_after,
            budget_deltas,
            transition,
        }
    }

    fn ensure_posture_initialized(&self, posture_state: &mut Option<PostureRuntimeState>) {
        let Some(program) = self.posture_program.as_ref() else {
            return;
        };
        if posture_state.is_some() {
            return;
        }

        let initial = &program.initial_state;
        let budgets = program
            .states
            .get(initial)
            .map(|s| s.initial_budgets())
            .unwrap_or_default();
        *posture_state = Some(PostureRuntimeState::new(initial, budgets));
    }

    /// Apply time-based transitions (timeout) on each request.
    fn apply_timeout_transitions(&self, posture_state: &mut PostureRuntimeState) {
        let Some(program) = self.posture_program.as_ref() else {
            return;
        };
        // Pseudocode: parse entered_at, compare now, apply first matching timeout transition.
        // Any transition should reset entered_at and budgets for the new state.
        let _ = program;
        let _ = posture_state;
    }

    fn posture_precheck(&self, action: &GuardAction<'_>, state: &PostureRuntimeState) -> PosturePrecheck {
        let Some(program) = self.posture_program.as_ref() else {
            return PosturePrecheck::allow();
        };

        let Some(current) = program.states.get(&state.current_state) else {
            return PosturePrecheck::deny(
                "posture",
                format!("unknown posture state '{}'", state.current_state),
            );
        };
        let capability = Capability::from_action(action);

        // Check capability allowed in current state
        if !current.capabilities.contains(&capability) {
            return PosturePrecheck::deny(
                "posture",
                format!("action '{}' not allowed in state '{}'", capability, state.current_state),
            );
        }

        // Check budget not exhausted
        let budget_key = capability.budget_key();
        if let Some(counter) = state.budgets.get(budget_key) {
            if counter.is_exhausted() {
                return PosturePrecheck::deny(
                    "posture_budget",
                    format!("budget '{}' exhausted ({}/{})", budget_key, counter.used, counter.limit),
                );
            }
        }

        PosturePrecheck::allow()
    }

    fn posture_postcheck(
        &self,
        action: &GuardAction<'_>,
        report: &GuardReport,
        posture_state: &mut Option<PostureRuntimeState>,
    ) -> (Option<TransitionRecord>, String, HashMap<String, i64>) {
        let Some(program) = &self.posture_program else {
            return (None, "default".to_string(), HashMap::new());
        };
        let Some(state) = posture_state.as_mut() else {
            return (None, "default".to_string(), HashMap::new());
        };

        let mut budget_deltas = HashMap::new();

        // Determine trigger based on result
        let trigger = if !report.overall.allowed {
            match report.overall.severity {
                Severity::Critical => Some(TransitionTrigger::CriticalViolation),
                _ => Some(TransitionTrigger::AnyViolation),
            }
        } else {
            // Consume budget on success
            let capability = Capability::from_action(action);
            let budget_key = capability.budget_key();
            if let Some(counter) = state.budgets.get_mut(budget_key) {
                if counter.try_consume() {
                    // Delta is "used" (+1) to match receipt snapshot semantics.
                    budget_deltas.insert(budget_key.to_string(), 1);
                }
                if counter.is_exhausted() {
                    Some(TransitionTrigger::BudgetExhausted)
                } else {
                    None
                }
            } else {
                None
            }
        };

        // Find and apply matching transition
        if let Some(trigger) = trigger {
            if let Some(t) = program.find_transition(&state.current_state, &trigger) {
                let record = TransitionRecord {
                    from: state.current_state.clone(),
                    to: t.to.clone(),
                    trigger: trigger.to_string(),
                    at: chrono::Utc::now().to_rfc3339(),
                };

                // Update state
                state.current_state = t.to.clone();
                state.entered_at = chrono::Utc::now().to_rfc3339();
                state.transition_history.push(record.clone());

                // Reset budgets for new state
                if let Some(new_state_config) = program.states.get(&t.to) {
                    state.budgets = new_state_config.initial_budgets();
                }

                return (Some(record), t.to.clone(), budget_deltas);
            }
        }

        (None, state.current_state.clone(), budget_deltas)
    }
}
```

#### New Types: `crates/clawdstrike/src/posture/report.rs`

```rust
#[derive(Clone, Debug, Serialize)]
pub struct PostureAwareReport {
    pub guard_report: GuardReport,
    pub posture_before: String,
    pub posture_after: String,
    pub budget_deltas: HashMap<String, i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition: Option<TransitionRecord>,
}

#[derive(Clone, Debug)]
pub struct PosturePrecheck {
    pub allowed: bool,
    pub guard: String,
    pub message: String,
}

impl PosturePrecheck {
    pub fn allow() -> Self {
        Self { allowed: true, guard: "posture".into(), message: "".into() }
    }
    pub fn deny(guard: &str, message: String) -> Self {
        Self { allowed: false, guard: guard.into(), message }
    }
}
```

### 5.3 Receipt Enhancement

Receipts are currently schema/version locked and parsed with `deny_unknown_fields` in hush-core. Adding new *top-level* receipt fields would require a receipt schema bump plus multi-language updates.

**Decision (recommended for 1.2.0):** keep receipt schema stable and embed posture/budget/transition information under `receipt.metadata` using a namespaced key.

#### Proposed Receipt Metadata Shape

```json
{
  "clawdstrike": {
    "posture": {
      "state_before": "work",
      "state_after": "work",
      "budgets_before": {
        "file_writes": { "used": 5, "limit": 50 }
      },
      "budgets_after": {
        "file_writes": { "used": 6, "limit": 50 }
      },
      "budget_deltas": { "file_writes": 1 },
      "transition": null
    }
  }
}
```

#### Implementation Notes

- `Receipt` already has `metadata: Option<JsonValue>` (so this is additive).
- Multiple components already write receipt metadata (e.g., engine uses `metadata.clawdstrike.*`, CLI uses `metadata.hush.*`). To keep this additive, implement a small **JSON object merge** helper so adding posture metadata does not overwrite existing keys.
- Mirror the same posture snapshot into `AuditEvent.metadata.clawdstrike.posture` so observe/synth can work from audit exports without needing receipts.

#### Optional Future (only if needed)

If/when we want first-class typed receipt fields, bump receipt schema to `1.1.0` and teach verifiers/SDKs to accept both `1.0.0` and `1.1.0`. Treat that as a separate migration project.

### 5.4 Interaction with Existing Features

| Feature | Interaction | Notes |
|---------|-------------|-------|
| **fail_fast** | Unchanged | Posture precheck is a separate early exit |
| **Async guards** | Gated by posture | If `egress` not in capabilities, async guards don't run |
| **Custom guards** | Unaware of posture | Engine handles posture, guards see same GuardAction |
| **Policy merge/extends** | Posture deep-merges | Child posture states override base by name |
| **Policy scoping** | Applied before posture | Resolved policy includes posture, scoping doesn't change |

### 5.5 Posture Merge Behavior

When using `extends` with posture:

```yaml
# Base policy
posture:
  initial: observe
  states:
    observe: { capabilities: [file_access] }
    work: { capabilities: [file_access, file_write] }

# Child policy (extends base)
posture:
  states:
    work:  # Override work state
      capabilities: [file_access, file_write, egress]
    elevated:  # Add new state
      capabilities: [file_access, file_write, egress, shell]
```

Result: `observe` inherited, `work` overridden, `elevated` added.

---

## 6. hushd Plan

### 6.1 Session/Posture Keying

**Decision:** Posture state is keyed by `session_id`.

| Key Type | Behavior | Rationale |
|----------|----------|-----------|
| **session_id** (chosen) | Each session has independent posture | Natural boundary, matches existing SessionContext |
| user identity | Shared across sessions | Too coarse; one bad session affects all |
| process | Per-process isolation | Not applicable for hushd (multi-process) |
| workspace | Project-level posture | Possible future extension |

### 6.2 Session Storage

#### Leveraging Existing Infrastructure

The existing session system already supports arbitrary state storage:

**`crates/clawdstrike/src/identity.rs:156`** - `SessionContext.state`:
```rust
pub struct SessionContext {
    pub session_id: String,
    // ... identity, timestamps, roles, permissions ...

    /// Arbitrary key-value state - USE THIS FOR POSTURE
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<HashMap<String, serde_json::Value>>,
}
```

**`crates/hushd/src/session/mod.rs:31`** - `StoredSession`:
```rust
pub struct StoredSession {
    pub session: SessionContext,  // Contains the state field
    pub terminated_at: Option<String>,
}
```

**`crates/hushd/src/session/mod.rs:37`** - `SessionUpdates`:
```rust
pub struct SessionUpdates {
    // ... other fields ...
    pub state: Option<HashMap<String, serde_json::Value>>,  // Can update state!
}
```

#### Posture State Schema (stored in `SessionContext.state["posture"]`)

```rust
/// Stored as JSON in SessionContext.state["posture"]
#[derive(Serialize, Deserialize)]
pub struct PostureRuntimeState {
    pub current_state: String,
    pub entered_at: String,  // ISO-8601
    pub budgets: HashMap<String, BudgetCounter>,
    pub transition_history: Vec<TransitionRecord>,
}

#[derive(Serialize, Deserialize)]
pub struct BudgetCounter {
    pub used: u64,
    pub limit: u64,
}

#[derive(Serialize, Deserialize)]
pub struct TransitionRecord {
    pub from: String,
    pub to: String,
    pub trigger: String,
    pub at: String,  // ISO-8601
}
```

#### Existing Storage Backends (no changes needed)

**`crates/hushd/src/session/mod.rs`**:
- `InMemorySessionStore` (line 55) - `Arc<tokio::sync::RwLock<HashMap<String, StoredSession>>>` (primarily used in unit tests)
- `SqliteSessionStore` (line 145) - Persists to the control-plane SQLite DB (`config.control_db`, or `audit_db` by default)

**Persistence Strategy:**

- **Current hushd default:** SQLite-backed sessions (survive daemon restart until TTL/termination)
- **Unit tests:** In-memory session store is used in tests
- **Implication for posture:** If posture lives in `SessionContext.state["posture"]`, it will persist with the session unless explicitly cleared/reset on restart

### 6.3 Concurrency Handling

Budgets and transitions are **security controls**. They only work if posture runtime state updates are:

- **Atomic** (no lost updates)
- **Merge-safe** (no clobbering unrelated session state keys)
- **Serialized per session** (no budget overspend from concurrent requests)

The existing `SessionStore` trait (line 45 in `session/mod.rs`) already handles updates:

```rust
pub trait SessionStore: Send + Sync {
    fn set(&self, record: &StoredSession) -> Result<()>;
    fn get(&self, session_id: &str) -> Result<Option<StoredSession>>;
    fn update(&self, session_id: &str, updates: SessionUpdates) -> Result<Option<StoredSession>>;
    // ...
}
```

#### Current Reality (must be fixed for strict budgets)

- `SessionUpdates.state` **replaces the entire** `session.state` map (`apply_updates()` assigns `record.session.state = Some(value)`).
- `SqliteSessionStore::update()` is currently **read → modify → write** using separate `lock_conn()` calls (`get()` then `set()`), so it is **last-write-wins** under concurrency.
- `InMemorySessionStore` uses a single write lock, so it behaves atomically in tests, but production defaults to SQLite.

#### Required Invariants

1. If posture is configured, a session with missing `state["posture"]` must be **initialized to `posture.initial`** (no implicit “allow all”).
2. Two concurrent checks in the same session must not both observe “remaining=1” and both allow.
3. Updating `state["posture"]` must not clobber other state keys (e.g., `bound_*` session binding fields).

#### Concrete Recommendation (executor-ready)

**(A) Add merge-patch semantics for session state**

Add a merge-style update path so callers can update `state["posture"]` without replacing the entire map:

- Extend `SessionUpdates` with `state_patch: Option<HashMap<String, serde_json::Value>>`, applied as:
  - `None` → no change
  - `Some(patch)` → `session.state = merge(session.state, patch)` (key-wise insert/replace)
- Keep `SessionUpdates.state` as “replace entire map” for rare cases (admin operations).

**(B) Serialize posture-affecting operations per session**

Introduce a per-session async lock (in `SessionManager`) and hold it across **precheck → guard evaluation → postcheck → session write**:

- Suggested implementation: `DashMap<String, Arc<tokio::sync::Mutex<()>>>` (or equivalent) keyed by `session_id`.
- Use this lock in:
  - `/api/v1/check` when posture is enabled
  - manual transition endpoint (`/api/v1/session/{id}/transition`)
  - any API that mutates `state["posture"]`

This is the simplest correctness baseline: it avoids budget overspend without requiring atomic per-budget SQL.

**(C) Make SQLite `update()` atomic**

Change `SqliteSessionStore::update()` to perform the entire read-modify-write under **one** `lock_conn()` and a single SQLite transaction:

- `BEGIN IMMEDIATE` (or equivalent) to prevent interleaving writers
- `SELECT session_json ...` → apply updates/patch → `UPDATE sessions ...`

**(D) Fail closed if posture updates cannot be persisted**

If posture is configured and the server cannot apply the posture update (store error), return `500` (or deny) rather than allowing an action without consuming budgets/transitions.

#### Optional Future Upgrade (higher concurrency)

If per-session serialization becomes a throughput bottleneck, move budgets to a dedicated table with atomic counters (e.g., `UPDATE ... SET used = used + 1 WHERE used < limit`) and use reservation/rollback semantics. This is strictly more complex; treat it as a later optimization, not the initial baseline.

```rust
// Recommendation: add a SessionManager helper:
//   sessions.merge_state(session_id, patch_map) -> atomic + merge-safe.
let patch = HashMap::from([(
    "posture".to_string(),
    serde_json::to_value(&posture_state)?,
)]);

state.sessions.merge_state(&session_id, patch)?;
```

### 6.4 Cache Interplay

```
┌──────────────────────────────────────────────────────────────────────┐
│                    CACHE vs SESSION STATE                            │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  PolicyEngineCache                   SessionStore                    │
│  ─────────────────                   ────────────                    │
│  Key: policy_hash                    Key: session_id                 │
│  Value: compiled engine              Value: posture + budgets        │
│  ├── PostureProgram (immutable)      ├── current_state (mutable)    │
│  ├── Guards (immutable)              ├── budget counters (mutable)  │
│  └── Settings (immutable)            └── transition_history         │
│                                                                      │
│  Cached, shared across sessions      Per-session, not cached        │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**Key insight:** `PostureProgram` (the compiled posture rules) is part of the cached engine. `SessionPosture` (the runtime state) is per-session.

### 6.5 Request/Response Schema Changes

#### CheckRequest (unchanged for compatibility)

```rust
pub struct CheckRequest {
    pub action_type: String,
    pub target: String,
    pub content: Option<String>,
    pub args: Option<serde_json::Value>,
    pub session_id: Option<String>,
    pub agent_id: Option<String>,
}
```

#### CheckResponse (extended)

```rust
pub struct CheckResponse {
    pub allowed: bool,
    pub guard: String,
    pub severity: String,
    pub message: String,
    pub details: Option<serde_json::Value>,

    // NEW: posture information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureInfo>,
}

pub struct PostureInfo {
    pub state: String,
    pub budgets: HashMap<String, BudgetInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition: Option<TransitionInfo>,
}
```

### 6.6 New Endpoints

#### POST /api/v1/session/{session_id}/transition

Manual posture transition (for `user_approval` trigger):

```rust
pub struct TransitionRequest {
    pub to_state: String,
    pub trigger: String,  // "user_approval" | "user_denial"
}

pub struct TransitionResponse {
    pub success: bool,
    pub from_state: String,
    pub to_state: String,
    pub message: Option<String>,
}
```

#### GET /api/v1/session/{session_id}/posture

Get current posture state:

```rust
pub struct PostureResponse {
    pub state: String,
    pub entered_at: String,  // ISO-8601
    pub budgets: HashMap<String, BudgetInfo>,
    pub transition_history: Vec<TransitionInfo>,
}
```

---

## 7. CLI Plan

### 7.1 Existing Commands (Unchanged)

| Command | Status |
|---------|--------|
| `hush policy show` | Unchanged |
| `hush policy validate` | Extended to validate posture |
| `hush policy lint` | Extended to lint posture |
| `hush policy diff` | Works with posture blocks |
| `hush policy migrate` | Extended for 1.1.0 → 1.2.0 |
| `hush policy simulate` | Extended with posture tracking |
| `hush policy impact` | Works with posture changes |
| `hush policy test` | Extended for posture assertions |

### 7.2 New Commands

#### `hush policy observe`

Run in observe mode, recording all events. This builds on the existing `hush run` infrastructure.

```bash
# Start observe mode (writes events to file)
hush policy observe --out events.jsonl -- my-agent-cmd

# With explicit policy (uses permissive + logging)
hush policy observe --policy clawdstrike:permissive --out events.jsonl -- my-agent-cmd

# Connect to hushd and observe a session
hush policy observe --hushd-url http://localhost:8080 --session my-session --out events.jsonl
```

**Key insight:** `hush policy observe` is essentially `hush run --policy clawdstrike:permissive --events-out events.jsonl` with a cleaner UX.

**Implementation:**

```rust
// File: crates/hush-cli/src/policy_observe.rs

use crate::hush_run;  // Reuse existing run infrastructure

#[derive(Debug, clap::Args)]
pub struct PolicyObserveCommand {
    /// Policy to use (default: clawdstrike:permissive)
    #[arg(long, default_value = "clawdstrike:permissive")]
    policy: String,

    /// Output JSONL file for observed events
    #[arg(long, default_value = "hush.events.jsonl")]
    out: PathBuf,

    /// Connect to hushd instead of running locally
    #[arg(long)]
    hushd_url: Option<String>,

    /// Session ID when using hushd
    #[arg(long)]
    session: Option<String>,

    /// Command to run (if not using hushd)
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

pub async fn cmd_policy_observe(
    args: PolicyObserveCommand,
    remote_extends: &remote_extends::RemoteExtendsConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    if args.hushd_url.is_some() {
        // Observe a hushd session by exporting the audit log filtered by session_id:
        //   GET /api/v1/audit?session_id=...&format=jsonl
        // and mapping AuditEvent → PolicyEvent JSONL for synth/simulate compatibility.
        observe_hushd_session(&args).await
    } else {
        // Delegate to hush run with observe-friendly defaults
        let run_args = hush_run::RunArgs {
            policy: args.policy,
            events_out: args.out.to_string_lossy().to_string(),
            // Observe is primarily about capturing `PolicyEvent` JSONL; the receipt can be ignored.
            receipt_out: "hush.observe.receipt.json".to_string(),
            signing_key: "hush.key".to_string(),
            no_proxy: false,
            proxy_port: 0,
            sandbox: false,
            hushd_url: None,
            hushd_token: None,
            command: args.command,
        };
        hush_run::cmd_run(run_args, remote_extends, stdout, stderr).await
    }
}
```

**Event Schema (events.jsonl):**

```json
{"eventId":"evt-1","eventType":"file_read","timestamp":"2026-02-05T10:00:00Z","sessionId":"sess-1","data":{"type":"file","path":"/src/main.rs","operation":"read"},"metadata":{"decision":{"allowed":true,"guard":"forbidden_path","severity":"info","message":"Allowed"}}}
{"eventId":"evt-2","eventType":"network_egress","timestamp":"2026-02-05T10:00:02Z","sessionId":"sess-1","data":{"type":"network","host":"api.github.com","port":443,"protocol":"tcp"},"metadata":{"decision":{"allowed":true,"guard":"egress_allowlist","severity":"info","message":"Allowed"}}}
```

#### `hush policy synth`

Synthesize a least-privilege policy candidate from observed events. The goal is **reviewability**:

- generate a candidate policy (usually as a small overlay that `extends` a base),
- generate a **diff** against the base for code review,
- generate **risk notes** (what was widened, what might break).

```bash
# Basic synthesis (standalone policy)
hush policy synth events.jsonl --out candidate.yaml --risk-out candidate.risks.md

# With base policy to extend
hush policy synth events.jsonl --extends clawdstrike:default \
  --out candidate.yaml \
  --diff-out candidate.diff.json \
  --risk-out candidate.risks.md

# With posture (generate states based on activity patterns)
hush policy synth events.jsonl --with-posture --out candidate.yaml
```

**Implementation:**

```rust
// File: crates/hush-cli/src/policy_synth.rs

pub struct PolicySynthCommand {
    events: PathBuf,

    #[arg(long)]
    extends: Option<String>,

    #[arg(long, default_value = "candidate.yaml")]
    out: PathBuf,

    /// Optional: write a machine-readable diff versus the resolved base policy
    #[arg(long)]
    diff_out: Option<PathBuf>,

    /// Write a human-readable risk report (recommended)
    #[arg(long, default_value = "candidate.risks.md")]
    risk_out: PathBuf,

    #[arg(long)]
    with_posture: bool,

    #[arg(long)]
    json: bool,
}

pub async fn cmd_policy_synth(args: PolicySynthCommand) -> Result<()> {
    let events = load_events(&args.events)?;
    let base = load_base_policy_if_any(&args.extends)?;
    let candidate = synthesize_policy(&events, &args, base.as_ref())?;

    // Always write the candidate policy YAML.
    write_policy(&args.out, &candidate)?;

    // If requested and a base exists, write a review diff.
    if let (Some(diff_out), Some(base)) = (&args.diff_out, &base) {
        write_policy_diff(diff_out, base, &candidate)?;
    }

    // Always write risk notes.
    write_risk_report(&args.risk_out, &events, base.as_ref(), &candidate)?;
}
```

**Synthesis Heuristics:**

| Observation | Synthesized Rule |
|-------------|------------------|
| Network to `api.github.com` | `egress_allowlist.allow: ["api.github.com"]` |
| Files read/written under repo | `path_allowlist.*_allow: ["**/my-repo/**"]` |
| Max 47 file writes | `posture.states.work.budgets.file_writes: 75` (p95 + margin) |
| No shell commands | `posture.states.work.capabilities: [no shell]` |

**Safety principle:** synth should default to **tightening** or **scoping**, not loosening.

- `forbidden_path` is a denylist-style guard today. Observe/synth can safely *tighten* denies (add patterns), but it must **not** auto-synthesize broad `exceptions` from normal file access.
- If an observed workload truly needs an exception to an existing forbidden pattern, emit it only as a **review-only risk note**, not as a default policy edit.

**Safety Defaults (always included):**

```yaml
# Always synthesized, never removed
guards:
  forbidden_path:
    patterns:
      - "**/.ssh/**"
      - "**/.aws/**"
      - "**/.env*"

  secret_leak:
    enabled: true
```

**Example Output:**

```yaml
# Generated by: hush policy synth events.jsonl
# Events analyzed: 1,247
# Time range: 2026-02-05T09:00:00Z to 2026-02-05T17:00:00Z
# Files written:
# - candidate.yaml (policy overlay)
# - candidate.diff.json (diff vs base, if --extends provided)
# - candidate.risks.md (risk notes)
# WARNING: Review before deploying - this is a starting point, not final policy

version: "1.2.0"
name: Synthesized Policy
description: Auto-generated from observed events
extends: clawdstrike:default

guards:
  path_allowlist:
    enabled: true
    file_access_allow:
      - "**/my-repo/**"
    file_write_allow:
      - "**/my-repo/**"

  egress_allowlist:
    allow:
      - "api.github.com"
      - "registry.npmjs.org"
      - "api.openai.com"
    default_action: block

posture:
  initial: work

  states:
    work:
      capabilities:
        - file_access
        - file_write
        - egress
        - mcp_tool
      budgets:
        file_writes: 75      # observed max: 47, p95: 52
        egress_calls: 30     # observed max: 18, p95: 22
        mcp_tool_calls: 150  # observed max: 89, p95: 112

    quarantine:
      capabilities: []

  transitions:
    - { from: "*", to: quarantine, on: critical_violation }
```

### 7.3 Extended Commands

#### `hush policy simulate` (extended)

```bash
# Simulate with posture tracking
hush policy simulate my-policy.yaml events.jsonl --track-posture

# Output includes posture state at each event
```

**Enhanced Output:**

```json
{
  "eventId": "evt-123",
  "outcome": "allowed",
  "decision": { "allowed": true, "denied": false, "warn": false, "guard": null, "severity": null, "message": "Allowed", "reason": null },
  "report": { "overall": { "allowed": true, "guard": "engine", "severity": "info", "message": "Allowed" }, "per_guard": [] },
  "posture": {
    "state": "work",
    "budgets": {"file_writes": {"used": 5, "limit": 50}},
    "transition": null
  }
}
```

#### `hush policy test` (extended)

```yaml
# Test file with posture assertions
name: Posture Tests
policy: ./my-policy.yaml

suites:
  - name: Posture Transitions
    tests:
      - name: starts in observe
        context:
          session_posture: null  # Fresh session
        input:
          action_type: file_access
          target: /src/main.rs
        expect:
          allowed: true
          posture_state: observe

      - name: transitions to quarantine on critical violation
        context:
          session_posture:
            state: work
        input:
          action_type: file_access
          target: /etc/shadow
        expect:
          allowed: false
          posture_state: quarantine
          posture_transition:
            from: work
            to: quarantine
            trigger: critical_violation
```

---

## 8. Test Plan

### 8.1 Unit Tests

#### Schema Parsing & Validation

| Test File | Tests |
|-----------|-------|
| `crates/clawdstrike/src/posture.rs` | `test_posture_parsing`, `test_posture_validation`, `test_invalid_state_names`, `test_missing_initial`, `test_unreachable_states` |
| `crates/clawdstrike/src/policy.rs` | `test_1_2_0_with_posture`, `test_1_2_0_without_posture`, `test_1_1_0_still_works` |

```rust
#[test]
fn test_posture_parsing() {
    let yaml = r#"
        version: "1.2.0"
        posture:
          initial: observe
          states:
            observe: { capabilities: [file_access] }
    "#;

    let policy = Policy::from_yaml(yaml).unwrap();
    assert!(policy.posture.is_some());
    assert_eq!(policy.posture.unwrap().initial, "observe");
}

#[test]
fn test_unknown_capability_rejected() {
    let yaml = r#"
        version: "1.2.0"
        posture:
          initial: work
          states:
            work: { capabilities: [unknown_thing] }
    "#;

    let result = Policy::from_yaml(yaml);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("unknown capability"));
}
```

#### Migration

| Test File | Tests |
|-----------|-------|
| `crates/hush-cli/src/policy_migrate.rs` | `test_1_1_to_1_2_no_posture`, `test_1_1_to_1_2_preserves_guards` |

### 8.2 Engine Tests

#### Posture Precheck

| Test | Description |
|------|-------------|
| `test_precheck_allows_capability` | Action allowed when in capabilities |
| `test_precheck_denies_missing_capability` | Action denied when not in capabilities |
| `test_precheck_budget_exhausted` | Action denied when budget exhausted (`used >= limit`) |
| `test_precheck_no_posture_allows_all` | No posture block = all allowed |

#### Budget Enforcement

| Test | Description |
|------|-------------|
| `test_budget_consumes_on_allow` | `used` increments (remaining decrements) after allowed action |
| `test_budget_not_consumed_on_deny` | Counter unchanged after denied action |
| `test_budget_exhaustion_triggers_transition` | Budget exhausted → quarantine |

#### Transitions

| Test | Description |
|------|-------------|
| `test_violation_triggers_transition` | Critical violation → quarantine |
| `test_wildcard_from_matches_any` | `from: "*"` matches all states |
| `test_transition_resets_budgets` | New state gets fresh budget limits |
| `test_timeout_transition` | Time-based state downgrade |

### 8.3 Integration Tests

#### hushd + CLI Flows

| Test | Flow |
|------|------|
| `test_session_posture_lifecycle` | Create session → make requests → verify posture changes |
| `test_manual_transition` | POST /api/v1/session/{id}/transition → verify state change |
| `test_budget_across_requests` | Multiple requests → budget depletes → quarantine |
| `test_policy_reload_preserves_session` | Hot-reload policy → session state intact |

#### Observe → Synth Flow

| Test | Flow |
|------|------|
| `test_observe_records_events` | Run observe → verify events.jsonl |
| `test_synth_produces_valid_policy` | Synth from events → policy validates |
| `test_synth_safety_defaults` | Synthesized policy always has secret protection |

### 8.4 Golden Receipt Snapshots

```
tests/golden/receipts/
├── posture_allow.json           # Receipt metadata includes posture snapshot
├── posture_deny_capability.json # Denied due to missing capability (posture precheck)
├── posture_deny_budget.json     # Denied due to exhausted budget
├── posture_transition.json      # Receipt metadata showing state transition
└── no_posture_legacy.json       # Legacy receipt (no posture metadata)
```

### 8.5 Fuzz/Property Tests

```rust
// Property: posture transitions are deterministic
#[test]
fn prop_transition_deterministic() {
    proptest!(|(
        state in "[a-z]+",
        trigger in prop_oneof![Just(CriticalViolation), Just(BudgetExhausted)],
    )| {
        let result1 = find_transition(&program, &state, &trigger);
        let result2 = find_transition(&program, &state, &trigger);
        assert_eq!(result1, result2);
    });
}

// Property: budget never goes negative
#[test]
fn prop_budget_non_negative() {
    proptest!(|(ops in vec(prop_oneof![Just(Decrement), Just(Reset)], 0..100))| {
        let mut counter = BudgetCounter { used: 0, limit: 50 };
        for op in ops {
            match op {
                Decrement => { counter.try_consume(); }
                Reset => { counter.used = 0; }
            }
            assert!(counter.used <= counter.limit);
        }
    });
}
```

### 8.6 Acceptance Criteria per PR

| PR | Acceptance Criteria |
|----|---------------------|
| PR1: Schema | All existing 1.1.0 tests pass; new 1.2.0 parsing tests pass |
| PR2: Validation | `hush policy validate` catches all new validation errors |
| PR3: Path Allowlist | `path_allowlist` guard enforces “only these paths”; normalization shared with forbidden_path |
| PR4: Engine Posture | Posture precheck tests pass; missing runtime state initializes to `posture.initial` |
| PR5: Budgets | Budget tests pass; budget consumption is deterministic |
| PR6: Transitions | Transition tests pass; wildcard + timeout semantics correct |
| PR7: hushd Integration | Session posture updates are atomic/merge-safe; per-session serialization prevents budget overspend |
| PR8: Metadata | Receipt/audit metadata include posture snapshots without schema bump; metadata merges correctly |
| PR9: CLI Observe | `hush policy observe` produces canonical PolicyEvent JSONL |
| PR10: CLI Synth | `hush policy synth` produces valid overlays + diff + risk notes; no unsafe auto-loosening |
| PR11: CLI Extensions | simulate/test/migrate support posture assertions and tracking |
| PR12: Docs | New docs render; examples validate |
| PR13: DAG (optional) | Performance wins measured; receipts explain evaluation path |

---

## 9. Doc Plan

### 9.1 New Documentation

| File | Content |
|------|---------|
| `docs/src/concepts/postures.md` | Conceptual overview: states, capabilities, budgets, transitions |
| `docs/src/guides/posture-policy.md` | Tutorial: writing your first posture policy |
| `docs/src/guides/observe-synth.md` | Tutorial: observe → synth → tighten workflow |
| `docs/src/reference/posture-schema.md` | Reference: all posture fields, validation rules |

### 9.2 Updated Documentation

| File | Changes |
|------|---------|
| `docs/src/reference/policy-schema.md` | Add posture section, update version to 1.2.0 |
| `docs/src/getting-started/first-policy.md` | Add note about posture being optional |
| `docs/src/concepts/decisions.md` | Add posture to decision flow diagram |

### 9.3 New Examples

| File | Description |
|------|-------------|
| `examples/policies/minimal-posture.yaml` | Simplest posture policy |
| `examples/policies/enterprise-posture.yaml` | Full observe/work/elevated/quarantine |
| `examples/policies/synthesized-example.yaml` | Example output from synth |

### 9.4 Backwards Compatibility Documentation

```markdown
# Backwards Compatibility Guarantees

## Policy Schema

| Version | Status | Notes |
|---------|--------|-------|
| 1.1.0 | Supported | No posture features |
| 1.2.0 | Current | Posture optional |

## Behavior Guarantees

1. **Existing 1.1.0 policies work unchanged**
   - No version bump required
   - Same evaluation behavior
   - Same receipts (no posture metadata)

2. **1.2.0 policies without posture work like 1.1.0**
   - Omitting `posture:` block = no posture features
   - All capabilities implicitly allowed
   - No budget limits

3. **Receipts are additive**
   - **Current reality:** receipts are schema/version locked (`RECEIPT_SCHEMA_VERSION`) and parsed with `deny_unknown_fields` in hush-core, so *new top-level fields are a breaking change* for older consumers.
   - **Options:**
     - (a) Bump receipt schema (e.g., `1.1.0`) + teach verifiers to accept both `1.0.0` and `1.1.0` (Rust + TS + Py).
     - (b) Keep receipt schema `1.0.0` and place posture info under `receipt.metadata` (additive for strict consumers).
```

---

## 10. PR Series Roadmap

### PR 1: Schema Foundation

**Title:** `feat(policy): add 1.2.0 schema with posture types`

**Scope:**
- Bump `POLICY_SCHEMA_VERSION` to support both 1.1.0 and 1.2.0
- Add `PostureConfig`, `PostureState`, `PostureTransition` types
- Add `posture` field to `Policy` struct (optional)
- Serde parsing with `deny_unknown_fields`

**Files:**
- `crates/clawdstrike/src/policy.rs` (modify)
- `crates/clawdstrike/src/posture.rs` (new)
- `packages/clawdstrike-policy/src/policy/schema.ts` (modify)

**Tests:**
- `test_1_2_0_parsing`
- `test_1_1_0_still_works`
- `test_posture_optional`

**Acceptance:**
- [ ] 1.1.0 policies parse and work unchanged
- [ ] 1.2.0 policies with posture parse correctly
- [ ] Unknown fields in posture rejected

---

### PR 2: Schema Validation

**Title:** `feat(policy): validate posture configuration`

**Scope:**
- Validate state names unique
- Validate initial state exists
- Validate capabilities known
- Validate budgets non-negative
- Validate transitions reference existing states
- Warn on unreachable states

**Files:**
- `crates/clawdstrike/src/policy.rs` (extend `validate()`)
- `crates/clawdstrike/src/posture.rs` (add validation)
- `crates/hush-cli/src/policy_lint.rs` (extend)

**Tests:**
- `test_validation_*` (10+ test cases)

**Acceptance:**
- [ ] All validation rules from section 4.8 implemented
- [ ] `hush policy validate` reports posture errors

---

### PR 3: Filesystem Allowlist Guard

**Title:** `feat(guards): add path_allowlist filesystem scoping guard`

**Scope:**
- Add `guards.path_allowlist` config to policy schema (optional; default disabled)
- Implement `PathAllowlistGuard` (deny-by-default when enabled)
- Add shared `normalize_path_for_policy()` helper and use it in both `forbidden_path` and `path_allowlist`
- Extend policy validation to validate allowlist glob patterns

**Files:**
- `crates/clawdstrike/src/guards/path_allowlist.rs` (new)
- `crates/clawdstrike/src/guards/mod.rs` (export)
- `crates/clawdstrike/src/guards/forbidden_path.rs` (use shared normalization helper)
- `crates/clawdstrike/src/policy.rs` (add config field + instantiate guard + stable order)
- `packages/clawdstrike-policy/src/policy/schema.ts` (add schema field)

**Tests:**
- `test_path_allowlist_allows_in_scope`
- `test_path_allowlist_denies_out_of_scope`
- `test_normalize_path_lexical_traversal`

**Acceptance:**
- [ ] Existing policies behave unchanged (guard is disabled unless configured)
- [ ] When enabled, file/patch actions outside allowlist are blocked
- [ ] Path normalization is shared with `forbidden_path`

---

### PR 4: Engine Posture Precheck

**Title:** `feat(engine): posture capability precheck`

**Scope:**
- Compile `PostureConfig` → `PostureProgram`
- Add `posture_precheck()` to engine
- Early deny if capability not in current state
- No budget handling yet (next PR)

**Files:**
- `crates/clawdstrike/src/engine.rs` (modify)
- `crates/clawdstrike/src/posture.rs` (add `PostureProgram`)

**Tests:**
- `test_precheck_allows_capability`
- `test_precheck_denies_missing_capability`
- `test_no_posture_allows_all`

**Acceptance:**
- [ ] Capability precheck blocks disallowed actions
- [ ] Existing guard tests still pass
- [ ] No posture = all allowed

---

### PR 5: Budget Enforcement

**Title:** `feat(engine): budget counters and exhaustion`

**Scope:**
- Track budget counters in `PostureRuntimeState` (stored in `SessionContext.state["posture"]`)
- Consume budgets on allowed actions (increment `used`)
- Deny when budget exhausted
- Reset budgets on state transition

**Files:**
- `crates/clawdstrike/src/posture/runtime.rs` (new)
- `crates/clawdstrike/src/engine.rs` (modify)

**Tests:**
- `test_budget_consumes`
- `test_budget_exhausted_denies`
- `test_budget_reset_on_transition`

**Acceptance:**
- [ ] Budget counters update correctly
- [ ] Exhausted budget blocks action
- [ ] State transition resets budgets

---

### PR 6: Transitions

**Title:** `feat(engine): posture state transitions`

**Scope:**
- Implement `posture_postcheck()`
- Violation triggers (critical, any)
- Budget exhaustion trigger
- Wildcard `from: "*"` matching
- Transition history tracking

**Files:**
- `crates/clawdstrike/src/engine.rs` (modify)
- `crates/clawdstrike/src/posture.rs` (add transition logic)

**Tests:**
- `test_critical_violation_transition`
- `test_wildcard_from`
- `test_transition_history`

**Acceptance:**
- [ ] Violations trigger configured transitions
- [ ] Transition history recorded
- [ ] Wildcard matching works

---

### PR 7: hushd Integration

**Title:** `feat(hushd): session posture state management`

**Scope:**
- Store posture state in `SessionContext`
- Return posture info in `CheckResponse`
- Add `/api/v1/session/{id}/transition` endpoint
- Add `/api/v1/session/{id}/posture` endpoint
- Add merge-safe session state patching (`state_patch`) and per-session serialization for posture updates
- Make SQLite session updates atomic (single conn lock + transaction) when posture is enabled

**Files:**
- `crates/hushd/src/session/mod.rs` (modify)
- `crates/hushd/src/api/check.rs` (modify)
- `crates/hushd/src/api/session.rs` (modify)

**Tests:**
- Integration tests for session posture lifecycle

**Acceptance:**
- [ ] Session posture persists across requests
- [ ] API returns posture information
- [ ] Manual transition endpoint works

---

### PR 8: Receipt/Audit Metadata Enrichment

**Title:** `feat(receipt): add posture snapshot to receipt.metadata`

**Scope:**
- Keep receipt schema stable (no new top-level fields)
- Add posture/budget/transition snapshot under `receipt.metadata.clawdstrike.posture` when available
- Add a JSON object merge helper for receipt metadata so multiple writers (engine + CLI) don't clobber keys
- Mirror posture snapshot under `AuditEvent.metadata.clawdstrike.posture` for observe/synth
- Golden snapshot updates (metadata-only)

**Files:**
- `crates/hush-core/src/receipt.rs` (modify; merge helper)
- `crates/hush-cli/src/hush_run.rs` (modify; merge instead of replace metadata)
- `tests/golden/receipts/` (add new snapshots)

**Tests:**
- `test_receipt_metadata_merge`
- Golden snapshot tests

**Acceptance:**
- [ ] Receipts include posture metadata when applicable
- [ ] Existing receipt consumers still verify (`version` unchanged)
- [ ] Golden snapshots match

---

### PR 9: CLI Policy Observe

**Title:** `feat(cli): add policy observe command`

**Scope:**
- New `hush policy observe` command
- Event recording to JSONL
- Works with local engine or hushd

**Files:**
- `crates/hush-cli/src/policy_observe.rs` (new)
- `crates/hush-cli/src/main.rs` (add subcommand)

**Tests:**
- `test_observe_produces_jsonl`
- `test_observe_event_schema`

**Acceptance:**
- [ ] `hush policy observe` works
- [ ] Events written in correct format
- [ ] Works with both local and hushd modes

---

### PR 10: CLI Policy Synth

**Title:** `feat(cli): add policy synth command`

**Scope:**
- New `hush policy synth` command
- Event analysis and policy generation
- Safety defaults always included
- Optional posture generation
- Emit review diff (vs base) + risk notes by default
- Generate `path_allowlist` patterns from observed file access/write events

**Files:**
- `crates/hush-cli/src/policy_synth.rs` (new)
- `crates/hush-cli/src/main.rs` (add subcommand)

**Tests:**
- `test_synth_produces_valid_policy`
- `test_synth_safety_defaults`
- `test_synth_with_posture`
- `test_synth_emits_diff_and_risks`

**Acceptance:**
- [ ] `hush policy synth` produces valid YAML
- [ ] `--diff-out` produces a reviewable diff vs base policy
- [ ] `--risk-out` explains new allowlists/budgets and any review-only suggestions
- [ ] Safety defaults always present
- [ ] Generated policy passes validation

---

### PR 11: CLI Extensions

**Title:** `feat(cli): extend simulate/test for posture`

**Scope:**
- Extend `hush policy simulate` with `--track-posture`
- Extend `hush policy test` with posture assertions
- Update `hush policy migrate` for 1.1.0 → 1.2.0

**Files:**
- `crates/hush-cli/src/policy_pac.rs` (modify)
- `crates/hush-cli/src/policy_test.rs` (modify)
- `crates/hush-cli/src/policy_migrate.rs` (modify)

**Tests:**
- `test_simulate_posture_tracking`
- `test_posture_assertions`
- `test_migrate_1_1_to_1_2`

**Acceptance:**
- [ ] Simulate shows posture state
- [ ] Tests can assert on posture
- [ ] Migration works

---

### PR 12: Documentation

**Title:** `docs: posture policies and observe/synth workflow`

**Scope:**
- New conceptual docs
- New tutorials
- Reference updates
- Example policies

**Files:**
- `docs/src/concepts/postures.md` (new)
- `docs/src/guides/posture-policy.md` (new)
- `docs/src/guides/observe-synth.md` (new)
- `docs/src/reference/posture-schema.md` (new)
- `docs/src/reference/policy-schema.md` (modify)
- `examples/policies/*.yaml` (new)

**Acceptance:**
- [ ] All new docs render correctly
- [ ] Examples are valid and tested
- [ ] Backwards compat documented

---

### PR 13: Internal DAG (Optional, Future)

**Title:** `feat(engine): internal guard DAG evaluation`

**Scope:**
- Define internal pipeline representation
- Fast-path / standard-path / deep-path evaluation
- Receipt shows evaluation path taken
- No user-facing schema changes

**Files:**
- `crates/clawdstrike/src/pipeline.rs` (new)
- `crates/clawdstrike/src/engine.rs` (modify)

**Tests:**
- `test_fast_path_taken`
- `test_deep_path_on_suspicious`
- `test_receipt_shows_path`

**Acceptance:**
- [ ] DAG evaluation works
- [ ] Receipts explainable
- [ ] Performance improvement measurable

---

## 11. Open Questions / Decisions Needed

| # | Question | Options | Recommendation |
|---|----------|---------|----------------|
| 1 | **Timeout transitions: server-side or client tick?** | (a) hushd background task (b) Checked on each request | (b) Check on request - simpler, no background threads |
| 2 | **Posture state persistence on daemon restart?** | (a) Persist with sessions (SQLite) (b) Clear posture on restart | (a) Persist by default - otherwise budgets can be bypassed via restart; add operator override if needed |
| 3 | **Budget scope: per-session or per-identity?** | (a) Per-session (b) Per-identity across sessions | (a) Per-session - cleaner boundary, matches existing session model |
| 4 | **Posture merge with extends: states merge or replace?** | (a) Merge by state name (b) Child replaces all | (a) Merge by name - more composable |
| 5 | **DAG pipelines: expose in schema or hide?** | (a) User-authored DAGs (b) Internal optimization only | (b) Internal only - keeps UX simple |
| 6 | **Observe mode: separate CLI or daemon mode?** | (a) `hush policy observe` CLI (b) hushd `--observe` flag | (a) CLI command - more explicit, works standalone |
| 7 | **Synth output: complete policy or patch?** | (a) Full standalone policy (b) Diff/patch + risk notes | (b) Diff/patch + risk notes - reviewable and safer; full YAML optional |
| 8 | **Version negotiation: 1.1.0 vs 1.2.0?** | (a) Accept both; gate new fields on 1.2.0 (b) Require 1.2.0 always | (a) Accept both - but require 1.2.0 for posture/path_allowlist to keep intent explicit |

---

## Appendix A: Capability Mapping

| Capability | GuardAction | Relevant Guards |
|------------|-------------|-----------------|
| `file_access` | `FileAccess` | ForbiddenPath, PathAllowlist |
| `file_write` | `FileWrite` | ForbiddenPath, PathAllowlist, SecretLeak, PatchIntegrity |
| `egress` | `NetworkEgress` | EgressAllowlist, async guards |
| `shell` | `ShellCommand` | (none built-in today; posture gating/custom guards enforce) |
| `mcp_tool` | `McpTool` | McpTool |
| `patch` | `Patch` | ForbiddenPath, PathAllowlist, PatchIntegrity |

## Appendix B: Transition Trigger Mapping

| Trigger | Condition | Source |
|---------|-----------|--------|
| `user_approval` | Manual API call | `/api/v1/session/{id}/transition` |
| `user_denial` | Manual API call | `/api/v1/session/{id}/transition` |
| `critical_violation` | `GuardResult.allowed=false && severity=Critical` | Engine postcheck |
| `any_violation` | `GuardResult.allowed=false` | Engine postcheck |
| `timeout` | `now - posture.entered_at > transition.after` | Engine precheck |
| `budget_exhausted` | `counter.used >= counter.limit` | Engine postcheck |

## Appendix C: Event Schema for Observe/Synth

```typescript
// Canonical input for observe/synth should be the existing PolicyEvent JSONL format
// emitted/consumed by `hush policy eval|simulate`:
// - `crates/hush-cli/src/policy_event.rs`
// - `crates/hushd/src/policy_event.rs`
//
// Decision results (allow/deny/warn, guard, severity, message) are typically carried in
// `metadata.decision` when events are produced by an instrumented runtime.
interface PolicyEvent {
  eventId: string;
  eventType:
    | 'file_read'
    | 'file_write'
    | 'network_egress'
    | 'command_exec'
    | 'patch_apply'
    | 'tool_call'
    | 'secret_access'
    | 'custom'
    | string;
  timestamp: string; // ISO-8601
  sessionId?: string;
  data: { type: string; [k: string]: unknown };
  metadata?: unknown;
}
```

---

## Appendix D: Related Roadmap Files

This roadmap is the main document. As implementation proceeds, detailed specs may be broken into separate files:

| File | Content | Status |
|------|---------|--------|
| `nextgen-policy-roadmap.md` | This file - main overview | ✅ Active |
| `posture-schema-spec.md` | Detailed YAML schema specification | 📋 Create during PR1 |
| `posture-validation-rules.md` | Complete validation rule catalog | 📋 Create during PR2 |
| `synth-heuristics.md` | Policy synthesis algorithm details | 📋 Create during PR10 |

---

## Appendix E: Glossary

| Term | Definition |
|------|------------|
| **Posture** | Named security state (e.g., "observe", "work", "quarantine") with associated capabilities and budgets |
| **Capability** | A type of action an agent can perform (file_access, file_write, egress, shell, mcp_tool, patch) |
| **Budget** | Numeric limit on a capability type that depletes with usage |
| **Transition** | Movement from one posture state to another, triggered by events or time |
| **PostureProgram** | Compiled representation of posture rules (immutable, cached with engine) |
| **PostureRuntimeState** | Mutable session state: current posture, budgets, history (stored in SessionContext.state) |
| **Observe mode** | Running with permissive policy to record events for later synthesis |
| **Synth** | Generating a least-privilege policy from observed events |

---

## Changelog

| Date | Change |
|------|--------|
| 2026-02-05 | Initial draft |
