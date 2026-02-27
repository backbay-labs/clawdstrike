# OpenClaw Adapter-Core Alignment Plan

Status: Proposed
Author: Architecture review
Last updated: 2026-02-25

> Update (2026-02-26): This remains a forward-looking architecture plan.  
> Launch-blocker closure and runtime verification status are tracked in [`../audits/2026-02-26-openclaw-launch-revalidation.md`](../audits/2026-02-26-openclaw-launch-revalidation.md).

## Problem Statement

The `@clawdstrike/openclaw` adapter is architecturally divergent from all other framework adapters (vercel-ai, langchain, claude, openai, opencode). Every other adapter implements the `FrameworkAdapter` interface from `@clawdstrike/adapter-core` and delegates to `BaseToolInterceptor`. The openclaw adapter has its own parallel architecture built around OpenClaw's hook system (`registerHook`/`on`), creating:

1. **Duplicated logic that does not benefit from adapter-core bug fixes.** The openclaw `PolicyEngine` reimplements guard orchestration, decision aggregation, and output sanitization independently of `BaseToolInterceptor`. Fixes to the base interceptor (e.g., audit event emission, PII redaction, error-to-deny conversion) do not propagate.

2. **Type safety issues requiring unsafe casts.** The CUA bridge handler (`hooks/cua-bridge/handler.ts:296`) must cast adapter-core `PolicyEvent` to the local `PolicyEvent` via `as unknown as import('../../types.js').PolicyEvent` because the two type hierarchies diverged. The engine also casts back via `toCanonicalEvent()` at `policy/engine.ts:843`.

3. **Inconsistent behavior across adapters.**
   - PII redaction labels differ: openclaw uses `[REDACTED:email]`, `[REDACTED:phone]`, `[REDACTED:ssn]`, `[REDACTED:credit_card]` (see `sanitizer/output-sanitizer.ts`), while adapter-core uses `[REDACTED_EMAIL]`, `[REDACTED_SSN]`, `[REDACTED_PHONE]` (see `base-tool-interceptor.ts:351-363`).
   - Error types differ: openclaw blocks via `toolEvent.preventDefault = true` with message strings; adapter-core adapters can throw `ClawdstrikeBlockedError` with structured `Decision` payloads.
   - Audit event shapes differ: openclaw's `AuditStore` uses `{ decision: 'allowed' | 'denied' }` (string enum), while adapter-core's `AuditEvent` uses a full `Decision` object with status/reason_code/severity.

4. **No interoperability with framework-agnostic tooling.** Code built against the `FrameworkAdapter` interface (generic tool runners, audit exporters, session summarizers) cannot consume openclaw because it does not implement that interface.

## Current State

### Source files inventoried

- `packages/adapters/clawdstrike-adapter-core/src/` -- 26 source files
- `packages/adapters/clawdstrike-openclaw/src/` -- 38 source files
- `packages/adapters/clawdstrike-vercel-ai/src/` -- 13 source files (reference conforming adapter)
- `packages/adapters/clawdstrike-langchain/src/` -- 12 source files (reference conforming adapter)
- `packages/adapters/clawdstrike-claude/src/` -- delegates to `createFrameworkAdapter()`
- `packages/adapters/clawdstrike-openai/src/` -- delegates to `createFrameworkAdapter()`
- `packages/adapters/clawdstrike-opencode/src/` -- delegates to `createFrameworkAdapter()`

### What openclaw has that others do not

1. **Approval workflow** (`hooks/approval-state.ts`, `hooks/tool-preflight/handler.ts:348-443`). LRU-backed in-memory approval cache with allow-once (10 min TTL), allow-session (6 hr TTL), allow-always (7 day TTL). Polls an external approval API (`CLAWDSTRIKE_APPROVAL_URL`) with agent token authentication. No other adapter or adapter-core has any notion of approval.

2. **Security prompt generation** (`security-prompt.ts`). Generates a markdown prompt from the loaded `Policy` object describing network, filesystem, tool, and violation handling constraints. Injected at agent bootstrap via the `agent:bootstrap` hook.

3. **Decision caching** (implicit via the approval state). The `peekApproval()` / `checkAndConsumeApproval()` functions serve as a decision cache: once a tool+resource pair is approved, subsequent checks for the same pair skip policy evaluation for the TTL window.

4. **Tool classification heuristics** (`hooks/tool-preflight/handler.ts:44-109`). A tokenizer splits tool names on camelCase/snake_case/kebab boundaries and classifies them as read-only, destructive, or unknown using two token sets (31 read-only tokens, 30 destructive tokens). This determines whether pre-flight evaluation runs at all.

5. **CLI commands** (`cli/` directory, registered via `api.registerCli`). `clawdstrike status` and `clawdstrike check <action> <resource>` commands integrated into the OpenClaw CLI surface.

6. **Policy loader and validator** (`policy/loader.ts`, `policy/validator.ts`). YAML parsing, `extends` inheritance resolution, built-in ruleset loading. Separate from `@clawdstrike/policy` but overlapping.

7. **Defense-in-depth command path extraction** (`policy/engine.ts:71-137`). Extracts filesystem path candidates from shell command strings (including redirections like `>`, `>>`, `-o`/`--output` flags, inline `>path` forms) and runs each through filesystem guards. Bounded to 64 checks per command.

### What openclaw is missing relative to adapter-core conforming adapters

| # | Gap | adapter-core source | Impact |
|---|-----|---------------------|--------|
| 1 | `FrameworkAdapter` interface implementation | `adapter.ts` | Cannot be used by generic adapter tooling |
| 2 | `BaseToolInterceptor` usage | `base-tool-interceptor.ts` | Misses unified beforeExecute/afterExecute/onError lifecycle |
| 3 | `SecurityContext` for per-session tracking | `context.ts` | No structured session state (checkCount, violationCount, blockedTools, auditEvents) |
| 4 | Standard `AuditLogger` integration | `audit.ts` | Openclaw's `AuditStore` has incompatible schema (string-enum decisions, file-backed JSONL) |
| 5 | Standard `OutputSanitizer` integration | `sanitizer.ts`, `default-output-sanitizer.ts` | Openclaw has its own sanitizer with different redaction labels |
| 6 | `ToolCallTranslator` support | `adapter.ts:75-84` | No pluggable event translation; CUA bridge does it manually |
| 7 | `ClawdstrikeBlockedError` thrown on denial | `errors.ts` | Openclaw uses `preventDefault = true` + message strings |
| 8 | `EventHandlers` callbacks | `adapter.ts:50-56` | No onBeforeEvaluate/onAfterEvaluate/onBlocked/onWarning/onError hooks |
| 9 | `createSessionSummary()` usage | `finalize-context.ts` | No session summary generation |
| 10 | Correct peer dependency version alignment | `package.json` | `@clawdstrike/adapter-core: ^0.1.1` is present but minimally used |

## Feature Comparison Matrix

| Feature | adapter-core | openclaw | vercel-ai | langchain | claude | openai | opencode |
|---------|-------------|----------|-----------|-----------|--------|--------|----------|
| `FrameworkAdapter` | defines | **NO** | YES | YES | YES | YES | YES |
| `BaseToolInterceptor` | defines | **NO** | YES | YES | YES (via delegate) | YES (via delegate) | YES (via delegate) |
| `SecurityContext` | defines | **NO** | YES | YES | YES | YES | YES |
| `SessionSummary` | defines | **NO** | YES (inline) | YES (via helper) | YES (via delegate) | YES (via delegate) | YES (via delegate) |
| `AuditLogger` | defines | **NO** (own `AuditStore`) | YES | YES | YES | YES | YES |
| `OutputSanitizer` | defines | **NO** (own sanitizer) | YES | YES | YES | YES | YES |
| `ClawdstrikeBlockedError` | defines | **NO** | YES (duplicate) | YES (re-export) | YES (via delegate) | YES (via delegate) | YES (via delegate) |
| `EventHandlers` | defines | **NO** | YES | YES | YES | YES | YES |
| `ToolCallTranslator` | defines | **NO** | NO | NO | YES | YES | NO |
| CUA support | types only | **YES** (full bridge) | NO | NO | YES (translator) | YES (translator) | NO |
| Decision caching | NO | **YES** (LRU + TTL) | NO | NO | NO | NO | NO |
| Approval workflow | NO | **YES** (API + LRU) | NO | NO | NO | NO | NO |
| Security prompts | NO | **YES** | NO | NO | NO | NO | NO |
| CLI integration | NO | **YES** | NO | NO | NO | NO | NO |
| Tool classification | NO | **YES** (tokenizer) | NO | NO | NO | NO | NO |
| Command path extraction | NO | **YES** (defense-in-depth) | NO | NO | NO | NO | NO |
| Policy loader/validator | NO (in `@clawdstrike/policy`) | **YES** (own copy) | NO | NO | NO | NO | NO |

## Proposed Architecture

### Phase 1: Type Unification (Low risk, high value)

**Goal:** Eliminate parallel type hierarchies and unsafe casts.

**Changes:**

1. Replace local `PolicyEvent`, `Decision`, `EventData`, `EventType`, `Severity`, `DecisionStatus` type definitions in `packages/adapters/clawdstrike-openclaw/src/types.ts` with re-exports from `@clawdstrike/adapter-core`. The local types are structurally identical (verified by code inspection) except openclaw's `EventData` union omits `CustomEventData`.

2. Add openclaw-specific extensions via intersection types where needed:
   ```typescript
   // types.ts
   export type { PolicyEvent, Decision, EventData, EventType, Severity } from '@clawdstrike/adapter-core';
   export type { CuaEventData } from '@clawdstrike/adapter-core';

   // Openclaw-specific extensions
   export type OpenClawEventData = EventData;  // adapter-core's union already includes CuaEventData
   ```

3. Eliminate the `as unknown as` cast in `hooks/cua-bridge/handler.ts:296`. Once both sides share the same `PolicyEvent` type, the cast becomes unnecessary:
   ```typescript
   // Before (handler.ts:296)
   const decision: Decision = await policyEngine.evaluate(cuaEvent as unknown as import('../../types.js').PolicyEvent);
   // After
   const decision: Decision = await policyEngine.evaluate(cuaEvent);
   ```

4. Eliminate the `toCanonicalEvent()` identity cast in `policy/engine.ts:840-844`:
   ```typescript
   // Before
   function toCanonicalEvent(event: PolicyEvent): CanonicalPolicyEvent {
     return event as unknown as CanonicalPolicyEvent;
   }
   // After: direct usage, no cast needed
   ```

5. Align PII redaction labels in `sanitizer/output-sanitizer.ts` with adapter-core format:
   - `[REDACTED:email]` becomes `[REDACTED_EMAIL]`
   - `[REDACTED:phone]` becomes `[REDACTED_PHONE]`
   - `[REDACTED:ssn]` becomes `[REDACTED_SSN]`
   - `[REDACTED:credit_card]` becomes `[REDACTED_CREDIT_CARD]`

**Files changed:**
- `packages/adapters/clawdstrike-openclaw/src/types.ts` -- replace definitions with re-exports, keep openclaw-specific types (Policy, GuardToggles, hook event types, etc.)
- `packages/adapters/clawdstrike-openclaw/src/hooks/cua-bridge/handler.ts` -- remove cast
- `packages/adapters/clawdstrike-openclaw/src/policy/engine.ts` -- remove `toCanonicalEvent()`, remove `CanonicalPolicyEvent` import alias
- `packages/adapters/clawdstrike-openclaw/src/sanitizer/output-sanitizer.ts` -- align labels

**Risk:** Low. Type re-exports are a non-breaking change for consumers. The `Decision` type in both packages is already structurally identical (discriminated union on `status` with `reason_code` required for non-allow). PII label changes affect output format; document as a minor version bump.

**Verification:** `npm run typecheck` in `clawdstrike-openclaw` must pass with zero errors. Existing tests must remain green.

### Phase 2: Create `OpenClawAdapter` Class (Medium risk)

**Goal:** Make openclaw usable via the `FrameworkAdapter` interface without changing how existing OpenClaw hook-based integrations work.

**Changes:**

1. Create `packages/adapters/clawdstrike-openclaw/src/openclaw-adapter.ts`:
   ```typescript
   import type { FrameworkAdapter, AdapterConfig, SecurityContext, GenericToolCall, SessionSummary } from '@clawdstrike/adapter-core';
   import { createSecurityContext, createSessionSummary } from '@clawdstrike/adapter-core';
   import { PolicyEngine } from './policy/engine.js';

   export class OpenClawAdapter implements FrameworkAdapter {
     readonly name = 'openclaw';
     readonly version = '0.1.1';
     private engine: PolicyEngine;
     private config: AdapterConfig;

     constructor(engine: PolicyEngine, config: AdapterConfig = {}) { ... }
     async initialize(config: AdapterConfig): Promise<void> { ... }
     createContext(metadata?: Record<string, unknown>): SecurityContext { ... }
     async interceptToolCall(context: SecurityContext, toolCall: GenericToolCall) { ... }
     async processOutput(context: SecurityContext, toolCall: GenericToolCall, output: unknown) { ... }
     async finalizeContext(context: SecurityContext): Promise<SessionSummary> { ... }
     getEngine() { ... }
     getHooks() { ... }
   }
   ```

2. The adapter delegates to the existing `PolicyEngine` for evaluation but wraps results in `SecurityContext` tracking. This is a new code path parallel to the hook handlers -- it does not replace them.

3. Expose `getEngine()` for direct engine access (matching claude/openai adapter pattern).

4. Export from `packages/adapters/clawdstrike-openclaw/src/index.ts`.

**Files changed:**
- New file: `packages/adapters/clawdstrike-openclaw/src/openclaw-adapter.ts`
- `packages/adapters/clawdstrike-openclaw/src/index.ts` -- add export

**Risk:** Medium. This is additive (new class, new export). No existing behavior changes. Risk is in ensuring the adapter's evaluation path produces identical decisions to the hook-based path for the same inputs.

**Verification:** Add `openclaw-adapter.test.ts` with fixture-driven tests that assert decision parity between `OpenClawAdapter.interceptToolCall()` and direct `PolicyEngine.evaluate()` for the same events.

### Phase 3: Consolidate Engine Singletons (Medium risk)

**Goal:** Replace 4 independent `PolicyEngine` singletons with a single shared instance.

**Current state:** Each hook handler module maintains its own singleton:

| Module | Singleton variable | Created by |
|--------|--------------------|------------|
| `hooks/tool-preflight/handler.ts` | `let engine: PolicyEngine \| null` | `initialize(config)` or `getEngine()` |
| `hooks/cua-bridge/handler.ts` | `let engine: PolicyEngine \| null` | `initialize(config)` or `getEngine()` |
| `hooks/tool-guard/handler.ts` | (imports `getEngine` from preflight) | Shared with preflight |
| `plugin.ts` | (creates inline engines) | `new PolicyEngine(config)` in CLI check command |

**Changes:**

1. Create a shared engine holder module:
   ```typescript
   // packages/adapters/clawdstrike-openclaw/src/engine-holder.ts
   import { PolicyEngine } from './policy/engine.js';
   import type { ClawdstrikeConfig } from './types.js';

   let sharedEngine: PolicyEngine | null = null;

   export function initializeEngine(config: ClawdstrikeConfig): PolicyEngine {
     sharedEngine = new PolicyEngine(config);
     return sharedEngine;
   }

   export function getSharedEngine(config?: ClawdstrikeConfig): PolicyEngine {
     if (!sharedEngine) {
       sharedEngine = new PolicyEngine(config ?? {});
     }
     return sharedEngine;
   }
   ```

2. Update `plugin.ts` to initialize once and pass to all handlers.

3. Update each hook handler to import from the shared holder instead of maintaining local singletons.

**Files changed:**
- New file: `packages/adapters/clawdstrike-openclaw/src/engine-holder.ts`
- `packages/adapters/clawdstrike-openclaw/src/plugin.ts` -- use shared initializer
- `packages/adapters/clawdstrike-openclaw/src/hooks/tool-preflight/handler.ts` -- remove local singleton, import shared
- `packages/adapters/clawdstrike-openclaw/src/hooks/cua-bridge/handler.ts` -- remove local singleton, import shared

**Risk:** Medium. The CUA bridge and preflight handlers currently have isolated engines. If their `initialize()` calls receive different configs (they should not, but it is not enforced), consolidation could change behavior. Mitigation: add an assertion in `initializeEngine()` that warns if called more than once with different configs.

**Verification:** All existing hook handler tests must pass. Add a test that initializing with the same config and calling `getSharedEngine()` from two different modules returns the same instance.

### Phase 4: Integrate BaseToolInterceptor (Higher risk, careful migration)

**Goal:** Use `BaseToolInterceptor` for the core interception lifecycle within the hook handlers, gaining automatic audit event emission, excluded tools, error handler callbacks, and PII redaction.

**Changes:**

1. The `OpenClawAdapter` class (from Phase 2) already uses `BaseToolInterceptor` internally. In this phase, we refactor the hook handlers to optionally delegate to the same interceptor when the `OpenClawAdapter` is initialized.

2. Create a `ToolCallTranslator` for openclaw that encapsulates the existing tool classification and event inference logic:
   ```typescript
   export function openclawToolCallTranslator(input: ToolCallTranslationInput): PolicyEvent | null {
     const eventType = inferPolicyEventType(input.toolName, input.parameters);
     if (eventType === null) return null; // read-only, skip
     return buildPolicyEvent(input.sessionId ?? '', input.toolName, input.parameters, eventType);
   }
   ```

3. Wire the translator into the `AdapterConfig.translateToolCall` so `BaseToolInterceptor` uses openclaw's inference logic.

4. Preserve openclaw-specific behavior as pre/post hooks:
   - Approval workflow runs as a pre-hook before `BaseToolInterceptor.beforeExecute()`.
   - Tool classification (read-only skip) is encoded in the translator returning `null`.

5. Maintain backward compatibility: the existing `registerHook`-based path continues to work for users who do not instantiate `OpenClawAdapter`.

**Files changed:**
- `packages/adapters/clawdstrike-openclaw/src/openclaw-adapter.ts` -- add translator wiring
- `packages/adapters/clawdstrike-openclaw/src/hooks/tool-preflight/handler.ts` -- extract `inferPolicyEventType` and `buildPolicyEvent` as named exports for reuse
- New file: `packages/adapters/clawdstrike-openclaw/src/openclaw-translator.ts`

**Risk:** Higher. Changing the interception lifecycle could alter:
- **Hook registration order.** OpenClaw's hook system runs handlers in registration order. Wrapping in `BaseToolInterceptor` changes the evaluation path. The CUA bridge handler must still run before the general preflight handler.
- **Decision caching interaction.** `BaseToolInterceptor` has no caching. The approval state lookup must happen before interceptor evaluation.
- **Error semantics.** `BaseToolInterceptor` returns `{ proceed: false, decision }` on deny. The hook system expects `toolEvent.preventDefault = true`. A bridge layer must translate.

**Verification:** Full regression test suite. Add integration tests that simulate OpenClaw hook event sequences and verify identical decisions, messages, and side effects.

### Phase 5: Promote Unique Features Upstream

**Goal:** Contribute openclaw-specific innovations to adapter-core or a shared utilities package so all adapters can benefit.

**Changes (backlog, each is an independent PR):**

1. **Decision caching** -- Contribute to adapter-core as an optional `CachingToolInterceptor` wrapper or `BaseToolInterceptor` constructor option. The LRU + TTL + hashed-key approach from `approval-state.ts` is framework-agnostic.

2. **Tool classification heuristics** -- Contribute the tokenizer and read-only/destructive classification as an opt-in behavior in adapter-core. Useful for any adapter that wants to skip pre-flight checks on read-only tools.

3. **Approval workflow** -- Contribute as a composable module (`@clawdstrike/approval` or an `ApprovalInterceptor` in adapter-core). The polling-based approval API integration is framework-agnostic.

4. **Security prompt generation** -- Contribute to adapter-core. The `generateSecurityPrompt(policy)` function is useful for any adapter that supports agent bootstrapping.

5. **Defense-in-depth command path extraction** -- Contribute to `@clawdstrike/policy` or adapter-core. The `extractCommandPathCandidates()` function and associated heuristics are reusable.

**Risk:** Low per contribution. Each is additive and opt-in.

## Dependency Changes

- `@clawdstrike/adapter-core`: Already a dependency (`^0.1.1`). Phase 1-3 increase usage of existing exports. Phase 4 may require adapter-core to expose additional hooks (e.g., pre-evaluation callback). If so, bump to `^0.2.0`.
- No new dependencies needed for Phases 1-4.
- Phase 5 contributions may create new packages (`@clawdstrike/approval`) or add exports to adapter-core.

## Migration Risks

### 1. Hook registration order

OpenClaw's hook system runs handlers in the order they are registered. Currently `plugin.ts:173-183` registers:
1. `cuaBridgeHandler` (tool_call)
2. `toolPreflightHandler` (tool_call)
3. `toolGuardHandler` (tool_result_persist)
4. `agentBootstrapHandler` (agent:bootstrap)

CUA detection must run before general preflight so that CUA tool calls are routed to the CUA bridge and not evaluated as generic tools. Changing from direct handlers to `BaseToolInterceptor`-wrapped handlers must preserve this ordering.

**Mitigation:** Keep the hook registration order unchanged. Only change the internal implementation of each handler, not its registration.

### 2. Decision caching interaction

`BaseToolInterceptor` has no caching or approval awareness. If Phase 4 wraps preflight in `BaseToolInterceptor`, the approval check must happen before `interceptor.beforeExecute()` and short-circuit if a valid approval exists.

**Mitigation:** Implement as a pre-hook: check approval state first, return early if approved, otherwise delegate to interceptor.

### 3. Approval workflow is not modeled in adapter-core

The approval workflow (submit request, poll for resolution, record result) has no equivalent in the `FrameworkAdapter` or `BaseToolInterceptor` interfaces. It must remain as an openclaw-specific extension.

**Mitigation:** The `OpenClawAdapter` class exposes approval-related methods that are not part of the `FrameworkAdapter` interface. Consumers who need approval must use `OpenClawAdapter` directly rather than through the generic interface.

### 4. PII label format change (Phase 1)

Changing redaction labels from `[REDACTED:email]` to `[REDACTED_EMAIL]` is a user-visible output change. Any downstream processing that pattern-matches on the old labels will break.

**Mitigation:** Bump minor version. Document the change in CHANGELOG. Consider a transition period where both labels are recognized by downstream parsers.

### 5. Singleton consolidation race conditions (Phase 3)

If `plugin.ts` initialization and hook handler invocation happen concurrently (unlikely in practice but possible in test environments), the shared engine might not be initialized when a handler runs.

**Mitigation:** The `getSharedEngine()` function already handles this by creating a default engine. Add a warning log when this fallback is triggered to surface misconfiguration.

## Cross-Adapter Inconsistencies to Fix (All Adapters)

These issues are outside openclaw specifically but surfaced during this analysis. Each should be a separate PR.

### 1. vercel-ai defines duplicate `ClawdstrikeBlockedError`

`packages/adapters/clawdstrike-vercel-ai/src/errors.ts` defines its own `ClawdstrikeBlockedError` class with identical shape to `@clawdstrike/adapter-core`'s version (`packages/adapters/clawdstrike-adapter-core/src/errors.ts`). This means `instanceof` checks across packages will fail. Should re-export from adapter-core instead.

### 2. vercel-ai builds `SessionSummary` inline

`packages/adapters/clawdstrike-vercel-ai/src/vercel-ai-adapter.ts:55-82` builds the `SessionSummary` object inline with manual field mapping. LangChain correctly uses `createSessionSummary(context, this.config)` from adapter-core. Vercel-ai should do the same.

### 3. All adapters hardcode version strings

Every adapter has a hardcoded `version` property (e.g., `'0.1.0'`, `'0.1.1'`). These should be derived from their respective `package.json` at build time to avoid version drift.

### 4. PII redaction labels differ between openclaw and adapter-core

Documented above in Phase 1. Openclaw uses `[REDACTED:email]` format; adapter-core uses `[REDACTED_EMAIL]` format. After Phase 1, openclaw will be aligned.

## Timeline

| Phase | Sprint | Risk | Key Deliverable |
|-------|--------|------|-----------------|
| Phase 1: Type Unification | This sprint | Low | Remove unsafe casts, align PII labels, re-export shared types |
| Phase 2: Create `OpenClawAdapter` | Next sprint | Medium | `FrameworkAdapter` implementation for openclaw |
| Phase 3: Consolidate Engine Singletons | Next sprint | Medium | Single shared `PolicyEngine` instance across all handlers |
| Phase 4: Integrate `BaseToolInterceptor` | Sprint after | Higher | Unified interception lifecycle with backward compatibility |
| Phase 5: Promote Unique Features | Backlog | Low | Upstream contributions (caching, classification, approval, security prompts) |

Cross-adapter fixes (duplicate errors, inline summaries, hardcoded versions) can be done independently and should not block openclaw alignment work.

## Exit Criteria

1. `OpenClawAdapter` passes the same fixture-driven decision parity tests as other adapters.
2. Zero `as unknown as` casts in the openclaw package.
3. PII redaction output matches adapter-core format.
4. Existing OpenClaw plugin hook-based integration continues to work (no breaking changes for existing users).
5. All tests pass: `npm test` in `clawdstrike-openclaw`, `clawdstrike-adapter-core`, `clawdstrike-vercel-ai`, `clawdstrike-langchain`.
