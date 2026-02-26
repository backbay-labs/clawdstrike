# OpenClaw Plugin Correctness Findings (2026-02-25)

> Historical snapshot (2026-02-25).  
> Current branch status is tracked in [`2026-02-26-openclaw-launch-revalidation.md`](./2026-02-26-openclaw-launch-revalidation.md).

## Audit Metadata

- **Audit date:** 2026-02-25
- **Scope:** OpenClaw adapter plugin (`packages/adapters/clawdstrike-openclaw`), supporting SDK modules (`packages/sdk/hush-ts`, `packages/sdk/hush-py`), and downstream consumers (`apps/desktop`, `apps/agent`)
- **Type:** Point-in-time correctness review (launch readiness)
- **Branch:** `feat/clawdstrike-sdks-launch`
- **Finding count:** 11 (3 High, 5 Medium, 3 Low)

## Executive Summary

11 correctness issues were identified during launch readiness review of the OpenClaw adapter plugin and its integration surface. Three are rated High due to potential for security policy bypass or silent data loss at process exit. Five are Medium, affecting classification accuracy, validation honesty, approval lifecycle, and cross-component protocol compatibility. Three are Low, covering dead code, decision metadata loss, and a behavioral change in the Python SDK that may break downstream callers.

No issues require emergency rollback. All are remediable with targeted fixes. The most urgent items are C1 (egress port mismatch), C3 (CUA severity bypass), and C4 (buffered event loss on shutdown).

---

## Findings

### C1 — `wss:` Port Default Wrong in Tool-Guard Handler

| Field | Value |
|-------|-------|
| **ID** | C1 |
| **Severity** | High |
| **Location** | `packages/adapters/clawdstrike-openclaw/src/hooks/tool-guard/handler.ts:503` |
| **Status** | Open |

**Description:**
The `extractNetworkInfo` function in the tool-guard (post-execution) handler defaults `wss://` URLs to port 80 instead of 443. The port default logic at line 503 only checks `parsed.protocol === 'https:'`:

```typescript
port: parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80),
```

The equivalent function in the preflight handler (`tool-preflight/handler.ts:287`) correctly handles this:

```typescript
port: parsed.port
  ? parseInt(parsed.port, 10)
  : (parsed.protocol === 'https:' || parsed.protocol === 'wss:' ? 443 : 80),
```

The same omission exists in the command-extraction branch at line 518, which also only checks `https:`.

**Impact:**
Post-execution egress checks evaluate `wss://` connections against port 80 instead of 443. This creates two failure modes:
1. If the egress allowlist permits `host:443` but not `host:80`, a legitimate `wss://` connection is incorrectly denied post-execution.
2. If the egress allowlist permits `host:80` but not `host:443`, a `wss://` connection to a non-allowed port is incorrectly allowed.

Since the preflight handler correctly classifies `wss:` on port 443, the same tool action can receive conflicting verdicts pre- and post-execution.

**Remediation:**
Add `parsed.protocol === 'wss:'` alongside `'https:'` in both port-default branches of the tool-guard handler's `extractNetworkInfo`:

```typescript
port: parsed.port
  ? parseInt(parsed.port, 10)
  : (parsed.protocol === 'https:' || parsed.protocol === 'wss:' ? 443 : 80),
```

Apply the same fix at lines 503 and 518. Add a test case that asserts `wss://example.com/ws` resolves to port 443 in the tool-guard handler.

---

### C2 — `looksLikePatchApply` Over-classifies File Writes as Patches

| Field | Value |
|-------|-------|
| **ID** | C2 |
| **Severity** | Medium |
| **Location** | `packages/adapters/clawdstrike-openclaw/src/hooks/tool-preflight/handler.ts:304-308` |
| **Status** | Open |

**Description:**
The `looksLikePatchApply` heuristic includes a catch-all condition that classifies any parameter set containing both `filePath` and `content` (or `newContent`) as a patch operation:

```typescript
function looksLikePatchApply(params: Record<string, unknown>): boolean {
  return typeof params.patch === 'string'
    || typeof params.diff === 'string'
    || typeof params.patchContent === 'string'
    || (typeof params.filePath === 'string' && (typeof params.content === 'string' || typeof params.newContent === 'string'));
}
```

A tool call like `writeFile({ filePath: "/foo", content: "bar" })` triggers `patch_apply` classification. This routes plain file writes through the `PatchIntegrityGuard` instead of the `ForbiddenPathGuard` / `SecretLeakGuard` file-write pipeline.

**Impact:**
- File write operations are evaluated against the wrong guard chain. A write to a forbidden path could pass the patch integrity check and bypass the forbidden-path guard.
- False positives: benign file writes may be denied by patch-specific validation (e.g., diff format checks).
- The `inferPolicyEventType` function at line 148 calls `looksLikePatchApply` before `looksLikeFileWrite`, so the over-broad condition takes priority.

**Remediation:**
Remove the `filePath + content` disjunct from `looksLikePatchApply`. This case should fall through to `looksLikeFileWrite` (which already checks for `filePath + content`):

```typescript
function looksLikePatchApply(params: Record<string, unknown>): boolean {
  return typeof params.patch === 'string'
    || typeof params.diff === 'string'
    || typeof params.patchContent === 'string';
}
```

Verify that `looksLikeFileWrite` at line 324 correctly catches the `filePath + content` case. Add test cases for `writeFile({ filePath, content })` asserting `file_write` classification, and for `applyPatch({ patch: "..." })` asserting `patch_apply` classification.

---

### C3 — CUA Bridge Skips Severity Check on Prior Approvals

| Field | Value |
|-------|-------|
| **ID** | C3 |
| **Severity** | High |
| **Location** | `packages/adapters/clawdstrike-openclaw/src/hooks/cua-bridge/handler.ts:282-289` |
| **Status** | Open |

**Description:**
When a prior approval exists for a CUA (Computer Use Agent) action, the CUA bridge handler bypasses all policy evaluation regardless of severity:

```typescript
const prior = peekApproval(sessionId, toolName, resource);
if (prior) {
  toolEvent.messages.push(
    `[clawdstrike:cua-bridge] CUA ${kind}: using prior ${prior.resolution} approval for ${toolName}`,
  );
  return;
}
```

The preflight handler correctly re-evaluates critical-severity denials even when a prior approval exists (line 481):

```typescript
if (severity !== 'critical') {
  const prior = peekApproval(sessionId, toolName, resource);
  if (prior) { ... }
}
```

The CUA bridge checks for prior approvals *before* policy evaluation, so the severity of the current policy decision is never computed.

**Impact:**
A CUA action that was previously approved but is now rated `critical` by policy (e.g., due to a policy update or changed threat conditions) would still be allowed through the CUA bridge. This violates the fail-closed invariant for critical-severity decisions and creates an inconsistency between the preflight and CUA enforcement paths.

**Remediation:**
Move the prior-approval check to after policy evaluation and gate it on severity:

```typescript
const decision: Decision = await policyEngine.evaluate(cuaEvent as unknown as import('../../types.js').PolicyEvent);

if (decision.status === 'deny') {
  const severity = decision.severity ?? 'high';

  if (severity !== 'critical') {
    const prior = peekApproval(sessionId, toolName, resource);
    if (prior) {
      toolEvent.messages.push(
        `[clawdstrike:cua-bridge] CUA ${kind}: using prior ${prior.resolution} approval for ${toolName}`,
      );
      return;
    }
  }

  toolEvent.preventDefault = true;
  // ... existing deny handling
}
```

Add test cases covering: (a) prior approval honored for non-critical CUA denial, (b) prior approval ignored for critical CUA denial.

---

### C4 — `AlertingExporter.shutdown()` Drops Buffered Events

| Field | Value |
|-------|-------|
| **ID** | C4 |
| **Severity** | High |
| **Location** | `packages/sdk/hush-ts/src/siem/exporters/alerting.ts:428-431` |
| **Status** | Open |

**Description:**
The `AlertingExporter` class overrides `shutdown()` without calling `super.shutdown()`:

```typescript
async shutdown(): Promise<void> {
  this.pagerduty?.shutdown();
  this.opsgenie?.stopHeartbeat();
}
```

The base class `BaseExporter` in `packages/sdk/hush-ts/src/siem/framework.ts:206-208` defines `shutdown()` as:

```typescript
async shutdown(): Promise<void> {
  await this.flush();
}
```

`BaseExporter.flush()` drains the internal event buffer and exports pending events. By skipping `super.shutdown()`, the `AlertingExporter` silently discards any buffered security events on process exit.

All other SIEM exporters in the codebase either inherit the base `shutdown()` or call `super.shutdown()` in their overrides.

**Impact:**
Security events buffered between the last flush interval and process exit are permanently lost. In a normal shutdown scenario with the default 5-second flush interval, up to 5 seconds of security events (policy denials, guard violations, threat detections) may be silently dropped. This is particularly impactful for PagerDuty/OpsGenie alerting, where a critical denial event at process exit would never trigger an alert.

**Remediation:**
Add `await super.shutdown()` at the beginning of the override:

```typescript
async shutdown(): Promise<void> {
  await super.shutdown();
  this.pagerduty?.shutdown();
  this.opsgenie?.stopHeartbeat();
}
```

The `super.shutdown()` call must precede the PagerDuty/OpsGenie teardown so that buffered events are exported before the alerting clients are shut down. Add a test asserting that events buffered before `shutdown()` are exported to the configured alerting target.

---

### C5 — `on_violation` Values `isolate`/`escalate` Pass Validation but Are Unimplemented

| Field | Value |
|-------|-------|
| **ID** | C5 |
| **Severity** | Medium |
| **Location** | `packages/adapters/clawdstrike-openclaw/src/policy/validator.ts:8` (validation) vs `packages/adapters/clawdstrike-openclaw/src/policy/engine.ts:784-801` (runtime) |
| **Status** | Open |

**Description:**
The policy validator accepts four `on_violation` values:

```typescript
const VALID_VIOLATION_ACTIONS = new Set(['cancel', 'warn', 'isolate', 'escalate']);
```

However, the engine's `applyOnViolation` method only handles two of them:

```typescript
private applyOnViolation(decision: Decision): Decision {
  const action = this.policy.on_violation;
  if (decision.status !== 'deny') return decision;

  if (action === 'warn') {
    return warnDecision(/* ... */);
  }

  if (action && action !== 'cancel') {
    console.warn(`[clawdstrike] Unhandled on_violation action: "${action}" — treating as deny`);
  }

  return decision;
}
```

Setting `on_violation: 'isolate'` or `on_violation: 'escalate'` passes policy validation without errors or warnings, but at runtime both are silently treated as `deny` with only a `console.warn` log.

**Impact:**
Policy authors who set `on_violation: 'isolate'` or `on_violation: 'escalate'` believe they are configuring isolation or escalation behavior. In practice, the agent is hard-denied. This creates a false sense of configurability and may cause operational confusion when policies behave as deny-all instead of escalating to a human reviewer.

**Remediation:**
Option A (preferred): Remove `'isolate'` and `'escalate'` from the validator's accepted values until they are implemented. Add a lint warning when these values are encountered in existing policies:

```typescript
const VALID_VIOLATION_ACTIONS = new Set(['cancel', 'warn']);
```

Option B: Implement `isolate` and `escalate` behaviors (e.g., `isolate` pauses the agent session, `escalate` triggers an approval request). This is a larger effort and should be scoped separately.

In either case, document the change in the policy schema changelog and add a deprecation notice for existing policies using these values.

---

### C6 — Audit Logger Handler Is Dead Code

| Field | Value |
|-------|-------|
| **ID** | C6 |
| **Severity** | Low |
| **Location** | `packages/adapters/clawdstrike-openclaw/src/hooks/audit-logger/handler.ts` |
| **Status** | Open |

**Description:**
The audit-logger hook handler is defined but never imported, initialized, or registered in `plugin.ts`. A search for `audit-logger`, `audit_logger`, or `auditLogger` in the plugin source yields no references beyond the handler's own `HOOK.md` descriptor.

The handler itself has limited functionality:
- Only handles `tool_result_persist` events (not `tool_call` or `tool_guard`).
- Only logs to `console` via a custom logger wrapper.
- Does not record policy decisions, capture preflight blocks, or emit structured audit events.
- Has zero test coverage.

**Impact:**
No functional impact (the code is unreachable). The risk is maintenance burden and false confidence: the existence of an `audit-logger/` directory suggests audit logging is active when it is not. New contributors may assume audit events are being captured.

**Remediation:**
Option A: Wire the handler into `plugin.ts` with proper structured audit event recording that captures policy decisions across all hook types (preflight deny, tool-guard deny, CUA bridge deny, approval lifecycle). Add test coverage.

Option B: Remove the `audit-logger/` directory and its `HOOK.md` entirely. If audit logging is planned for a future release, track it as a feature request rather than shipping dead code.

---

### C7 — Classification Divergence Between Preflight and Tool-Guard

| Field | Value |
|-------|-------|
| **ID** | C7 |
| **Severity** | Medium |
| **Location** | `packages/adapters/clawdstrike-openclaw/src/hooks/tool-preflight/handler.ts:117` (token-based) vs `packages/adapters/clawdstrike-openclaw/src/hooks/tool-guard/handler.ts:364` (substring-based) |
| **Status** | Open |

**Description:**
The preflight and tool-guard handlers use fundamentally different classification strategies for the same tool names:

**Preflight (`inferPolicyEventType`):** Tokenizes the tool name by splitting on `_`, `-`, `/`, `.`, and whitespace, then performs set lookups against token sets (`DESTRUCTIVE_TOKENS`, `READ_ONLY_TOKENS`, `NETWORK_TOKENS`).

**Tool-guard (`inferEventType`):** Uses `.includes()` substring matching against the lowercased tool name.

```typescript
// tool-guard/handler.ts:369
if (lowerName.includes('patch') || lowerName.includes('diff') || lowerName.includes('apply_patch')) {
  return 'patch_apply';
}
```

This creates classification divergence for tool names where a substring match does not correspond to a token boundary. Example: a tool named `"patchwork"`:
- **Preflight:** tokenizes to `["patchwork"]`. No destructive token match (the set contains `"patch"`, not `"patchwork"`). Falls through to `tool_call`.
- **Tool-guard:** `"patchwork".includes("patch")` is `true`. Classified as `patch_apply`.

The same tool action is evaluated against different guard chains pre- and post-execution.

**Impact:**
- A tool that preflight classifies as `tool_call` (generic) may be classified as `patch_apply` by the tool-guard, causing it to be evaluated against patch integrity guards post-execution that it was not checked against pre-execution.
- Conversely, a tool that preflight routes through destructive checks may be classified differently post-execution, skipping post-execution guards that should have run.
- This inconsistency undermines the defense-in-depth model where pre- and post-execution checks should apply the same guard chain.

**Remediation:**
Extract the classification logic into a shared module (e.g., `packages/adapters/clawdstrike-openclaw/src/classification.ts`) used by both handlers. Use the token-based approach (which is more precise) as the canonical implementation. Replace the substring-based logic in the tool-guard handler with a call to the shared classifier.

Add regression tests that assert classification parity for edge cases: `"patchwork"`, `"getReadme"`, `"shellac"`, `"execute_bash"`, `"diff_viewer"`.

---

### C8 — Approval Resolution Events Not Handled

| Field | Value |
|-------|-------|
| **ID** | C8 |
| **Severity** | Medium |
| **Location** | `apps/desktop/src/context/OpenClawDirectFallback.tsx:184-207`, `apps/agent/src-tauri/src/openclaw/manager.rs:815` |
| **Status** | Open |

**Description:**
Both the desktop TypeScript client and the Rust agent only handle `exec.approval.requested` events from the gateway protocol. Neither handles `exec.approval.resolved` or `exec.approval.rejected`:

**Desktop (`OpenClawDirectFallback.tsx:184-207`):**

```typescript
export function applyGatewayEventFrame(
  current: OpenClawGatewayRuntime,
  frame: GatewayEventFrame
): OpenClawGatewayRuntime {
  if (frame.event === "presence") { /* ... */ }

  if (frame.event === "exec.approval.requested") {
    // Adds to queue, deduplicates by id, caps at 100
    // ...
  }

  return current;  // All other events are no-ops
}
```

**Rust agent (`manager.rs:815`):**

```rust
"exec.approval.requested" => {
    // Adds to exec_approval_queue, deduplicates, truncates to 100
}
```

No `"exec.approval.resolved"` or `"exec.approval.rejected"` match arm exists.

**Impact:**
Resolved and rejected approvals are never removed from the approval queue. The queue grows monotonically until it hits the cap (100 in Rust, 100 in desktop with 20 displayed). Users see stale approval requests in the UI that have already been acted upon. In the Rust agent, stale entries consume memory and slow linear scans on the queue.

**Remediation:**
Add handlers for `exec.approval.resolved` and `exec.approval.rejected` in both clients that remove the matching entry from the queue by ID:

```typescript
if (frame.event === "exec.approval.resolved" || frame.event === "exec.approval.rejected") {
  const id = (frame.payload as { id?: string })?.id;
  if (!id) return current;
  return {
    ...current,
    execApprovalQueue: current.execApprovalQueue.filter((a) => a.id !== id),
  };
}
```

Apply the equivalent logic in the Rust agent's match arm. Add test cases for both resolution and rejection events.

---

### C9 — Protocol Auth Field Mismatch Between Desktop and Rust

| Field | Value |
|-------|-------|
| **ID** | C9 |
| **Severity** | Medium |
| **Location** | `apps/desktop/src/services/openclaw/gatewayProtocol.ts:64-67` vs `apps/agent/src-tauri/src/openclaw/protocol.rs:94-101` |
| **Status** | Open |

**Description:**
The TypeScript desktop client and the Rust agent use different field names for device-based authentication in the gateway protocol auth block.

**TypeScript (`gatewayProtocol.ts:64-67`):**

```typescript
auth?: {
  token?: string;
  deviceToken?: string;
};
```

**Rust (`protocol.rs:94-101`):**

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayAuth {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}
```

The Rust struct has `password` where the TypeScript client sends `deviceToken`. The `#[serde(rename_all = "camelCase")]` attribute means the Rust struct expects `{ "token": "...", "password": "..." }` on the wire. A TypeScript client sending `{ "token": "...", "deviceToken": "..." }` will have the `deviceToken` field silently ignored during deserialization (serde skips unknown fields by default).

**Impact:**
Device token authentication from the desktop client to a Rust-based gateway silently fails. The `password` field in the Rust struct is always `None` when the desktop client connects. If the gateway requires device token auth, the connection may be rejected or fall back to unauthenticated mode. The `token` field works correctly in both implementations.

**Remediation:**
Align the field names across both implementations. Two options:

Option A (preferred): Add `device_token` to the Rust struct (serialized as `deviceToken` by `rename_all = "camelCase"`):

```rust
pub struct GatewayAuth {
    pub token: Option<String>,
    pub device_token: Option<String>,
    #[deprecated]
    pub password: Option<String>,
}
```

Option B: Rename the TypeScript field to `password` to match the Rust struct. This is less descriptive but requires fewer changes.

Add a cross-language serialization test that verifies the TypeScript auth payload deserializes correctly in Rust.

---

### C10 — `combineDecisions` Discards Metadata on Rank Ties

| Field | Value |
|-------|-------|
| **ID** | C10 |
| **Severity** | Low |
| **Location** | `packages/adapters/clawdstrike-openclaw/src/policy/engine.ts:846-848` |
| **Status** | Open |

**Description:**
The `combineDecisions` function returns the `base` decision when both `base` and `next` have the same rank:

```typescript
function combineDecisions(base: Decision, next: Decision): Decision {
  const rank: Record<string, number> = { deny: 2, warn: 1, allow: 0 };
  return (rank[next.status] ?? 0) > (rank[base.status] ?? 0) ? next : base;
}
```

When both decisions are `deny` (rank 2 vs rank 2), the comparison `2 > 2` is `false`, so `base` is returned. The `next` decision's metadata -- including `reason`, `guard`, `severity`, `reason_code`, and any threat intelligence evidence -- is silently discarded.

**Impact:**
When multiple guards deny the same action, only the first guard's evidence is preserved in the final decision. Downstream consumers (audit logs, approval requests, SIEM exporters) see an incomplete picture. For example, if both the `ForbiddenPathGuard` and `SecretLeakGuard` deny a write, only the forbidden-path reason appears in the audit trail; the secret leak detection is lost.

**Remediation:**
Option A (minimal): Merge reasons on rank ties by appending the `next` decision's reason to the `base` decision:

```typescript
function combineDecisions(base: Decision, next: Decision): Decision {
  const rank: Record<string, number> = { deny: 2, warn: 1, allow: 0 };
  if ((rank[next.status] ?? 0) > (rank[base.status] ?? 0)) return next;
  if (base.status === next.status && next.reason) {
    return {
      ...base,
      reason: base.reason
        ? `${base.reason}; ${next.reason}`
        : next.reason,
    };
  }
  return base;
}
```

Option B: Return an array of decisions and let downstream consumers handle aggregation. This is a larger change that affects the Decision type contract.

---

### C11 — Python `verify_signature` Exception Narrowing Is Breaking

| Field | Value |
|-------|-------|
| **ID** | C11 |
| **Severity** | Low |
| **Location** | `packages/sdk/hush-py/src/clawdstrike/core.py:88` |
| **Status** | Open |

**Description:**
The `verify_signature` function narrows its exception handling from a broad `except Exception` to `except (BadSignatureError, CryptoError)`:

```python
def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    try:
        verify_key = VerifyKey(public_key)
        verify_key.verify(message, signature)
        return True
    except (BadSignatureError, CryptoError):
        return False
```

This change was introduced in commit `a376e17c` ("fix: address PR review comments"). While semantically correct for the fail-closed design philosophy (unexpected errors should propagate rather than silently returning `False`), it is a behavioral breaking change.

Previously, malformed inputs (e.g., a `public_key` of wrong length triggering `ValueError`, or a non-bytes input triggering `TypeError`) would return `False`. Now they propagate as uncaught exceptions.

**Impact:**
Callers that relied on `verify_signature` never raising exceptions will experience unhandled `TypeError` or `ValueError` crashes when passing malformed input. This is particularly relevant for callers that use `verify_signature` as a boolean predicate without wrapping it in try/except. The behavioral change is semantically correct (fail-closed) but may break existing integrations.

**Remediation:**
1. Document the behavioral change in the SDK changelog with a migration note.
2. Consider catching known edge-case exceptions for input validation errors while still propagating truly unexpected errors:

```python
except (BadSignatureError, CryptoError, TypeError, ValueError):
    return False
```

Alternatively, validate inputs explicitly before calling into `nacl` and raise a descriptive `CryptoError` for malformed inputs, keeping the exception surface predictable:

```python
if not isinstance(public_key, bytes) or len(public_key) != 32:
    raise CryptoError("public_key must be 32 bytes")
```

Add test cases for malformed inputs (`None`, empty bytes, wrong-length keys) to document and lock the expected behavior.

---

## Summary Table

| ID | Title | Severity | Component | Status |
|----|-------|----------|-----------|--------|
| C1 | `wss:` port default wrong in tool-guard handler | High | openclaw/tool-guard | Open |
| C2 | `looksLikePatchApply` over-classifies file writes | Medium | openclaw/tool-preflight | Open |
| C3 | CUA bridge skips severity check on prior approvals | High | openclaw/cua-bridge | Open |
| C4 | `AlertingExporter.shutdown()` drops buffered events | High | hush-ts/siem | Open |
| C5 | `on_violation` values `isolate`/`escalate` unimplemented | Medium | openclaw/policy | Open |
| C6 | Audit logger handler is dead code | Low | openclaw/audit-logger | Open |
| C7 | Classification divergence between preflight and tool-guard | Medium | openclaw/hooks | Open |
| C8 | Approval resolution events not handled | Medium | desktop + agent | Open |
| C9 | Protocol auth field mismatch between desktop and Rust | Medium | desktop + agent | Open |
| C10 | `combineDecisions` discards metadata on rank ties | Low | openclaw/policy | Open |
| C11 | Python `verify_signature` exception narrowing is breaking | Low | hush-py | Open |

## Recommended Remediation Priority

**Immediate (before launch):**
1. **C1** — Port default fix is a one-line change with high security impact.
2. **C3** — CUA severity bypass is a policy enforcement gap.
3. **C4** — Buffered event loss affects audit integrity.

**Short-term (first post-launch patch):**
4. **C7** — Classification divergence creates inconsistent enforcement.
5. **C2** — Over-classification routes writes through wrong guards.
6. **C5** — Validator/engine mismatch creates false configurability.
7. **C8** — Stale approvals degrade UI and waste resources.

**Medium-term:**
8. **C9** — Protocol field mismatch blocks device token auth.
9. **C10** — Metadata loss on ties affects audit completeness.
10. **C11** — Document and stabilize Python SDK exception contract.
11. **C6** — Remove dead code or implement properly.
