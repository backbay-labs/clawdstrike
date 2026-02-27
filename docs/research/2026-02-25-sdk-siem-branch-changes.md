# SDK and SIEM Exporter Branch Changes Analysis

> Analysis of changes to `hush-ts` (TypeScript SDK), `hush-py` (Python SDK), and SIEM
> exporters on the `feat/clawdstrike-sdks-launch` branch. Covers every changed file in
> the SDK and SIEM surface area, identifies behavioral impacts, and flags issues requiring
> action before merge.

**Status**: Research
**Date**: 2026-02-25
**Audience**: SDK maintainers, security architecture, QA

---

## Table of Contents

1. [Overview](#1-overview)
2. [Fail-Closed Guard Evaluation (TS + Python)](#2-fail-closed-guard-evaluation-ts--python)
3. [SIEM Exporter Changes](#3-siem-exporter-changes)
4. [Python SDK Changes](#4-python-sdk-changes)
5. [SIEM Framework Changes](#5-siem-framework-changes)
6. [Issue Summary](#6-issue-summary)
7. [Recommendations](#7-recommendations)

---

## 1. Overview

The `feat/clawdstrike-sdks-launch` branch introduces changes across four commits
(`0177d344`, `a376e17c`, `682e1da8`, `aa9a1702`) touching 19 files. This analysis covers
the SDK and SIEM exporter subset: the TypeScript SDK (`packages/sdk/hush-ts`), the Python
SDK (`packages/sdk/hush-py`), and the SIEM integration layer (`packages/sdk/hush-ts/src/siem`).

The changes fall into four categories:

1. **Fail-closed guard evaluation** -- Both SDKs now catch guard exceptions and treat them
   as deny decisions with `Severity.CRITICAL`. This is the correct security posture
   (fail-closed), but has no test coverage.
2. **SIEM exporter hardening** -- Timer leak prevention, `@experimental` tagging, and a
   correctness fix to webhook export counts. One bug introduced: `AlertingExporter.shutdown()`
   drops buffered events.
3. **Python SDK expansion** -- Six new secret detection patterns, patch action support in
   `SecretLeakGuard`, exception narrowing in `verify_signature()`, and dependency updates.
4. **SIEM framework additions** -- New `filtered` field in `ExportResult`, module-level
   `@experimental` tag.

---

## 2. Fail-Closed Guard Evaluation (TS + Python)

### 2.1. TypeScript -- `packages/sdk/hush-ts/src/clawdstrike.ts`

**Change**: Added try/catch around `guard.check()` calls in two locations:
- `ClawdstrikeSession.check()` (line 1190-1199)
- `Clawdstrike.check()` (line 1497-1506)

Guards that throw exceptions now produce a deny decision with `Severity.CRITICAL` and a
message containing the original error:

```ts
let result: GuardResult;
try {
  result = guard.check(guardAction, guardContext);
} catch (error) {
  result = GuardResult.block(
    guard.name,
    Severity.CRITICAL,
    `Guard evaluation error (fail-closed): ${error instanceof Error ? error.message : String(error)}`,
  );
}
```

**Import change**: `GuardResult` moved from type-only import to value import (line 45).
This is required because `GuardResult.block()` is called as a runtime value in the catch
block. Previously, `GuardResult` was imported as `import type { Guard, GuardResult }`.

**Behavioral impact**: Previously, a guard throwing an exception would propagate as an
unhandled error, crashing the evaluation pipeline. Now it is caught and treated as a deny
decision. This is the correct security posture per the project's fail-closed design
philosophy (documented in CLAUDE.md). The guard name is preserved in the result, enabling
operators to identify which guard failed.

**Test coverage**: NONE. No test verifies that a throwing guard produces a deny/critical
result. Both `ClawdstrikeSession` and `Clawdstrike` paths are untested for this behavior.

### 2.2. Python -- `packages/sdk/hush-py/src/clawdstrike/core.py` and `policy.py`

**Change in `policy.py` (line 836-843)**: Same fail-closed pattern in `PolicyEngine.check()`:

```python
try:
    result = guard.check(action, context)
except Exception as e:
    result = GuardResult.block(
        guard=guard.name,
        severity=Severity.CRITICAL,
        message=f"Guard evaluation error (fail-closed): {e}",
    )
```

This required a new import of `Severity` from `clawdstrike.guards.base` (line 14).

**Change in `core.py` (line 88)**: Exception narrowing in `verify_signature()`:

```python
# Before:
except (BadSignatureError, Exception):
    return False

# After:
except (BadSignatureError, CryptoError):
    return False
```

This narrows the catch from `Exception` (all exceptions) to `CryptoError` (PyNaCl's base
cryptographic error class). The import on line 14 was updated from
`from nacl.exceptions import BadSignatureError` to
`from nacl.exceptions import BadSignatureError, CryptoError`.

**Behavioral impact of exception narrowing**: This is a **breaking behavioral change**.
The previous `except (BadSignatureError, Exception)` clause caught everything -- including
`TypeError` from malformed key bytes, `ValueError` from incorrect key lengths, and any
other unexpected exception. All such cases returned `False` (signature invalid).

With the narrowed clause, only `BadSignatureError` and `CryptoError` are caught. Other
exceptions (e.g., `TypeError` if `public_key` is `None`, `ValueError` from garbage input)
now propagate to the caller. If the caller does not handle these, it will crash rather
than gracefully returning `False`.

Whether this is correct depends on the caller's expectations:
- **If callers expect `verify_signature()` to never throw**: This is a regression.
- **If callers expect `verify_signature()` to throw on invalid input types**: This is a
  correctness fix (the original broad catch masked programming errors).

The commit message (`fix: address PR review comments`) does not document this design
decision. Given the fail-closed philosophy, the narrowing is defensible -- but it needs
documentation and the callers need review.

**Test coverage**: NONE for either change. No test sends a throwing guard through the
Python `PolicyEngine`, and no test exercises `verify_signature()` with non-crypto
exception-triggering input.

---

## 3. SIEM Exporter Changes

### 3.1. `@experimental` Tags -- All Exporters

All 6 exporter classes now have `/** @experimental */` JSDoc tags:

| File | Class |
|------|-------|
| `siem/exporters/alerting.ts` | `AlertingExporter` |
| `siem/exporters/datadog.ts` | `DatadogExporter` |
| `siem/exporters/elastic.ts` | `ElasticExporter` |
| `siem/exporters/splunk.ts` | `SplunkExporter` |
| `siem/exporters/sumo-logic.ts` | `SumoLogicExporter` |
| `siem/exporters/webhooks.ts` | `WebhookExporter` |

A module-level `@experimental` tag was also added to `siem/index.ts`:

```ts
/**
 * SIEM integration module.
 * @experimental This module is experimental and its API may change in future releases.
 * Exporters have not been validated against production SIEM services.
 */
```

**Assessment**: Correctly and consistently applied. No issues.

### 3.2. Timer Leak Prevention -- `siem/exporters/alerting.ts`

**Change**: Added `.unref()` calls on `setInterval` timers in two locations:

1. `PagerDutyClient` auto-resolve timer (line 135-137):
   ```ts
   if (typeof this.autoResolveTimer === 'object' && 'unref' in this.autoResolveTimer) {
     this.autoResolveTimer.unref();
   }
   ```

2. `OpsGenieClient` heartbeat timer (line 310-312):
   ```ts
   if (typeof this.heartbeatTimer === 'object' && 'unref' in this.heartbeatTimer) {
     this.heartbeatTimer.unref();
   }
   ```

**Impact**: Timers no longer prevent Node.js process exit. This is the correct behavior
for a library -- users should not need to call `shutdown()` just to let their process
terminate gracefully. The `typeof` guard ensures compatibility in non-Node.js environments
where `setInterval` returns a number rather than a `Timeout` object.

**Test coverage**: None, but appropriate as an infrastructure change. The `.unref()` call
is a Node.js runtime behavior that is not meaningfully unit-testable.

### 3.3. `AlertingExporter.shutdown()` Bug -- HIGH SEVERITY

**Location**: `siem/exporters/alerting.ts:428-431`

```ts
async shutdown(): Promise<void> {
  this.pagerduty?.shutdown();
  this.opsgenie?.stopHeartbeat();
}
```

**Problem**: `AlertingExporter.shutdown()` overrides the base class `shutdown()` without
calling `super.shutdown()`. The `BaseExporter.shutdown()` implementation in
`siem/framework.ts:206-208` drains the event buffer:

```ts
async shutdown(): Promise<void> {
  await this.flush();
}
```

**Impact**: When `AlertingExporter.shutdown()` is called (e.g., during process exit or
exporter teardown), any events buffered but not yet flushed are **silently dropped**.
Security events that were accepted into the buffer but not yet sent to PagerDuty or
OpsGenie are lost without error or warning.

This is particularly dangerous because:
- The `BaseExporter` uses a flush interval (default 5000ms) to batch events.
- Events arriving in the last flush window before shutdown are guaranteed to be lost.
- The `.unref()` timer fix (3.2 above) makes this more likely to trigger, because the
  process can now exit while events are still buffered.

**Fix**: Add `await super.shutdown();` before the client teardown:

```ts
async shutdown(): Promise<void> {
  await super.shutdown();  // flush buffered events
  this.pagerduty?.shutdown();
  this.opsgenie?.stopHeartbeat();
}
```

### 3.4. WebhookExporter `exported` Count Fix

**Location**: `siem/exporters/webhooks.ts:72-96`

**Before**:
```ts
for (const event of events) {
  if (!this.shouldNotify(event)) {
    exported += 1;  // BUG: counted as exported
    continue;
  }
  // ... actual export ...
}
return { exported, failed: errors.length, errors };
```

**After**:
```ts
let filtered = 0;
for (const event of events) {
  if (!this.shouldNotify(event)) {
    filtered += 1;  // correctly counted as filtered
    continue;
  }
  // ... actual export ...
}
return { exported, failed: errors.length, filtered, errors };
```

**Behavioral change**: `exported` counts will be lower than before for users with filter
rules (`minSeverity`, `includeGuards`, `excludeGuards`). Previously, events that were
skipped by `shouldNotify()` were counted in `exported`, inflating the metric. Now they
are correctly tracked in a separate `filtered` field.

**This is a correctness fix.** The previous behavior was overcounting exports. However,
any monitoring or alerting built on `ExportResult.exported` values will see a change in
reported numbers. This is backward compatible in type (the `filtered` field is optional
on `ExportResult`) but observable in metrics.

**Test coverage**: None for the new `filtered` count semantics.

### 3.5. WebhookExporter vs AlertingExporter Filtering Divergence -- MEDIUM

The two filtering methods have different semantics:

**`AlertingExporter.shouldAlert()`** (line 364-382):
```ts
private shouldAlert(event: SecurityEvent): boolean {
  if (event.decision.allowed) {
    return false;  // <-- skips allowed events
  }
  // ... severity threshold, guard include/exclude ...
}
```

**`WebhookExporter.shouldNotify()`** (line 99-109):
```ts
private shouldNotify(event: SecurityEvent): boolean {
  // Does NOT filter on event.decision.allowed
  if (this.cfg.minSeverity && severityOrd(event.decision.severity) < severityOrd(this.cfg.minSeverity)) {
    return false;
  }
  // ... guard include/exclude ...
}
```

**Divergence**: `AlertingExporter` filters out events where `event.decision.allowed === true`
(i.e., only alerts on denied actions). `WebhookExporter` does not filter on `decision.allowed`
-- webhooks fire for both allowed and denied events (if severity threshold and guard filters
are met).

This may be intentional:
- **Alerting** = violations only (PagerDuty/OpsGenie alerts should only fire when something
  is blocked)
- **Webhooks** = full visibility (downstream consumers may want to see all evaluated events)

However, this divergence is **undocumented**. Neither the JSDoc comments, the public API
documentation, nor the commit messages explain the design intent.

Additionally, `AlertingExporter.export()` does not track the filtered count:

```ts
const alertEvents = events.filter(e => this.shouldAlert(e));
if (alertEvents.length === 0) {
  return { exported: 0, failed: 0, errors: [] };  // no 'filtered' field
}
```

Since `WebhookExporter` now correctly tracks `filtered`, the two exporters are inconsistent
in their `ExportResult` reporting.

---

## 4. Python SDK Changes

### 4.1. `SecretLeakGuard` -- New Patterns and Patch Support

**Location**: `packages/sdk/hush-py/src/clawdstrike/guards/secret_leak.py`

**6 new secret patterns** added to `DEFAULT_SECRET_PATTERNS` (all severity `critical`):

| Pattern Name | Regex | Notes |
|-------------|-------|-------|
| `aws_secret_key` | `(?i)aws[_\-]?secret[_\-]?access[_\-]?key...{40}` | Case-insensitive, matches key-value pairs |
| `github_pat` | `github_pat_[A-Za-z0-9_]{82}` | Fine-grained personal access token format |
| `anthropic_key` | `\bsk-ant-[A-Za-z0-9_-]{40,}` | Word-boundary anchored |
| `npm_token` | `npm_[A-Za-z0-9]{36}` | npm automation tokens |
| `slack_token` | `xox[baprs]-[A-Za-z0-9\-]{10,}` | Covers bot, app, user, and other Slack token types |
| `generic_secret` | `(?i)(secret\|password\|passwd\|pwd)...{8,}` | Case-insensitive generic matcher |

**New action type support**: `action_type == "patch"` (line 124, 140-149):

```python
def handles(self, action: GuardAction) -> bool:
    if action.action_type in ("file_write", "patch"):  # was: == "file_write"
        return True
```

The patch content extraction (line 140-149) mirrors the existing `file_write` extraction
but additionally checks `action.diff` first (for structured diff content), then falls
back to `action.content`:

```python
if action.action_type == "patch":
    if action.diff is not None:
        return action.diff
    if action.content is not None:
        try:
            return action.content.decode("utf-8", errors="replace")
        except (AttributeError, UnicodeDecodeError):
            return str(action.content)
    return ""
```

**Test coverage**: NONE for new patterns or the patch action type. The `generic_secret`
pattern is broad and may produce false positives on configuration files with passwords
like `password=changeme1` (8+ chars). Testing against representative inputs is needed.

### 4.2. `JailbreakGuard` -- Configuration Documentation

**Location**: `packages/sdk/hush-py/src/clawdstrike/guards/jailbreak.py`

Added a documentation comment on the `session_aggregation` config field:

```python
# session_aggregation is accepted in configuration but not yet implemented.
# Matching Rust's exponential decay model is non-trivial; this field is
# reserved for future use.
session_aggregation: bool = True
```

This clarifies that the Python `JailbreakGuard` accepts the `session_aggregation` config
key (for YAML compatibility with Rust) but does not implement it. No behavioral change.

### 4.3. `policy.py` -- Variable Rename and Type Annotation

**Variable rename** (line 563-574): `patterns` renamed to `sl_patterns` in the
`secret_leak` guard merging logic within `Policy._merge()`:

```python
# Before:
patterns = secret_leak.patterns
if "patterns" in g:
    patterns = merge_secret_patterns(patterns, child.secret_leak.patterns)

# After:
sl_patterns: List[SecretPattern] = secret_leak.patterns
if "patterns" in g:
    sl_patterns = merge_secret_patterns(sl_patterns, child.secret_leak.patterns)
```

This fixes potential variable shadowing (the name `patterns` could shadow an outer scope
or be confused with other guard pattern variables in the same method) and adds an explicit
type annotation.

**Type annotation on `to_yaml()` return** (line 777):

```python
# Before:
return yaml.dump(data, default_flow_style=False, sort_keys=False)

# After:
result: str = yaml.dump(data, default_flow_style=False, sort_keys=False)
return result
```

This addresses a `mypy` complaint: `yaml.dump()` returns `Any` when the `stream` parameter
is omitted. The intermediate variable with explicit `str` annotation satisfies the type
checker. No behavioral change.

### 4.4. `pyproject.toml` -- Dependency and Build Updates

**New dev dependency** (line 37):
```toml
"types-PyYAML>=6.0",
```

Type stubs for PyYAML, required for the `mypy` type annotation changes in `policy.py`.

**New wheel build config** (line 47-48):
```toml
[tool.hatch.build.targets.wheel.force-include]
"../../../rulesets" = "clawdstrike/rulesets"
```

This bundles the top-level `rulesets/` directory (containing built-in YAML policies like
`permissive.yaml`, `default.yaml`, `strict.yaml`, `ai-agent.yaml`, `cicd.yaml`) into the
Python wheel at `clawdstrike/rulesets/`. This enables the Python SDK to resolve built-in
ruleset references (e.g., `extends: ["strict"]`) from the installed package rather than
requiring the rulesets to be present on the filesystem.

---

## 5. SIEM Framework Changes

### 5.1. `ExportResult.filtered` Field -- `siem/framework.ts`

**Change** (line 45): New optional field added to the `ExportResult` type:

```ts
export interface ExportResult {
  exported: number;
  failed: number;
  filtered?: number;  // NEW
  errors: ExportError[];
}
```

**Used by**: `WebhookExporter` (correctly tracks filtered events).

**Not used by**: `AlertingExporter` (also filters events via `shouldAlert()` but does not
report the filtered count).

**Backward compatible**: Optional field; existing code that destructures or accesses
`ExportResult` will not break.

### 5.2. `siem/index.ts` -- Module-Level Tag

The `@experimental` JSDoc block was added at the top of the module barrel file. No
structural changes to the re-exports.

---

## 6. Issue Summary

| # | Issue | Severity | File | Line(s) | Status |
|---|-------|----------|------|---------|--------|
| 1 | `AlertingExporter.shutdown()` drops buffered events by not calling `super.shutdown()` | HIGH | `siem/exporters/alerting.ts` | 428-431 | Open |
| 2 | No tests for fail-closed guard behavior (TS + Python) | HIGH | `clawdstrike.ts`, `core.py`, `policy.py` | 1190, 1497, 836 | Open |
| 3 | Python `verify_signature()` exception narrowing is a breaking behavioral change | MEDIUM | `core.py` | 88 | Open |
| 4 | Webhook/Alerting filtering divergence undocumented | MEDIUM | `webhooks.ts`, `alerting.ts` | 99, 364 | Open |
| 5 | No tests for new Python `SecretLeakGuard` patterns or patch action | MEDIUM | `secret_leak.py` | 47-79, 124, 140-149 | Open |
| 6 | `AlertingExporter` does not track `filtered` count (inconsistent with `WebhookExporter`) | LOW | `alerting.ts` | 388 | Open |
| 7 | No tests for `exported` count semantics change in `WebhookExporter` | LOW | `webhooks.ts` | 72-96 | Open |

---

## 7. Recommendations

### 7.1. Before Merge (blocking)

1. **Fix `AlertingExporter.shutdown()`** (Issue #1): Add `await super.shutdown();` at the
   top of the override. Without this, the `.unref()` timer fix makes event loss on process
   exit more likely, not less.

2. **Add tests for fail-closed guard behavior** (Issue #2): Both SDKs need at least one
   test that registers a guard which throws, invokes `check()`, and asserts the result is
   `deny` with `Severity.CRITICAL`. Suggested locations:
   - TypeScript: `packages/sdk/hush-ts/tests/clawdstrike.test.ts`
   - Python: `packages/sdk/hush-py/tests/test_policy_engine.py`

### 7.2. Fast-Follow (before GA)

3. **Document `verify_signature()` exception narrowing** (Issue #3): Either:
   - Restore the broad catch if callers expect `verify_signature()` to never throw, or
   - Audit all callers to ensure they handle non-crypto exceptions, and document the
     contract change in the changelog.

4. **Document filtering divergence** (Issue #4): Add JSDoc to both `shouldAlert()` and
   `shouldNotify()` explaining the design intent (alerting = violations only, webhooks =
   all evaluated events). If this distinction is not intentional, align the behavior.

5. **Track `filtered` count in `AlertingExporter`** (Issue #6): Update
   `AlertingExporter.export()` to include `filtered: events.length - alertEvents.length`
   in the `ExportResult`.

### 7.3. Backlog

6. **Expand Python test coverage** (Issue #5): Add tests for each of the 6 new secret
   patterns, including edge cases for the `generic_secret` pattern (false positive risk on
   config files). Add tests for the `patch` action type in `SecretLeakGuard`.

7. **Add tests for `WebhookExporter` count semantics** (Issue #7): Verify that `exported`
   excludes filtered events and `filtered` is correctly populated.
