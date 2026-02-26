# OpenClaw Plugin Test Coverage Gap Analysis

**Date:** 2026-02-25
**Branch:** `feat/clawdstrike-sdks-launch`
**Author:** Clawdstrike SDKs Team
**Status:** Pre-merge review

> Historical snapshot (2026-02-25).  
> Current branch status (2026-02-26): OpenClaw adapter tests are **26 files / 455 tests passing**, and adapter-core cross-adapter tests are now runnable (**57 tests passing**).  
> See [`../audits/2026-02-26-openclaw-launch-revalidation.md`](../audits/2026-02-26-openclaw-launch-revalidation.md).

---

## Context

At the time of this pre-merge audit, branch `feat/clawdstrike-sdks-launch` introduced changes to the openclaw adapter, policy engine, SDK, and SIEM exporters. The snapshot then reported 242 TypeScript tests passing. This report preserves that point-in-time analysis.

## Current Test Suite Status

| Suite | Count | Status |
| --- | --- | --- |
| TypeScript (openclaw adapter) | 242 tests across 19 files | All pass |
| Rust (workspace) | All crate tests | All pass |
| Clippy | `-D warnings` | Clean |
| Skipped/disabled tests | 0 | N/A |

### Test file inventory (openclaw adapter)

| File | Location |
| --- | --- |
| `engine.test.ts` | `src/policy/engine.test.ts` |
| `loader.test.ts` | `src/policy/loader.test.ts` |
| `validator.test.ts` | `src/policy/validator.test.ts` |
| `security-prompt.test.ts` | `src/security-prompt.test.ts` |
| `policy-check.test.ts` | `src/tools/policy-check.test.ts` |
| `agent-bootstrap handler.test.ts` | `src/hooks/agent-bootstrap/handler.test.ts` |
| `cua-bridge handler.test.ts` | `src/hooks/cua-bridge/handler.test.ts` |
| `cua-bridge fixture-runtime.test.ts` | `src/hooks/cua-bridge/fixture-runtime.test.ts` |
| `tool-preflight handler.test.ts` | `src/hooks/tool-preflight/handler.test.ts` |
| `audit.test.ts` | `src/cli/commands/audit.test.ts` |
| `policy.test.ts (cli)` | `src/cli/commands/policy.test.ts` |
| `approval-utils.test.ts` | `tests/approval-utils.test.ts` |
| `decision-cache.test.ts` | `tests/decision-cache.test.ts` |
| `guards.test.ts` | `tests/guards.test.ts` |
| `hooks.test.ts` | `tests/hooks.test.ts` |
| `policy.test.ts` | `tests/policy.test.ts` |
| `tool-preflight.test.ts` | `tests/tool-preflight.test.ts` |
| `tools.test.ts` | `tests/tools.test.ts` |
| `hello-agent.test.ts (e2e)` | `tests/e2e/hello-agent.test.ts` |

All paths relative to `packages/adapters/clawdstrike-openclaw/`.

---

## Gap Analysis

### Tier 1 -- Branch Changes with Zero Test Coverage [CRITICAL]

These gaps represent code that was modified or added in this branch and has zero test coverage. They are the highest priority for pre-merge work.

#### T1: `combineDecisions` rank-based logic

- **File changed:** `packages/adapters/clawdstrike-openclaw/src/policy/engine.ts` (lines 846-849)
- **What changed:** The `combineDecisions` function was replaced from "last wins" semantics to rank-based combining using a severity map: `{ deny: 2, warn: 1, allow: 0 }`. The higher-ranked decision wins; ties preserve the first decision.

```typescript
function combineDecisions(base: Decision, next: Decision): Decision {
  const rank: Record<string, number> = { deny: 2, warn: 1, allow: 0 };
  return (rank[next.status] ?? 0) > (rank[base.status] ?? 0) ? next : base;
}
```

- **What's untested:** No unit test for `combineDecisions` exists. No integration test exercises multi-guard scenarios where a warn-after-deny ordering was previously buggy under "last wins" semantics.
- **Risk:** If the rank map has an unexpected status value (e.g., a custom decision status from a guard plugin), the fallback to `0` treats it as `allow`, potentially downgrading a deny.
- **Proposed tests:**
  1. `base=deny + next=warn` -- should return `deny` (regression against old "last wins")
  2. `base=warn + next=deny` -- should return `deny`
  3. `base=deny + next=deny` -- should return `base` (first deny preserved)
  4. `base=allow + next=warn` -- should return `warn`
  5. `base=allow + next=allow` -- should return `base`
  6. Unknown status in `next` -- should fall back gracefully

#### T2: Audit mode metadata preservation

- **File changed:** `packages/adapters/clawdstrike-openclaw/src/policy/engine.ts` (lines 268-277)
- **What changed:** The `applyMode` method in audit mode now preserves `reason_code`, `reason`, `message`, `guard`, and `severity` from the original decision while overriding `status` to `allow`. The `message` field is prefixed with `[audit] Original decision: <status>`.

```typescript
private applyMode(result: Decision, mode: EvaluationMode): Decision {
  if (mode === 'audit') {
    return {
      status: 'allow',
      reason_code: result.reason_code,
      reason: result.reason,
      message: `[audit] Original decision: ${result.status} — ${result.message ?? result.reason ?? 'no reason'}`,
      guard: result.guard,
      severity: result.severity,
    };
  }
  // ...
}
```

- **What's untested:** Existing tests only validate `decision.status === 'allow'` for audit mode (the `warns but allows in advisory mode` test at line 39 of `engine.test.ts` covers advisory mode, not audit mode). No test validates the preserved fields (`guard`, `severity`, `reason`, `reason_code`) or the `[audit] Original decision:` message format.
- **Risk:** Consumers relying on audit-mode decisions for observability dashboards or SIEM integrations may silently receive empty `guard`/`severity` fields if the underlying decision shape changes.
- **Proposed tests:**
  1. Configure engine with `mode: 'audit'`, trigger a deny (e.g., forbidden path to `~/.ssh/id_rsa`), verify `status === 'allow'` AND `guard === 'forbidden_path'` AND `severity` is populated AND `message` contains `"Original decision: deny"`
  2. Same setup, trigger a warn, verify the original `reason` and `reason_code` are preserved
  3. Verify that `message` uses the `reason` fallback when `message` is undefined on the original decision

#### T3: New DESTRUCTIVE_TOKENS (7 tokens)

- **File changed:** `packages/adapters/clawdstrike-openclaw/src/hooks/tool-preflight/handler.ts` (line 58)
- **Tokens added:** `append`, `replace`, `deploy`, `push`, `send`, `publish`, `upload`

```typescript
const DESTRUCTIVE_TOKENS = new Set([
  'write', 'delete', 'remove', 'rm', 'kill', 'exec', 'run', 'install',
  'uninstall', 'create', 'update', 'modify', 'patch', 'put', 'post',
  'move', 'mv', 'rename', 'chmod', 'chown', 'drop', 'truncate',
  'edit', 'command', 'bash', 'save', 'overwrite', 'unlink', 'terminal',
  'append', 'replace', 'deploy', 'push', 'send', 'publish', 'upload',
]);
```

- **What's untested:** No tests exist for any of these 7 new tokens. The `upload` token was also simultaneously removed from `NETWORK_TOKENS`, changing its classification from "network" to "destructive" -- this reclassification has no test coverage.
- **Risk:** Tools named `deploy_to_prod`, `git_push`, `send_email`, `publish_package`, or `upload_artifact` are now classified as destructive and trigger full policy evaluation. If this classification is incorrect for any agent's tool naming conventions, it could cause unexpected blocks.
- **Proposed tests:** For each of the 7 new tokens, verify that a tool name containing that token is classified as `destructive` by the `classifyTool` function and triggers policy evaluation via `inferPolicyEventType`. Specific examples:
  1. `append_file` -- destructive
  2. `find_and_replace` -- destructive (contains `replace`)
  3. `deploy_service` -- destructive
  4. `git_push` -- destructive
  5. `send_message` -- destructive
  6. `npm_publish` -- destructive
  7. `upload_artifact` -- destructive (previously would have been classified as network)

#### T4: New NETWORK_TOKENS (4 tokens)

- **File changed:** `packages/adapters/clawdstrike-openclaw/src/hooks/tool-preflight/handler.ts` (line 70)
- **Tokens added:** `api`, `download`, `socket`, `connect`

```typescript
const NETWORK_TOKENS = new Set([
  'fetch', 'http', 'web', 'curl', 'request',
  'api', 'download', 'socket', 'connect'
]);
```

- **What's untested:** No tests for any of these 4 new tokens. The interaction between `connect` as a network token and `connect` appearing in CUA event type strings (e.g., `remote.session.connect`) is also untested in the preflight handler context.
- **Risk:** Tools named `api_call`, `download_file`, `socket_connect` are now classified as network egress and evaluated against egress allowlists. If an agent uses `api` as a generic tool name prefix, this could trigger unexpected blocks.
- **Proposed tests:**
  1. `api_call` -- network egress classification
  2. `download_file` -- network egress classification
  3. `socket_connect` -- network egress classification
  4. `connect_db` -- network egress classification; verify interaction with CUA bridge does not conflict

#### T5: 172.17-31.* egress deny ranges

- **Files changed:** `packages/adapters/clawdstrike-openclaw/rulesets/ai-agent-minimal.yaml` (lines 26-40), `packages/adapters/clawdstrike-openclaw/rulesets/ai-agent.yaml` (lines 39-53)
- **What changed:** Both rulesets now deny the full RFC 1918 172.16.0.0/12 range by enumerating `172.16.*` through `172.31.*` individually. Previously only `172.16.*` was present.

```yaml
denied_domains:
  - "172.16.*"
  - "172.17.*"
  # ... through ...
  - "172.31.*"
```

- **What's untested:** No test validates hosts in the `172.17.*` through `172.31.*` ranges. Existing egress guard tests only cover named domains and the primary private ranges (`127.*`, `10.*`, `192.168.*`, `172.16.*`).
- **Risk:** The expanded deny list may interact with Docker default bridge network addresses (172.17.0.0/16) and other container orchestration subnets. If agents legitimately need to reach container-internal services, these rules will silently block them.
- **Proposed tests:**
  1. Egress guard evaluation with host `172.25.0.1` -- should be denied
  2. Egress guard evaluation with host `172.31.255.255` -- should be denied
  3. Egress guard evaluation with host `172.32.0.1` -- should be allowed (outside the /12 range)
  4. Egress guard evaluation with host `172.15.255.255` -- should be allowed (below the /12 range)

#### T8: Fail-closed guard try/catch (TypeScript + Python)

- **Files changed:**
  - `packages/sdk/hush-ts/src/clawdstrike.ts` (lines 1191-1198, 1498-1505)
  - `packages/sdk/hush-py/src/clawdstrike/policy.py` (lines 836-843)
- **What changed:** Guards that throw unhandled exceptions during `check()` are now caught and produce a `deny` decision with `Severity.CRITICAL` and a message prefixed with `"Guard evaluation error (fail-closed)"`.

TypeScript:
```typescript
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

Python:
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

- **What's untested:** No test in either language creates a guard that throws and verifies the engine returns deny with critical severity. This is the core fail-closed contract of the system.
- **Risk:** If the catch block itself has an error (e.g., `guard.name` is undefined when the guard constructor throws), the fail-closed guarantee is violated. Without tests, regressions are invisible.
- **Proposed tests:**
  1. **TypeScript:** Register a custom guard whose `check()` throws `new Error('boom')`. Verify the engine returns `{ status: 'deny', severity: 'critical' }` and the message contains `"fail-closed"`.
  2. **TypeScript:** Register a custom guard whose `check()` throws a non-Error value (e.g., a string). Verify the same behavior.
  3. **Python:** Same as above using `pytest` -- a guard that raises `RuntimeError('boom')` should produce a deny with `CRITICAL` severity.

---

### Tier 2 -- Pre-existing Gaps Affecting Branch Safety [HIGH]

These are gaps that existed before this branch but are relevant because the branch's changes interact with or depend on the untested code.

#### T6: Tool-guard handler -- NO test file exists

- **Location:** `packages/adapters/clawdstrike-openclaw/src/hooks/tool-guard/handler.ts`
- **Impact:** This 595-line file contains:
  - An LRU `DecisionCache` class with TTL expiration, eviction, and stable stringify logic
  - Output sanitization traversing arbitrary nested objects (up to depth 32)
  - Approval consumption via `checkAndConsumeApproval`
  - Event type inference via `inferEventType` using substring matching (different algorithm from the preflight handler's token-based classification)
  - Network info extraction with URL parsing including protocol-based port defaults
  - File content extraction with a 2MB cap
  - Patch info extraction from result fallback
- **Specific bug found during review:** `extractNetworkInfo` (line 503) defaults port to `80` for non-`https:` protocols but does not handle `wss:` (WebSocket Secure), which should default to `443`. This means `wss://example.com/ws` would be evaluated with port `80`.

```typescript
port: parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80),
```

- **Proposed test file:** Create `src/hooks/tool-guard/handler.test.ts` covering:
  1. `inferEventType` substring classification (patch, read, write, exec, network, fallback)
  2. `DecisionCache` -- LRU eviction at max capacity, TTL expiration, cache key construction
  3. Allow-only caching (deny decisions should NOT be cached per line 236)
  4. `extractNetworkInfo` with `wss:` URLs (regression for port default bug)
  5. `extractNetworkInfo` with URL-in-command extraction
  6. `sanitizeUnknown` with nested objects, arrays, circular references, depth > 32
  7. `stableStringify` with BigInt, Symbol, undefined, circular refs

#### T7: Tool-preflight handler -- only 1 test case

- **Location:** `packages/adapters/clawdstrike-openclaw/src/hooks/tool-preflight/handler.test.ts`
- **Current coverage:** A single test validates that `web_search` is preflighted even when its name contains the read-only token `search` (because `web` is a NETWORK_TOKEN).
- **Missing coverage:**
  - Destructive classification for any destructive token
  - `classifyTool` function: destructive wins over read-only, unknown fallback
  - Approval flow: `CLAWDSTRIKE_APPROVAL_URL` and `CLAWDSTRIKE_AGENT_TOKEN` env vars
  - Warn decision path (tool should proceed but messages should include warning)
  - All five heuristic functions:
    - `looksLikePatchApply` -- `patch`, `diff`, `patchContent` fields, and the `filePath + content` compound path
    - `looksLikeCommandExec` -- `command`, `cmd`, `args`, `argv` fields
    - `looksLikeNetworkEgress` -- `url`, `endpoint`, `href`, `host`, `hostname` fields
    - `looksLikeFileWrite` -- `content`, `text`, `contentBase64`, `base64`, `patch`, `diff`, `operation` fields
    - `tokenize` -- camelCase splitting, delimiter splitting, edge cases with consecutive uppercase
  - `buildPolicyEvent` per event type: `file_read`, `file_write`, `command_exec`, `patch_apply`, `network_egress`, `tool_call`
  - `extractNetworkInfo` -- URL parsing, command-embedded URL extraction, host/port fallback
  - `inferPolicyEventType` -- interaction between classification and DESTRUCTIVE_EVENT_MAP

---

### Tier 3 -- Lower Priority Gaps [MEDIUM]

These are correctness and consistency issues that should be addressed post-merge.

#### T9: AlertingExporter `filtered` count inconsistency

- **Files:** `packages/sdk/hush-ts/src/siem/exporters/alerting.ts` vs `packages/sdk/hush-ts/src/siem/exporters/webhooks.ts`
- **Issue:** The `ExportResult` interface defines `filtered?: number`. `WebhookExporter.export()` tracks and returns a `filtered` count (line 75-76, 96 of webhooks.ts). `AlertingExporter.export()` does not track `filtered` at all -- events that fail `shouldAlert()` are silently excluded, and the returned result has `exported: 0, failed: 0` with no indication that events were filtered.
- **Impact:** Observability dashboards relying on `filtered` counts for AlertingExporter will always see `undefined`, making it impossible to distinguish "no events received" from "all events filtered."
- **Proposed fix:** Add `filtered` tracking to `AlertingExporter.export()` matching the pattern in `WebhookExporter`.

#### T10: `looksLikePatchApply` refinement

- **File:** `packages/adapters/clawdstrike-openclaw/src/hooks/tool-preflight/handler.ts` (lines 304-309)
- **Issue:** The function returns `true` for `filePath + content` (compound check) but also returns `true` for `filePath + newContent`. No test exists for either path. Additionally, no regression test covers the `filePath`-only case (which correctly returns `false`).

```typescript
function looksLikePatchApply(params: Record<string, unknown>): boolean {
  return typeof params.patch === 'string'
    || typeof params.diff === 'string'
    || typeof params.patchContent === 'string'
    || (typeof params.filePath === 'string' && (typeof params.content === 'string' || typeof params.newContent === 'string'));
}
```

- **Proposed tests:**
  1. `{ patch: '...' }` -- true
  2. `{ diff: '...' }` -- true
  3. `{ filePath: '/foo', content: '...' }` -- true
  4. `{ filePath: '/foo', newContent: '...' }` -- true
  5. `{ filePath: '/foo' }` -- false (regression)
  6. `{}` -- false

#### T11: `type` removed from READ_ONLY_TOKENS

- **File:** `packages/adapters/clawdstrike-openclaw/src/hooks/tool-preflight/handler.ts` (lines 45-50)
- **Issue:** The current `READ_ONLY_TOKENS` set does not include `type`. If a previous version included it, tools with names like `get_type` or `file_type` would now fall through to `unknown` classification instead of `read_only`. No test validates this behavior change for non-CUA tools that include "type" in their name.
- **Impact:** Low -- most tools with "type" in the name also contain other read-only tokens like "get" or "list".

#### T12: Python SecretLeakGuard -- new patterns and patch action support

- **File:** `packages/sdk/hush-py/src/clawdstrike/guards/secret_leak.py`
- **New patterns (6):** `aws_secret_key`, `github_pat`, `anthropic_key`, `npm_token`, `slack_token`, `generic_secret`
- **New capability:** The `handles()` method now returns `True` for `action_type == "patch"`, and `_extract_text()` has a dedicated `patch` branch that reads `action.diff` or `action.content`.
- **What's untested:**
  1. None of the 6 new patterns are tested with matching input strings
  2. The `patch` action type path through `handles()` and `_extract_text()` is untested
  3. The `generic_secret` pattern is intentionally broad (`(?i)(secret|password|passwd|pwd)...`) and may have false-positive issues
- **Proposed tests:**
  1. For each new pattern, provide a matching string and verify `GuardResult.block`
  2. Create a `GuardAction` with `action_type="patch"` and `diff` containing a secret -- verify block
  3. Test `generic_secret` false-positive boundary cases (e.g., `password_reset_token = "abcdefgh"`)

---

## CI Pipeline Gaps

### 1. `mise.toml` CI task only runs Rust checks

The `[tasks.ci]` task in `mise.toml` runs:
- `cargo fmt --all -- --check`
- `cargo clippy --workspace -- -D warnings`
- `cargo test --workspace`
- `cargo check` for Tauri app crates
- Architecture guardrail scripts

It does **not** run any TypeScript tests (`vitest`), Python tests (`pytest`), or the TypeScript smoke checks (`scripts/smoke-ts-file-deps.sh`). The `test:packages:ts` and `test:packages:py` tasks exist but are not invoked by the `ci` task.

### 2. No vitest coverage threshold enforcement

The vitest configuration at `packages/adapters/clawdstrike-openclaw/vitest.config.ts` enables V8 coverage reporting but does not set any threshold:

```typescript
coverage: {
  provider: 'v8',
  reporter: ['text', 'json', 'html'],
  // No thresholds configured
},
```

Without thresholds, coverage can silently regress with each merge.

### 3. No unified local CI command for Rust + TS + Python

There is no single command that runs all language-specific CI checks. Developers must manually run:
- `mise run ci` (Rust only)
- `npm test --workspace=packages/adapters/clawdstrike-openclaw` (TS)
- `pytest packages/sdk/hush-py` (Python)

---

## Recommendations

### Before merge (blocking)

| Priority | Gap | Effort | Impact |
| --- | --- | --- | --- |
| P0 | T1: `combineDecisions` unit tests | Small (4-6 test cases) | Prevents silent regression of multi-guard decision aggregation |
| P0 | T2: Audit mode metadata preservation tests | Small (3 test cases) | Validates SIEM/observability integration contract |
| P0 | T3: New DESTRUCTIVE_TOKENS tests | Small (7 test cases) | Prevents false-positive blocks on common tool names |
| P0 | T4: New NETWORK_TOKENS tests | Small (4 test cases) | Prevents false-positive egress blocks |
| P0 | T5: 172.17-31.* egress deny range tests | Small (4 test cases) | Validates RFC 1918 full range enforcement |
| P0 | T8: Fail-closed guard try/catch tests | Medium (3 TS + 1 Python) | Core fail-closed contract of the entire system |

### Fast-follow (within 1 sprint)

| Priority | Gap | Effort | Impact |
| --- | --- | --- | --- |
| P1 | T6: Create `tool-guard/handler.test.ts` | Large (new test file, ~15 test cases) | 595 lines of security-critical code with zero tests |
| P1 | T7: Expand `tool-preflight/handler.test.ts` | Large (~20 test cases) | Only 1 test case for a complex handler |
| P1 | T12: Python SecretLeakGuard new patterns | Medium (8 test cases) | 6 new patterns + patch action untested |

### Infrastructure improvements

| Priority | Action | Effort |
| --- | --- | --- |
| P1 | Add `npm test` and `pytest` to `mise.toml` `[tasks.ci]` | Small |
| P2 | Set vitest coverage thresholds (e.g., 70% statements, 60% branches) | Small |
| P2 | Create a unified `mise run ci:all` task that runs Rust + TS + Python | Small |
| P3 | Fix `wss:` port default bug in `tool-guard/handler.ts` `extractNetworkInfo` (T6) | Small |
| P3 | Add `filtered` count to `AlertingExporter.export()` (T9) | Small |

---

## Appendix: Test Count by File

Test counts sourced from `vitest` run on branch `feat/clawdstrike-sdks-launch` as of 2026-02-25.

| Test file | Test count |
| --- | --- |
| `src/policy/engine.test.ts` | 14 |
| `src/policy/loader.test.ts` | varies |
| `src/policy/validator.test.ts` | varies |
| `src/security-prompt.test.ts` | varies |
| `src/tools/policy-check.test.ts` | varies |
| `src/hooks/agent-bootstrap/handler.test.ts` | varies |
| `src/hooks/cua-bridge/handler.test.ts` | varies |
| `src/hooks/cua-bridge/fixture-runtime.test.ts` | varies |
| `src/hooks/tool-preflight/handler.test.ts` | 1 |
| `src/cli/commands/audit.test.ts` | varies |
| `src/cli/commands/policy.test.ts` | varies |
| `tests/approval-utils.test.ts` | varies |
| `tests/decision-cache.test.ts` | varies |
| `tests/guards.test.ts` | varies |
| `tests/hooks.test.ts` | varies |
| `tests/policy.test.ts` | varies |
| `tests/tool-preflight.test.ts` | varies |
| `tests/tools.test.ts` | varies |
| `tests/e2e/hello-agent.test.ts` | varies |
| **Total** | **242** |

**Notable:** `src/hooks/tool-guard/handler.ts` has **no test file at all**.
