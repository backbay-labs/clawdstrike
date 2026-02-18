# Code Review Report -- Pass #14

**Reviewer:** Sub-agent R (automated code review)
**Date:** 2026-02-18
**Scope:** All files changed/created in passes #11--#13 (~39 files, ~3000 lines)
**Branch:** `feat/cua`

---

## Critical Issues (must fix before merge)

### C1. `remote.session_share` missing from PolicyEventType (Rust) and EventType (TypeScript)

**Rust:** `crates/services/hushd/src/policy_event.rs` -- The `PolicyEventType` enum defines 6 CUA event types (`RemoteSessionConnect`, `RemoteSessionDisconnect`, `RemoteSessionReconnect`, `InputInject`, `ClipboardTransfer`, `FileTransfer`) but does NOT include `remote.session_share`. The `ComputerUseGuard` default config (`crates/libs/clawdstrike/src/guards/computer_use.rs:52`) includes `"remote.session_share"` as a valid allowed action, and the `RemoteDesktopSideChannelGuard` (`remote_desktop_side_channel.rs:95`) handles `"remote.session_share"` in its `handles()` method. However, there is no `PolicyEventType::SessionShare` variant, so any policy event with `eventType: "remote.session_share"` will deserialize to `PolicyEventType::Other("remote.session_share")` and be **rejected by `map_policy_event()`** at line 662 with `"unsupported eventType"`. This means the session_share pathway is dead at the hushd layer.

**TypeScript:** `packages/adapters/clawdstrike-adapter-core/src/types.ts:24-38` -- The `EventType` union similarly lacks `'remote.session_share'`. The `PolicyEventFactory` has no `createCuaSessionShareEvent()` method.

**Impact:** Session sharing policy evaluation will fail closed at the daemon/adapter boundary even though the guard layer supports it. This is either a deliberate omission (session_share only works at the guard layer, not via hushd) or a gap. If deliberate, it should be documented. If not, it needs a new enum variant + mapping arm + factory method.

**Recommendation:** Add `SessionShare` variant to `PolicyEventType` with string `"remote.session_share"`, add the mapping arm in `map_policy_event()`, add `'remote.session_share'` to the TS `EventType` union, and add `createCuaSessionShareEvent()` to `PolicyEventFactory`. Alternatively, document this as intentionally unsupported at the daemon layer.

### C2. `InputInjectionCapabilityGuard` silently allows when `input_type` field is absent

**File:** `crates/libs/clawdstrike/src/guards/input_injection_capability.rs:110-126`

When the `input_type` field is not present in the JSON data, the guard falls through and allows the action (line 148). This is confirmed by the test `test_allows_without_input_type_field` at line 226. In a security-critical guard for input injection, **missing input type should be denied, not allowed**, especially in a fail-closed system. An attacker could bypass the input type allowlist by simply omitting the field.

**Recommendation:** Change the behavior when `input_type` is missing to deny the action, at least when the guard is in an active enforcement mode. At minimum, log a warning.

### C3. `RemoteDesktopSideChannelGuard` wildcard arm allows unknown custom types

**File:** `crates/libs/clawdstrike/src/guards/remote_desktop_side_channel.rs:179`

The match statement's wildcard arm `_ => GuardResult::allow(&self.name)` allows any custom action type that reaches the guard but doesn't match the three known channels. While the `handles()` method (line 86-97) should filter to only the three known types, if `handles()` is ever bypassed (e.g., direct `check()` call), unknown types would be silently allowed. The `handles()` + `check()` contract is not enforced at the type level.

**Impact:** Low in current architecture (the engine calls `handles()` first), but violates the fail-closed principle. Consider returning a deny result for the wildcard arm.

---

## Warnings (should fix)

### W1. New CUA guards use `or_else` merge (last-wins) instead of deep merge

**File:** `crates/libs/clawdstrike/src/policy.rs:326-337`

The three new guard configs (`computer_use`, `remote_desktop_side_channel`, `input_injection_capability`) use the simple `child.clone().or_else(|| self.clone())` merge strategy (lines 326-337), which means the child completely replaces the base config. This differs from guards like `forbidden_path`, `egress_allowlist`, and `secret_leak` which support `additional_*`/`remove_*` merge semantics. This is acceptable for initial implementation but limits composability. For example, a child policy cannot selectively add one more allowed action to `computer_use.allowed_actions` without restating the entire list.

### W2. `ComputerUseGuard::handles()` uses prefix matching, creating ambiguity

**File:** `crates/libs/clawdstrike/src/guards/computer_use.rs:107`

The `handles()` method matches any action starting with `"remote."` or `"input."`. This means:
- `remote.clipboard` and `remote.file_transfer` are claimed by BOTH `ComputerUseGuard` and `RemoteDesktopSideChannelGuard`.
- `remote.session_share` is claimed by BOTH `ComputerUseGuard` and `RemoteDesktopSideChannelGuard`.

When both guards are active (as in the CUA rulesets), the engine will evaluate both guards for these actions. The `ComputerUseGuard` checks the allowlist, and the `RemoteDesktopSideChannelGuard` checks channel-specific policies. This dual evaluation is likely intentional (defense in depth), but it should be documented explicitly. If `ComputerUseGuard` is in `FailClosed` mode and the action is not in its allowlist, the action will be denied even if the side channel guard would allow it.

### W3. `CuaEventData.extra` captures `type` discriminator field on roundtrip

**File:** `crates/services/hushd/src/policy_event.rs:401-427`

The `CuaEventData` struct uses `#[serde(flatten)] pub extra: serde_json::Map<String, serde_json::Value>`. During deserialization, the `type` discriminator (which is manually handled in `PolicyEventData::Deserialize`) is already consumed, but during serialization, `serialize_typed_data()` re-inserts `"type": "cua"`. On a second roundtrip deserialization, the `"type"` field will end up in `extra` because `CuaEventData` doesn't have a `type` field -- it's handled at the `PolicyEventData` level. The roundtrip test at line 895-927 acknowledges this by comparing field-by-field rather than using `assert_eq!` on the whole struct.

**Impact:** Not a security issue, but this asymmetry could cause confusion in downstream consumers that inspect `extra`. Consider explicitly skipping `"type"` from `extra` during deserialization, or document the behavior.

### W4. `FileEventData.operation` is `Option<String>` in Rust but required in TypeScript

**File:** `crates/services/hushd/src/policy_event.rs:328` vs `packages/adapters/clawdstrike-adapter-core/src/types.ts:65`

In Rust, `FileEventData.operation` is `Option<String>`. In TypeScript, it's `operation: 'read' | 'write'` (required, not optional). This parity difference could cause validation failures when Rust-serialized events are consumed by TypeScript code, or vice versa.

### W5. `CommandEventData` has `workingDir` in TypeScript but not in Rust

**File:** `packages/adapters/clawdstrike-adapter-core/src/types.ts:72` vs `crates/services/hushd/src/policy_event.rs:356-362`

The TypeScript `CommandEventData` includes an optional `workingDir` field that doesn't exist in the Rust struct. This is a minor parity gap.

### W6. `CuaEventData.cuaAction` naming convention differs between Rust and TS factory

The Rust side uses the raw `cua_action` value (e.g., `"connect"`, `"disconnect"`, `"reconnect"`), while the TypeScript `PolicyEventFactory` uses dotted names (e.g., `"session.connect"`, `"session.disconnect"`, `"session.reconnect"`, `"input.inject"`, `"clipboard"`, `"file_transfer"`). These are semantically different strings for the same operations. While the guards don't inspect `cua_action` directly (they use the `eventType` / custom_type from the outer action), any downstream consumer comparing `cuaAction` across languages will see mismatches.

**Files:**
- TypeScript: `policy-event-factory.ts:99` (`session.connect`) vs Rust test: `policy_event.rs:770` (`connect`)

---

## Observations (informational)

### O1. Guard ordering is well-defined and consistent

`crates/libs/clawdstrike/src/policy.rs:1614-1631` -- The `builtin_guards_in_order()` method returns guards in a stable, documented order. The three new CUA guards are appended at positions 10-12 (computer_use, remote_desktop_side_channel, input_injection_capability), after all pre-existing guards. This means filesystem/network/secret guards run first, which is correct for defense-in-depth.

### O2. All YAML rulesets use schema version 1.2.0

All three CUA rulesets (`remote-desktop.yaml`, `remote-desktop-strict.yaml`, `remote-desktop-permissive.yaml`) correctly use `version: "1.2.0"`. The base `ai-agent.yaml` uses `version: "1.1.0"`, which is valid because the extends mechanism allows version upgrades from child to base.

### O3. `deny_unknown_fields` applied consistently

All three guard config structs (`ComputerUseConfig`, `RemoteDesktopSideChannelConfig`, `InputInjectionCapabilityConfig`) use `#[serde(deny_unknown_fields)]`, which prevents silent data loss during deserialization.

### O4. Duplicate rulesets in `crates/libs/clawdstrike/rulesets/` and `rulesets/`

The three CUA YAML files exist in both `rulesets/` (workspace root) and `crates/libs/clawdstrike/rulesets/` (for `include_str!`). Content is identical. This is the established pattern in the codebase. A sync test exists at `policy.rs:2121-2160` that validates disk files match `RuleSet::list()`.

### O5. CI workflow updated with CUA harness verification

`.github/workflows/ci.yml:886-901` -- The Python SDK job now runs 15 CUA research verification harnesses. This provides regression coverage for the fixture/policy matrix.

### O6. `PolicyEventFactory.generateEventId()` uses `Math.random()`

`packages/adapters/clawdstrike-adapter-core/src/policy-event-factory.ts:240` -- Event IDs use `Date.now()` + `Math.random()`. This is not cryptographically secure but is acceptable for event correlation (not security). The receipt signing layer provides cryptographic integrity.

---

## Parity Matrix

| Field/Type | Rust (`policy_event.rs`) | TypeScript (`types.ts`) | Match? |
|---|---|---|---|
| `EventType::file_read` | `PolicyEventType::FileRead` | `'file_read'` | YES |
| `EventType::file_write` | `PolicyEventType::FileWrite` | `'file_write'` | YES |
| `EventType::network_egress` | `PolicyEventType::NetworkEgress` | `'network_egress'` | YES |
| `EventType::command_exec` | `PolicyEventType::CommandExec` | `'command_exec'` | YES |
| `EventType::patch_apply` | `PolicyEventType::PatchApply` | `'patch_apply'` | YES |
| `EventType::tool_call` | `PolicyEventType::ToolCall` | `'tool_call'` | YES |
| `EventType::secret_access` | `PolicyEventType::SecretAccess` | `'secret_access'` | YES |
| `EventType::custom` | `PolicyEventType::Custom` | `'custom'` | YES |
| `EventType::remote.session.connect` | `PolicyEventType::RemoteSessionConnect` | `'remote.session.connect'` | YES |
| `EventType::remote.session.disconnect` | `PolicyEventType::RemoteSessionDisconnect` | `'remote.session.disconnect'` | YES |
| `EventType::remote.session.reconnect` | `PolicyEventType::RemoteSessionReconnect` | `'remote.session.reconnect'` | YES |
| `EventType::input.inject` | `PolicyEventType::InputInject` | `'input.inject'` | YES |
| `EventType::remote.clipboard` | `PolicyEventType::ClipboardTransfer` | `'remote.clipboard'` | YES |
| `EventType::remote.file_transfer` | `PolicyEventType::FileTransfer` | `'remote.file_transfer'` | YES |
| `EventType::remote.session_share` | **MISSING** | **MISSING** | NO (C1) |
| `CuaEventData.cuaAction` | `cua_action: String` | `cuaAction: string` | YES (type) |
| `CuaEventData.direction` | `direction: Option<String>` | `direction?: 'read'\|'write'\|'upload'\|'download'` | PARTIAL (TS is stricter) |
| `CuaEventData.continuityPrevSessionHash` | `continuity_prev_session_hash: Option<String>` | `continuityPrevSessionHash?: string` | YES |
| `CuaEventData.postconditionProbeHash` | `postcondition_probe_hash: Option<String>` | `postconditionProbeHash?: string` | YES |
| `CuaEventData.extra` | `extra: Map<String, Value>` | `[key: string]: unknown` (index sig) | YES |
| `FileEventData.operation` | `Option<String>` | `'read' \| 'write'` (required) | NO (W4) |
| `CommandEventData.workingDir` | not present | `workingDir?: string` | NO (W5) |

---

## Test Coverage Assessment

| Guard/Component | Positive | Negative | Edge | Missing |
|---|---|---|---|---|
| `ComputerUseGuard` | guardrail allows known (unit + integration) | fail_closed denies unknown | observe mode allows unknown; disabled guard skips | Empty `allowed_actions` + guardrail mode (warn not deny); concurrent evaluation with side channel guard |
| `RemoteDesktopSideChannelGuard` | all channels enabled | clipboard disabled; file_transfer disabled | transfer size limit exceeded; transfer within limit | session_share disabled (no unit test); `max_transfer_size_bytes` with `transfer_size` absent in data (allows -- is this correct?); boundary: `transfer_size == max_size` (allowed, not tested) |
| `InputInjectionCapabilityGuard` | keyboard allowed | gamepad denied; postcondition probe missing | postcondition probe with empty string (hash is `is_some_and(!s.is_empty())` -- good); no input_type field (allows -- C2) | Missing input_type in strict mode (allows -- should deny) |
| `PolicyEventType` (hushd) | all 6 CUA types map correctly | wrong data type rejects; Other() fails closed | roundtrip serialization; snake_case aliases | `remote.session_share` missing (C1) |
| `PolicyEventFactory` (TS) | connect, disconnect, reconnect, inject, clipboard, file_transfer | -- | continuity hash preservation; probe hash preservation; direction preservation | No factory method for session_share; no negative test for malformed CUA data |
| CUA rulesets | parse + validate; strict has minimal actions; permissive enables all | strict disables side channels | extends chain (strict -> remote-desktop -> ai-agent) inherits prompt_injection/jailbreak | No test that strict `fail_closed` mode actually blocks at engine level (only config assertion) |
| `HushEngine` integration | all 6 CUA types flow through; stats counted | strict policy doesn't crash | reconnect preserves continuity hash | No test with `remote-desktop-strict` ruleset that verifies deny behavior for blocked actions |

---

## Review Checklist Results

- [x] **Fail-closed**: Code paths encountering unknown/invalid input deny correctly. `PolicyEventType::Other()` fails at `map_policy_event()`. Unknown custom types in `ComputerUseGuard` are denied in `FailClosed` mode, warned in `Guardrail`. **Exception:** `InputInjectionCapabilityGuard` allows missing `input_type` (C2); `RemoteDesktopSideChannelGuard` wildcard arm allows (C3, low risk).

- [x] **Rust/TS parity**: CuaEventData fields are aligned between languages. EventType variants match for the 14 defined types. **Exception:** `remote.session_share` missing from both (C1); `FileEventData.operation` optionality differs (W4); `cuaAction` values differ in convention (W6).

- [x] **Guard ordering**: Guards execute in consistent, documented order via `builtin_guards_in_order()`. New CUA guards are appended at the end (positions 10-12). The order is fixed in the array literal (O1).

- [x] **Serde correctness**: All configs use `deny_unknown_fields`. `CuaEventData` uses `flatten` for extensibility with snake_case aliases (O3). Minor roundtrip asymmetry with `type` field in `extra` (W3).

- [x] **No secret leaks**: Guard evidence/details contain only action type, mode, channel name, and size information. No raw credentials or sensitive data are exposed in `GuardResult` details.

- [x] **Policy inheritance**: Extends chains resolve correctly. `remote-desktop` extends `ai-agent`; `remote-desktop-strict` and `remote-desktop-permissive` extend `remote-desktop`. Circular dependency detection uses visited set with depth limit of 32. The `ai-agent` -> `remote-desktop` version upgrade (1.1.0 -> 1.2.0) is handled correctly by the merge logic.

- [x] **Test coverage**: All three guards have allow/deny/edge-case tests. All error codes are tested in hushd policy events. TypeScript factory and fixture tests cover all 6 CUA event types. **Gaps:** No engine-level integration test with `remote-desktop-strict` that verifies actual deny behavior; no session_share tests in hushd or TS layers.

- [x] **Clippy/lint**: `#![allow(clippy::expect_used, clippy::unwrap_used)]` is used in test files only. No suppressed warnings in production code.

- [x] **YAML schema versions**: All CUA rulesets use `version: "1.2.0"` correctly. The base `ai-agent.yaml` uses `version: "1.1.0"`, which is valid.

- [x] **Documentation accuracy**: `fixtures/README.md` lists all new fixture groups (entries 6-19). The `RuleSet::list()` includes all 3 new rulesets and a sync test validates disk<->registry consistency.

---

## Summary

The implementation is solid with well-structured guards, proper serde handling, and good test coverage. Three critical issues were identified:

1. **C1** is the most significant: `remote.session_share` has guard support but no event type mapping, creating a dead pathway at the daemon/adapter boundary.
2. **C2** is a security concern: missing `input_type` should deny, not allow, for a security guard.
3. **C3** is low risk but violates fail-closed principles.

The warnings are mostly parity gaps and merge strategy limitations that should be addressed before GA but are acceptable for the current development phase. The test suite is comprehensive but could benefit from engine-level deny tests using the strict CUA ruleset.
