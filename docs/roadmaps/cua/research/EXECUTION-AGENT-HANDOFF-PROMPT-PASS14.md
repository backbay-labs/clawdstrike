# Pass #14 Orchestration Agent Handoff Prompt

> Copy-paste this entire file as a prompt to the next orchestration agent.

---

## Mission

You are a **Coordinator agent** running a parallel team to complete all remaining CUA Gateway work. Your responsibilities:

1. **Code Review** — Thorough review of all pass #11–#13 changes (39 files, ~3000 lines)
2. **E3** — OpenClaw CUA bridge hardening
3. **E4** — trycua/cua connector evaluation
4. **Cleanup** — Fix any issues found in code review, update docs

**Hard requirement:** Run as a TEAM of sub-agents in parallel. Do not run as a single serial agent.

---

## Team Structure

| Agent | Role | Tools Needed |
|-------|------|-------------|
| **Coordinator** (you) | Dispatch tasks, validate outputs, update CI/INDEX/REVIEW-LOG | All |
| **Sub-agent R** | Code reviewer — thorough review of all pass #11–#13 code | Read-only |
| **Sub-agent E3** | OpenClaw CUA bridge hardening | Read + Write + Bash |
| **Sub-agent E4** | trycua connector evaluation | Read + Write + Bash |
| **Sub-agent V** | Independent validator — run all harnesses + tests at end | Read + Bash |

Merge order: R reports first (so E3/E4 can incorporate findings) → E3/E4 in parallel → V validates everything → Coordinator finalizes.

---

## Current State

### What's been done (Passes #7–#13)

All backlog items A1–A4, B1–B3, C1–C3, D1–D2, E1, E2 are **complete**.

- **3 CUA guards** in Rust: `computer_use`, `remote_desktop_side_channel`, `input_injection_capability`
- **6 CUA event types** in `PolicyEventType` enum: `remote.session.connect/disconnect/reconnect`, `input.inject`, `remote.clipboard`, `remote.file_transfer`
- **`CuaEventData` struct** in Rust with `cua_action`, `direction`, `continuity_prev_session_hash`, `postcondition_probe_hash`
- **TS parity**: `CuaEventData` interface + 6 factory methods in `adapter-core`
- **3 built-in rulesets**: `remote-desktop`, `remote-desktop-strict`, `remote-desktop-permissive`
- **15 Python fixture harnesses** (112 total checks, all pass)
- **372 Rust tests** (315 unit + 57 integration), clippy clean
- **23 TS tests** in adapter-core (18 existing + 5 new)

### Uncommitted changes (39 files on `feat/cua` branch)

**Modified (10):**
- `.github/workflows/ci.yml` — 15 roadmap harnesses added
- `crates/libs/clawdstrike/src/guards/mod.rs` — 3 new guard module declarations
- `crates/libs/clawdstrike/src/policy.rs` — GuardConfigs + 3 rulesets in resolver
- `crates/services/hushd/src/policy_event.rs` — 6 CUA event types + CuaEventData + map_policy_event
- `fixtures/README.md` — 19 fixture groups listed
- `packages/adapters/clawdstrike-adapter-core/src/index.ts` — CuaEventData export
- `packages/adapters/clawdstrike-adapter-core/src/policy-event-factory.test.ts` — 5 CUA tests
- `packages/adapters/clawdstrike-adapter-core/src/policy-event-factory.ts` — 6 CUA factory methods
- `packages/adapters/clawdstrike-adapter-core/src/policy-event-fixtures.test.ts` — CUA event type validation
- `packages/adapters/clawdstrike-adapter-core/src/types.ts` — EventType union + CuaEventData interface

**New (29):**
- `crates/libs/clawdstrike/src/guards/computer_use.rs`
- `crates/libs/clawdstrike/src/guards/input_injection_capability.rs`
- `crates/libs/clawdstrike/src/guards/remote_desktop_side_channel.rs`
- `crates/libs/clawdstrike/tests/cua_guard_integration.rs` (8 tests)
- `crates/libs/clawdstrike/tests/cua_guards.rs` (8 tests)
- `crates/libs/clawdstrike/tests/cua_rulesets.rs` (15 tests)
- `crates/services/hushd/tests/cua_policy_events.rs` (6 tests)
- `rulesets/remote-desktop.yaml`, `remote-desktop-strict.yaml`, `remote-desktop-permissive.yaml`
- `crates/libs/clawdstrike/rulesets/` (duplicates for `include_str!`)
- `docs/roadmaps/cua/` (INDEX.md, deep-research-report.md, 9 topic files, execution backlog, review log, 15 YAML suites, 15 Python validators, 15 JSON reports, schema packages)
- `fixtures/` (15 fixture directories with cases.json + README.md each)

### What's remaining

| Item | Priority | Status |
|------|----------|--------|
| **Code review** of passes #11–#13 | Critical | Not started |
| **E3**: OpenClaw CUA bridge hardening | P1 | Not started |
| **E4**: trycua/cua connector evaluation | P1 | Not started |
| Update EXECUTION-BACKLOG.md checkboxes | Housekeeping | Not started |

---

## Sub-agent R: Code Review Instructions

### Scope

Review ALL files changed/created in passes #11–#13. This is a security-critical codebase (runtime enforcement for AI agents). The review must be thorough.

### Files to review (read every one)

**Rust guards (security-critical):**
1. `crates/libs/clawdstrike/src/guards/computer_use.rs` — Check: mode logic (observe/guardrail/fail_closed), `handles()` prefix matching, unknown action handling
2. `crates/libs/clawdstrike/src/guards/remote_desktop_side_channel.rs` — Check: channel enable/disable, transfer size enforcement, edge cases
3. `crates/libs/clawdstrike/src/guards/input_injection_capability.rs` — Check: input type allowlist, postcondition probe enforcement

**Rust integration (trust-critical):**
4. `crates/services/hushd/src/policy_event.rs` — Check: CuaEventData deserialization, validate() completeness, map_policy_event() routing, fail-closed on unknown types
5. `crates/libs/clawdstrike/src/policy.rs` — Check: GuardConfigs merge_with(), create_guards() ordering, builtin_guards_in_order()

**Rulesets (policy-critical):**
6. `rulesets/remote-desktop.yaml` — Check: guard configs match code expectations, extends chain valid
7. `rulesets/remote-desktop-strict.yaml` — Check: fail_closed mode actually restricts, no permissive leaks
8. `rulesets/remote-desktop-permissive.yaml` — Check: observe mode behavior, explicit about what it opens

**TypeScript (cross-language parity):**
9. `packages/adapters/clawdstrike-adapter-core/src/types.ts` — Check: CuaEventData fields match Rust struct, EventType union complete
10. `packages/adapters/clawdstrike-adapter-core/src/policy-event-factory.ts` — Check: factory methods produce correct eventType/cuaAction mappings

**Tests (coverage):**
11. All test files — Check: positive/negative coverage, edge cases, fail-closed assertions

### Review checklist

- [ ] **Fail-closed**: Every code path that encounters unknown/invalid input must deny, not silently pass
- [ ] **Rust/TS parity**: CuaEventData fields, EventType variants, and event mappings are identical across languages
- [ ] **Guard ordering**: Guards execute in consistent, documented order
- [ ] **Serde correctness**: Deserialization with unknown fields doesn't silently drop data or pass validation
- [ ] **No secret leaks**: Guard evidence/details don't include raw sensitive data
- [ ] **Policy inheritance**: extends chains resolve correctly without infinite loops
- [ ] **Test coverage**: All guards have allow/deny/edge-case tests; all error codes are tested
- [ ] **Clippy/lint**: No suppressed warnings without justification
- [ ] **YAML schema versions**: Rulesets use correct schema version (1.2.0 for posture model)
- [ ] **Documentation accuracy**: REVIEW-LOG, INDEX, and README entries match actual artifacts

### Output format

Produce a structured report:
```
## Code Review Report — Pass #14

### Critical Issues (must fix before merge)
- [file:line] description

### Warnings (should fix)
- [file:line] description

### Observations (informational)
- description

### Parity Matrix
| Field | Rust | TypeScript | Match? |
|-------|------|-----------|--------|

### Test Coverage Assessment
| Guard/Component | Positive | Negative | Edge | Missing |
|----------------|----------|----------|------|---------|
```

Write the report to `docs/roadmaps/cua/research/pass14-code-review-report.md`.

---

## Sub-agent E3: OpenClaw CUA Bridge Hardening

### Context

The `@clawdstrike/openclaw` adapter (`packages/adapters/clawdstrike-openclaw/src/`) has mature tool preflight/postflight handling but no CUA-specific event routing. It needs to emit canonical CUA events using the factory methods from adapter-core.

### Deliverables

1. **Update OpenClaw hooks** to detect CUA actions and emit canonical CUA events via `PolicyEventFactory`:
   - `createCuaConnectEvent()` for session/navigation actions
   - `createCuaInputInjectEvent()` for click/type/key actions
   - `createCuaClipboardEvent()` for clipboard read/write
   - `createCuaFileTransferEvent()` for file upload/download

2. **Add CUA-specific tests** in `packages/adapters/clawdstrike-openclaw/`:
   - CUA action → canonical event mapping tests
   - Allow/deny/approval scenarios for CUA actions
   - Fail-closed on unknown CUA action types

3. **Fixture-driven validation**:
   - `openclaw_cua_bridge_suite.yaml` — suite definition
   - `fixtures/policy-events/openclaw-bridge/v1/cases.json` — 9 cases
   - `verify_openclaw_cua_bridge.py` — Python validator harness
   - Run report confirming 9/9 pass

4. **Ensure parity**: OpenClaw CUA paths must resolve to the same guard decisions and reason codes as direct adapter-core paths.

### Key files to read first
- `packages/adapters/clawdstrike-openclaw/src/plugin.ts` — main plugin entry
- `packages/adapters/clawdstrike-openclaw/src/tool-preflight/handler.ts` — preflight logic
- `packages/adapters/clawdstrike-openclaw/src/tool-guard/handler.ts` — post-execution guard
- `packages/adapters/clawdstrike-adapter-core/src/policy-event-factory.ts` — canonical factory methods
- `docs/roadmaps/cua/research/policy_event_mapping.yaml` — event mapping contract

### Design constraints
- Use `PolicyEventFactory` from adapter-core — do NOT manually construct `PolicyEvent` objects
- Fail closed on unknown CUA action types with stable error codes
- Preserve existing non-CUA tool preflight/postflight behavior (no regressions)
- Run `npm test` in the openclaw package to verify no regressions

---

## Sub-agent E4: trycua/cua Connector Evaluation

### Context

`trycua/cua` is an external runtime candidate for multi-provider CUA execution. This is an evaluation/documentation task, not a full integration.

### Deliverables

1. **Connector evaluation document**: `docs/roadmaps/cua/research/trycua-connector-evaluation.md`
   - What `trycua/cua` provides (execution backends, action types, event model)
   - How it maps to the canonical contract (8 flow surfaces from `canonical_adapter_cua_contract.yaml`)
   - Compatibility matrix: which flows are supported, which require translation, which are unsupported
   - Fail-closed boundaries: what happens when trycua sends unsupported fields/flows
   - Integration architecture: connector as adapter layer, not trust-root replacement

2. **Prototype connector harness**:
   - `trycua_connector_suite.yaml` — suite definition (flow compatibility matrix)
   - `fixtures/policy-events/trycua-connector/v1/cases.json` — 9 fixture cases testing:
     - Supported flows produce valid canonical events
     - Unsupported flows fail closed
     - Unknown action types fail closed
     - Evidence handoff fields are preserved or explicitly rejected
   - `verify_trycua_connector.py` — Python validator harness
   - Run report confirming 9/9 pass

3. **Compatibility matrix** in the evaluation doc:

```
| trycua Flow | Canonical Flow Surface | Status | Notes |
|-------------|----------------------|--------|-------|
| ...         | connect              | ...    | ...   |
```

### Key references
- `docs/roadmaps/cua/research/canonical_adapter_cua_contract.yaml` — canonical contract (source of truth)
- `docs/roadmaps/cua/research/09-ecosystem-integrations.md` — integration strategy
- `https://github.com/trycua/cua` — external repo (read README only, do not clone)
- `docs/roadmaps/cua/research/provider_conformance_suite.yaml` — cross-provider parity model

### Design constraints
- Treat trycua as execution backend candidate, NOT as trust-root replacement
- Clawdstrike owns canonical contract, verifier order, and receipt semantics
- Fail closed on any trycua output that can't be mapped to canonical contract
- Document all incompatibilities explicitly

---

## Sub-agent V: Validator Instructions

Run AFTER Sub-agents R, E3, and E4 complete. Your job is independent validation.

### Validation steps

1. **All Python harnesses** (should be 17 total after E3/E4):
```bash
python3 docs/roadmaps/cua/research/verify_cua_migration_fixtures.py
python3 docs/roadmaps/cua/research/verify_remote_desktop_policy_matrix.py
python3 docs/roadmaps/cua/research/verify_injection_capabilities.py
python3 docs/roadmaps/cua/research/verify_policy_event_mapping.py
python3 docs/roadmaps/cua/research/verify_postcondition_probes.py
python3 docs/roadmaps/cua/research/verify_remote_session_continuity.py
python3 docs/roadmaps/cua/research/verify_envelope_semantic_equivalence.py
python3 docs/roadmaps/cua/research/verify_repeatable_latency_harness.py
python3 docs/roadmaps/cua/research/verify_verification_bundle.py
python3 docs/roadmaps/cua/research/verify_browser_action_policy.py
python3 docs/roadmaps/cua/research/verify_session_recording_evidence.py
python3 docs/roadmaps/cua/research/verify_orchestration_isolation.py
python3 docs/roadmaps/cua/research/verify_cua_policy_evaluation.py
python3 docs/roadmaps/cua/research/verify_canonical_adapter_contract.py
python3 docs/roadmaps/cua/research/verify_provider_conformance.py
python3 docs/roadmaps/cua/research/verify_openclaw_cua_bridge.py
python3 docs/roadmaps/cua/research/verify_trycua_connector.py
```

2. **Rust tests**:
```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

3. **TypeScript tests**:
```bash
npm test --workspace=packages/adapters/clawdstrike-adapter-core
npm test --workspace=packages/adapters/clawdstrike-openclaw
```

4. **Cross-check**: Verify that code review fixes from Sub-agent R were applied

5. **Report**: Write validation summary to stdout

---

## Coordinator: Finalization Checklist

After all sub-agents complete:

1. **Apply code review fixes** from Sub-agent R's report (critical issues only block merge)
2. **Update CI** (`.github/workflows/ci.yml`):
   - Add E3 and E4 validators to the roadmap harness step (17 total)
3. **Update INDEX.md** with:
   - E3 artifacts (suite, fixtures, harness, report)
   - E4 artifacts (evaluation doc, suite, fixtures, harness, report)
   - Code review report link
   - Updated status table (Ecosystem Integrations → Pass #14)
   - Updated program status paragraph
4. **Update REVIEW-LOG.md** with pass #14 entry
5. **Update fixtures/README.md** with 2 new fixture groups (#20, #21)
6. **Update EXECUTION-BACKLOG.md**: Mark E3 and E4 as complete, update program definition of done
7. **Update 09-ecosystem-integrations.md**: Check off implementation TODO items
8. **Run final validation sweep** (Sub-agent V results)
9. **Report final tallies**: total harnesses, total fixture checks, total Rust tests, total TS tests

### Success criteria

- All E workstream items (E1–E4) complete with passing fixtures
- Code review report produced with no unresolved critical issues
- CI runs 17 roadmap harnesses on every PR/push
- All fixture checks pass (expected: ~130 total)
- All Rust tests pass (expected: ~387+)
- All TS tests pass
- Clippy clean with `-D warnings`
- INDEX, REVIEW-LOG, README all current

---

## Repository context

- **Repo root**: `/Users/connor/Medica/backbay/standalone/clawdstrike-cua`
- **Branch**: `feat/cua`
- **Design philosophy**: Fail-closed. Invalid policies reject at load time; errors during evaluation deny access.
- **Rust MSRV**: 1.93
- **Policy schema version**: 1.2.0 (supports posture model)
- **Guard trait**: `crates/libs/clawdstrike/src/guards/mod.rs` — sync `Guard` trait with `handles()` + `check()`
- **Commit style**: Conventional Commits (`feat(scope):`, `fix(scope):`, etc.)
- **CI config**: `.github/workflows/ci.yml`

### Key commands
```bash
cargo build --workspace                    # Build all
cargo test --workspace                     # Test all Rust
cargo clippy --workspace -- -D warnings    # Lint
npm test --workspace=packages/adapters/clawdstrike-adapter-core  # TS tests
python3 docs/roadmaps/cua/research/verify_*.py  # All harnesses
```
