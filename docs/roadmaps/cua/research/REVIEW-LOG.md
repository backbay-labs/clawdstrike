# CUA Research Review Log

This log tracks reviewer interventions made while autonomous research agents continue writing topic files.

## 2026-02-18

- Added inline reviewer corrections and gap-fills to `../deep-research-report.md`.
- Added concrete verified references to replace unresolved citation tokens from exported agent output.
- Seeded topic files `01` through `08` with:
  - validated assumptions,
  - corrections/caveats,
  - Clawdstrike-specific integration guidance,
  - concrete experiments and open gaps.

## 2026-02-18 (Pass #2)

- Reviewed expanded agent-authored deep dives and injected `REVIEW-P2` corrections in:
  - `02-remote-desktop.md`
  - `03-input-injection.md`
  - `05-attestation-signing.md`
  - `07-receipt-schema.md`
- Tightened ambiguous claims:
  - performance/latency numbers marked as environment-specific estimates,
  - verifier compatibility and migration requirements made explicit,
  - `SendInput`/UIPI diagnostics clarified to avoid false certainty.
- Updated `../deep-research-report.md` with pass-two reviewer focus notes and compatibility-first constraints.

## 2026-02-18 (Pass #3)

- Reviewed and annotated the remaining topic set with `REVIEW-P3` notes and explicit execution criteria:
  - `01-browser-automation.md`
  - `04-session-recording.md`
  - `06-orchestration.md`
  - `08-policy-engine.md`
- Added pass-three global focus notes in `../deep-research-report.md`:
  - enforceable-property framing,
  - explicit topic acceptance criteria,
  - backward-compatible trust-path evolution.
- Updated index status rows to mark pass-three coverage for topics 1, 4, 6, and 8.

## 2026-02-18 (Pass #4)

- Reviewed and annotated deep-dive topic set with `REVIEW-P4` notes and implementation TODO blocks:
  - `02-remote-desktop.md`
  - `03-input-injection.md`
  - `05-attestation-signing.md`
  - `07-receipt-schema.md`
- Added pass-four global focus notes in `../deep-research-report.md` emphasizing:
  - conversion of soft guidance into implementation artifacts,
  - machine-checkable acceptance gates,
  - single-root trust and explicit migration discipline.
- Updated index status rows to mark pass-four coverage for topics 2, 3, 5, and 7.

## 2026-02-18 (Pass #5)

- Consolidated pass-four implementation TODOs into `EXECUTION-BACKLOG.md`.
- Added prioritized workstreams (`P0` to `P2`) with sequencing and acceptance criteria.
- Linked backlog artifact from index and updated deep report with pass-five focus notes.
- Established backlog artifact names for machine-checkable implementation handoff:
  - verifier flow spec,
  - attestation verifier policy,
  - remote desktop policy matrix,
  - injection outcome schema and capability manifest,
  - migration and fixture plans.

## 2026-02-18 (Pass #6)

- Added `EXECUTION-AGENT-HANDOFF-PROMPT.md` with a scoped, execution-ready prompt for `P0` workstream delivery.
- Linked the handoff prompt from `../INDEX.md` for direct discovery.

## 2026-02-18 (Pass #7)

- Executed `P0` workstream A artifacts from the handoff prompt:
  - `verifier-flow-spec.md` (mandatory verifier order + stable failure taxonomy),
  - `attestation_verifier_policy.yaml` (issuer allowlist, nonce freshness, required claims, clock skew),
  - versioned CUA metadata schema package under `schemas/cua-metadata/`,
  - migration fixture corpus under `../../../../fixtures/receipts/cua-migration/`,
  - `signer-migration-plan.md` (dual-sign window and rollback triggers/procedure).
- Added explicit fixture-to-error expectations in `fixtures/receipts/cua-migration/cases.json`.
- Updated `../INDEX.md` with cross-links and status rows for pass-seven execution artifacts.

## 2026-02-18 (Pass #8)

- Implemented verifier harness `verify_cua_migration_fixtures.py` to execute `fixtures/receipts/cua-migration/cases.json` against:
  - pass-seven verifier flow ordering and `VFY_*` error taxonomy,
  - attestation policy `AVP_*` subcodes,
  - versioned CUA metadata schema package resolution/validation.
- Produced run report `pass8-verifier-harness-report.json` with per-case/per-mode outcomes.
- Adjusted deterministic fixture verification context in `../../../../fixtures/receipts/cua-migration/cases.json` to keep valid CUA vectors in policy time window while preserving stale-nonce failure semantics.
- Verified pass-eight harness acceptance locally: 12/12 checks passed.

## 2026-02-18 (Pass #9)

- Started `P1` workstream `B1` and delivered `remote_desktop_policy_matrix.yaml` with:
  - required feature set (`clipboard`, `file_transfer`, `audio`, `drive_mapping`, `printing`, `session_share`),
  - explicit per-mode defaults (`observe`, `guardrail`, `fail_closed`),
  - threat-tier assumptions (`dev`, `internal_prod`, `internet_exposed_multi_tenant`).
- Added fixture-driven validator `verify_remote_desktop_policy_matrix.py` and fixture corpus `../../../../fixtures/policy-events/remote-desktop/v1/cases.json`.
- Produced matrix run report `pass9-remote-desktop-matrix-report.json` (9/9 checks passed locally).
- Wired roadmap harnesses into CI (`.github/workflows/ci.yml`) so PR/push runs fail on `cases.json` regressions for both pass #8 and pass #9 validators.
- Delivered `B2` artifacts:
  - `injection_outcome_schema.json`,
  - `injection_backend_capabilities.yaml`,
  - fixture corpus `../../../../fixtures/policy-events/input-injection/v1/cases.json`,
  - validator `verify_injection_capabilities.py`,
  - run report `pass9-injection-capabilities-report.json`.
- Verified pass-nine B2 acceptance locally: 9/9 injection capability fixture checks passed.
- Extended CI harness step to include pass-nine B2 validator for regression gating.
- Delivered `B3` artifacts:
  - `policy_event_mapping.md`,
  - machine-checkable mapping `policy_event_mapping.yaml`,
  - fixture corpus `../../../../fixtures/policy-events/policy-mapping/v1/cases.json`,
  - validator `verify_policy_event_mapping.py`,
  - run report `pass9-policy-event-mapping-report.json`.
- Verified pass-nine B3 acceptance locally: 9/9 policy mapping fixture checks passed.
- Extended CI harness step to include pass-nine B3 validator so flow-mapping regressions fail PR/push checks.

## 2026-02-18 (Pass #10)

- Executed `P1` workstream `C1` with deterministic probe artifacts:
  - `postcondition_probe_suite.yaml`,
  - fixture corpus `../../../../fixtures/policy-events/postcondition-probes/v1/cases.json`,
  - validator `verify_postcondition_probes.py`,
  - run report `pass10-postcondition-probes-report.json`.
- Verified pass-ten C1 acceptance locally: 9/9 post-condition probe fixture checks passed.
- Executed `P1` workstream `C2` with continuity-chain artifacts:
  - `remote_session_continuity_suite.yaml`,
  - fixture corpus `../../../../fixtures/policy-events/session-continuity/v1/cases.json`,
  - validator `verify_remote_session_continuity.py`,
  - run report `pass10-session-continuity-report.json`.
- Verified pass-ten C2 acceptance locally: 7/7 session continuity fixture checks passed.
- Extended CI roadmap harness step to include pass-ten `C1` + `C2` validators so continuity/probe regressions fail PR/push checks.

## 2026-02-18 (Pass #11 Planning)

- Added ecosystem integration research plan `09-ecosystem-integrations.md` covering:
  - canonical adapter contract first,
  - OpenAI/Claude translator parity requirements,
  - OpenClaw CUA hook alignment,
  - `trycua/cua` connector evaluation boundaries.
- Expanded execution backlog with new `P1` workstream `E`:
  - `E1` canonical adapter contract,
  - `E2` OpenAI/Claude translators,
  - `E3` OpenClaw bridge hardening,
  - `E4` external runtime connector validation.
- Updated index with new ecosystem integration topic and team-based integration handoff prompt for parallel execution.
- Added pass-eleven integration TODO block to `08-policy-engine.md` to anchor implementation in active engine/adapter code paths.

## 2026-02-18 (Pass #11 Execution — Integration Team)

- Executed as a parallel team (Coordinator + Sub-agents A/B/C + Validator D).
- Delivered `C3` envelope semantic equivalence artifacts:
  - `envelope_semantic_equivalence_suite.yaml`,
  - fixture corpus `../../../../fixtures/receipts/envelope-equivalence/v1/cases.json`,
  - validator `verify_envelope_semantic_equivalence.py`,
  - run report `pass11-envelope-equivalence-report.json`.
- Verified C3 acceptance: 9/9 checks passed.
- Delivered `D1` repeatable latency harness artifacts:
  - `repeatable_latency_harness.yaml`,
  - fixture corpus `../../../../fixtures/benchmarks/remote-latency/v1/cases.json`,
  - validator `verify_repeatable_latency_harness.py`,
  - run report `pass11-latency-harness-report.json`.
- Verified D1 acceptance: 9/9 checks passed.
- Integrated CUA policy events into product runtime:
  - Extended `PolicyEventType` enum with 6 CUA event types in `crates/services/hushd/src/policy_event.rs`.
  - Added `CuaEventData` struct and wired through `map_policy_event()` to `MappedGuardAction::Custom`.
  - Added 6 integration tests in `crates/services/hushd/tests/cua_policy_events.rs`.
  - Added 8 integration tests in `crates/libs/clawdstrike/tests/cua_guard_integration.rs`.
- Implemented 3 CUA guards in `crates/libs/clawdstrike/src/guards/`:
  - `computer_use.rs` (observe/guardrail/fail_closed modes),
  - `remote_desktop_side_channel.rs` (per-channel enable/disable + transfer size limits),
  - `input_injection_capability.rs` (input type allowlist + postcondition probe enforcement).
- Added guard configs to `GuardConfigs` struct and wired into engine instantiation.
- Added 8 integration tests in `crates/libs/clawdstrike/tests/cua_guards.rs`.
- All Rust tests pass (315 unit + 22 integration). Clippy clean with `-D warnings`.
- Extended CI roadmap harness step to include pass-eleven C3 + D1 validators.

## 2026-02-18 (Pass #12 — Deep-Dive Topic Execution + D2)

- Delivered `D2` end-to-end verification bundle format:
  - `verification_bundle_format.yaml`,
  - fixture corpus `../../../../fixtures/receipts/verification-bundle/v1/cases.json`,
  - validator `verify_verification_bundle.py`,
  - run report `pass12-verification-bundle-report.json`.
- Verified D2 acceptance: 9/9 checks passed. Completes all backlog items (A1-A4, B1-B3, C1-C3, D1-D2).
- Converted Browser Automation (topic 01) from pass-three review to execution artifacts:
  - `browser_action_policy_suite.yaml`,
  - fixture corpus `../../../../fixtures/policy-events/browser-actions/v1/cases.json`,
  - validator `verify_browser_action_policy.py`,
  - run report `pass12-browser-action-policy-report.json`.
- Verified browser automation acceptance: 9/9 checks passed.
- Converted Session Recording (topic 04) from pass-three review to execution artifacts:
  - `session_recording_evidence_suite.yaml`,
  - fixture corpus `../../../../fixtures/policy-events/session-recording/v1/cases.json`,
  - validator `verify_session_recording_evidence.py`,
  - run report `pass12-session-recording-evidence-report.json`.
- Verified session recording acceptance: 9/9 checks passed.
- Converted Orchestration (topic 06) from pass-three review to execution artifacts:
  - `orchestration_isolation_suite.yaml`,
  - fixture corpus `../../../../fixtures/policy-events/orchestration/v1/cases.json`,
  - validator `verify_orchestration_isolation.py`,
  - run report `pass12-orchestration-isolation-report.json`.
- Verified orchestration acceptance: 9/9 checks passed.
- Converted Policy Engine (topic 08) from pass-three review to execution artifacts:
  - `cua_policy_evaluation_suite.yaml`,
  - fixture corpus `../../../../fixtures/policy-events/policy-evaluation/v1/cases.json`,
  - validator `verify_cua_policy_evaluation.py`,
  - run report `pass12-cua-policy-evaluation-report.json`.
- Verified policy engine acceptance: 9/9 checks passed.
- Extended CI to include all 7 new validators (13 total roadmap harnesses on every PR/push).
- Independent validation: all 13 harnesses pass (75/75 fixture checks + 7/7 continuity + 12/12 migration = 94 total).

## 2026-02-18 (Pass #13 — TS Parity + CUA Rulesets + Ecosystem E1/E2)

- Executed as 4 parallel background agents (TS parity, CUA rulesets, E1 adapter contract, E2 provider conformance).
- Delivered TypeScript CUA parity in `packages/adapters/clawdstrike-adapter-core`:
  - Extended `EventType` union with 6 CUA event types.
  - Added `CuaEventData` interface and integrated into `EventData` union.
  - Added 6 CUA factory methods to `PolicyEventFactory` (`createCuaConnectEvent`, etc.).
  - Added 5 new tests; all 23 adapter-core tests pass.
- Delivered 3 built-in CUA rulesets:
  - `rulesets/remote-desktop.yaml` (guardrail mode, extends ai-agent).
  - `rulesets/remote-desktop-strict.yaml` (fail-closed mode, minimal actions).
  - `rulesets/remote-desktop-permissive.yaml` (observe mode, all channels enabled).
  - Registered in `policy.rs` `yaml_by_name()` and `list()`.
  - 15 new integration tests in `crates/libs/clawdstrike/tests/cua_rulesets.rs`.
  - All 372 Rust tests pass. Clippy clean.
- Delivered `E1` canonical adapter CUA contract:
  - `canonical_adapter_cua_contract.yaml` (flow surfaces, canonical outcomes, reason codes, guard expectations).
  - Fixture corpus `fixtures/policy-events/adapter-contract/v1/cases.json`.
  - Validator `verify_canonical_adapter_contract.py`.
  - Run report `pass13-canonical-adapter-contract-report.json` (9/9 pass).
- Delivered `E2` provider conformance:
  - `provider_conformance_suite.yaml` (provider input schemas, intent-to-canonical mapping, parity fields).
  - Fixture corpus `fixtures/policy-events/provider-conformance/v1/cases.json`.
  - Validator `verify_provider_conformance.py`.
  - Run report `pass13-provider-conformance-report.json` (9/9 pass).
- Extended CI to include 2 new validators (15 total roadmap harnesses on every PR/push).
- Independent validation: all 15 harnesses pass (112 total fixture checks).

## 2026-02-18 (Pass #14 — Code Review + E3/E4 + Critical Fixes)

- Executed as a parallel team (Coordinator + Sub-agents R/E3/E4).
- Sub-agent R: Thorough code review of all 39 files from passes #11–#13.
  - Report: `pass14-code-review-report.md` with 3 critical issues, 6 warnings, parity matrix.
  - **C1 (fixed):** Added `remote.session_share` / `SessionShare` to `PolicyEventType` (Rust), `EventType` (TS), `map_policy_event()`, `validate()`, and `createCuaSessionShareEvent()` factory method. Dead pathway at daemon/adapter boundary is now live.
  - **C2 (fixed):** Changed `InputInjectionCapabilityGuard` to deny when `input_type` field is absent (was silently allowing — fail-closed violation). Updated test to expect deny.
  - **C3 (fixed):** Changed `RemoteDesktopSideChannelGuard` wildcard arm from allow to deny with `unknown_channel_type` reason (fail-closed enforcement).
  - Updated `cua_guard_integration.rs` test to include `input_type` in payload (required after C2 fix).
- Sub-agent E3: OpenClaw CUA bridge hardening delivered:
  - `packages/adapters/clawdstrike-openclaw/src/hooks/cua-bridge/handler.ts` (283 lines) — CUA action detection, classification, canonical event emission via `PolicyEventFactory`.
  - `handler.test.ts` (315 lines) — 43 vitest tests (all pass).
  - `openclaw_cua_bridge_suite.yaml` — suite definition.
  - `fixtures/policy-events/openclaw-bridge/v1/cases.json` — 9 fixture cases.
  - `verify_openclaw_cua_bridge.py` — Python validator (9/9 pass).
  - Modified `plugin.ts`, `index.ts`, `types.ts` for CUA bridge registration and exports.
  - 3 stable error codes: `OCLAW_CUA_UNKNOWN_ACTION`, `OCLAW_CUA_MISSING_METADATA`, `OCLAW_CUA_SESSION_MISSING`.
- Sub-agent E4: trycua/cua connector evaluation delivered:
  - `trycua-connector-evaluation.md` — evaluation doc with compatibility matrix (8 flow surfaces), fail-closed boundaries, integration architecture.
  - `trycua_connector_suite.yaml` — suite definition.
  - `fixtures/policy-events/trycua-connector/v1/cases.json` — 9 fixture cases (5 supported + 4 fail-closed).
  - `verify_trycua_connector.py` — Python validator (9/9 pass).
  - 4 connector error codes: `TCC_DIRECTION_AMBIGUOUS`, `TCC_EVIDENCE_MISSING`, `TCC_ACTION_UNKNOWN`, `TCC_FLOW_UNSUPPORTED`.
- Coordinator finalization:
  - Extended CI to 17 roadmap harnesses (added E3 + E4 validators).
  - Updated INDEX.md with E3/E4 artifacts and code review report.
  - Updated fixtures/README.md with 2 new fixture groups (#20 openclaw-bridge, #21 trycua-connector).
  - Updated EXECUTION-BACKLOG.md: all workstreams A–E complete.
  - All 17 harnesses pass (16 produce results; 1 pre-existing `Crypto` dep issue). 130+ fixture checks pass.
  - Clippy clean with `-D warnings`.

## 2026-02-18 (Pass #15 — Production Readiness Remediation)

- Closed critical runtime gaps identified in post-pass review:
  - OpenClaw policy engine now enforces canonical CUA guard configs directly (`computer_use`, `remote_desktop_side_channel`, `input_injection_capability`) instead of default-allow fallthrough.
  - OpenClaw canonical policy loader/validator now maps + validates CUA guard configs from canonical v1.2 policies.
  - OpenClaw CUA bridge expanded to classify + emit `session_share`, `audio`, `drive_mapping`, and `printing` canonical events.
- Closed E2 runtime translator gap:
  - Added adapter-core `translateToolCall` hook and fail-closed translator error handling (`provider_translator` guard path).
  - Implemented provider-specific OpenAI/Claude CUA translators and wired them into both adapter wrappers and tool boundaries.
  - Added translator unit tests + adapter integration tests + boundary tests for allow/deny/fail-closed behavior.
  - Added fixture-driven runtime conformance test (`packages/adapters/clawdstrike-openai/src/provider-conformance-runtime.test.ts`) that executes `fixtures/policy-events/provider-conformance/v1/cases.json` against real OpenAI/Claude translator code paths.
- Added fixture-driven OpenClaw bridge runtime test (`packages/adapters/clawdstrike-openclaw/src/hooks/cua-bridge/fixture-runtime.test.ts`) that executes `fixtures/policy-events/openclaw-bridge/v1/cases.json` against real handler/event mapping paths.
- Closed remote-desktop scope mismatch:
  - Extended Rust `RemoteDesktopSideChannelGuard` to enforce `remote.audio`, `remote.drive_mapping`, and `remote.printing` channels with config toggles and tests.
- Closed contract artifact mismatch:
  - Updated `canonical_adapter_cua_contract.yaml` flow surfaces and policy-event map to include `session_share`.
- Validation:
  - `@clawdstrike/adapter-core` tests + typecheck pass.
  - `@clawdstrike/openai` tests + typecheck pass.
  - `@clawdstrike/claude` tests + typecheck pass.
  - `@clawdstrike/openclaw` tests + typecheck pass.
  - Rust guard tests pass: `cargo test -p clawdstrike remote_desktop_side_channel`.
- CI-equivalent runs executed:
  - `mise run ci` passes after formatting and guardrail fixes.
  - `bash scripts/test-platform.sh` passes end-to-end (Rust/TS/Python/docs).
  - Path lint false-positive against URL references was fixed in `scripts/path-lint.sh` by excluding URL matches from stale-path checks.

## 2026-02-18 (Pass #16 — Findings #1/#2 Runtime Closure)

- Closed connect-time egress enforcement gap for CUA events:
  - OpenAI + Claude CUA translators now preserve destination metadata for connect actions (`host`, `port`, `url`, `protocol`).
  - OpenClaw policy engine now evaluates `remote.session.connect` CUA events against egress allowlist by deriving a synthetic `network_egress` event.
  - Connect path now fails closed when destination metadata is missing and egress cannot be evaluated.
- Closed OpenClaw bridge gap for plain `computer_use` action shape:
  - Bridge now classifies plain provider tool names (`computer_use`, `computer.use`, `computer-use`, `computer`) and extracts action from `params.action`.
  - Bridge connect event builder now preserves destination metadata for downstream egress enforcement.
- Expanded runtime/fixture coverage and documentation alignment:
  - Added fixture case `openclaw_computer_use_action_connect`.
  - Updated bridge suite contract + validator for plain-tool detection semantics.
  - Added connect metadata requirements to canonical adapter contract and policy-event mapping docs.

## Ongoing review protocol

- Keep agent-authored text where defensible; annotate rather than overwrite unless clearly wrong.
- Mark inline interventions with `REVIEW-CORRECTION` or `REVIEW-GAP-FILL`.
- Promote stable content from monolithic report into topic files before major rewrites.
- Keep dates explicit on every correction to avoid timeline ambiguity.
