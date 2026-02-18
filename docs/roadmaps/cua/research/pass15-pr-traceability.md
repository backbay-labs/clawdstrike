# Pass #15 PR Traceability (Findings -> Fixes)

Date: 2026-02-18

This section maps each original finding from the post-execution review to concrete code/test changes in this PR.

## Finding 1: OpenClaw emitted CUA events but did not enforce CUA policy guards

Resolution:
- OpenClaw policy engine now evaluates CUA events via explicit `checkCua()` path and enforces:
  - `guards.computer_use`
  - `guards.remote_desktop_side_channel`
  - `guards.input_injection_capability`
- OpenClaw canonical policy translation now maps these guard configs from canonical policy.
- OpenClaw validator now validates these guard configs and rejects malformed/unknown fields.

Changed files:
- `packages/adapters/clawdstrike-openclaw/src/policy/engine.ts`
- `packages/adapters/clawdstrike-openclaw/src/policy/loader.ts`
- `packages/adapters/clawdstrike-openclaw/src/policy/validator.ts`
- `packages/adapters/clawdstrike-openclaw/src/types.ts`

Tests:
- `packages/adapters/clawdstrike-openclaw/src/policy/engine.test.ts`
- `packages/adapters/clawdstrike-openclaw/src/policy/loader.test.ts`
- `packages/adapters/clawdstrike-openclaw/src/policy/validator.test.ts`

## Finding 2: E2 marked complete, but runtime translators were not provider-specific

Resolution:
- Added adapter-core translator hook (`translateToolCall`) and fail-closed handling for translation failures.
- Added provider-specific runtime translators:
  - OpenAI translator
  - Claude translator
- Wired translators into both adapter path and tool-boundary path.

Changed files:
- `packages/adapters/clawdstrike-adapter-core/src/adapter.ts`
- `packages/adapters/clawdstrike-adapter-core/src/base-tool-interceptor.ts`
- `packages/adapters/clawdstrike-adapter-core/src/index.ts`
- `packages/adapters/clawdstrike-openai/src/openai-cua-translator.ts`
- `packages/adapters/clawdstrike-openai/src/openai-adapter.ts`
- `packages/adapters/clawdstrike-openai/src/tool-boundary.ts`
- `packages/adapters/clawdstrike-claude/src/claude-cua-translator.ts`
- `packages/adapters/clawdstrike-claude/src/claude-adapter.ts`
- `packages/adapters/clawdstrike-claude/src/tool-boundary.ts`

Tests:
- `packages/adapters/clawdstrike-adapter-core/src/base-tool-interceptor.test.ts`
- `packages/adapters/clawdstrike-openai/src/openai-cua-translator.test.ts`
- `packages/adapters/clawdstrike-openai/src/openai-adapter.test.ts`
- `packages/adapters/clawdstrike-openai/src/tool-boundary.test.ts`
- `packages/adapters/clawdstrike-claude/src/claude-cua-translator.test.ts`
- `packages/adapters/clawdstrike-claude/src/claude-adapter.test.ts`
- `packages/adapters/clawdstrike-claude/src/tool-boundary.test.ts`

## Finding 3: Integration harnesses were synthetic contract checks, not runtime-backed

Resolution:
- Added runtime fixture-driven provider conformance execution against real OpenAI/Claude translator code paths.
- Added runtime fixture-driven OpenClaw bridge test that executes `cases.json` against real bridge handler + canonical event path.

Changed files:
- `packages/adapters/clawdstrike-openai/src/provider-conformance-runtime.test.ts`
- `packages/adapters/clawdstrike-openclaw/src/hooks/cua-bridge/fixture-runtime.test.ts`

Fixture inputs consumed at runtime:
- `fixtures/policy-events/provider-conformance/v1/cases.json`
- `fixtures/policy-events/openclaw-bridge/v1/cases.json`

## Finding 4: Roadmap artifacts inconsistent on scope/features

Resolution:
- Runtime side-channel guard in Rust now covers matrix-required channels:
  - `remote.audio`
  - `remote.drive_mapping`
  - `remote.printing`
- Canonical adapter contract now includes `session_share` in flow surfaces and policy-event map.
- Backlog/index/review log updated to reflect pass #15 runtime remediation state.

Changed files:
- `crates/libs/clawdstrike/src/guards/remote_desktop_side_channel.rs`
- `docs/roadmaps/cua/research/canonical_adapter_cua_contract.yaml`
- `docs/roadmaps/cua/research/EXECUTION-BACKLOG.md`
- `docs/roadmaps/cua/INDEX.md`
- `docs/roadmaps/cua/research/REVIEW-LOG.md`

Tests:
- Rust unit tests in `crates/libs/clawdstrike/src/guards/remote_desktop_side_channel.rs`
- `cargo test -p clawdstrike remote_desktop_side_channel`

## Open Questions Resolved

1. E2 scope: runtime translation complete or contract-design complete?
- Resolved: runtime translation complete. Provider-specific translators now execute in real adapter/tool-boundary runtime paths.

2. OpenClaw role: enforce canonical CUA guard configs directly or only emit CUA audit events?
- Resolved: enforce directly. OpenClaw policy engine now enforces canonical CUA guards in deterministic evaluation.

## Follow-up Patch: Findings #1 + #2 (Runtime + Fixtures + Docs)

Date: 2026-02-18

Finding #1 follow-up (CUA connect egress enforcement gap):
- OpenAI/Claude CUA translators now preserve connect destination metadata (`host`, `port`, `url`, `protocol`) when available.
- OpenClaw policy engine now enforces egress policy on `remote.session.connect` CUA events via synthetic `network_egress` evaluation.
- Connect events now fail closed when destination metadata is missing and egress evaluation cannot be performed.

Changed files:
- `packages/adapters/clawdstrike-openai/src/openai-cua-translator.ts`
- `packages/adapters/clawdstrike-openai/src/openai-cua-translator.test.ts`
- `packages/adapters/clawdstrike-claude/src/claude-cua-translator.ts`
- `packages/adapters/clawdstrike-claude/src/claude-cua-translator.test.ts`
- `packages/adapters/clawdstrike-openclaw/src/policy/engine.ts`
- `packages/adapters/clawdstrike-openclaw/src/policy/engine.test.ts`

Finding #2 follow-up (OpenClaw bridge plain `computer_use` tool shape gap):
- OpenClaw CUA bridge now detects plain provider tool names (`computer_use`, `computer.use`, `computer-use`, `computer`) and resolves actions from `params.action`.
- OpenClaw bridge now preserves connect destination metadata in canonical CUA connect events.
- Added fixture case coverage for plain `computer_use` + `action=connect`.

Changed files:
- `packages/adapters/clawdstrike-openclaw/src/hooks/cua-bridge/handler.ts`
- `packages/adapters/clawdstrike-openclaw/src/hooks/cua-bridge/handler.test.ts`
- `packages/adapters/clawdstrike-openclaw/src/hooks/cua-bridge/fixture-runtime.test.ts`
- `fixtures/policy-events/openclaw-bridge/v1/cases.json`
- `fixtures/policy-events/openclaw-bridge/v1/README.md`

Docs/validator alignment:
- `docs/roadmaps/cua/research/openclaw_cua_bridge_suite.yaml`
- `docs/roadmaps/cua/research/verify_openclaw_cua_bridge.py`
- `docs/roadmaps/cua/research/canonical_adapter_cua_contract.yaml`
- `docs/roadmaps/cua/research/policy_event_mapping.yaml`

## CI-Equivalent Pre-Merge Status

Executed:
- `mise run ci`
- `bash scripts/test-platform.sh`

Result:
- Both commands now pass end-to-end in this branch after:
  - running `cargo fmt --all`,
  - fixing path-lint URL false positives in `scripts/path-lint.sh`.

Targeted validation for this PR scope passed:
- `npm run test --workspace @clawdstrike/adapter-core`
- `npm run test --workspace @clawdstrike/openai`
- `npm run typecheck --workspace @clawdstrike/openai`
- `npm run test --workspace @clawdstrike/claude`
- `npm run test --workspace @clawdstrike/openclaw`
- `cargo test -p clawdstrike remote_desktop_side_channel`
- `python3 docs/roadmaps/cua/research/verify_canonical_adapter_contract.py`
- `python3 docs/roadmaps/cua/research/verify_provider_conformance.py`
- `python3 docs/roadmaps/cua/research/verify_openclaw_cua_bridge.py`

## Pass #17 Addendum: Runtime Hardening + Contract Parity

Date: 2026-02-18

### Gap 1: hushd CUA side-channel parity for emitted events

Resolution:
- Added hushd support for:
  - `remote.audio`
  - `remote.drive_mapping`
  - `remote.printing`
- Updated policy-event mapping/roundtrip logic to handle these event types consistently.

Changed files:
- `crates/services/hushd/src/policy_event.rs`
- `crates/services/hushd/tests/cua_policy_events.rs`

Tests:
- `cargo test -p hushd policy_event -- --nocapture`
- `cargo test -p hushd -q tests::cua_policy_events`

### Gap 2: deterministic `reason_code` at runtime decision boundaries

Resolution:
- Adapter-core decision contract now requires `reason_code` for non-allow decisions.
- OpenClaw policy engine now emits deterministic reason codes across deny/warn paths.
- hushd/hush-cli policy-eval JSON now includes `decision.reason_code`.
- Fail-closed paths normalized to `ADC_GUARD_ERROR`.

Changed files:
- `packages/adapters/clawdstrike-adapter-core/src/types.ts`
- `packages/adapters/clawdstrike-adapter-core/src/engine-response.ts`
- `packages/adapters/clawdstrike-adapter-core/src/base-tool-interceptor.ts`
- `packages/adapters/clawdstrike-openclaw/src/types.ts`
- `packages/adapters/clawdstrike-openclaw/src/policy/engine.ts`
- `crates/services/hushd/src/api/eval.rs`
- `crates/services/hush-cli/src/policy_pac.rs`

Tests/fixtures:
- `crates/services/hush-cli/src/tests.rs`
- `crates/services/hushd/tests/integration.rs`
- `fixtures/policy-events/v1/expected/default.decisions.json`

### Gap 3: provider conformance coverage breadth and runtime scope

Resolution:
- Provider conformance suite expanded to full canonical flow surface.
- Runtime fixture set expanded accordingly.
- Provider scope clarified to OpenAI/Claude for E2 (OpenClaw covered by dedicated bridge suite).

Changed files:
- `docs/roadmaps/cua/research/provider_conformance_suite.yaml`
- `fixtures/policy-events/provider-conformance/v1/cases.json`
- `packages/adapters/clawdstrike-openai/src/provider-conformance-runtime.test.ts`

Validation:
- `python3 docs/roadmaps/cua/research/verify_provider_conformance.py`

### Gap 4: matrix-to-ruleset drift

Resolution:
- Aligned `rulesets/remote-desktop.yaml` with matrix-required channel posture.
- Added fixture-driven ruleset alignment verifier.
- Wired verifier into CI.

Changed files:
- `rulesets/remote-desktop.yaml`
- `fixtures/policy-events/remote-desktop-ruleset-alignment/v1/cases.json`
- `docs/roadmaps/cua/research/verify_remote_desktop_ruleset_alignment.py`
- `.github/workflows/ci.yml`

Validation:
- `python3 docs/roadmaps/cua/research/verify_remote_desktop_ruleset_alignment.py`

### Gap 5: verifier taxonomy (`VFY_*`) implementation

Resolution:
- `hush-core` verify path now emits deterministic verifier error codes.
- CLI verify JSON/text output now surfaces structured `error_code` for parse/shape/signature failures.

Changed files:
- `crates/libs/hush-core/src/receipt.rs`
- `crates/services/hush-cli/src/main.rs`
- `crates/services/hush-cli/src/tests.rs`

Validation:
- `cargo test -p hush-core`
- `cargo test -p hush-cli`

### Full platform status for this addendum

Executed:
- `mise run ci`
- `bash scripts/test-platform.sh`

Result:
- Both commands pass end-to-end after the above changes.
