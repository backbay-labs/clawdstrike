# CUA Execution Backlog (Passes #5-#17)

This backlog originated from pass-four review and tracks implementation + closure status across passes #5-#17 for:

- `02-remote-desktop.md`
- `03-input-injection.md`
- `05-attestation-signing.md`
- `07-receipt-schema.md`

Date: 2026-02-18

## Prioritization rubric

- `P0`: Required to preserve trust guarantees and fail-closed behavior.
- `P1`: Required for robust production enforcement and auditability.
- `P2`: Required for operational optimization and rollout confidence.

## Workstream A: Trust and verifier foundation (`P0`)

### A1. Reference verifier flow specification

- Priority: `P0`
- Source: `07-receipt-schema.md` pass-four TODO
- Deliverable:
  - `docs/roadmaps/cua/research/verifier-flow-spec.md`
- Scope:
  - mandatory check order,
  - error taxonomy and stable error codes,
  - baseline `SignedReceipt` compatibility requirements.
- Acceptance:
  - malformed fixture corpus produces deterministic failures,
  - valid baseline and CUA-extended fixtures pass with identical verdict semantics.

### A2. Attestation verifier policy

- Priority: `P0`
- Source: `05-attestation-signing.md` pass-four TODO
- Deliverable:
  - `docs/roadmaps/cua/research/attestation_verifier_policy.yaml`
- Scope:
  - issuer allowlist,
  - nonce TTL and freshness checks,
  - required claim set,
  - clock-skew tolerance.
- Acceptance:
  - stale nonce and wrong-issuer vectors fail predictably,
  - policy file fully drives verifier behavior without hidden defaults.

### A3. Schema package and migration fixtures

- Priority: `P0`
- Source: `07-receipt-schema.md` pass-four TODO
- Deliverable:
  - versioned JSON Schema package for CUA metadata extension,
  - migration fixtures for `v1 baseline`, `v1 + cua`, and malformed variants.
- Acceptance:
  - schema compatibility tests pass,
  - unknown required fields fail closed,
  - supported additive fields remain backward-compatible.

### A4. Signer migration and rollback plan

- Priority: `P0`
- Source: `05-attestation-signing.md` pass-four TODO
- Deliverable:
  - `docs/roadmaps/cua/research/signer-migration-plan.md`
- Scope:
  - dual-sign period,
  - verifier compatibility window,
  - rollback triggers and procedures.
- Acceptance:
  - dual-sign fixtures verify across old/new verifier paths,
  - rollback drill returns to baseline signing without receipt format breakage.

## Workstream B: Enforcement surface normalization (`P1`)

### B1. Remote desktop policy matrix

- Priority: `P1`
- Source: `02-remote-desktop.md` pass-four TODO
- Deliverable:
  - `docs/roadmaps/cua/research/remote_desktop_policy_matrix.yaml`
- Scope:
  - protocol features (`clipboard`, `file_transfer`, `audio`, `drive_mapping`, `printing`, `session_share`),
  - per-mode defaults (`observe`, `guardrail`, `fail_closed`),
  - threat-tier assumptions (`dev`, `internal_prod`, `internet_exposed_multi_tenant`).
- Acceptance:
  - matrix can be transformed directly into policy events and guard decisions,
  - no feature path remains undefined for any mode,
  - matrix-to-ruleset drift is checked in CI via fixture harness.

### B2. Injection outcome schema and capability manifest

- Priority: `P1`
- Source: `03-input-injection.md` pass-four TODO
- Deliverable:
  - `docs/roadmaps/cua/research/injection_outcome_schema.json`
  - `docs/roadmaps/cua/research/injection_backend_capabilities.yaml`
- Scope:
  - outcome states (`accepted`, `applied`, `verified`, `denied`, `unknown`),
  - standardized reason codes,
  - per-backend feature/permission limits.
- Acceptance:
  - each backend produces machine-parseable outcomes for success/failure classes,
  - unknown backend capability combinations fail closed.

### B3. End-to-end policy-event mapping

- Priority: `P1`
- Source: `02-remote-desktop.md` and `03-input-injection.md` pass-four TODOs
- Deliverable:
  - `docs/roadmaps/cua/research/policy_event_mapping.md`
- Scope:
  - connect, input, clipboard, transfer, reconnect, disconnect flows,
  - mapped guard coverage and audit event outputs.
- Acceptance:
  - every side effect has explicit preflight policy check and post-action audit artifact,
  - mapping cross-references existing guard model without introducing ambiguous paths.

## Workstream C: Evidence integrity and continuity (`P1`)

### C1. Post-condition probes for injected actions

- Priority: `P1`
- Source: `03-input-injection.md` pass-four TODO
- Deliverable:
  - deterministic probe suite for click/type/scroll/key-chord verification.
- Acceptance:
  - probe results distinguish "accepted by API" vs "applied in UI",
  - ambiguous target and focus-steal cases fail with explicit reason codes.

### C2. Remote session continuity tests

- Priority: `P1`
- Source: `02-remote-desktop.md` pass-four TODO
- Deliverable:
  - continuity test suite for reconnect, packet loss, and gateway restart.
- Acceptance:
  - hash chain continuity preserved across reconnect,
  - orphaned actions are detectable and audited.

### C3. Envelope semantic equivalence tests

- Priority: `P1`
- Source: `07-receipt-schema.md` pass-four TODO
- Deliverable:
  - wrapper equivalence test suite for baseline payload vs wrapped payloads.
- Acceptance:
  - canonical payload semantics remain identical across supported wrappers,
  - verifier verdict parity holds for all supported fixture classes.

## Workstream D: Operational readiness (`P2`)

### D1. Repeatable latency harness

- Priority: `P2`
- Source: `02-remote-desktop.md` pass-four TODO
- Deliverable:
  - benchmark harness with fixed host class, codec, frame size, and warm/cold cache scenarios.
- Acceptance:
  - benchmark outputs include full environment metadata,
  - results are reproducible across repeated runs within defined variance bounds.

### D2. End-to-end verification bundle format

- Priority: `P2`
- Source: `05-attestation-signing.md` pass-four TODO
- Deliverable:
  - bundle format containing receipt, attestation evidence, and verification transcript.
- Acceptance:
  - third-party verifier can validate bundle without hidden context,
  - transcript captures pass/fail checkpoints and policy used.

## Workstream E: Ecosystem adapter integrations (`P1`)

### E1. Canonical CUA adapter contract in `adapter-core`

- Priority: `P1`
- Source: integration gap identified after pass-ten artifact completion
- Deliverable:
  - canonical CUA policy-event/action contract in adapter core (provider-neutral),
  - stable reason-code and outcome mapping used across adapters.
- Scope:
  - map CUA flows (`connect`, `input`, `clipboard`, `transfer`, `reconnect`, `disconnect`) into canonical events,
  - keep trust root and verifier semantics owned by Clawdstrike,
  - fail closed on unknown provider action variants.
- Acceptance:
  - all provider adapters emit the same canonical event/outcome surface for equivalent CUA actions,
  - unknown provider action payloads are rejected with deterministic fail-closed codes.

### E2. OpenAI and Claude CUA translators

- Priority: `P1`
- Source: ecosystem integration objective for popular computer-use stacks
- Deliverable:
  - provider translators from OpenAI/Claude computer-use tool payloads into canonical CUA contract,
  - conformance fixtures proving parity.
- Scope:
  - OpenAI computer-use tool request/response mapping,
  - Claude computer-use tool request/response mapping,
  - normalization of action kinds and post-condition outcomes,
  - OpenClaw validation remains in E3 bridge runtime fixtures (separate scope).
- Acceptance:
  - canonical output parity holds across equivalent OpenAI/Claude action vectors,
  - translator regressions fail CI via fixture-driven conformance tests.

### E3. OpenClaw CUA bridge hardening

- Priority: `P1`
- Source: existing `clawdstrike-openclaw` plugin and hook infrastructure
- Deliverable:
  - OpenClaw hook updates to emit canonical CUA events and audit fields,
  - policy mapping parity with core adapter flow.
- Scope:
  - preflight event routing updates,
  - post-action outcome + audit field mapping,
  - shared fail-closed behavior with adapter core.
- Acceptance:
  - OpenClaw CUA paths resolve to the same guard decisions and reason classes as core adapters,
  - tool-boundary tests cover allow/deny/approval and post-condition failure classes.

### E4. `trycua/cua` runtime/backend connector evaluation

- Priority: `P1`
- Source: external runtime candidate for multi-provider CUA execution
- Deliverable:
  - connector evaluation doc + prototype integration harness,
  - compatibility matrix against canonical contract requirements.
- Scope:
  - treat `trycua/cua` as execution backend candidate (not trust-root replacement),
  - validate event/output normalization and evidence handoff constraints.
- Acceptance:
  - prototype can feed canonical CUA events/outcomes into Clawdstrike policy/evidence pipeline,
  - unsupported fields or semantics are explicitly identified with fail-closed handling rules.

## Sequencing proposal

1. Execute `A1` + `A2` + `A3` first.
2. Run `A4` after verifier + schema baseline are fixed.
3. Execute `B1` + `B2`, then derive `B3`.
4. Parallelize `C1`/`C2`/`C3` after mapping artifacts exist.
5. Run `D1`/`D2` once enforcement and verifier paths stabilize.
6. Execute `E1` first, then parallelize `E2`/`E3`, and run `E4` as connector validation against the same canonical contract.

## Program definition of done

Scope note: this definition applies to the implementation backlog for passes #5-#17. Pass #18 tracks release-gate validation work (notarization + long soak + host-level RDP side-channel evidence) in `pass18-notarization-soak-rdp-plan.md`.

- [x] All `P0` workstreams complete with passing fixtures and documented rollback paths.
- [x] All side-effect channels have deterministic policy-event mapping and guard coverage.
- [x] Receipt verification remains backward-compatible with current baseline trust root.
- [x] Evidence and attestation bundles are independently verifiable from stored artifacts.
- [x] All `P1` ecosystem adapter integrations (E1–E4) complete with passing harnesses.
- [x] Code review of all CUA implementation passes completed with critical issues resolved.
- [x] CI runs roadmap harnesses on every PR/push.

### Completion status (Pass #15)

All workstreams A–E are **complete**, with post-review production remediation applied:
- **A1–A4** (Trust Foundation): Verifier flow, attestation policy, schema package, signer migration.
- **B1–B3** (Enforcement Surface): Remote desktop matrix, injection capabilities, policy event mapping.
- **C1–C3** (Evidence Integrity): Post-condition probes, session continuity, envelope equivalence.
- **D1–D2** (Operational Readiness): Latency harness, verification bundle.
- **E1–E4** (Ecosystem): Canonical adapter contract, provider conformance, OpenClaw bridge, trycua connector.

Pass #15 closes the remaining production gaps from code review:
- OpenClaw now enforces canonical CUA guard configs at runtime (no CUA default-allow fallthrough).
- OpenAI/Claude adapters now run provider-specific CUA translators in the runtime path (not fixture-only mapping).
- Remote desktop side-channel runtime scope now includes audio/drive-mapping/printing in Rust guard enforcement.

### Follow-up completion status (Pass #16)

Pass #16 closes two follow-up runtime confidence gaps discovered after Pass #15:
- `remote.session.connect` now enforces egress allowlist in the OpenClaw runtime path and fails closed when destination metadata is missing.
- OpenClaw bridge now supports plain `computer_use`/`computer` tool-call shape with `action` metadata, with fixture + validator coverage.

### Runtime hardening status (Pass #17)

Pass #17 closes additional production-hardening gaps discovered after Pass #16:
- `hushd` canonical policy-event support now includes `remote.audio`, `remote.drive_mapping`, and `remote.printing` end-to-end.
- Runtime policy decision payloads now emit deterministic `reason_code` values (`ADC_POLICY_*` + normalized mapped codes), including Rust eval boundaries consumed by adapter-core engines.
- Provider conformance suite/runtime fixtures now cover the full canonical flow surface (`connect`, `input`, `clipboard_read/write`, upload/download transfer, `session_share`, `reconnect`, `disconnect`) for OpenAI + Claude.
- OpenClaw provider scope is now explicitly separated from E2 conformance and covered by the dedicated OpenClaw bridge runtime fixture suite.
- Added fixture-driven matrix-to-ruleset drift harness (`verify_remote_desktop_ruleset_alignment.py`) and wired it into CI.

### Release-gate validation status (Pass #18, in progress)

Pass #18 runs post-implementation production-readiness blockers:
- Signed/notarized/stapled macOS artifact validation.
- 6-24h soak reliability run with reconnect/restart pressure.
- Full Windows/Linux host-side RDP side-channel matrix evidence.
- Remaining PR review thread closure with runtime/test/doc alignment.

Current checkpoint:
- Harness stability hardening merged (`run-cua-soak.sh` timeout + bounded iteration, `run-rdp-sidechannel-matrix.sh` timeout/restore guards).
- Full matrix evidence produced under `docs/roadmaps/cua/research/artifacts/rdp-sidechannel-20260219-033112/`.
- Review-driven parity fixes merged for `hush-cli` CUA policy-event support and bundled/root ruleset alignment.
- Post-pass follow-up queued: deduplicate `hushd` + `hush-cli` `policy_event` parsing/mapping into a shared module to prevent future drift.

Tracking doc:
- `docs/roadmaps/cua/research/pass18-notarization-soak-rdp-plan.md`
