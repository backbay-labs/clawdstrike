# Execution Agent Handoff Prompt (Pass #11: Integration Team)

## Context

You are executing inside this repository:

- Root: `/Users/connor/Medica/backbay/standalone/clawdstrike-cua`
- Research index: `docs/roadmaps/cua/INDEX.md`
- Review log: `docs/roadmaps/cua/research/REVIEW-LOG.md`
- Prioritized backlog: `docs/roadmaps/cua/research/EXECUTION-BACKLOG.md`

Current state as of **2026-02-18**:

- `P0` completed (`A1`-`A4`) with fixture-driven verifier harness.
- `P1` artifact work completed for `B1`/`B2`/`B3`/`C1`/`C2` with deterministic fixtures + validators + CI gating.
- Remaining high-priority items to start now:
  - `C3` envelope semantic equivalence tests,
  - `D1` repeatable latency harness,
  - integration of existing roadmap contracts into product runtime paths,
  - ecosystem adapter integration workstream `E` (`E1`-`E4`).

## Mission

Shift from research artifacts to **actual Clawdstrike integration** while completing `C3` + `D1` end-to-end and starting ecosystem integration workstream `E`.

You are not writing docs-only deliverables. You are implementing runtime/product code plus tests.

## Mandatory Operating Model: Team of Sub-Agents

You MUST execute as a **team** with parallel workstreams and independent validation.

Required structure:

1. **Coordinator agent**
   - Owns task graph, merge ordering, and conflict resolution.
   - Keeps a live integration checklist and blocks merges if acceptance gates are red.

2. **Sub-agent A: Runtime policy/event integration**
   - Integrates remote/CUA event mappings into active runtime paths.
   - Focus areas:
     - `crates/services/hushd/src/**`
     - `crates/libs/clawdstrike/src/**`
     - `packages/policy/clawdstrike-policy/src/**`

3. **Sub-agent B: Receipt/verifier integration + C3**
   - Implements envelope semantic equivalence harness and fixtures.
   - Ensures verifier verdict parity across wrapper forms.
   - Focus areas:
     - `crates/libs/hush-core/src/receipt.rs`
     - `crates/libs/hush-core/tests/**`
     - `packages/sdk/hush-py/src/clawdstrike/receipt.py`
     - `docs/roadmaps/cua/research/verify_*` + fixtures

4. **Sub-agent C: D1 latency harness**
   - Implements repeatable latency harness with fixed host class/codec/frame-size/warm-cold runs.
   - Produces machine-readable reports with reproducibility checks.
   - Focus areas:
     - `docs/roadmaps/cua/research/**`
     - `fixtures/benchmarks/**` (create if absent)
     - CI hooks in `.github/workflows/ci.yml`

5. **Sub-agent D: Independent validator (must be separate from A/B/C)**
   - Re-runs all harnesses/tests after merges.
   - Verifies fail-closed behavior and checks reproducibility thresholds.
   - Rejects partial implementations that lack deterministic tests.

Parallelism requirement:

- A/B/C run concurrently.
- D runs after each merge batch and at final gate.
- Do not run this as a serial single-agent pass.

## Hard Constraints

- Preserve baseline `SignedReceipt` trust root compatibility.
- Fail closed on unknown schema/profile/action/version conditions.
- No silent behavior drift; every new path must be test-backed.
- Keep changes scoped; avoid unrelated refactors.
- If uncertain, encode as explicit TODO/assumption with deterministic guard behavior.

## Required Deliverables

### 1) C3 Envelope semantic equivalence

Create/update:

- `docs/roadmaps/cua/research/envelope_semantic_equivalence_suite.yaml`
- `fixtures/receipts/envelope-equivalence/v1/cases.json`
- `fixtures/receipts/envelope-equivalence/v1/README.md`
- `docs/roadmaps/cua/research/verify_envelope_semantic_equivalence.py`
- `docs/roadmaps/cua/research/pass11-envelope-equivalence-report.json`

Acceptance:

- Canonical payload semantics are identical across supported wrappers.
- Verifier verdict parity holds for all fixture classes.
- Unknown wrapper/version conditions fail closed.

### 2) D1 Repeatable latency harness

Create/update:

- `docs/roadmaps/cua/research/repeatable_latency_harness.yaml`
- `fixtures/benchmarks/remote-latency/v1/cases.json`
- `fixtures/benchmarks/remote-latency/v1/README.md`
- `docs/roadmaps/cua/research/verify_repeatable_latency_harness.py`
- `docs/roadmaps/cua/research/pass11-latency-harness-report.json`

Acceptance:

- Includes full environment metadata in output.
- Fixed host class, codec, frame size, warm/cold cache scenarios are enforced.
- Repeated-run variance checks are deterministic and threshold-gated.

### 3) Product integration (not docs-only)

Implement concrete runtime wiring for existing B/C artifacts in at least one active execution path:

- policy-event mapping (`connect/input/clipboard/transfer/reconnect/disconnect`) into runtime decision and audit flow,
- post-condition outcome states propagated into auditable artifacts,
- session continuity chain fields propagated through reconnect/recovery path.

Add/update integration tests proving behavior.

## CI and Tracking Updates

Update all relevant tracking artifacts:

- `docs/roadmaps/cua/research/REVIEW-LOG.md` (new pass entry)
- `docs/roadmaps/cua/INDEX.md` (links + status + program status)
- `fixtures/README.md` (new fixture groups)
- `.github/workflows/ci.yml` (new C3/D1 validators and any targeted integration checks)

## Validation Gates (must run and pass)

At minimum, run:

- Existing roadmap harnesses (`pass8`/`pass9`/`pass10` validators)
- New `C3` and `D1` validators
- Targeted integration tests for touched Rust/TS/Python paths

If a full matrix is too expensive locally, run targeted suites and state what was not run.

## Execution Protocol

1. Coordinator creates branch plan and assigns A/B/C in parallel.
2. Each sub-agent opens with file-level plan and expected tests.
3. Merge order: B/C (artifacts + harnesses) -> A (runtime integration consuming contracts) -> D validation.
4. D independently re-runs gates and signs off or returns blocking failures.
5. Final report must include exact files changed and acceptance status per workstream.

## Final Response Format

Return:

1. Team execution summary (A/B/C/D)
2. Files created/updated by workstream
3. Validation results (exact pass/fail counts)
4. Remaining risks/open questions
5. Exact next pass recommendation
