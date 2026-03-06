# Verification Matrix

> **Status:** Draft | **Date:** 2026-03-06
>
> This document defines the verification contract for each fleet-security
> workstream and the cross-stream end-to-end gates that must pass before the
> program is considered integrated.

## Verification Layers

Every lane must satisfy three layers of proof:

1. lane-local verification
2. review verification
3. cross-stream integration verification

Lane-local proof is the worker’s job. Review and integration proof are the
orchestrator’s job.

## Lane Verification Table

| Lane | Required Commands | Required Artifacts | Review Gate |
|---|---|---|---|
| `ORCH` | `cargo fmt --all`, `mdbook build docs` | merge notes, review output, rebased migration set | all shared-file diffs are intentional |
| `A1` | `cargo fmt --all`, `cargo clippy -p clawdstrike-control-api --all-targets -- -D warnings`, `cargo test -p clawdstrike-control-api` | migration output, CRUD test coverage, backfill notes | principal and compatibility flows are both covered |
| `A2` | `cargo fmt --all`, `cargo clippy -p clawdstrike-control-api -p hunt-correlate -p clawdstrike-ocsf --all-targets -- -D warnings`, `cargo test -p clawdstrike-control-api -p hunt-correlate -p clawdstrike-ocsf` | rule fixtures, finding fixtures, suppression tests | rule storage, finding generation, and suppression semantics are explicit |
| `A3` | `cargo fmt --all`, `cargo clippy -p clawdstrike-control-api -p hush-multi-agent --all-targets -- -D warnings`, `cargo test -p clawdstrike-control-api -p hush-multi-agent` | action-state tests, publish/ack fixtures, rollback notes | response state machine and ack semantics are proven |
| `A4` | `cargo fmt --all`, `cargo clippy -p clawdstrike-control-api -p hunt-query -p hunt-correlate -p clawdstrike-ocsf --all-targets -- -D warnings`, `cargo test -p clawdstrike-control-api -p hunt-query -p hunt-correlate -p clawdstrike-ocsf` | search/timeline fixtures, normalized event samples, saved-hunt examples | event ingestion and retrieval are both covered |
| `A5` | `npm --prefix apps/control-console run typecheck`, `npm --prefix apps/control-console test`, `npm --prefix apps/control-console run build` | UI screenshots or notes, API fixture tests, navigation notes | console reads the cloud model rather than local-only shims |
| `A6` | `cargo fmt --all`, `cargo clippy -p clawdstrike-control-api --all-targets -- -D warnings`, `cargo test -p clawdstrike-control-api` | case lifecycle tests, bundle export fixtures, retention notes | evidence bundle semantics are explicit and reproducible |
| `A7` | `cargo fmt --all`, `cargo clippy -p clawdstrike-control-api -p hush-multi-agent --all-targets -- -D warnings`, `cargo test -p clawdstrike-control-api -p hush-multi-agent` | graph query fixtures, lineage samples, revocation pivots | graph joins are stable and queryable |
| `A8` | `cargo fmt --all`, `cargo test -p clawdstrike-ocsf`, plus tests for each touched bridge crate | mapper fixtures, platform caveats, normalization examples | every new field is justified by a downstream consumer |

## Review Procedure

Every worker branch should be reviewed through Codex before merge.

Recommended command pattern:

```bash
mkdir -p ../clawdstrike-orchestration/<lane>

(
  cd ../clawdstrike-worktrees/<lane> &&
  codex exec review \
    --base main \
    --full-auto \
    -o ../../clawdstrike-orchestration/<lane>/review.md
)
```

If the branch is not rebased on `main`, the orchestrator should rebase first or
review against the expected upstream branch instead of forcing review noise.

## Cross-Stream Integration Scenarios

These are the end-to-end scenarios the orchestrator should use to prove the
program is actually converging.

### `E2E-1`: Enrollment to Effective Policy

Proves:

- directory principals exist
- memberships resolve correctly
- effective policy can be computed centrally
- agent policy distribution remains compatible

Required lanes:

- `A1`
- `A3` if policy reload actions are included

Evidence:

- SQL backfill output
- API create/list responses for principals and memberships
- agent-side policy sync proof

### `E2E-2`: Event to Detection to Suppression

Proves:

- normalized events can be stored
- rules can produce findings
- suppressions affect resulting findings correctly

Required lanes:

- `A2`
- `A4`

Evidence:

- sample event fixture
- finding output fixture
- suppression behavior test

### `E2E-3`: Detection to Response Acknowledgement

Proves:

- findings can trigger operator actions
- actions are published durably
- the target agent acknowledges execution

Required lanes:

- `A2`
- `A3`
- `A4` if hunt joins are part of the scenario

Evidence:

- action ledger rows
- publish/ack payload samples
- lifecycle transition test output

### `E2E-4`: Hunt Query to Timeline to Case

Proves:

- events are queryable
- timeline reconstruction works
- investigations can become case artifacts

Required lanes:

- `A4`
- `A6`

Evidence:

- query response fixture
- timeline response fixture
- evidence bundle export

### `E2E-5`: Delegation to Graph Pivot

Proves:

- grants and delegation edges are persisted
- graph pivots from principal to finding to response are possible

Required lanes:

- `A1`
- `A3`
- `A4`
- `A7`

Evidence:

- graph query fixture
- lineage sample
- pivot result screenshots or JSON samples

### `E2E-6`: Console Operator Flow

Proves:

- the control console is pointed at fleet APIs
- an operator can view a finding, inspect a principal, and issue a response

Required lanes:

- `A1`
- `A2`
- `A3`
- `A4`
- `A5`

Evidence:

- frontend test output
- built UI
- API fixture coverage

### `E2E-7`: Detection Pack Distribution

Proves:

- detection pack metadata is distributable through `policy-pack`
- installed detection content activates correctly

Required lanes:

- `A2`

Evidence:

- pack metadata fixture
- install or activation fixture
- rule listing proof

### `E2E-8`: Bridge Telemetry to Normalized Envelope

Proves:

- bridge output maps into the fleet event envelope
- downstream hunt and detection surfaces can consume the new fields

Required lanes:

- `A4`
- `A8`

Evidence:

- bridge fixture input
- normalized event output
- OCSF export sample if relevant

## Global Merge Criteria

The program should not be called “execution underway” unless:

- `A1`, `A2`, and `A3` have real code branches with verification bundles
- at least one orchestrator review has been run through `codex exec review`
- the worktree layout and migration slots are being followed

The program should not be called “first integrated slice complete” unless:

- `E2E-1`
- `E2E-2`
- `E2E-3`

all pass against merged code.
