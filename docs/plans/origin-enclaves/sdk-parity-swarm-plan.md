# Origin Enclaves SDK Parity Swarm Plan

> Status: Draft
> Branch family: `feature/sdk-origin-parity-*`

## Ownership Map

| Lane | Role | Ownership | Shared-file boundary |
|---|---|---|---|
| `sdk-orch` | Orchestrator | `docs/specs/19-origin-sdk-parity-api-contract.md`, `docs/plans/origin-enclaves/sdk-parity-roadmap.md`, `docs/plans/origin-enclaves/sdk-parity-swarm-plan.md`, shared fixtures, final README wording | Owns compatibility language, fixture schema, and merge sequencing |
| `sdk-py1` | Worker | `packages/sdk/hush-py/src/clawdstrike/types.py`, `packages/sdk/hush-py/src/clawdstrike/guards/base.py`, `packages/sdk/hush-py/src/clawdstrike/policy.py`, `packages/sdk/hush-py/src/clawdstrike/__init__.py`, Python type/policy tests | Public Python contract and schema gating |
| `sdk-py2` | Worker | `packages/sdk/hush-py/src/clawdstrike/clawdstrike.py`, `packages/sdk/hush-py/src/clawdstrike/backend.py`, `packages/sdk/hush-py/src/clawdstrike/native.py`, `packages/sdk/hush-py/hush-native/src/lib.rs`, Python runtime/session/native tests | Python runtime plumbing and native/daemon forwarding |
| `sdk-go1` | Worker | `packages/sdk/hush-go/clawdstrike.go`, `packages/sdk/hush-go/guards/guard.go`, `packages/sdk/hush-go/policy/policy.go`, `packages/sdk/hush-go/policy/config.go`, Go policy tests | Public Go contract and schema gating |
| `sdk-go2` | Worker | `packages/sdk/hush-go/engine/engine.go`, `packages/sdk/hush-go/session/session.go`, `packages/sdk/hush-go/adapter/context.go`, `packages/sdk/hush-go/adapter/base_interceptor.go`, `packages/sdk/hush-go/daemon_checker.go`, Go runtime/session tests | Go runtime, adapter, and daemon forwarding |

## Recommended Waves

### Wave 0

- `sdk-orch`
- Deliverables:
  - contract finalized
  - compatibility matrix finalized
  - helper names and alias rules frozen

### Wave 1

- `sdk-py1`
- `sdk-go1`
- Parallel because write ownership is disjoint.
- Neither lane should merge unless its runtime lane immediately follows or the contract lane fails closed on unsupported origin usage.

### Wave 2

- `sdk-py2`
- `sdk-go2`
- Each runtime lane depends on its matching contract lane.
- Shared contract docs remain orchestrator-owned.

### Wave 3

- `sdk-orch`
- Deliverables:
  - fixture consolidation if both lanes produced compatible vectors
  - README alignment
  - final verification sweep

## Lane Briefs

### `sdk-py1`

- Add `OriginContext`, alias handling, and `version: "1.4.0"` schema gating in the Python public layer.
- Add explicit fail-closed behavior for unsupported origin-aware policy usage.

Verification:

- `uv run --project packages/sdk/hush-py pytest packages/sdk/hush-py/tests/test_policy.py`
- `ruff check packages/sdk/hush-py`
- `mypy --strict packages/sdk/hush-py/src`

### `sdk-py2`

- Add public origin types and helper APIs under `packages/sdk/hush-py/src/clawdstrike/`.
- Extend native binding context parsing in `packages/sdk/hush-py/hush-native/src/lib.rs`.
- Add daemon/native tests and explicit unsupported-backend errors for the pure-Python path.

Verification:

- `uv run --project packages/sdk/hush-py pytest packages/sdk/hush-py/tests/test_native_engine.py`
- `uv run --project packages/sdk/hush-py pytest packages/sdk/hush-py/tests/test_session.py`
- `uv run --project packages/sdk/hush-py pytest packages/sdk/hush-py/tests/test_core.py`

### `sdk-go1`

- Add Go origin models, JSON tags, helper constructors, and schema-version guardrails.

Verification:

- `cd packages/sdk/hush-go && go test ./policy/... ./guards/...`

### `sdk-go2`

- Add origin models plus `GuardContext.WithOrigin(...)`.
- Extend daemon request serialization in `packages/sdk/hush-go/daemon_checker.go`.
- Add `Session.CheckWithContext(...)` and explicit unsupported-origin errors for the local-engine path.

Verification:

- `cd packages/sdk/hush-go && go test ./...`

## Merge Discipline

- Merge orchestrator docs first if either lane needs to rename helpers or adjust alias rules.
- Merge `sdk-py1` immediately before `sdk-py2`, and `sdk-go1` immediately before `sdk-go2`, unless the contract lane already fails closed on unsupported origin usage.
- Merge Python before Go only if the shared fixture shape changes; otherwise either language can land first.
- Keep `README` edits for both SDKs in the final orchestrator pass to avoid conflicts.

## Swarm Metadata Note

Execution now runs with dedicated SDK parity lanes appended to `.codex/swarm/lanes.tsv` and `.codex/swarm/waves.tsv`.

Guardrails:

- the existing Huntronomer lanes remain untouched
- SDK parity lanes are appended under `sdk-*`
- shared contract docs and README alignment stay orchestrator-owned even when worker lanes are active
