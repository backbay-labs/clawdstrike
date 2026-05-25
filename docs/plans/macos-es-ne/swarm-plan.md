# macOS EndpointSecurity + NetworkExtension Swarm Plan

## Objective

Execute the first implementation wave for a ClawdStrike macOS integration that:

- moves the privileged macOS host to `apps/agent`
- adds native EndpointSecurity and NetworkExtension components behind a frozen host and policy contract
- extends receipts and sandbox attestation so macOS enforcement is reported accurately
- adds the entitlement, signing, notarization, and CI wiring required for macOS delivery

This document is now the active implementation map. The research wave is complete, and the control docs below are the required source of truth for any macOS security-software lane.

## Control Docs

- `docs/plans/clawdstrike/macos-es-ne/network-extension-provider-and-topology.md`
- `docs/plans/clawdstrike/macos-es-ne/endpoint-security-auth-contract.md`
- `docs/plans/clawdstrike/macos-es-ne/deployment-and-verification.md`

## Frozen Decisions And Platform Gates

- `apps/agent` is the containing app for privileged macOS components.
- Privileged ES and NE logic must not run in the Tauri UI process. They live in dedicated macOS-specific components behind the agent host.
- `apps/desktop` is deferred from the active implementation wave. Desktop readout can follow after the core host, policy, and packaging path is stable.
- Policy and attestation contracts must be frozen before the ES and NE implementation lanes run.
- Packaging, entitlements, signing, and notarization stay serialized after the runtime surfaces exist.
- the first macOS network-provider baseline is a content filter provider, not transparent proxy
- the first macOS privileged-bundle topology is one combined system extension under `apps/agent`
- macOS enforcement semantics are not Linux fd-injection semantics; ES timeout, fail-open, and degraded-state behavior are mandatory contract surfaces
- Developer ID system-extension deployment is the active packaging baseline; Mac App Store and app-extension deployment are deferred

## Current Repo Anchors

- Runtime launch and sandbox mode selection:
  - `crates/services/hush-cli/src/hush_run.rs`
  - `crates/services/hush-cli/src/supervised_exec.rs`
- Policy translation and runtime enforcement:
  - `crates/libs/clawdstrike/src/sandbox/capability_builder.rs`
  - `crates/libs/clawdstrike/src/sandbox/supervisor.rs`
  - `crates/libs/clawdstrike/src/sandbox/never_grant.rs`
- Attestation and receipt surface:
  - `crates/libs/clawdstrike/src/sandbox/attestation.rs`
  - `crates/services/hush-cli/tests/supervisor_tests.rs`
- Chosen macOS containing app:
  - `apps/agent/src-tauri/src/main.rs`
  - `apps/agent/src-tauri/src/daemon.rs`
  - `apps/agent/src-tauri/Cargo.toml`
  - `apps/agent/src-tauri/tauri.conf.json`
  - `apps/agent/src-tauri/build.rs`
- Packaging, signing, and release wiring:
  - `apps/agent/scripts/prepare-bundled-hushd.sh`
  - `scripts/notarize-agent-macos.sh`
  - `.github/workflows/ci.yml`
  - `.github/workflows/release.yml`

## Shared Files

These stay orchestrator-owned for the active implementation wave:

- `.codex/swarm/lanes.tsv`
- `.codex/swarm/waves.tsv`
- `docs/plans/clawdstrike/macos-es-ne/swarm-plan.md`
- `docs/plans/clawdstrike/macos-es-ne/network-extension-provider-and-topology.md`
- `docs/plans/clawdstrike/macos-es-ne/endpoint-security-auth-contract.md`
- `docs/plans/clawdstrike/macos-es-ne/deployment-and-verification.md`
- `docs/plans/multi-agent/codex-swarm-playbook.md`
- `Cargo.toml`
- `Cargo.lock`

## Serialized Assets

These are not shared across active worker lanes. They are either lane-owned or deferred until their lane wave:

- `apps/agent/src-tauri/Cargo.toml`
  lane owner: `HOST`
- `apps/agent/src-tauri/Cargo.lock`
  lane owner: `HOST`
- `apps/agent/src-tauri/src/main.rs`
  lane owner: `HOST`
- `apps/agent/src-tauri/src/daemon.rs`
  lane owner: `HOST`
- `apps/agent/src-tauri/src/macos/**`
  lane owner: `HOST`
- `crates/libs/clawdstrike/src/sandbox/capability_builder.rs`
  lane owner: `POLAT`
- `crates/libs/clawdstrike/src/sandbox/supervisor.rs`
  lane owner: `POLAT`
- `crates/libs/clawdstrike/src/sandbox/never_grant.rs`
  lane owner: `POLAT`
- `crates/libs/clawdstrike/src/sandbox/attestation.rs`
  lane owner: `POLAT`
- `crates/services/hush-cli/src/hush_run.rs`
  lane owner: `POLAT`
- `crates/services/hush-cli/src/supervised_exec.rs`
  lane owner: `POLAT`
- `crates/services/hush-cli/tests/supervisor_tests.rs`
  lane owner: `POLAT`
- `apps/agent/src-tauri/macos/system-extension/endpoint-security/**`
  lane owner: `ESINT`
- `apps/agent/src-tauri/macos/system-extension/network-extension/**`
  lane owner: `NEINT`
- `apps/agent/src-tauri/tauri.conf.json`
  lane owner: `PKG`
- `apps/agent/src-tauri/build.rs`
  lane owner: `PKG`
- `apps/agent/scripts/prepare-bundled-hushd.sh`
  lane owner: `PKG`
- `scripts/notarize-agent-macos.sh`
  lane owner: `PKG`
- `.github/workflows/ci.yml`
  lane owner: `PKG`
- `.github/workflows/release.yml`
  lane owner: `PKG`
- `apps/agent/src-tauri/macos/system-extension/entitlements/**`
  lane owner: `PKG`
- `apps/agent/src-tauri/macos/system-extension/plists/**`
  lane owner: `PKG`
- `apps/agent/src-tauri/macos/system-extension/profiles/**`
  lane owner: `PKG`

## Lane Map

### ORCH

Owns initiative coordination, lane boundaries, merge sequencing, and the final consolidated handoff.

Outputs:

- implementation-wave readiness
- merge queue decisions
- shared-file policy
- shared registration integration for `Cargo.toml` and `Cargo.lock` when lane work requires it
- exception approval when a lane wants to violate the content-filter baseline or combined-system-extension topology
- updated swarm metadata

### HOST

First write lane. Builds the containing-app foundation in `apps/agent`.

Owned files:

- `apps/agent/src-tauri/Cargo.toml`
- `apps/agent/src-tauri/Cargo.lock`
- `apps/agent/src-tauri/src/main.rs`
- `apps/agent/src-tauri/src/daemon.rs`
- `apps/agent/src-tauri/src/macos/**`

Required outcomes:

- agent-side macOS host module layout
- extension install, approval, activation, and degraded-state surface for the combined system extension
- local IPC and service contract for ES and NE components
- no provider-specific policy decisions that conflict with the control docs
- no packaging or workflow edits

### POLAT

Second write lane. Freezes policy translation, runtime bridge, and attestation semantics.

Owned files:

- `crates/libs/clawdstrike/src/sandbox/capability_builder.rs`
- `crates/libs/clawdstrike/src/sandbox/supervisor.rs`
- `crates/libs/clawdstrike/src/sandbox/never_grant.rs`
- `crates/libs/clawdstrike/src/sandbox/attestation.rs`
- `crates/services/hush-cli/src/hush_run.rs`
- `crates/services/hush-cli/src/supervised_exec.rs`
- `crates/services/hush-cli/tests/supervisor_tests.rs`
- optional new files under `crates/libs/clawdstrike/src/sandbox/macos/**`

Required outcomes:

- frozen host-to-runtime contract consumed by ES and NE lanes
- provider-agnostic network mediation contract that does not hard-code transparent proxy as the macOS target
- attestation schema that can report macOS provider install, activation, health, and degraded state
- backward-compatible receipt attestation deserialization for pre-POLAT `platform.mechanism` and legacy runtime-only payloads
- truthful outer receipt metadata when supervised enforcement is unavailable or degraded
- replacement for the current non-Linux supervised dead-end
- explicit fail-open, timeout, and dropped-event handling contract for macOS ES
- no packaging or workflow edits

### ESINT

Third-wave write lane. Implements the EndpointSecurity part of the combined system extension against the frozen host and policy contract.

Owned files:

- `apps/agent/src-tauri/macos/system-extension/endpoint-security/**`
- optional fixtures under `fixtures/macos/endpoint-security/**`

Required outcomes:

- ES-native component implementation under the combined system-extension surface
- process and file event mapping that matches the contract frozen by `POLAT`
- deadline-miss, dropped-event, and degraded-state counters exposed to the host and attestation surface
- no Linux-style fd-injection claims in code or handoff evidence
- no edits to `apps/agent/src-tauri/**` outside the lane-owned new component surface

### NEINT

Third-wave write lane. Implements the NetworkExtension part of the combined system extension against the frozen host and policy contract.

Owned files:

- `apps/agent/src-tauri/macos/system-extension/network-extension/**`
- optional fixtures under `fixtures/macos/network-extension/**`

Required outcomes:

- native NE component implementation aligned with the frozen network contract
- content-filter provider baseline implementation, unless ORCH approves a documented transparent-proxy exception
- host-consumable status and counter output
- no edits to `apps/agent/src-tauri/**` outside the lane-owned new component surface

### PKG

Final write lane. Serializes macOS bundle metadata, signing, entitlements, notarization, and CI release wiring.

Owned files:

- `apps/agent/src-tauri/tauri.conf.json`
- `apps/agent/src-tauri/build.rs`
- `apps/agent/scripts/prepare-bundled-hushd.sh`
- `scripts/notarize-agent-macos.sh`
- `.github/workflows/ci.yml`
- `.github/workflows/release.yml`
- `apps/agent/src-tauri/macos/system-extension/entitlements/**`
- `apps/agent/src-tauri/macos/system-extension/plists/**`
- `apps/agent/src-tauri/macos/system-extension/profiles/**`

Required outcomes:

- macOS entitlement and plist assets for the containing app plus combined system extension
- signed and notarized build path for the containing app plus combined system extension
- deployment evidence aligned with TN3134 and TN3165 constraints
- CI and release checks that fail closed on missing macOS packaging artifacts
- no edits to policy or runtime contract files

### Review Lanes

Each write lane is followed by a dedicated reviewer lane:

- `RHOST` reviews `HOST`
- `RPOLAT` reviews `POLAT`
- `RESINT` reviews `ESINT`
- `RNEINT` reviews `NEINT`
- `RPKG` reviews `PKG`

Reviewer outputs must be findings-first and must call out ownership violations, contract drift, missing tests, failure-mode gaps, and merge risk.

## Dependency Graph

- `HOST` depends on the control-doc baseline that `apps/agent` is the containing app and the combined system extension is the first-wave topology.
- `POLAT` depends on `HOST` being merged or otherwise frozen via reviewed handoff.
- `ESINT` depends on `POLAT` being merged or otherwise frozen via reviewed handoff plus the EndpointSecurity AUTH contract remaining unchanged.
- `NEINT` depends on `POLAT` being merged or otherwise frozen via reviewed handoff plus the content-filter baseline remaining unchanged unless ORCH approves an exception.
- `PKG` depends on `HOST`, `POLAT`, `ESINT`, and `NEINT` being merged or otherwise frozen via reviewed handoff.
- Review lanes gate the next write wave. Do not advance on author self-report alone.
- Desktop readout is a follow-on initiative, not part of this active lane map.
- no lane may override the provider or topology control docs without an ORCH-reviewed exception handoff

## Verification Matrix

### HOST

- `cargo check --manifest-path apps/agent/src-tauri/Cargo.toml`
- unit or fixture evidence for approval-blocked, provider-inactive, and degraded-state host readout

### POLAT

- `cargo test -p hush-cli supervisor_tests -- --nocapture`
- `cargo test -p hush-cli --test supervisor_tests -- --nocapture`
- `cargo test -p clawdstrike sandbox:: -- --nocapture`
- `cargo test -p hush-cli hush_run::tests -- --nocapture`
- end-to-end `run_hush_with_receipt(..., true, ...)` evidence showing degraded non-Linux supervised runs do not serialize or verdict as successful supervised enforcement
- verification that macOS attestation does not report enforced success when a required provider is inactive, degraded, or missing approval

### ESINT

- `cargo check --manifest-path apps/agent/src-tauri/Cargo.toml`
- `swift build --package-path apps/agent/src-tauri/macos/system-extension/endpoint-security`
- synthetic deadline-miss or dropped-event evidence that degrades host health and attestation instead of claiming enforced success
- synthetic missing-Full-Disk-Access evidence that surfaces degraded ES state

### NEINT

- `cargo check --manifest-path apps/agent/src-tauri/Cargo.toml`
- `swift build --package-path apps/agent/src-tauri/macos/system-extension/network-extension`
- provider-selection evidence showing the content-filter baseline or an approved transparent-proxy exception
- provider-unavailable evidence that degrades host health and attestation instead of silently bypassing mediation

### PKG

- `cargo check --manifest-path apps/agent/src-tauri/Cargo.toml`
- on a macOS signer with Apple credentials: `bash scripts/notarize-agent-macos.sh`
- on a macOS signer or QA host: activation evidence for approved and denied system-extension install paths
- restart or relaunch evidence showing either reactivation or explicit degraded-state reporting
- when signer credentials are unavailable in the worker environment, leave a blocked release-gate handoff instead of claiming the lane is fully verified

### Review Lanes

- confirm lane verification actually ran or explain why it could not
- reject any transparent-proxy default without the documented exception handoff
- reject any macOS receipt or status claim that reports enforcement while a required provider is inactive or degraded
- review only the owned files plus the reviewed lane's handoff evidence

## Merge Order

1. `HOST`
2. `POLAT`
3. `ESINT` and `NEINT`
4. `PKG`
5. ORCH consolidation

`ESINT` and `NEINT` may merge in either order after both are reviewed, but `PKG` does not start until both are accepted.

## Wave5 Readiness

`HOST` and `POLAT` now freeze the following implementation-facing contract for `ESINT` and `NEINT`:

- host readout lives in `apps/agent/src-tauri/src/macos/status.rs`, `apps/agent/src-tauri/src/macos/host.rs`, and `/api/v1/agent/health`; next waves must populate that surface instead of inventing a parallel status model
- receipt attestation lives in `crates/libs/clawdstrike/src/sandbox/attestation.rs`; next waves must drive `provider_states`, `deadline_miss_count`, `dropped_event_count`, and degraded reasons through that surface rather than side-channel metadata
- outer receipt metadata in `crates/services/hush-cli/src/hush_run.rs` must downgrade `hush.sandbox` and fail the verdict when supervised enforcement is requested but unavailable or degraded
- macOS networking remains the implemented `ProxyOnly` runtime with an explicit legacy backend hint; `NEINT` may not rename that live backend to a more abstract contract string unless the actual implementation changes with ORCH approval
- reviewer lanes for wave5 must reject any ES or NE patch that bypasses these frozen surfaces or silently widens the contract

## Wave Order

- `wave0`: `ORCH`
- `wave1`: `HOST`
- `wave2`: `RHOST`
- `wave3`: `POLAT`
- `wave4`: `RPOLAT`
- `wave5`: `ESINT`, `NEINT`
- `wave6`: `RESINT`, `RNEINT`
- `wave7`: `PKG`
- `wave8`: `RPKG`
- `wave9`: `ORCH`

## Stop Condition

The implementation wave is complete when ORCH can hand back:

- merged host foundation in `apps/agent`
- merged policy and attestation contract for macOS enforcement
- reviewed ES and NE component implementations
- merged packaging and release wiring for macOS delivery
- reviewed evidence for denied, degraded, and restart-path behavior
- a follow-on recommendation for desktop diagnostics and operator readout
