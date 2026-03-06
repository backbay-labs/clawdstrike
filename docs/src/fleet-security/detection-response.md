# Detection, Hunt, and Response

This document defines the target investigation and response model for the fleet
platform.

## Objective

The platform needs to support three operator loops:

- detect suspicious behavior
- investigate what actually happened
- respond without losing execution truth

## Event Sources

The target detection plane should ingest and normalize at least these classes of
evidence:

- policy decisions and guard violations
- signed receipts and execution attestations
- endpoint and runtime liveness
- approval requests and resolutions
- host telemetry from kernel and OS bridges
- network flow telemetry
- Kubernetes audit telemetry
- inventory and posture scan results

Current anchors:

- `crates/bridges/tetragon-bridge`
- `crates/bridges/hubble-bridge`
- `crates/bridges/auditd-bridge`
- `crates/bridges/k8s-audit-bridge`
- `crates/bridges/darwin-telemetry-bridge`
- `crates/libs/hunt-query`
- `crates/libs/clawdstrike-policy-event`

## Detection Model

The initial detection model should support:

- threshold and rule-based detections
- posture drift detections
- policy bypass and disabled-control detections
- suspicious delegation-chain detections
- exfiltration and lateral movement detections
- correlation between agent actions and host/network telemetry

The current alert surface under `control-api` is useful but still narrow. It is
configuration and dispatch oriented, not yet a full detection system.

Current anchors:

- `crates/services/control-api/src/routes/alerts.rs`
- `crates/services/control-api/src/services/alerter.rs`

## Hunt Model

The hunt plane should evolve from the existing CLI into a service-backed
investigation workflow.

Core capabilities:

- structured historical search
- timeline reconstruction
- graph traversal across principals, sessions, and delegation edges
- IOC matching and watch mode
- saved hunts
- investigation cases with retained evidence

Current anchors:

- `docs/src/hunt/index.md`
- `docs/src/hunt/architecture.md`
- `crates/services/hush-cli/src/hunt.rs`
- `crates/libs/hunt-query`
- `crates/libs/hunt-correlate`

## Provenance Graph

One of the distinctive pieces of this platform should be a first-class swarm
provenance graph.

It should let operators answer:

- which agent spawned or delegated to which child
- which grants were used
- which tool call produced which downstream side effect
- which endpoint or runtime executed the action
- where the trust chain stopped being reliable

The current UI graph under `apps/control-console/src/components/advanced/ForceGraph.tsx`
is a good visualization seed, but it is event-derived and lightweight. The
target system needs a persisted graph model and query surface.

## Response Model

Response should be explicit, signed, and auditable.

Response actions should include:

- `transition_posture`
- `quarantine_principal`
- `revoke_grant`
- `revoke_enrollment`
- `request_policy_reload`
- `terminate_session`
- `kill_switch`

The endpoint side of this is already partially implemented.

Current anchors:

- `apps/agent/src-tauri/src/posture_commands.rs`
- `crates/services/hushd/src/api/mod.rs`
- `crates/services/hushd/src/api/session`

What is still missing is the cloud-side response plane that owns action intent,
authorization, publication, acknowledgement, and audit history.

## Data Retention and Evidence

Response and hunt become much more valuable when evidence is packaged and
retained consistently.

The platform should standardize:

- canonical event identity
- event-to-principal joins
- case bundles
- signed replay artifacts
- retention policy by tenant and event class

Current anchors:

- `crates/services/control-api/src/routes/compliance.rs`
- `crates/services/hushd/src/api/spine_replay.rs`

## Immediate Design Priority

The first implementation milestone should not be "build a new SIEM."

It should be:

1. normalize fleet evidence around principals, sessions, and grants
2. expose that data through a hunt and response backend
3. let operators take signed response actions against that model

For the first concrete contracts, see the
[Response Action Contract Spec](response-action-contract.md), the
[Response Execution Pipeline Spec](response-execution-pipeline.md), the
[Normalized Fleet Event Envelope Spec](normalized-fleet-event-envelope.md), the
[Hunt Backend API and Data Model Spec](hunt-backend.md), and the
[Detection and Rule Model Spec](detection-rule-model.md).
