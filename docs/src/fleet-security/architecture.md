# Target Architecture

This document describes the target architecture for Clawdstrike as the security
control plane for autonomous agent fleets.

## System Overview

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Fleet Control Plane                                 │
│                                                                             │
│  ┌─────────────────────┐   ┌──────────────────────┐   ┌──────────────────┐  │
│  │ Directory and Trust │   │ Policy and Grants    │   │ Response Plane   │  │
│  │ - tenants           │   │ - inheritance        │   │ - quarantine     │  │
│  │ - swarms            │   │ - capability groups  │   │ - revoke         │  │
│  │ - projects          │   │ - session grants     │   │ - posture change │  │
│  │ - agents/runtimes   │   │ - posture budgets    │   │ - kill switch    │  │
│  │ - delegation graph  │   │ - approvals          │   │ - runbooks       │  │
│  └──────────┬──────────┘   └──────────┬───────────┘   └─────────┬────────┘  │
│             │                         │                         │           │
│             └──────────────┬──────────┴──────────┬──────────────┘           │
│                            │                     │                          │
│                   ┌────────v─────────────────────v────────┐                 │
│                   │        Event and Evidence Plane        │                 │
│                   │ - signed envelopes                     │                 │
│                   │ - receipts                             │                 │
│                   │ - heartbeat and liveness               │                 │
│                   │ - audit and telemetry facts            │                 │
│                   │ - evidence exports                     │                 │
│                   └────────┬─────────────────────┬────────┘                 │
│                            │                     │                          │
│                   ┌────────v─────────┐  ┌────────v─────────┐                │
│                   │ Hunt Plane       │  │ Detection Plane  │                │
│                   │ - query          │  │ - rules          │                │
│                   │ - timeline       │  │ - baselines      │                │
│                   │ - graph walk     │  │ - suppression    │                │
│                   │ - IOC match      │  │ - escalation     │                │
│                   │ - case context   │  │ - case creation  │                │
│                   └──────────────────┘  └──────────────────┘                │
└─────────────────────────────────────────────────────────────────────────────┘
                 ▲                           ▲                           ▲
                 │                           │                           │
┌────────────────┴──────────────┐  ┌─────────┴─────────┐  ┌─────────────┴────┐
│ Desktop / Endpoint Agents     │  │ Telemetry Bridges │  │ Operator Console  │
│ - hushd                       │  │ - tetragon        │  │ - fleet view      │
│ - local API/UI                │  │ - hubble          │  │ - directory       │
│ - policy enforcement          │  │ - auditd          │  │ - hunts           │
│ - approvals                   │  │ - k8s audit       │  │ - detections      │
│ - posture transitions         │  │ - darwin          │  │ - response        │
└───────────────────────────────┘  └───────────────────┘  └──────────────────┘
```

## Core Planes

### Directory and trust plane

This plane owns durable identity and topology:

- Who an endpoint, runtime, agent, or subagent is
- Which tenant, swarm, project, or mission it belongs to
- What delegation chain produced it
- Which trust anchors and enrollment claims are valid

This is the part that turns the platform into more than telemetry plumbing.

### Policy and grants plane

This plane decides what applies to a principal at a moment in time:

- Inherited fleet policy
- Role or capability-group policy
- Session-scoped grants
- Approval-gated escalations
- Posture transitions

The policy engine already exists. The missing piece is a fleet-wide source of
truth for inheritance and grant issuance.

### Event and evidence plane

This plane is the connective tissue between enforcement and investigation:

- Signed envelopes
- Receipts
- Heartbeats and liveness
- Telemetry facts from bridges and runtimes
- Compliance and evidence export

Without this plane, hunt and response collapse into untrusted logging.

### Hunt plane

This plane provides the operator workflows for investigation:

- Search historical events
- Reconstruct timelines
- Traverse delegation and spawn edges
- Correlate agent actions with host and network telemetry
- Build cases and evidence bundles

The CLI hunt stack is the seed of this plane, not the final shape.

### Response plane

This plane lets operators act on the fleet:

- Quarantine one runtime or a full swarm segment
- Downgrade to observe-only or restricted posture
- Revoke grants or enrollment state
- Force policy reload
- Kill a live session

The platform should treat response as signed, auditable state change rather than
as an ad hoc control message.

## Control Flow

### 1. Enrollment

1. An endpoint agent generates a keypair and requests enrollment.
2. The control plane binds that endpoint to a tenant and directory object.
3. The control plane issues transport credentials and trust anchors.
4. The endpoint begins policy sync, heartbeat, and signed approval flows.

Current anchors:

- `apps/agent/src-tauri/src/enrollment.rs`
- `crates/services/control-api/src/routes/agents.rs`
- `crates/services/control-api/src/routes/tenants.rs`

### 2. Policy distribution

1. Directory membership and posture resolve to an effective policy set.
2. Tenant, swarm, group, role, and session overlays are merged.
3. Effective policy is published to the endpoint/runtime.
4. Endpoints enforce policy locally and emit evidence for decisions.

Current anchors:

- `crates/services/control-api/src/routes/policies.rs`
- `apps/agent/src-tauri/src/policy_sync.rs`
- `crates/services/hushd/src/api/policy_scoping.rs`

### 3. Detection and investigation

1. Agent actions and host telemetry become signed facts and receipts.
2. Detections and hunts operate on normalized event data.
3. Investigations pivot across policy events, host telemetry, and delegation lineage.
4. Cases produce auditable evidence bundles.

Current anchors:

- `crates/libs/hunt-query`
- `crates/libs/hunt-correlate`
- `crates/services/hush-cli/src/hunt.rs`
- `crates/bridges/*`

### 4. Response

1. An operator or automation issues a signed response action.
2. The control plane records the action and publishes it to target agents/runtimes.
3. Endpoints verify, apply, and confirm the action.
4. The action and its downstream effects become part of the evidence graph.

Current anchors:

- `apps/agent/src-tauri/src/posture_commands.rs`
- `apps/agent/src-tauri/src/approval_sync.rs`
- `crates/services/control-api/src/routes/approvals.rs`

## Source-of-Truth Boundaries

The architecture should converge on these boundaries:

| Concern | Target source of truth |
|---|---|
| Fleet identity and topology | Cloud directory/control plane |
| Effective endpoint policy | Cloud directory plus endpoint cache |
| Immediate enforcement | Local agent and `hushd` |
| Host and network telemetry | Bridge pipelines and signed envelope streams |
| Investigation state | Fleet hunt and case backend |
| Response actions | Cloud response plane with endpoint acknowledgements |

## Design Constraints

- Fail closed when trust or policy state is missing
- Treat response actions as signed and auditable
- Preserve offline and degraded-mode operation on endpoints
- Keep local enforcement viable even if the cloud plane is unavailable
- Avoid splitting identity semantics across incompatible local and cloud models
