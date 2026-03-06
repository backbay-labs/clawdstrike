# Response Execution Pipeline Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification defines the end-to-end pipeline that turns a response
> action into an executed, acknowledged, and auditable fleet operation.

## 1. Objective

The response-action contract defines what a response action is. This spec
defines how it flows through the platform:

- how targets are resolved
- how commands are published
- how endpoints execute them
- how acknowledgements and retries work
- how resulting state changes feed policy, hunt, and operator views

## 2. Existing Anchors

- Response action contract:
  `docs/src/fleet-security/response-action-contract.md`
- Current endpoint posture command subscriber:
  `apps/agent/src-tauri/src/posture_commands.rs`
- Current NATS subject helpers:
  `apps/agent/src-tauri/src/nats_subjects.rs`
- Current local session termination and posture APIs:
  `crates/services/hushd/src/api/session.rs`
- Current cloud SSE stream:
  `crates/services/control-api/src/routes/events.rs`

## 3. Design Invariants

- the durable response-action row exists before transport publication
- bulk actions are expanded into explicit per-target deliveries
- execution is idempotent on `action_id`
- command verification is mandatory before local execution
- acknowledgements are explicit facts, not inferred side effects
- state projection happens after execution facts arrive, not before
- failed delivery and failed execution are different states

## 4. Pipeline Stages

The response pipeline should be implemented as seven stages:

1. action creation
2. authorization and approval
3. target resolution and expansion
4. delivery planning
5. command publication
6. local execution and acknowledgement
7. state projection and evidence emission

## 5. Stage 1: Action Creation

An operator or service creates a `response_action`.

Examples:

- quarantine one principal
- reload policy on all endpoints in a project
- revoke a grant and all of its descendants
- terminate one active session

At this stage the platform should:

- validate the request payload
- persist the action row
- attach source detection, case, approval, or policy references
- assign an initial status of `queued`

No transport publication should happen before the action record exists.

## 6. Stage 2: Authorization and Approval

The pipeline should then decide whether the action may execute immediately or
must wait for explicit approval.

Recommended rules:

- `kill_switch`, `revoke_principal`, and `quarantine_principal` require
  admin-grade rights
- service-originated actions must identify the initiating service principal
- actions tied to detections retain the source detection ID
- high-risk bulk actions may require a second approval gate

This stage results in:

- `approved`
- `cancelled`
- or still `queued` pending approval

## 7. Stage 3: Target Resolution and Expansion

Not every response action targets a single endpoint.

Target expansion rules:

| Target kind | Resolution result |
|---|---|
| `endpoint` | one endpoint delivery |
| `session` | one local session termination or posture transition |
| `principal` | one or more endpoint/runtime deliveries depending on bindings |
| `grant` | one grant state change plus optional descendant revocation set |
| `swarm` | expand to principals/endpoints in swarm |
| `project` | expand to principals/endpoints in project |

The expansion step should produce a stable execution plan:

```typescript
export interface ResponseExecutionPlan {
  actionId: string;
  generatedAt: string;
  deliveries: Array<{
    deliveryId: string;
    targetKind: string;
    targetId: string;
    principalId?: string;
    endpointAgentId?: string;
    runtimeAgentId?: string;
    sessionId?: string;
    transportSubject?: string;
    localExecutor?: "endpoint_agent" | "hushd_api" | "cloud_only";
  }>;
}
```

## 8. Stage 4: Delivery Planning

Each expanded target should become a delivery record before publication.

Required properties per delivery:

- delivery subject or executor path
- current status
- attempt count
- publication timestamp
- acknowledgement deadline if required
- last error if any

This is where the pipeline decides whether the action is executed via:

- NATS command publication to an endpoint or runtime
- a local `hushd` session API call
- a cloud-only state transition such as grant revocation

## 9. Stage 5: Command Publication

The publisher should wrap the action payload in a signed envelope and publish to
the planned transport subject.

Recommended publication paths:

| Action type | Current executor | Target publication path |
|---|---|---|
| `transition_posture` | endpoint agent / hushd | response subject, mirrored to legacy posture subject during migration |
| `request_policy_reload` | endpoint agent | response subject, mirrored to legacy posture subject during migration |
| `kill_switch` | endpoint agent | response subject, mirrored to legacy posture subject during migration |
| `terminate_session` | hushd or endpoint-local API | direct local executor or endpoint relay |
| `revoke_grant` | cloud + runtime consumers | cloud state change plus revocation publication |
| `quarantine_principal` | cloud + endpoint | lifecycle change plus restrictive overlay publication |

Publication result:

- mark delivery `published`
- record the publication time
- emit a `response_action_published` fleet event

## 10. Stage 6: Local Execution and Acknowledgement

The local executor must:

1. verify the signed envelope
2. reject unknown or expired actions
3. enforce idempotency by `action_id`
4. execute the local change
5. send an acknowledgement fact

Acknowledgement payload follows the response-action contract, but the pipeline
should also persist execution metadata:

- executor version
- resulting lifecycle or posture state
- local error if execution failed
- observed timestamp

## 11. Stage 7: State Projection and Evidence Emission

After acknowledgement or cloud-only execution completes, the pipeline should
project the result into the rest of the fleet plane.

Required downstream updates:

- principal lifecycle changes
- effective-policy invalidation and reconcile
- session state updates
- grant revocation propagation
- normalized fleet event emission
- console stream updates

Design rule:

response action acknowledgement is not the end. It is the trigger for state
projection and evidence generation.

## 12. Retry and Timeout Behavior

Retries should be delivery-scoped, not action-scoped.

Recommended behavior:

- retry transport publish failures with bounded backoff
- do not retry explicit target rejections automatically
- mark delivery `expired` if acknowledgement deadline passes
- allow operator-driven manual retry from the action detail view

If a target is `dead` or offline:

- keep the action and delivery visible
- mark it as unacknowledged or expired
- do not silently treat no response as success

## 13. Failure Modes

The pipeline should distinguish these failures:

| Failure class | Meaning |
|---|---|
| validation failure | request invalid before execution plan exists |
| authorization failure | actor not allowed to execute |
| target resolution failure | no valid targets or mixed invalid target set |
| publication failure | command never reached transport |
| execution failure | target received command but could not execute |
| acknowledgement timeout | target may be offline or non-responsive |
| projection failure | action executed but cloud-side state update failed |

This separation is required for operator trust and reliable retries.

## 14. Audit and Event Outputs

Each major stage should emit a normalized fleet event:

- `response_action_created`
- `response_action_approved`
- `response_action_published`
- `response_action_acknowledged`
- `response_action_failed`
- `response_action_expired`
- `response_action_projected`

Those facts should feed:

- hunt timeline
- fleet console stream
- OCSF export where applicable
- response detail views

## 15. Current Compatibility Path

The existing endpoint command path can serve as the first executor.

Today that means:

- `transition_posture`, `kill_switch`, and `request_policy_reload` are executed
  by the desktop agent command subscriber
- session termination and session posture changes already exist in `hushd`
- the cloud still needs the orchestration, delivery ledger, and acknowledgement
  ingestion layers

This is enough to stage the pipeline incrementally rather than waiting for a
full rewrite.

## 16. Implementation Notes

This spec is meant to pair with:

- [Response Action Contract Spec](response-action-contract.md)
- [Principal Lifecycle Spec](principal-lifecycle.md)
- [Effective Policy Resolution Spec](effective-policy-resolution.md)
- [Normalized Fleet Event Envelope Spec](normalized-fleet-event-envelope.md)
- [Fleet Console Read Model Spec](fleet-console-read-model.md)
