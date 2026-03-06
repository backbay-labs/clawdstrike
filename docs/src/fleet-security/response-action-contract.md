# Response Action Contract Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification defines the first signed, auditable response-action contract
> for fleet operations.

## 1. Objective

The endpoint side of Clawdstrike already supports posture commands and kill
switches. What is missing is a cloud-owned contract for issuing, tracking,
authorizing, delivering, and acknowledging response actions.

This spec defines that contract.

## 2. Existing Anchors

- Existing NATS command subjects: `apps/agent/src-tauri/src/nats_subjects.rs`
- Existing endpoint command handler: `apps/agent/src-tauri/src/posture_commands.rs`
- Existing approval resolution route: `crates/services/control-api/src/routes/approvals.rs`
- Existing local session termination and posture transition: `crates/services/hushd/src/api/session.rs`

## 3. Design Invariants

- Every response action has a stable `action_id`.
- Every response action is tenant-scoped and target-scoped.
- Transport payloads are signed Spine envelopes.
- Delivery is idempotent on `action_id`.
- Targets must acknowledge execution or explicit refusal.
- Response actions are queryable as first-class audit records.
- Bulk actions are materialized into per-target deliveries.

## 4. Supported Action Types

| Action type | Target kinds | Purpose |
|---|---|---|
| `transition_posture` | `endpoint`, `runtime`, `session` | Move target into a named posture state |
| `request_policy_reload` | `endpoint`, `runtime` | Reload effective policy without changing posture |
| `terminate_session` | `session` | Terminate active execution context |
| `kill_switch` | `endpoint`, `runtime`, `session` | Emergency deny-all and restart/terminate behavior |
| `quarantine_principal` | `principal`, `swarm`, `project` | Isolate target from broad capability use |
| `revoke_grant` | `grant` | Cancel delegated capability or approved exception |
| `revoke_principal` | `principal` | Disable a principal entirely |

## 5. Canonical Payload

```typescript
export type ResponseTargetKind =
  | "endpoint"
  | "runtime"
  | "session"
  | "principal"
  | "grant"
  | "swarm"
  | "project";

export interface ResponseAction {
  actionId: string;
  tenantId: string;
  actionType:
    | "transition_posture"
    | "request_policy_reload"
    | "terminate_session"
    | "kill_switch"
    | "quarantine_principal"
    | "revoke_grant"
    | "revoke_principal";
  target: {
    kind: ResponseTargetKind;
    id: string;
  };
  requestedBy: {
    actorType: "user" | "service";
    actorId: string;
  };
  requestedAt: string;
  expiresAt?: string;
  reason: string;
  caseId?: string;
  sourceDetectionId?: string;
  sourceApprovalId?: string;
  requireAcknowledgement: boolean;
  payload?: Record<string, unknown>;
}
```

### Examples

#### Transition posture

```json
{
  "actionId": "resp_01JNDQ4F8B80N0QPSW4FJQ1H18",
  "tenantId": "2f9f15f9-...",
  "actionType": "transition_posture",
  "target": { "kind": "endpoint", "id": "agent-2f6dbe4b-..." },
  "requestedBy": { "actorType": "user", "actorId": "user:okta:alice" },
  "requestedAt": "2026-03-06T15:04:05Z",
  "reason": "Escalating suspicious egress",
  "requireAcknowledgement": true,
  "payload": {
    "toState": "restricted",
    "trigger": "soc_response"
  }
}
```

#### Kill switch

```json
{
  "actionId": "resp_01JNDQ6W1C5Y7G2KQF4R8Z2W14",
  "tenantId": "2f9f15f9-...",
  "actionType": "kill_switch",
  "target": { "kind": "endpoint", "id": "agent-2f6dbe4b-..." },
  "requestedBy": { "actorType": "service", "actorId": "svc:detection-engine" },
  "requestedAt": "2026-03-06T15:05:12Z",
  "reason": "Confirmed malicious delegation chain",
  "sourceDetectionId": "det_01JNDQ6F7P6D3E4N2B8Q6Y9H7C",
  "requireAcknowledgement": true,
  "payload": {
    "reason": "confirmed_malicious_delegation"
  }
}
```

## 6. Transport Contract

### 6.1 Subject model

Current endpoint behavior subscribes to:

```text
{subject_prefix}.posture.command.{agent_id}
```

The generalized response contract should introduce:

```text
{subject_prefix}.response.command.{target_kind}.{target_id}
{subject_prefix}.response.ack.{target_kind}.{target_id}
```

Compatibility rule:

- `transition_posture`, `kill_switch`, and `request_policy_reload` may continue to
  be mirrored to legacy `posture.command` subjects during migration.

### 6.2 Signed envelope

All published commands must be wrapped in a signed Spine envelope. The `fact`
payload is the `ResponseAction` JSON object.

## 7. Acknowledgement Contract

Targets must return an acknowledgement envelope with this payload:

```typescript
export interface ResponseActionAck {
  actionId: string;
  tenantId: string;
  target: {
    kind: ResponseTargetKind;
    id: string;
  };
  status: "acknowledged" | "rejected" | "failed" | "expired";
  observedAt: string;
  message?: string;
  resultingState?: string;
}
```

## 8. Delivery Lifecycle

| State | Meaning |
|---|---|
| `queued` | Created but not yet authorized for publication |
| `approved` | Authorized to publish |
| `published` | Sent to transport |
| `acknowledged` | Target confirmed execution |
| `rejected` | Target refused due to validation or local policy |
| `failed` | Delivery or execution failed |
| `expired` | Action expired before successful acknowledgement |
| `cancelled` | Operator cancelled outstanding action |

## 9. Proposed Database Schema

```sql
CREATE TABLE response_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    action_type TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    requested_by_type TEXT NOT NULL,
    requested_by_id TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    reason TEXT NOT NULL,
    case_id TEXT,
    source_detection_id TEXT,
    source_approval_id UUID,
    require_acknowledgement BOOLEAN NOT NULL DEFAULT true,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL DEFAULT 'queued',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE response_action_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id UUID NOT NULL REFERENCES response_actions(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    delivery_subject TEXT NOT NULL,
    published_at TIMESTAMPTZ,
    acknowledged_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'queued',
    last_error TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE response_action_acks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id UUID NOT NULL REFERENCES response_actions(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL,
    message TEXT,
    resulting_state TEXT,
    raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb
);
```

## 10. HTTP API

```text
POST   /api/v1/response-actions
GET    /api/v1/response-actions
GET    /api/v1/response-actions/{id}
POST   /api/v1/response-actions/{id}/cancel
POST   /api/v1/response-actions/{id}/retry
POST   /api/v1/response-actions/{id}/approve
```

### Create action request

```typescript
export interface CreateResponseActionRequest {
  actionType: ResponseAction["actionType"];
  target: ResponseAction["target"];
  reason: string;
  expiresAt?: string;
  caseId?: string;
  sourceDetectionId?: string;
  sourceApprovalId?: string;
  payload?: Record<string, unknown>;
}
```

## 11. Authorization Rules

- `kill_switch`, `revoke_principal`, and `quarantine_principal` require admin-grade permission.
- `transition_posture` and `request_policy_reload` may be allowed to operators with scoped fleet-response rights.
- Actions referencing an approval or detection should preserve that provenance.
- Service-driven actions must identify the initiating service principal explicitly.

## 12. Mapping to Existing Commands

| Existing endpoint command | Canonical response action |
|---|---|
| `set_posture` | `transition_posture` |
| `kill_switch` | `kill_switch` |
| `request_policy_reload` | `request_policy_reload` |

The existing endpoint implementation can remain as the local executor while the
cloud response plane matures around it.

For the end-to-end execution flow built on top of this contract, see the
[Response Execution Pipeline Spec](response-execution-pipeline.md).

## 13. Open Questions

- Should `terminate_session` execute through the endpoint agent, through `hushd`, or both?
- Should a `quarantine_principal` action always materialize to a posture transition, or can it also revoke active grants automatically?
- Do bulk actions need a separate batch object, or are they always decomposed immediately into per-target actions?
