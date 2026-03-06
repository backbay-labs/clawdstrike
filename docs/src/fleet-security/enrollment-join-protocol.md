# Enrollment and Join Protocol Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification defines how endpoints and future runtime principals join
> the fleet directory and receive their initial trust, transport, and policy
> bindings.

## 1. Objective

Clawdstrike already has a working cloud enrollment handshake for the desktop
agent. What is still missing is a broader fleet join contract that explains:

- what object is created in the directory when something joins
- which artifacts are minted and persisted during join
- how join failures roll back safely
- how runtime and delegated agents should join later without inventing a second
  identity system

This spec defines that contract.

## 2. Existing Anchors

- Agent enrollment client:
  `apps/agent/src-tauri/src/enrollment.rs`
- Cloud enrollment route:
  `crates/services/control-api/src/routes/agents.rs`
- Tenant enrollment-token issuance:
  `crates/services/control-api/src/routes/tenants.rs`
- Policy backfill and KV reconciliation:
  `crates/services/control-api/src/services/policy_distribution.rs`
- Agent-side policy sync:
  `apps/agent/src-tauri/src/policy_sync.rs`
- Agent-side trusted issuer pinning for approvals and commands:
  `apps/agent/src-tauri/src/enrollment.rs`,
  `apps/agent/src-tauri/src/posture_commands.rs`

## 3. Design Invariants

- join is the moment a durable principal enters the fleet directory
- endpoint-generated keys remain local; the control plane only receives the
  public key
- join must be tenant-scoped and replay-resistant
- enrollment-token consumption must be atomic
- transport credentials are not enough by themselves; the client must also pin
  the trusted command/approval issuer before enabling NATS
- failure after partial provisioning must roll back or leave a clear retry path

## 4. Principal Classes That Join

The fleet directory should support three join classes:

| Join class | Current status | Directory principal |
|---|---|---|
| Endpoint join | implemented baseline | `endpoint_agent` |
| Runtime join | planned | `runtime_agent` |
| Delegated join | planned | `delegated_agent` |

Phase 1 is endpoint-first. Runtime and delegated joins should be designed as
extensions of the same protocol family rather than separate systems.

## 5. Join Artifacts

Every successful join should produce or bind these artifacts:

| Artifact | Purpose | Current status |
|---|---|---|
| Enrollment token | authorize initial endpoint join | implemented |
| Local Ed25519 keypair | endpoint identity root | implemented |
| Directory principal | durable identity object | planned |
| `agent_id` | compatibility transport and status identity | implemented |
| NATS credentials | scoped fleet transport access | implemented |
| Subject prefix | tenant-scoped transport namespace | implemented |
| Trusted issuer | verify signed approvals and response commands | implemented |
| Effective policy bootstrap | initial enforcement state | implemented baseline |
| Join receipt | signed proof of join outcome | planned |

## 6. Current Endpoint Join Baseline

Today the endpoint join flow looks like this:

1. An operator creates a one-time enrollment token.
2. The agent generates a new Ed25519 keypair locally.
3. The agent sends `enrollment_token`, `public_key`, `hostname`, and `version`
   to `POST /api/v1/agents/enroll`.
4. The control API validates the token, locks the tenant row, checks the agent
   limit, inserts a new `agents` row, and atomically consumes the token.
5. After the transaction commits, the control plane provisions tenant-scoped
   NATS credentials.
6. If a tenant active policy exists, the control plane backfills the agent KV
   bucket with `policy.yaml`.
7. The agent persists enrollment state, transport bindings, the trusted issuer,
   and the private key locally.

Current request body:

```typescript
export interface EnrollRequest {
  enrollmentToken: string;
  publicKey: string;
  hostname: string;
  version: string;
}
```

Current response body:

```typescript
export interface EnrollResponse {
  agentUuid: string;
  tenantId: string;
  natsUrl: string;
  natsAccount: string;
  natsSubjectPrefix: string;
  natsToken: string;
  approvalResponseTrustedIssuer: string;
  agentId: string;
}
```

## 7. Target Endpoint Join Contract

The current response should grow into a directory-aware join response.

Recommended target shape:

```typescript
export interface EndpointJoinResponse {
  joinId: string;
  tenantId: string;
  principalId: string;
  principalType: "endpoint_agent";
  agentUuid: string;
  agentId: string;
  lifecycleState: "active" | "inactive" | "restricted" | "observe_only" | "quarantined" | "revoked";
  livenessState: "unknown" | "active" | "stale" | "dead";
  transport: {
    natsUrl: string;
    natsAccount: string;
    natsToken: string;
    subjectPrefix: string;
  };
  trust: {
    approvalResponseTrustedIssuer: string;
  };
  policyBootstrap?: {
    checksumSha256: string;
    version: number;
  };
  memberships?: {
    swarmIds: string[];
    projectIds: string[];
    capabilityGroupIds: string[];
  };
  issuedAt: string;
}
```

Compatibility rule:

- existing agents can keep consuming the current response fields
- `principal_id` and join metadata should be additive
- the stable join contract should remain compatible with local settings storage

## 8. Endpoint Join Phases

### 8.1 Pre-join

- operator creates enrollment token
- endpoint has not yet joined the tenant
- no transport channels are active

### 8.2 Key generation

- endpoint generates a new keypair locally
- previous local enrollment state is snapshotted for rollback

This already exists in `apps/agent/src-tauri/src/enrollment.rs`.

### 8.3 Control-plane transaction

Inside the control API:

- validate token and expiry
- lock token ownership row
- derive tenant context
- create compatibility `agents` row
- create or upsert endpoint `principal`
- atomically consume the one-time token

Target direction:

- the principal should become the durable identity object
- the `agents` row should remain the compatibility transport/status record

### 8.4 Transport provisioning

After the database transaction commits:

- provision NATS credentials
- assign the tenant subject prefix
- issue the trusted command/approval issuer

If transport provisioning fails, the control plane must clean up the created
join artifacts or reopen the token for retry. The existing enrollment rollback
already does this for agent creation and token consumption.

### 8.5 Policy bootstrap

If an effective policy already exists for the endpoint:

- write the compiled `policy.yaml` to the agent-scoped KV bucket
- do not wait for a later deploy event to bootstrap the agent

The join response may also include a checksum/version hint so the client can
confirm it converged to the intended policy.

### 8.6 Local commit

The endpoint should persist:

- enrolled flag
- `tenant_id`
- `agent_uuid`
- `agent_id`
- transport settings
- trusted issuer
- private key

The agent already restores previous settings if private-key persistence fails.
That rollback behavior should remain part of the join contract.

## 9. Runtime Join

Runtime principals should not reuse endpoint enrollment tokens. They should join
through a parent endpoint or session that is already trusted.

Recommended runtime join input:

```typescript
export interface RuntimeJoinRequest {
  parentPrincipalId: string;
  parentSessionId?: string;
  runtimeKind: string;
  publicKey: string;
  displayName?: string;
  metadata?: Record<string, unknown>;
}
```

Recommended runtime join output:

```typescript
export interface RuntimeJoinResponse {
  joinId: string;
  tenantId: string;
  principalId: string;
  principalType: "runtime_agent";
  lifecycleState: string;
  livenessState: string;
  trustChain: {
    parentPrincipalId: string;
    parentSessionId?: string;
  };
  transport?: {
    subjectPrefix: string;
    token: string;
  };
  issuedAt: string;
}
```

Phase 1 recommendation:

- do not block directory work on runtime join
- document runtime join now so endpoint and runtime identity stay compatible

## 10. Delegated Join

Delegated agents join through grants rather than enrollment tokens.

Required properties:

- the child principal is linked to the parent through a grant
- delegated join cannot exceed the parent capability ceiling
- the resulting principal becomes queryable in the directory and graph

This is specified further in
[Grants and Delegation Graph Contract Spec](grants-delegation-graph.md).

## 11. Rekey and Re-enrollment

The join family should eventually support:

- endpoint key rotation
- lost-device recovery
- reinstall on the same host
- rebind of an existing principal to a replacement transport identity

Recommended future routes:

```text
POST /api/v1/principals/{id}/rotate-key
POST /api/v1/principals/{id}/re-enroll
POST /api/v1/runtime-principals/join
```

Design rule:

re-enrollment should be explicit. It should not silently create duplicate
principals for the same endpoint unless the operator intended to replace the
identity.

## 12. Join Receipt

Each successful join should emit a signed receipt that captures:

- `join_id`
- `tenant_id`
- `principal_id`
- `principal_type`
- `agent_id` if present
- transport subject prefix
- trusted issuer
- policy checksum if bootstrapped
- issue time

Why this matters:

- hunt and compliance need proof of when a principal entered the fleet
- recovery flows need a durable join record
- operators need to distinguish successful join from partial provisioning

## 13. API Surface

Current:

```text
POST /api/v1/tenants/{id}/enrollment-tokens
POST /api/v1/agents/enroll
```

Recommended additions:

```text
GET  /api/v1/joins/{join_id}
POST /api/v1/runtime-principals/join
POST /api/v1/principals/{id}/rotate-key
POST /api/v1/principals/{id}/re-enroll
```

## 14. Compatibility Notes

This protocol is intentionally additive:

- current agent enrollment remains valid
- `agent_id` remains the transport compatibility identity
- the new directory principal becomes the durable control-plane identity
- policy bootstrap remains compatible with the existing `policy.yaml` KV
  contract

## 15. Implementation Notes

This spec is meant to pair with:

- [Directory Object Model Spec](directory-object-model.md)
- [Principal Lifecycle Spec](principal-lifecycle.md)
- [Effective Policy Resolution Spec](effective-policy-resolution.md)
- [Directory API Contract Spec](directory-api-contract.md)
- [Grants and Delegation Graph Contract Spec](grants-delegation-graph.md)
