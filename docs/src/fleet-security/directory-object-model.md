# Directory Object Model Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification defines the first durable cloud object model for Clawdstrike
> as a directory-grade control plane for autonomous agent fleets.

## 1. Objective

The existing codebase already supports enrollment, agent registration, policy
distribution, approvals, local RBAC, and delegation primitives. What is still
missing is a single cloud-backed model that represents:

- fleet structure
- principal identity
- delegated trust
- policy inheritance targets
- scoped grants

This spec defines that model.

## 2. Existing Anchors

The spec intentionally builds on current code rather than replacing it from
scratch.

- Cloud agent records: `crates/services/control-api/src/models/agent.rs`
- Cloud schema baseline: `crates/services/control-api/migrations/001_init.sql`
- Tenant enrollment and agent registration: `crates/services/control-api/src/routes/tenants.rs`, `crates/services/control-api/src/routes/agents.rs`
- Local scoped policy hierarchy: `crates/services/hushd/src/api/policy_scoping.rs`
- Local RBAC: `crates/services/hushd/src/api/rbac.rs`
- Multi-agent identities and capabilities: `crates/libs/hush-multi-agent/src/types.rs`
- Delegation tokens and revocation: `crates/libs/hush-multi-agent/src/token.rs`, `crates/libs/hush-multi-agent/src/revocation.rs`

## 3. Design Invariants

- Every directory object is scoped to exactly one tenant.
- Principal identifiers are immutable and opaque.
- Fleet structure is owned by the cloud control plane, not inferred from local telemetry alone.
- Effective policy is resolved centrally and cached locally.
- Delegation lineage is append-only; revocation is represented as separate state, not destructive mutation.
- Runtime liveness and posture are not the same as identity, but must join cleanly to identity.

## 4. Core Object Families

| Object | Purpose |
|---|---|
| `tenant` | Administrative and isolation boundary |
| `swarm` | Fleet segment or operational grouping |
| `project` | Work-scoped grouping such as environment, mission, or repo domain |
| `capability_group` | Named privilege grouping applied to principals |
| `principal` | Durable identity for endpoint, runtime, delegated agent, operator, or service |
| `principal_membership` | Membership edges from principals to swarms, projects, and capability groups |
| `session` | Time-bounded execution context |
| `grant` | Time-bounded delegated capability or approval-backed escalation |
| `delegation_edge` | Parent-child lineage between principals via grants |
| `policy_attachment` | Policy linked to a tenant, swarm, project, capability group, or principal |

## 5. Topology

```text
tenant
  -> swarm
    -> project
      -> capability_group
        -> principal
          -> session
            -> grant
              -> delegation_edge
```

Not every principal must belong to every layer, but the hierarchy gives the
control plane a consistent place to attach policy and membership.

## 6. Proposed Types

### 6.1 Principal types

```typescript
export type PrincipalType =
  | "endpoint_agent"
  | "runtime_agent"
  | "delegated_agent"
  | "operator"
  | "service_account";
```

### 6.2 Directory objects

```typescript
export interface FleetTenant {
  id: string;
  slug: string;
  name: string;
  status: "active" | "suspended" | "cancelled";
  plan: "team" | "enterprise";
}

export interface Swarm {
  id: string;
  tenantId: string;
  slug: string;
  name: string;
  kind: "fleet" | "cluster" | "department" | "mission" | "custom";
  status: "active" | "inactive";
  metadata?: Record<string, unknown>;
}

export interface Project {
  id: string;
  tenantId: string;
  swarmId?: string;
  slug: string;
  name: string;
  environment?: "dev" | "staging" | "prod" | "custom";
  metadata?: Record<string, unknown>;
}

export interface CapabilityGroup {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  capabilities: AgentCapability[];
  metadata?: Record<string, unknown>;
}

export interface Principal {
  id: string;
  tenantId: string;
  principalType: PrincipalType;
  stableRef: string;
  displayName: string;
  trustLevel: "untrusted" | "low" | "medium" | "high" | "system";
  lifecycleState:
    | "active"
    | "inactive"
    | "restricted"
    | "observe_only"
    | "quarantined"
    | "revoked";
  livenessState?: "unknown" | "active" | "stale" | "dead";
  publicKey?: string;
  metadata?: Record<string, unknown>;
}
```

Compatibility note:

- Phase 1 may still derive `stale` and `dead` from the existing `agents.status`
  field during backfill and transition work.
- The target directory API should expose lifecycle and liveness separately.
- See [Principal Lifecycle Spec](principal-lifecycle.md).

### 6.3 Membership and lineage

```typescript
export interface PrincipalMembership {
  id: string;
  tenantId: string;
  principalId: string;
  targetKind: "swarm" | "project" | "capability_group";
  targetId: string;
  role?: string;
  createdAt: string;
}

export interface Grant {
  id: string;
  tenantId: string;
  issuerPrincipalId: string;
  subjectPrincipalId: string;
  grantType: "delegation" | "approval" | "session_override";
  capabilities: AgentCapability[];
  expiresAt: string;
  status: "active" | "expired" | "revoked";
  sourceApprovalId?: string;
  sourceSessionId?: string;
  metadata?: Record<string, unknown>;
}

export interface DelegationEdge {
  id: string;
  tenantId: string;
  parentPrincipalId: string;
  childPrincipalId: string;
  grantId: string;
  tokenId?: string;
  issuedAt: string;
  expiresAt?: string;
  revokedAt?: string;
}
```

## 7. Proposed Postgres Schema

This is the first-pass schema shape. It is meant to extend the current control
API schema, not force a destructive replacement.

```sql
CREATE TABLE swarms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug)
);

CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    swarm_id UUID REFERENCES swarms(id) ON DELETE SET NULL,
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    environment TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, slug)
);

CREATE TABLE capability_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

CREATE TABLE principals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    principal_type TEXT NOT NULL,
    stable_ref TEXT NOT NULL,
    display_name TEXT NOT NULL,
    trust_level TEXT NOT NULL DEFAULT 'medium',
    lifecycle_state TEXT NOT NULL DEFAULT 'active',
    liveness_state TEXT NOT NULL DEFAULT 'unknown',
    public_key TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, principal_type, stable_ref)
);

CREATE TABLE principal_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    target_kind TEXT NOT NULL,
    target_id UUID NOT NULL,
    role TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    issuer_principal_id UUID NOT NULL REFERENCES principals(id),
    subject_principal_id UUID NOT NULL REFERENCES principals(id),
    grant_type TEXT NOT NULL,
    capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
    expires_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    source_approval_id UUID,
    source_session_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE delegation_edges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    parent_principal_id UUID NOT NULL REFERENCES principals(id),
    child_principal_id UUID NOT NULL REFERENCES principals(id),
    grant_id UUID NOT NULL REFERENCES grants(id),
    token_id TEXT,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE policy_attachments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_kind TEXT NOT NULL,
    target_id UUID NOT NULL,
    policy_ref TEXT NOT NULL,
    policy_yaml TEXT,
    merge_strategy TEXT NOT NULL DEFAULT 'merge',
    priority INTEGER NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT true,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

## 8. API Surface

The control API should add first-class routes for these objects.

```text
GET    /api/v1/swarms
POST   /api/v1/swarms
GET    /api/v1/swarms/{id}
PATCH  /api/v1/swarms/{id}

GET    /api/v1/projects
POST   /api/v1/projects
GET    /api/v1/projects/{id}
PATCH  /api/v1/projects/{id}

GET    /api/v1/capability-groups
POST   /api/v1/capability-groups
GET    /api/v1/capability-groups/{id}
PATCH  /api/v1/capability-groups/{id}

GET    /api/v1/principals
POST   /api/v1/principals
GET    /api/v1/principals/{id}
PATCH  /api/v1/principals/{id}

GET    /api/v1/principal-memberships
POST   /api/v1/principal-memberships
DELETE /api/v1/principal-memberships/{id}

GET    /api/v1/grants
POST   /api/v1/grants
GET    /api/v1/grants/{id}
POST   /api/v1/grants/{id}/revoke

GET    /api/v1/policy-attachments
POST   /api/v1/policy-attachments
PATCH  /api/v1/policy-attachments/{id}
DELETE /api/v1/policy-attachments/{id}
```

## 9. Effective Policy Resolution

The cloud control plane should resolve effective policy against this chain:

```text
tenant
  -> swarm memberships
    -> project memberships
      -> capability-group memberships
        -> principal
          -> active grants
            -> session overrides
```

The result should be published to endpoints and runtimes, but the attachment
graph itself should remain authoritative in the cloud.

## 10. Migration Strategy

The spec is designed to be adopted incrementally.

### Step 1

Keep current `tenants`, `users`, and `agents` tables. Add the new directory
tables beside them.

### Step 2

Backfill `principals` from:

- `agents` as `endpoint_agent`
- `users` as `operator`

### Step 3

Move policy deployment from tenant-only active policy to attachment-backed
effective policy resolution.

### Step 4

Join liveness, approvals, and response actions against `principals` instead of
against plain `agent_id` strings.

For execution sequencing, see the
[Directory Implementation Plan](directory-implementation.md) and
[Directory Migration Plan](directory-migrations.md).

## 11. Open Questions

- Should `runtime_agent` be a first-class `principal` or a runtime binding attached to an endpoint principal?
- Should capability groups store raw `AgentCapability` JSON or higher-level policy references?
- Should grants remain transport-shaped tokens, or also exist as first-class database records before publication?
- How much of the local `hushd` RBAC model should be copied versus adapted into the cloud directory?
