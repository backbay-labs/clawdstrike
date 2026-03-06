# Directory API Contract Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification defines the first cloud API surface for the fleet
> directory.

## 1. Objective

The directory model is only useful once operators and services can query and
mutate it through a stable API. The current `control-api` already exposes
tenant, agent, approval, policy, and event routes, but it does not yet expose
fleet topology or principal state as first-class resources.

This spec defines the route surface that should be added next.

## 2. Existing Anchors

- Current route registration: `crates/services/control-api/src/routes/mod.rs`
- Tenant CRUD and enrollment-token issuance:
  `crates/services/control-api/src/routes/tenants.rs`
- Agent register, list, get, heartbeat, and enroll:
  `crates/services/control-api/src/routes/agents.rs`
- Policy deploy and active-policy read:
  `crates/services/control-api/src/routes/policies.rs`
- Approval list and resolve:
  `crates/services/control-api/src/routes/approvals.rs`
- Existing authenticated role model:
  `crates/services/control-api/src/auth/mod.rs`

## 3. Design Invariants

- every route is tenant-scoped through `AuthenticatedTenant`
- opaque IDs are canonical; slugs are convenience identifiers
- write routes are additive-first and compatibility-safe
- read routes must support both operator UI needs and automation
- principal-backed APIs should coexist with legacy `agents` routes during
  migration

## 4. Authorization Model

Current role vocabulary in the control API is effectively:

- `owner`
- `admin`
- `member`
- `viewer`

Recommended directory route policy:

| Role | Directory read | Directory mutate |
|---|---|---|
| `viewer` | yes | no |
| `member` | yes | no in Phase 1 |
| `admin` | yes | yes |
| `owner` | yes | yes |

Phase 1 recommendation:

- keep write access limited to `admin` and `owner`
- do not add new role semantics until directory resources exist

## 5. Resource Families

The first directory API should expose:

- `swarms`
- `projects`
- `capability_groups`
- `principals`
- `principal_memberships`
- `policy_attachments`
- effective policy views
- principal state views

Grants and delegation edges are important, but they can remain read-oriented in
the next wave after core directory CRUD is landed.

## 6. Swarms

### Routes

```text
POST   /api/v1/swarms
GET    /api/v1/swarms
GET    /api/v1/swarms/{id}
PATCH  /api/v1/swarms/{id}
DELETE /api/v1/swarms/{id}
```

### Request shape

```typescript
export interface CreateSwarmRequest {
  slug: string;
  name: string;
  kind: "fleet" | "cluster" | "department" | "mission" | "custom";
  status?: "active" | "inactive";
  metadata?: Record<string, unknown>;
}
```

### List filters

```text
GET /api/v1/swarms?kind=mission&status=active&q=research
```

## 7. Projects

### Routes

```text
POST   /api/v1/projects
GET    /api/v1/projects
GET    /api/v1/projects/{id}
PATCH  /api/v1/projects/{id}
DELETE /api/v1/projects/{id}
```

### Request shape

```typescript
export interface CreateProjectRequest {
  swarmId?: string;
  slug: string;
  name: string;
  environment?: "dev" | "staging" | "prod" | "custom";
  metadata?: Record<string, unknown>;
}
```

### List filters

```text
GET /api/v1/projects?swarm_id=swm_123&environment=prod&q=payments
```

## 8. Capability Groups

### Routes

```text
POST   /api/v1/capability-groups
GET    /api/v1/capability-groups
GET    /api/v1/capability-groups/{id}
PATCH  /api/v1/capability-groups/{id}
DELETE /api/v1/capability-groups/{id}
```

### Request shape

```typescript
export interface CreateCapabilityGroupRequest {
  name: string;
  description?: string;
  capabilities: Array<Record<string, unknown>>;
  metadata?: Record<string, unknown>;
}
```

The `capabilities` field should remain raw JSON-compatible with
`AgentCapability`-shaped objects in Phase 1 rather than introducing another
reference layer prematurely.

## 9. Principals

### Routes

```text
GET    /api/v1/principals
GET    /api/v1/principals/{id}
PATCH  /api/v1/principals/{id}
GET    /api/v1/principals/{id}/state
GET    /api/v1/principals/{id}/memberships
GET    /api/v1/principals/{id}/effective-policy
POST   /api/v1/principals/{id}/effective-policy/reconcile
```

### List filters

```text
GET /api/v1/principals?principal_type=endpoint_agent
GET /api/v1/principals?lifecycle_state=quarantined
GET /api/v1/principals?liveness_state=stale
GET /api/v1/principals?swarm_id=swm_123
GET /api/v1/principals?project_id=prj_123
GET /api/v1/principals?capability_group_id=cap_123
GET /api/v1/principals?q=mac-mini-42
```

### Patch shape

```typescript
export interface UpdatePrincipalRequest {
  displayName?: string;
  trustLevel?: "untrusted" | "low" | "medium" | "high" | "system";
  lifecycleState?:
    | "active"
    | "inactive"
    | "restricted"
    | "observe_only"
    | "quarantined"
    | "revoked";
  metadata?: Record<string, unknown>;
  reason?: string;
}
```

Phase 1 write rule:

- do not allow `principal_type` or `stable_ref` mutation
- treat lifecycle transitions as auditable state changes even if implemented
  through `PATCH` initially

## 10. Principal Memberships

### Routes

```text
POST   /api/v1/principal-memberships
GET    /api/v1/principal-memberships
DELETE /api/v1/principal-memberships/{id}
```

### Request shape

```typescript
export interface CreatePrincipalMembershipRequest {
  principalId: string;
  targetKind: "swarm" | "project" | "capability_group";
  targetId: string;
  role?: string;
}
```

### Filters

```text
GET /api/v1/principal-memberships?principal_id=pri_123
GET /api/v1/principal-memberships?target_kind=project&target_id=prj_123
```

## 11. Policy Attachments

### Routes

```text
POST   /api/v1/policy-attachments
GET    /api/v1/policy-attachments
GET    /api/v1/policy-attachments/{id}
PATCH  /api/v1/policy-attachments/{id}
DELETE /api/v1/policy-attachments/{id}
```

### Request shape

```typescript
export interface CreatePolicyAttachmentRequest {
  targetKind: "tenant" | "swarm" | "project" | "capability_group" | "principal";
  targetId: string;
  priority?: number;
  mergeStrategy?: "deep_merge" | "replace";
  policyRef?: string;
  policyYaml?: string;
  metadata?: Record<string, unknown>;
}
```

Validation rules:

- at least one of `policyRef` or `policyYaml` must be present
- `targetKind=tenant` uses the authenticated tenant, not an arbitrary foreign
  tenant ID
- inline YAML must parse successfully before persistence

## 12. Effective Policy Endpoints

These routes are read-oriented but operationally important.

```text
GET  /api/v1/principals/{id}/effective-policy
GET  /api/v1/agents/{id}/effective-policy
POST /api/v1/principals/{id}/effective-policy/reconcile
```

Recommended response fields:

- compiled policy YAML
- checksum
- resolution version
- source attachments
- applied overlays
- last reconcile status

## 13. State and History Endpoints

The fleet console needs a stable read model for lifecycle, liveness, posture,
and recent transitions.

```text
GET /api/v1/principals/{id}/state
GET /api/v1/principals/{id}/state-history
```

History should include:

- automatic liveness transitions
- operator lifecycle changes
- response-action-linked transitions
- reason, actor, and timestamp

## 14. Compatibility Endpoints

The current `agents` routes remain valid during migration:

```text
POST /api/v1/agents
GET  /api/v1/agents
GET  /api/v1/agents/{id}
POST /api/v1/agents/heartbeat
POST /api/v1/agents/enroll
```

Compatibility requirements:

- `GET /agents` should eventually include `principal_id`
- `GET /principals` should become the preferred fleet directory listing
- new console work should target `principals` first where possible

## 15. Error Model

The API should continue using the existing `ApiError` shape and add stable
domain-specific codes.

Recommended new codes:

| Code | Meaning |
|---|---|
| `SWARM_NOT_FOUND` | referenced swarm does not exist in tenant |
| `PROJECT_NOT_FOUND` | referenced project does not exist in tenant |
| `CAPABILITY_GROUP_NOT_FOUND` | referenced group does not exist in tenant |
| `PRINCIPAL_NOT_FOUND` | principal missing |
| `PRINCIPAL_MEMBERSHIP_CONFLICT` | duplicate membership |
| `POLICY_ATTACHMENT_INVALID` | invalid attachment payload |
| `POLICY_RESOLUTION_FAILED` | effective-policy reconcile failed |
| `DIRECTORY_ROLE_FORBIDDEN` | actor lacks mutate access |

## 16. Rollout Sequence

Recommended route order:

1. `swarms`
2. `projects`
3. `capability-groups`
4. `principals`
5. `principal-memberships`
6. `policy-attachments`
7. effective-policy and state endpoints

This keeps CRUD aligned with the schema and backfill order in the directory
implementation plan.

## 17. Implementation Notes

This spec is intended to pair with:

- [Directory Object Model Spec](directory-object-model.md)
- [Effective Policy Resolution Spec](effective-policy-resolution.md)
- [Principal Lifecycle Spec](principal-lifecycle.md)
- [Directory Implementation Plan](directory-implementation.md)
