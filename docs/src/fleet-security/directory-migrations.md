# Directory Migration Plan

> **Status:** Draft | **Date:** 2026-03-06
>
> This document sequences the control-api schema changes needed to introduce the
> cloud directory model safely.

## Goal

Introduce directory-grade identity and topology into the cloud control plane
without breaking:

- current tenant creation
- current agent enrollment and registration
- current tenant-wide policy deployment
- current approval and heartbeat flows

## Migration Principles

- additive migrations first
- backfills must be idempotent
- compatibility columns stay in place until application code is fully migrated
- any new foreign key starts nullable if existing rows need backfill
- do not require runtime principals in the first schema slice

## Current Baseline

These migrations already exist:

- `001_init.sql`
- `002_adaptive_sdr_schema.sql`
- `003_adaptive_sdr_token_and_approval_flow.sql`
- `004_adaptive_sdr_active_policy.sql`
- `005_adaptive_sdr_approval_outbox.sql`

The directory plan should start at `006_...`.

## Proposed Migration Set

### Slice 1: Core directory tables

**Proposed file:** `crates/services/control-api/migrations/006_fleet_directory_core.sql`

Create:

- `swarms`
- `projects`
- `capability_groups`
- `principals`
- `principal_memberships`
- `grants`
- `delegation_edges`
- `policy_attachments`

This slice should not alter existing `agents`, `users`, or `approvals` rows yet.

### Slice 2: Principal backfill and compatibility links

**Proposed file:** `crates/services/control-api/migrations/007_fleet_directory_backfill.sql`

Add:

- nullable `principal_id UUID REFERENCES principals(id)` to `agents`

Backfill:

- `principals` from existing `agents` as `endpoint_agent`
- `principals` from existing `users` as `operator`
- `agents.principal_id` from the newly created endpoint principals
- compatibility-map `agents.status` into principal lifecycle and liveness fields

Recommended backfill shape:

```sql
ALTER TABLE agents
ADD COLUMN IF NOT EXISTS principal_id UUID REFERENCES principals(id);

INSERT INTO principals (
    tenant_id,
    principal_type,
    stable_ref,
    display_name,
    trust_level,
    lifecycle_state,
    liveness_state,
    public_key,
    metadata
)
SELECT
    a.tenant_id,
    'endpoint_agent',
    a.agent_id,
    a.name,
    a.trust_level,
    CASE a.status
        WHEN 'inactive' THEN 'inactive'
        WHEN 'revoked' THEN 'revoked'
        ELSE 'active'
    END,
    CASE a.status
        WHEN 'dead' THEN 'dead'
        WHEN 'stale' THEN 'stale'
        ELSE 'active'
    END,
    a.public_key,
    COALESCE(a.metadata, '{}'::jsonb)
FROM agents a
ON CONFLICT (tenant_id, principal_type, stable_ref) DO NOTHING;

UPDATE agents a
SET principal_id = p.id
FROM principals p
WHERE p.tenant_id = a.tenant_id
  AND p.principal_type = 'endpoint_agent'
  AND p.stable_ref = a.agent_id
  AND a.principal_id IS NULL;
```

### Slice 3: Policy attachment split, if needed

**Proposed file:** `crates/services/control-api/migrations/008_fleet_directory_policy_attachments.sql`

Only required if `policy_attachments` is not included in Slice 1.

Purpose:

- attach policy refs or inline YAML to swarm/project/capability-group/principal
- preserve `tenant_active_policies` for compatibility

### Slice 4: Principal references for fleet workflows

**Proposed file:** `crates/services/control-api/migrations/009_fleet_directory_references.sql`

Add:

- nullable `principal_id UUID REFERENCES principals(id)` to `approvals`
- optional principal references to any new response-action tables later

Backfill:

- `approvals.principal_id` via `tenant_id + agent_id -> principals`

Recommended shape:

```sql
ALTER TABLE approvals
ADD COLUMN IF NOT EXISTS principal_id UUID REFERENCES principals(id);

UPDATE approvals ap
SET principal_id = p.id
FROM principals p
WHERE p.tenant_id = ap.tenant_id
  AND p.principal_type = 'endpoint_agent'
  AND p.stable_ref = ap.agent_id
  AND ap.principal_id IS NULL;
```

### Slice 5: Constraint hardening

**Proposed file:** `crates/services/control-api/migrations/010_fleet_directory_hardening.sql`

Only after application code is migrated and backfills are proven safe.

Possible changes:

- `ALTER TABLE agents ALTER COLUMN principal_id SET NOT NULL`
- add unique indexes on memberships where needed
- add stricter check constraints for lifecycle and target kinds

## Detailed Table Notes

### `principals`

Recommended uniqueness:

```sql
UNIQUE (tenant_id, principal_type, stable_ref)
```

Rationale:

- preserves one durable directory object per known cloud identity
- allows the same `stable_ref` string to exist in different principal classes if needed

Recommended phase-1 columns:

- `lifecycle_state` for trust and control
- `liveness_state` for heartbeat-derived availability

If `liveness_state` is deferred from the first migration slice, the API should
still project it from `agents.status` as a compatibility field.

### `principal_memberships`

`target_id` is polymorphic, so strict FK enforcement cannot be done directly in
plain SQL without table split or trigger logic.

Phase 1 recommendation:

- keep `target_kind + target_id`
- enforce referential correctness in application logic and integration tests

### `policy_attachments`

Phase 1 recommendation:

- allow both `policy_ref` and `policy_yaml`
- application validation should require at least one to be present

## Application Rollout Sequence

### Step 1

Apply `006_fleet_directory_core.sql`.

No app behavior changes required.

### Step 2

Apply `007_fleet_directory_backfill.sql`.

Then update register and enrollment flows to create principals for new agents.

### Step 3

Ship directory CRUD APIs using the new tables.

### Step 4

Ship policy-attachment CRUD and effective-policy resolution.

### Step 5

Apply `009_fleet_directory_references.sql` and update approvals and heartbeat
flows to resolve principals.

### Step 6

After proving backfills and route usage in production-like environments, apply
constraint hardening.

## Rollback Strategy

Because the plan is additive-first:

- rolling back application code should still work after Slices 1-4
- new tables can remain unused temporarily without breaking current flows
- do not make `principal_id` non-null until the application no longer depends on agent-only joins

## Data Validation Queries

These should be run after Slice 2 and Slice 4.

### Agents missing principals

```sql
SELECT tenant_id, agent_id
FROM agents
WHERE principal_id IS NULL;
```

### Duplicate endpoint principals

```sql
SELECT tenant_id, stable_ref, COUNT(*)
FROM principals
WHERE principal_type = 'endpoint_agent'
GROUP BY tenant_id, stable_ref
HAVING COUNT(*) > 1;
```

### Approvals missing principal links

```sql
SELECT tenant_id, agent_id, request_id
FROM approvals
WHERE principal_id IS NULL;
```

## Open Questions

- Is a trigger-based polymorphic membership integrity check worth the complexity in Phase 1?
- Should `users` eventually gain a direct `principal_id`, or is operator backfill enough for the first implementation?
- Should runtime principals arrive before or after hunt backend normalization starts consuming principal joins?
