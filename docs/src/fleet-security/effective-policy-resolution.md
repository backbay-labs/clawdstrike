# Effective Policy Resolution Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification defines how the cloud directory resolves inherited policy
> into one effective policy bundle for a principal or agent.

## 1. Objective

Clawdstrike already has two important policy building blocks:

- cloud-side tenant active policy deploy in `crates/services/control-api/src/routes/policies.rs`
- local scoped policy and assignment semantics in `crates/services/hushd/src/api/policy_scoping.rs`

What is still missing is the fleet contract that connects them:

- which directory attachments participate in resolution
- in what order they apply
- how ties and conflicts are resolved
- what exact artifact is distributed to an agent
- how invalidation and fallback behave

This spec defines that contract.

## 2. Existing Anchors

- Cloud active-policy persistence and fanout:
  `crates/services/control-api/src/services/policy_distribution.rs`
- Tenant policy deploy routes:
  `crates/services/control-api/src/routes/policies.rs`
- Enrollment and heartbeat reconciliation:
  `crates/services/control-api/src/routes/agents.rs`,
  `crates/services/control-api/src/services/agent_heartbeat_consumer.rs`
- Local scoped policies, assignments, priority, and merge strategy:
  `crates/services/hushd/src/api/policy_scoping.rs`
- Agent KV watcher:
  `apps/agent/src-tauri/src/policy_sync.rs`

## 3. Design Invariants

- Effective policy is resolved centrally in the cloud.
- Endpoints enforce the resolved result and cache it locally.
- Resolution is deterministic for the same directory graph and attachment set.
- Resolution must stay compatible with the current `tenant_active_policies`
  table and `policy.yaml` agent KV contract during migration.
- Restrictive operator actions win over permissive inherited policy.
- Invalid policy artifacts must not silently widen access.

## 4. Resolution Inputs

The resolver operates over these inputs:

| Input | Source | Phase 1 status |
|---|---|---|
| Tenant base policy | `tenant_active_policies` or tenant attachment | required |
| Swarm attachments | `policy_attachments` | planned |
| Project attachments | `policy_attachments` | planned |
| Capability-group attachments | `policy_attachments` | planned |
| Principal attachments | `policy_attachments` | planned |
| Session or grant overrides | `grants` / approval flow | deferred to later phase |
| Response-imposed restriction overlays | lifecycle and response actions | required |

Phase 1 recommendation:

- resolve for endpoint principals first
- use `agents.principal_id` as the compatibility join
- continue publishing a single compiled YAML file to the per-agent KV bucket

## 5. Resolution Targets

The resolver must support these lookup forms:

```text
tenant + principal_id
tenant + agent_id
tenant + stable_ref
```

Canonical resolution target:

- `tenant_id`
- `principal_id`
- optional `agent_id`
- optional `session_id`

If only `agent_id` is provided, the cloud should resolve `agent_id ->
principal_id` first and continue from the principal.

## 6. Canonical Output

```typescript
export interface EffectivePolicyBundle {
  tenantId: string;
  principalId: string;
  agentId?: string;
  lifecycleState: string;
  livenessState?: string;
  compiledPolicyYaml: string;
  compiledPolicySha256: string;
  resolutionVersion: number;
  resolvedAt: string;
  sourceAttachments: Array<{
    attachmentId: string;
    targetKind: "tenant" | "swarm" | "project" | "capability_group" | "principal";
    targetId: string;
    priority: number;
    policyRef?: string;
    checksumSha256?: string;
  }>;
  appliedOverlays: string[];
}
```

Phase 1 distribution compatibility:

- publish `compiledPolicyYaml` to the existing agent-scoped KV key
  `policy.yaml`
- optionally publish metadata to a second key such as `policy-meta.json`
- keep the legacy tenant policy update subject as a best-effort compatibility
  signal

## 7. Resolution Order

The effective policy must be built in this order:

1. tenant base policy
2. swarm attachments
3. project attachments
4. capability-group attachments
5. principal attachments
6. active session or grant overrides
7. lifecycle and response restriction overlay

Within each layer:

1. sort by `priority ASC`
2. then `created_at ASC`
3. then stable `id ASC`
4. apply in order, where later artifacts override earlier artifacts

Rationale:

- higher priority wins because it is applied later
- stable tie-breaking makes hashes reproducible
- later, narrower scopes beat earlier, broader scopes

## 8. Membership Selection Rules

The resolver includes only memberships that are active at resolution time.

Phase 1 rules:

- include every direct swarm membership for the principal
- include every direct project membership for the principal
- include every direct capability-group membership for the principal
- do not infer membership from telemetry alone
- do not yet expand transitive capability-group nesting

If a principal is in multiple swarms or projects, all matching attachments
participate. Conflict resolution is handled by the ordered merge contract rather
than by forcing single membership.

## 9. Merge Semantics

Phase 1 merge behavior should stay intentionally strict:

- parse YAML into a normalized JSON representation first
- objects merge deeply by key
- scalars replace previous scalar values
- arrays replace previous arrays in full
- `null` removes the inherited value at that path

Why arrays replace instead of append:

- it avoids ambiguous allowlist expansion
- it keeps results deterministic and easy to diff
- it forces higher-precedence policy authors to declare the final intended list

If more specialized list-merge behavior is needed later, it should be added as
an explicit policy feature rather than implicit resolver magic.

## 10. Restriction Overlay Contract

Lifecycle and response state must be able to force a restrictive overlay even
if the inherited policy would otherwise be broader.

Required overlay mappings:

| State | Overlay effect |
|---|---|
| `active` | no extra restriction |
| `restricted` | apply restricted policy overlay |
| `observe_only` | deny mutating actions, preserve telemetry |
| `quarantined` | deny tool egress except fleet-control channels |
| `revoked` | deny all action execution and session starts |

These overlays should be stored as named policy fragments and applied last.

The overlay name should also be reported in `appliedOverlays` so operators can
see why the compiled policy became more restrictive.

## 11. Invalidation Rules

The resolver must invalidate a principal's compiled policy when any of these
change:

- a relevant `policy_attachment`
- principal memberships
- principal lifecycle state
- principal liveness state if liveness participates in overlay selection
- grant or session override state
- tenant active base policy

Phase 1 implementation recommendation:

- enqueue principal or agent reconciliation jobs
- debounce repeated invalidations for the same principal
- publish only when the compiled policy checksum actually changes

## 12. Failure and Fallback

If resolution fails:

- do not delete the last known good policy from agent KV
- mark the resolution attempt as failed in cloud audit state
- expose the failure on an operator-visible endpoint
- keep the endpoint on its last known compiled policy until a valid replacement
  is available

This matches the existing agent-side fail-closed behavior in
`apps/agent/src-tauri/src/policy_sync.rs`, which retains the last local policy
when KV entries are deleted.

## 13. API Surface

Recommended endpoints:

```text
GET /api/v1/principals/{id}/effective-policy
GET /api/v1/agents/{id}/effective-policy
POST /api/v1/principals/{id}/effective-policy/reconcile
GET /api/v1/effective-policies/{principal_id}/history
```

Recommended response shape:

```typescript
export interface EffectivePolicyResponse extends EffectivePolicyBundle {
  sourceAttachmentsDetailed: Array<{
    attachmentId: string;
    targetKind: string;
    targetId: string;
    priority: number;
    mergeStrategy: "deep_merge" | "replace";
    applied: boolean;
    error?: string;
  }>;
}
```

## 14. Compatibility With Current Deploy Flow

During migration:

- `POST /api/v1/policies/deploy` continues to set the tenant base policy
- the current per-agent KV write path remains valid
- enrollment and heartbeat reconciliation continue using the same bucket and key
- effective-policy resolution is inserted behind those flows rather than
  replacing them abruptly

In practical terms, the resolver becomes the new producer for `policy.yaml`,
while the transport contract stays stable for the endpoint.

## 15. Implementation Notes

This spec is meant to pair with:

- [Directory Object Model Spec](directory-object-model.md)
- [Principal Lifecycle Spec](principal-lifecycle.md)
- [Directory API Contract Spec](directory-api-contract.md)
- [Directory Implementation Plan](directory-implementation.md)

Milestone alignment:

- Milestone 3 exposes the read endpoints
- Milestone 4 implements resolution, invalidation, and compatibility fanout
