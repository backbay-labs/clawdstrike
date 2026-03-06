# Directory and Policy Plane

This document defines the target identity and policy model for autonomous agent
fleets.

## Objective

Clawdstrike needs a directory plane that can answer four classes of question:

- Identity: what is this endpoint, runtime, agent, or subagent?
- Membership: what tenant, swarm, project, role, and capability groups does it belong to?
- Policy: what inherited policy applies right now?
- Control: can the platform revoke, quarantine, downgrade, or approve changes immediately?

## Principal Types

The directory should model more than one kind of principal.

| Principal type | Description |
|---|---|
| Tenant | Administrative boundary and billing/isolation unit |
| Swarm | A fleet segment or operational grouping |
| Project / mission | Work-scoped grouping for runs and policy |
| Endpoint agent | The installed host-side agent instance |
| Runtime agent | A runtime or worker executing actions on behalf of a session |
| Session | A time-bounded execution context |
| Delegated subagent | A child principal created through delegation |
| Operator | Human or service identity acting on the fleet |

## Core Objects

The first durable directory model should include these object families:

- `tenant`
- `swarm`
- `project`
- `capability_group`
- `agent_principal`
- `runtime_principal`
- `session`
- `delegation_edge`
- `policy_attachment`
- `grant`
- `response_action`

## Policy Inheritance

The target inheritance chain is:

```text
global
  -> tenant
    -> swarm
      -> project
        -> capability group / role
          -> principal
            -> session grant / override
```

This is the fleet-native equivalent of group policy inheritance. It should be
resolvable centrally and enforceable locally.

## Session Grants

Agents should not rely on permanently broad capability envelopes. The control
plane should issue scoped, time-bounded grants for:

- specific tools
- specific repos or path sets
- specific network destinations
- specific model or MCP surfaces
- specific production environments

The existing approval flows and multi-agent delegation tokens already point in
this direction.

Current anchors:

- `crates/services/control-api/src/routes/approvals.rs`
- `apps/agent/src-tauri/src/approval_sync.rs`
- `crates/libs/hush-multi-agent/src/token.rs`

## Lifecycle States

Directory objects should carry explicit control state beyond simple liveness.

Recommended lifecycle and posture states:

- `active`
- `stale`
- `dead`
- `restricted`
- `observe_only`
- `quarantined`
- `revoked`

The current codebase already contains part of this model:

- `active`, `stale`, `dead`, `revoked` in `control-api` agent lifecycle
- posture values such as `standard`, `restricted`, `audit`, `locked` in the desktop agent

Those need to be unified into one platform-wide control vocabulary.

## Enrollment and Join Flow

The fleet directory should treat enrollment as a join operation:

1. endpoint proves possession of a new key
2. tenant-scoped enrollment token authorizes initial registration
3. control plane creates principal and transport bindings
4. endpoint receives policy sync and command channels
5. endpoint begins attested heartbeat and runtime registration

Current anchors:

- `crates/services/control-api/src/routes/tenants.rs`
- `crates/services/control-api/src/routes/agents.rs`
- `apps/agent/src-tauri/src/enrollment.rs`

## Required Additions

The current cloud control plane still needs:

- group and project objects
- inherited policy attachments in the cloud model
- directory-backed capability groups
- explicit grant issuance and expiry
- directory-backed revocation and quarantine actions
- delegated lineage storage
- cloud-side effective-policy resolution

## Relationship to `hushd`

`hushd` already contains local policy scoping and RBAC semantics. Those should
be treated as the policy engine and local enforcement substrate, not as the
long-term replacement for the cloud directory.

Current anchors:

- `crates/services/hushd/src/api/policy_scoping.rs`
- `crates/services/hushd/src/api/rbac.rs`
- `crates/services/hushd/src/api/agent_status.rs`

The key design rule is:

**The cloud directory should decide policy inheritance; endpoints should enforce
and cache the result.**

For the concrete schema and contract set, start with:

- [Directory Object Model Spec](directory-object-model.md)
- [Effective Policy Resolution Spec](effective-policy-resolution.md)
- [Principal Lifecycle Spec](principal-lifecycle.md)
- [Directory API Contract Spec](directory-api-contract.md)
- [Enrollment and Join Protocol Spec](enrollment-join-protocol.md)
