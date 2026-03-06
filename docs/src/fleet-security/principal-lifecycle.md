# Principal Lifecycle Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification defines the canonical lifecycle, liveness, and posture
> vocabulary for principals in the fleet directory.

## 1. Objective

Clawdstrike currently uses more than one control vocabulary:

- cloud `agents.status` values such as `active`, `stale`, `dead`, and `revoked`
- desktop posture commands using `standard`, `restricted`, `audit`, and `locked`
- session posture state in `hushd` using values such as `work` and `observe`

That is enough to build features, but not enough to run a coherent fleet
control plane. This spec separates what each state family means and defines how
they map to each other.

## 2. Existing Anchors

- Cloud agent model: `crates/services/control-api/src/models/agent.rs`
- Stale and dead heartbeat transitions:
  `crates/services/control-api/src/services/stale_agent_detector.rs`
- Remote posture commands:
  `apps/agent/src-tauri/src/posture_commands.rs`
- Local agent/runtime posture reporting:
  `crates/services/hushd/src/api/agent_status.rs`
- Session posture runtime state:
  `crates/services/hushd/src/session/mod.rs`,
  `crates/services/hushd/src/api/check.rs`

## 3. State Families

The platform should expose three distinct state families.

### 3.1 Directory lifecycle state

This is the operator-controlled trust and control state of a principal.

```typescript
export type PrincipalLifecycleState =
  | "active"
  | "inactive"
  | "restricted"
  | "observe_only"
  | "quarantined"
  | "revoked";
```

### 3.2 Liveness state

This is the heartbeat-derived presence state of an endpoint or runtime.

```typescript
export type PrincipalLivenessState =
  | "unknown"
  | "active"
  | "stale"
  | "dead";
```

### 3.3 Posture state

This is the local enforcement posture currently applied by the endpoint or
session runtime.

```typescript
export type EndpointPostureState =
  | "standard"
  | "restricted"
  | "audit"
  | "locked";

export type SessionPostureState =
  | "work"
  | "observe"
  | "locked";
```

## 4. Canonical Meanings

| State family | State | Meaning |
|---|---|---|
| lifecycle | `active` | principal is allowed to operate normally |
| lifecycle | `inactive` | principal is known but intentionally not in service |
| lifecycle | `restricted` | principal is allowed to operate under narrowed policy |
| lifecycle | `observe_only` | principal may observe and emit receipts but not mutate |
| lifecycle | `quarantined` | principal is isolated to fleet-control and evidence paths |
| lifecycle | `revoked` | principal is disabled and may not start or continue work |
| liveness | `active` | heartbeat is fresh |
| liveness | `stale` | heartbeat window exceeded but not yet dead |
| liveness | `dead` | heartbeat window exceeded past dead threshold |
| posture | `standard` / `work` | normal allowed execution mode |
| posture | `restricted` | reduced policy envelope |
| posture | `audit` / `observe` | monitor and report, deny mutating actions |
| posture | `locked` | deny-all / kill-switch posture |

## 5. Why Lifecycle and Liveness Must Split

`stale` and `dead` are not trust decisions. They are observations about recent
heartbeat activity. `quarantined` and `revoked` are operator or system control
decisions. They should not compete for the same field long term.

Target model:

- `principals.lifecycle_state` stores trust/control state
- `principals.liveness_state` stores heartbeat-derived availability

Compatibility note:

The first migration slices may continue to project `stale` and `dead` through a
single compatibility field because the existing `agents.status` column already
uses that shape. The public API should still start exposing both concepts
separately as soon as possible.

## 6. Mapping Rules

### 6.1 Lifecycle to endpoint posture

| Lifecycle state | Default endpoint posture | Notes |
|---|---|---|
| `active` | `standard` | normal enforcement |
| `inactive` | `standard` | no automatic restriction, but new work may be withheld |
| `restricted` | `restricted` | narrower policy overlay |
| `observe_only` | `audit` | no mutating actions |
| `quarantined` | `locked` | fleet-control traffic only |
| `revoked` | `locked` | transport and grant revocation should also occur |

### 6.2 Lifecycle to session posture

| Lifecycle state | Default session posture |
|---|---|
| `active` | `work` |
| `inactive` | `work` |
| `restricted` | `work` with restricted effective policy |
| `observe_only` | `observe` |
| `quarantined` | `locked` |
| `revoked` | `locked` |

### 6.3 Liveness interaction

Liveness does not directly change lifecycle state. Instead:

- `stale` raises operator visibility and can trigger hunt/detection rules
- `dead` prevents delivery acknowledgement and may block new session issuance
- response actions targeting a dead principal remain auditable but may expire

## 7. Allowed Transitions

Recommended lifecycle transitions:

| From | To | Trigger |
|---|---|---|
| `active` | `restricted` | operator action, policy automation |
| `active` | `observe_only` | operator action, detection automation |
| `active` | `quarantined` | operator action, confirmed compromise |
| `active` | `revoked` | operator action, trust revocation |
| `inactive` | `active` | operator restore |
| `restricted` | `active` | operator restore |
| `restricted` | `observe_only` | escalation |
| `restricted` | `quarantined` | escalation |
| `observe_only` | `restricted` | operator restore |
| `observe_only` | `active` | operator restore |
| `observe_only` | `quarantined` | escalation |
| `quarantined` | `restricted` | operator restore |
| `quarantined` | `active` | operator restore after validation |
| any non-revoked | `revoked` | explicit revocation |

Disallowed without explicit re-enrollment or restore workflow:

- `revoked -> active`
- `revoked -> restricted`
- `revoked -> observe_only`

## 8. Heartbeat-Driven Liveness Transitions

The cloud should continue to derive liveness from heartbeat age.

Current baseline in `stale_agent_detector.rs`:

- `active -> stale` after stale threshold
- `stale -> dead` after dead threshold
- heartbeat recovery moves the cloud agent back to `active`

Target rule:

- liveness transitions remain automatic
- lifecycle transitions remain explicit
- API responses should expose both fields together

## 9. Response Action Effects

The response plane should map actions onto lifecycle and posture consistently.

| Response action | Lifecycle result | Posture result |
|---|---|---|
| `transition_posture` | no lifecycle change by itself | direct posture change |
| `quarantine_principal` | `quarantined` | `locked` |
| `revoke_principal` | `revoked` | `locked` |
| `kill_switch` | no required lifecycle change, but commonly paired with `quarantined` | `locked` |
| `terminate_session` | no principal lifecycle change | terminate active session |
| `revoke_grant` | no lifecycle change | narrows effective policy and authority |

Design rule:

`transition_posture` is temporary local control. `quarantine_principal` and
`revoke_principal` are durable directory state transitions.

## 10. Effective-Policy Interaction

Lifecycle state must feed the effective-policy resolver.

Required effects:

- `restricted` applies a restrictive overlay
- `observe_only` applies an observe-only overlay
- `quarantined` applies a quarantine overlay
- `revoked` results in deny-all effective policy and revoked grants

Liveness state should not rewrite policy by default. It is an investigation
signal first, not a permission source.

## 11. Suggested API Shape

```typescript
export interface PrincipalStateView {
  principalId: string;
  lifecycleState: PrincipalLifecycleState;
  livenessState: PrincipalLivenessState;
  endpointPosture?: EndpointPostureState;
  sessionPosture?: SessionPostureState;
  lastHeartbeatAt?: string;
  stateReason?: string;
  updatedAt: string;
}
```

Recommended endpoints:

```text
GET  /api/v1/principals/{id}/state
POST /api/v1/principals/{id}/transition
GET  /api/v1/principals/{id}/state-history
```

The transition endpoint should be the durable directory operation. Legacy
agent-scoped posture commands remain transport compatibility paths until the
response-action contract fully owns command publication.

## 12. Audit Requirements

Every lifecycle transition should emit:

- actor
- previous state
- next state
- reason
- source action or detection
- linked response action ID if present

Liveness transitions should also be recorded, but clearly marked as automatic
system observations rather than operator decisions.

## 13. Implementation Notes

This spec sharpens the lifecycle model used in:

- [Directory Object Model Spec](directory-object-model.md)
- [Effective Policy Resolution Spec](effective-policy-resolution.md)
- [Response Action Contract Spec](response-action-contract.md)

Implementation recommendation:

- expose `lifecycle_state` and `liveness_state` in APIs before forcing a full
  database split
- keep current `agents.status` updates working as a compatibility source while
  the new principal state surfaces are introduced
