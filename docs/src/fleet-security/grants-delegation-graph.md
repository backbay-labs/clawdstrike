# Grants and Delegation Graph Contract Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification defines the durable cloud contract for scoped grants,
> delegation lineage, revocation, and graph queryability.

## 1. Objective

Clawdstrike already has strong local primitives for multi-agent delegation:

- signed delegation claims
- attenuation-only re-delegation
- revocation by token ID
- identity lookup and message verification

What is still missing is the durable fleet contract that turns those local
primitives into a cloud-visible grant and lineage graph.

This spec defines that contract.

## 2. Existing Anchors

- Delegation claims and token verification:
  `crates/libs/hush-multi-agent/src/token.rs`
- Revocation store:
  `crates/libs/hush-multi-agent/src/revocation.rs`
- Identity registry:
  `crates/libs/hush-multi-agent/src/identity_registry.rs`
- Capability and identity types:
  `crates/libs/hush-multi-agent/src/types.rs`
- Delegation-bearing message validation:
  `crates/libs/hush-multi-agent/src/message.rs`
- Existing correlation fields:
  `crates/libs/hush-multi-agent/src/correlation.rs`

## 3. Design Invariants

- every delegated authority event becomes a durable `grant`
- every re-delegation becomes an append-only lineage edge
- grants are attenuation-only; child capabilities cannot exceed the parent
  ceiling
- revocation is explicit state, not row deletion
- grant verification and grant persistence are separate steps
- expired or revoked ancestor grants invalidate descendant authority
- raw token facts must remain reconstructible for investigation

## 4. Existing Delegation Claims

Current `DelegationClaims` already carry most of the information needed by the
cloud graph:

| Claim | Meaning | Cloud mapping |
|---|---|---|
| `iss` | delegating agent | issuer principal |
| `sub` | receiving agent | subject principal |
| `aud` | expected verifier | grant audience |
| `iat` | issued at | issued timestamp |
| `exp` | expiration | expiration timestamp |
| `nbf` | not-before | validity lower bound |
| `jti` | token ID | external grant token ID |
| `cap` | delegated capabilities | grant capability payload |
| `chn` | chain of parent token IDs | derivation lineage |
| `cel` | capability ceiling | delegation ceiling |
| `pur` | purpose | operator-readable purpose |
| `ctx` | extra context | grant metadata |

That means the local token format should remain the source contract for grant
facts, while the cloud adds durability and graph queryability around it.

## 5. Canonical Cloud Objects

Recommended durable grant shape:

```typescript
export interface FleetGrant {
  id: string;
  tenantId: string;
  issuerPrincipalId: string;
  subjectPrincipalId: string;
  grantType: "delegation" | "approval" | "session_override";
  audience: string;
  tokenJti?: string;
  parentTokenJti?: string;
  capabilities: Array<Record<string, unknown>>;
  capabilityCeiling: Array<Record<string, unknown>>;
  purpose?: string;
  context?: Record<string, unknown>;
  sourceApprovalId?: string;
  sourceSessionId?: string;
  issuedAt: string;
  notBefore?: string;
  expiresAt: string;
  status: "active" | "expired" | "revoked";
  revokedAt?: string;
  revokedBy?: string;
  revokeReason?: string;
}
```

Recommended delegation edge shape:

```typescript
export interface DelegationGraphEdge {
  id: string;
  tenantId: string;
  parentGrantId?: string;
  parentTokenJti?: string;
  childGrantId: string;
  issuerPrincipalId: string;
  subjectPrincipalId: string;
  relationship: "delegates" | "reissues" | "derives";
  createdAt: string;
}
```

## 6. Graph Node Model

The durable graph should not be grant-only. It should connect grants to the
rest of the fleet control plane.

Recommended node kinds:

- `principal`
- `session`
- `grant`
- `approval`
- `response_action`

Recommended edge kinds:

- `issued_grant`
- `received_grant`
- `derived_from_grant`
- `spawned_principal`
- `approved_by`
- `revoked_by`
- `exercised_in_session`

This is the minimum graph needed to answer:

- who delegated to whom
- which grant lineage led to a sensitive action
- where a compromised chain should be cut

## 7. Grant Ingestion Pipeline

When the platform observes a delegation token, the ingestion path should:

1. verify signature
2. verify audience
3. verify time bounds
4. verify subject binding if known
5. verify token is not revoked
6. resolve issuer and subject principals
7. upsert durable grant record
8. derive graph edges from `chn`
9. emit a principal/grant graph event

Verification stays close to the local token contract. Persistence and graph
materialization happen after the token fact is trusted.

## 8. Parent and Chain Resolution

The cloud should treat `chn` as the parent-token lineage source.

Resolution rules:

- if `chn` is empty, the grant is a root grant in the observed lineage
- if `chn` contains one or more parent token IDs, create lineage links to the
  nearest known parent and preserve the full chain for evidence
- if a parent token is not yet known, keep the child grant and mark lineage as
  unresolved until backfilled

Why unresolved lineage matters:

- cloud ingestion order may not match issuance order
- historical imports may see child actions before parent grant records

## 9. Revocation Semantics

Current local revocation already operates by token ID (`jti`). The fleet
contract should preserve that mechanism and add cloud durability.

Required rules:

- revoking a grant marks `status = revoked`
- revocation retains the original grant row for audit
- descendant grants become invalid if any ancestor in their active lineage is
  revoked
- time-limited revocations are allowed if the revocation store supports them

Recommended revocation payload:

```typescript
export interface RevokeGrantRequest {
  reason: string;
  revokeDescendants?: boolean;
  caseId?: string;
  sourceDetectionId?: string;
}
```

Recommended default:

- `revokeDescendants = true`

That default matches the security intent of cutting the compromised trust chain
rather than only one link in isolation.

## 10. Grant Exercise Facts

A grant becomes operationally useful only when it is linked to execution.

The hunt/event pipeline should attach these fields where available:

- `grant_id`
- `delegation_token_id`
- `issuer_principal_id`
- `subject_principal_id`
- `grant_parent_id`
- `delegation_depth`
- `source_approval_id`
- `source_session_id`

This is what lets operators pivot from an event to the exact delegated
authority that made it possible.

## 11. Graph Query Contract

Recommended read endpoints:

```text
GET /api/v1/grants
GET /api/v1/grants/{id}
GET /api/v1/grants/{id}/lineage
GET /api/v1/principals/{id}/delegation-graph
GET /api/v1/principals/{id}/delegation-lineage
GET /api/v1/graph/paths?from={node_id}&to={node_id}
```

Recommended mutate endpoint:

```text
POST /api/v1/grants/{id}/revoke
```

Recommended graph response shape:

```typescript
export interface DelegationGraphSnapshot {
  rootNodeId?: string;
  nodes: Array<{
    id: string;
    kind: "principal" | "session" | "grant" | "approval" | "response_action";
    label: string;
    state?: string;
    metadata?: Record<string, unknown>;
  }>;
  edges: Array<{
    id: string;
    from: string;
    to: string;
    kind: string;
    metadata?: Record<string, unknown>;
  }>;
  generatedAt: string;
}
```

## 12. Cloud and Local Authority Split

The local multi-agent library remains the verification and issuance substrate.
The cloud directory becomes:

- the durable grant ledger
- the durable delegation graph
- the revocation source of record for fleet operations
- the operator query surface

That split preserves working local mechanics while giving the fleet platform a
real investigation and response model.

## 13. Relationship to Response Actions

Grant revocation should be a first-class response action.

When an operator or automated detection revokes a grant:

- create `response_action`
- update the durable grant status
- publish revocation to the appropriate fleet channel
- emit graph edges or state changes linking the revocation action to the grant

This ties the response plane directly into the delegation graph.

## 14. Compatibility Notes

This contract is intentionally built on the current token format rather than a
new token design.

Why:

- `DelegationClaims` already encode attenuation and chain rules correctly
- `RevocationStore` already uses token IDs and replay protection
- the missing layer is durability and graph materialization, not cryptographic
  primitives

## 15. Implementation Notes

This spec is meant to pair with:

- [Directory Object Model Spec](directory-object-model.md)
- [Response Action Contract Spec](response-action-contract.md)
- [Hunt Backend API and Data Model Spec](hunt-backend.md)
- [Fleet Console Read Model Spec](fleet-console-read-model.md)
