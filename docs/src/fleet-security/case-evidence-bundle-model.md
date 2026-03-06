# Case and Evidence Bundle Model Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification defines how detections, hunts, response actions, and raw
> evidence are grouped into durable cases and exportable evidence bundles.

## 1. Objective

The platform already has real evidence-bundle primitives in `hush-certification`
and evidence export routes in `hushd`. What is missing is the fleet-case model
that ties those primitives to:

- detection findings
- hunt timelines
- response actions
- directory principals and grants

This spec defines that model.

## 2. Existing Anchors

- Evidence bundle ZIP generation:
  `crates/libs/hush-certification/src/evidence/mod.rs`
- Existing evidence export routes:
  `crates/services/hushd/src/api/certification.rs`
- Existing evidence scopes:
  `crates/services/hushd/src/auth/types.rs`
- Compliance export and retention:
  `crates/services/control-api/src/routes/compliance.rs`
- Hunt backend and normalized events:
  `docs/src/fleet-security/hunt-backend.md`
  `docs/src/fleet-security/normalized-fleet-event-envelope.md`

## 3. Design Invariants

- cases are operator workflow objects
- evidence bundles are immutable exported artifacts
- raw evidence remains separately queryable even after bundling
- exported bundles must be signed and content-addressed
- case membership should reference evidence, not copy it blindly
- retention and expiry must be explicit

## 4. Canonical Case Record

```typescript
export interface FleetCase {
  id: string;
  tenantId: string;
  title: string;
  summary?: string;
  severity: "low" | "medium" | "high" | "critical";
  status: "open" | "in_progress" | "contained" | "closed";
  createdBy: string;
  createdAt: string;
  updatedAt: string;
  principalIds: string[];
  detectionIds: string[];
  responseActionIds: string[];
  grantIds: string[];
  tags: string[];
  metadata?: Record<string, unknown>;
}
```

## 5. Case Artifact Model

Cases should reference several artifact classes:

- normalized events
- raw envelopes
- detections
- response actions
- grants and delegation graph snapshots
- notes and operator annotations
- exported evidence bundles

Recommended reference shape:

```typescript
export interface CaseArtifactRef {
  id: string;
  caseId: string;
  artifactKind:
    | "fleet_event"
    | "raw_envelope"
    | "detection"
    | "response_action"
    | "grant"
    | "graph_snapshot"
    | "note"
    | "bundle_export";
  artifactId: string;
  addedBy: string;
  addedAt: string;
}
```

## 6. Evidence Bundle Record

The fleet platform should add a case-aware evidence export record on top of the
existing certification-oriented evidence bundle primitives.

```typescript
export interface FleetEvidenceBundle {
  exportId: string;
  tenantId: string;
  caseId?: string;
  status: "processing" | "completed" | "failed" | "expired";
  requestedBy: string;
  requestedAt: string;
  completedAt?: string;
  filePath?: string;
  sha256?: string;
  sizeBytes?: number;
  manifestRef?: string;
  expiresAt?: string;
}
```

## 7. Bundle Contents

Recommended bundle contents:

- `manifest.json`
- `events.jsonl`
- `raw/` signed raw envelopes or raw references
- `detections.json`
- `response-actions.json`
- `graph.json`
- `case.json`
- optional `ocsf.jsonl`

This extends the current evidence-bundle pattern in `hush-certification`, which
already emits signed manifests and audit/event payloads.

## 8. Signed Manifest Requirements

The manifest should include:

- export ID
- case ID if present
- generated time
- included artifact counts
- Merkle root for included evidence
- issuer public key and signature
- applied filters
- date range

This is already conceptually aligned with the existing signed evidence bundle
manifest emitted by `build_evidence_bundle_zip`.

## 9. Export Filters

Evidence exports should support:

- date range
- principal ID filters
- detection ID filters
- response action ID filters
- source families
- include/exclude raw envelopes
- include/exclude OCSF export projection

## 10. Retention and Expiry

Bundles should be treated as export artifacts with explicit retention.

Recommended rules:

- bundle records remain after file expiry for audit
- downloads expire on policy
- tenant retention policies cap stored export lifetime
- exported bundle expiry must not erase underlying retained evidence before its
  normal retention lifecycle

## 11. API Surface

Recommended case endpoints:

```text
GET    /api/v1/cases
POST   /api/v1/cases
GET    /api/v1/cases/{id}
PATCH  /api/v1/cases/{id}
POST   /api/v1/cases/{id}/artifacts
GET    /api/v1/cases/{id}/timeline
```

Recommended bundle endpoints:

```text
POST   /api/v1/cases/{id}/evidence/export
GET    /api/v1/evidence-bundles/{export_id}
GET    /api/v1/evidence-bundles/{export_id}/download
```

## 12. Compatibility Notes

The current `hushd` evidence export model should be treated as the local
evidence-export substrate, not thrown away. The fleet case model should reuse:

- signed manifest generation
- ZIP bundle creation
- export status tracking
- scoped read/export permissions

## 13. Implementation Notes

This spec is meant to pair with:

- [Normalized Fleet Event Envelope Spec](normalized-fleet-event-envelope.md)
- [Fleet Console Read Model Spec](fleet-console-read-model.md)
- [Detection API Contract Spec](detection-api-contract.md)
- [Detection Storage Model Spec](detection-storage-model.md)
