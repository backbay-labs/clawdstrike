# Normalized Fleet Event Envelope Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification defines the canonical event record that sits between raw
> evidence ingestion and downstream projections such as hunt queries, console
> streams, and OCSF export.

## 1. Objective

Clawdstrike already has several event shapes:

- raw signed Spine envelopes
- policy events and receipt-like guard facts
- hunt timeline events
- console SSE events
- OCSF export records

That is enough for point features, but not enough for a coherent fleet plane.
This spec defines the canonical normalized event that downstream systems should
share.

## 2. Existing Anchors

- Hunt backend event model:
  `docs/src/fleet-security/hunt-backend.md`
- Current cloud event stream:
  `crates/services/control-api/src/routes/events.rs`
- Current console SSE event shape:
  `apps/control-console/src/hooks/useSSE.ts`
- PolicyEvent to OCSF conversion:
  `crates/libs/clawdstrike-policy-event/src/ocsf.rs`
- Timeline event to OCSF conversion:
  `crates/libs/hunt-query/src/ocsf.rs`
- OCSF core crate:
  `crates/libs/clawdstrike-ocsf`

## 3. Design Invariants

- raw evidence remains the source of truth and is never discarded
- the normalized event is the canonical internal fleet record
- downstream read models are projections of the normalized event
- one canonical event ID maps to one observed fact
- principal, session, grant, and response-action joins are first-class
- OCSF is an export and interchange format, not the only internal event model

## 4. Event Layer Model

The platform should treat events as three layers:

### 4.1 Raw evidence layer

Examples:

- signed Spine envelopes
- raw receipt facts
- raw Tetragon and Hubble messages
- raw scan artifacts

### 4.2 Normalized fleet event layer

This is the canonical tenant-aware, joinable event record defined in this doc.

### 4.3 Projection layer

Examples:

- hunt query records
- console stream events
- response timeline items
- OCSF Detection Finding / Process Activity / Network Activity exports

## 5. Canonical Event Shape

```typescript
export interface FleetEventEnvelope {
  eventId: string;
  tenantId: string;
  source:
    | "receipt"
    | "tetragon"
    | "hubble"
    | "scan"
    | "response"
    | "directory"
    | "detection";
  kind:
    | "guard_decision"
    | "process_exec"
    | "process_exit"
    | "network_flow"
    | "scan_result"
    | "join_completed"
    | "principal_state_changed"
    | "response_action_created"
    | "response_action_updated"
    | "detection_fired";
  occurredAt: string;
  ingestedAt: string;
  severity?: "info" | "low" | "medium" | "high" | "critical";
  verdict?: "allow" | "deny" | "warn" | "none" | "forwarded" | "dropped";
  summary: string;
  actionType?: string;
  principal?: {
    principalId?: string;
    endpointAgentId?: string;
    runtimeAgentId?: string;
    principalType?: string;
  };
  sessionId?: string;
  grantId?: string;
  responseActionId?: string;
  detectionIds?: string[];
  target?: {
    kind?: string;
    id?: string;
    name?: string;
  };
  evidence: {
    rawRef: string;
    envelopeHash?: string;
    issuer?: string;
    schemaName?: string;
    signatureValid?: boolean;
  };
  attributes?: Record<string, unknown>;
}
```

## 6. Why This Is Not Just OCSF

OCSF matters, and the repo already has a real OCSF implementation. But OCSF is
not sufficient as the sole internal event contract for the fleet plane.

Why:

- internal joins need `principal_id`, `grant_id`, `response_action_id`, and
  directory-native identifiers
- the platform needs source-specific enrichment that should not be flattened
  away too early
- not every internal state transition maps neatly to a single OCSF class

Design rule:

- normalize internally first
- export to OCSF where needed
- keep the mapping explicit and reversible where possible

## 7. Relationship to HuntEvent

`HuntEvent` should be treated as a query-oriented projection of
`FleetEventEnvelope`, not as a separate canonical truth.

Recommended relationship:

- `FleetEventEnvelope` is the canonical normalized ingestion record
- `HuntEvent` is the indexed/search projection for hunt workflows
- `ConsoleStreamEvent` is the UI projection for live updates

This keeps one enrichment pipeline rather than parallel normalization paths.

## 8. Required Join Fields

Every normalized event should include these joins when known:

- `tenant_id`
- `principal_id`
- `endpoint_agent_id`
- `runtime_agent_id`
- `session_id`
- `grant_id`
- `response_action_id`

If a join is not yet resolvable:

- keep the event
- mark the field as absent
- allow later enrichment or backfill

The platform should not drop valid events just because one join target has not
been resolved yet.

## 9. Event Identity and Causality

The normalized event should also carry causal references where available.

Recommended optional fields:

- `causedByEventId`
- `relatedEventIds`
- `joinId`
- `sourceDetectionId`
- `sourceApprovalId`

These are especially important for:

- join flows
- response execution
- derived detections
- grant exercise and revocation trails

## 10. Source Family Mapping

Recommended source-to-kind examples:

| Source | Example kinds |
|---|---|
| `receipt` | `guard_decision` |
| `tetragon` | `process_exec`, `process_exit` |
| `hubble` | `network_flow` |
| `scan` | `scan_result` |
| `directory` | `join_completed`, `principal_state_changed` |
| `response` | `response_action_created`, `response_action_updated` |
| `detection` | `detection_fired` |

This keeps the source dimension separate from the semantic kind dimension.

## 11. OCSF Projection Contract

The normalized fleet event should map to OCSF through the existing
`clawdstrike-ocsf` crate and companion converters.

Expected mappings:

| Fleet event kind | OCSF class |
|---|---|
| `guard_decision` | Detection Finding |
| `detection_fired` | Detection Finding |
| `process_exec` / `process_exit` | Process Activity |
| `network_flow` | Network Activity |
| file-oriented scan or content activity | File Activity or Detection Finding depending on semantics |

Important distinction:

- `FleetEventEnvelope` is the operational record
- OCSF JSON is the export record

## 12. Console Stream Projection

The fleet console should not subscribe to raw envelopes directly.

Instead:

- ingest raw evidence
- normalize to `FleetEventEnvelope`
- project to `ConsoleStreamEvent`

This keeps the console stable even as raw evidence sources evolve.

## 13. Storage Guidance

The hunt backend already defines split storage for raw envelopes and normalized
events. This spec sharpens the normalized side.

Recommended storage split:

- raw envelope store for immutable evidence
- normalized fleet event store keyed by `event_id`
- indexed projections for hunt and console use

## 14. Example: Response-Driven State Change

One operator action may generate several normalized fleet events:

1. `response_action_created`
2. `response_action_updated` with `published`
3. `principal_state_changed`
4. `response_action_updated` with `acknowledged`

Each is its own event. The action record links them together, but the event
stream remains fact-oriented rather than mutable-object-oriented.

## 15. Implementation Notes

This spec is meant to pair with:

- [Hunt Backend API and Data Model Spec](hunt-backend.md)
- [Response Execution Pipeline Spec](response-execution-pipeline.md)
- [Detection and Rule Model Spec](detection-rule-model.md)
- [Fleet Console Read Model Spec](fleet-console-read-model.md)
