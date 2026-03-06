# Hunt Backend API and Data Model Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification defines the service-backed hunt plane that should evolve
> from the existing CLI and telemetry substrate.

## 1. Objective

The current hunt stack already supports query, timeline, correlate, watch, and
IOC workflows through the CLI. This spec defines the backend contract that turns
those capabilities into a fleet investigation service.

## 2. Existing Anchors

- Hunt query model: `crates/libs/hunt-query/src/query.rs`
- Timeline event model: `crates/libs/hunt-query/src/timeline.rs`
- Hunt CLI orchestration: `crates/services/hush-cli/src/hunt.rs`
- Current cloud event stream: `crates/services/control-api/src/routes/events.rs`
- Current control-console event shape: `apps/control-console/src/hooks/useSSE.ts`

## 3. Design Invariants

- Every normalized hunt event must retain a pointer to raw signed evidence.
- Query API must be a superset of current CLI filters.
- Normalized data is append-only or versioned; raw evidence is never rewritten.
- Heavy operations such as correlation and IOC jobs may run asynchronously.
- Principal, session, grant, and response-action joins are first-class.
- API output must be safe for direct console use and evidence export.

## 4. Service Responsibilities

The hunt backend should provide:

- historical search across normalized events
- timeline reconstruction
- saved hunts
- correlation jobs and result retrieval
- IOC matching jobs
- graph exploration over principal/session/grant relationships
- case-oriented evidence packaging

## 5. Normalized Event Model

The current `TimelineEvent` shape is the seed, but the backend needs a richer
record that is tenant-aware and joinable.

```typescript
export type HuntEventSource = "tetragon" | "hubble" | "receipt" | "scan";

export type HuntEventKind =
  | "process_exec"
  | "process_exit"
  | "process_kprobe"
  | "network_flow"
  | "guard_decision"
  | "scan_result";

export interface HuntEvent {
  eventId: string;
  tenantId: string;
  source: HuntEventSource;
  kind: HuntEventKind;
  timestamp: string;
  verdict: "allow" | "deny" | "warn" | "none" | "forwarded" | "dropped";
  severity?: string;
  summary: string;
  actionType?: string;
  process?: string;
  namespace?: string;
  pod?: string;
  sessionId?: string;
  endpointAgentId?: string;
  runtimeAgentId?: string;
  principalId?: string;
  grantId?: string;
  responseActionId?: string;
  envelopeHash?: string;
  issuer?: string;
  signatureValid?: boolean;
  rawRef: string;
}
```

### Required enrichment

The normalized event should preserve source-specific fields while adding fleet
joins that the current CLI does not yet have:

- tenant identifier
- principal identifier
- endpoint/runtime identifiers
- session identifier
- grant and delegation identifiers
- response-action joins
- raw evidence pointer

## 6. Storage Model

The backend should split storage into raw evidence and normalized query state.

### 6.1 Raw envelope store

Append-only store for signed evidence:

```sql
CREATE TABLE hunt_envelopes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    issuer TEXT,
    issued_at TIMESTAMPTZ NOT NULL,
    envelope_hash TEXT,
    schema_name TEXT,
    raw_envelope JSONB NOT NULL,
    signature_valid BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 6.2 Normalized event index

```sql
CREATE TABLE hunt_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    envelope_id UUID REFERENCES hunt_envelopes(id) ON DELETE SET NULL,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    verdict TEXT NOT NULL,
    severity TEXT,
    summary TEXT NOT NULL,
    action_type TEXT,
    process TEXT,
    namespace TEXT,
    pod TEXT,
    session_id TEXT,
    endpoint_agent_id TEXT,
    runtime_agent_id TEXT,
    principal_id TEXT,
    grant_id TEXT,
    response_action_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_hunt_events_tenant_time ON hunt_events(tenant_id, timestamp DESC);
CREATE INDEX idx_hunt_events_tenant_source ON hunt_events(tenant_id, source, timestamp DESC);
CREATE INDEX idx_hunt_events_tenant_principal ON hunt_events(tenant_id, principal_id, timestamp DESC);
CREATE INDEX idx_hunt_events_tenant_session ON hunt_events(tenant_id, session_id, timestamp DESC);
```

### 6.3 Saved hunts and jobs

```sql
CREATE TABLE saved_hunts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    query JSONB NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE hunt_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    job_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    request JSONB NOT NULL,
    result JSONB,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);
```

## 7. Query API

The first backend API should mirror current CLI semantics closely.

### 7.1 Search request

```typescript
export interface HuntQueryRequest {
  sources?: HuntEventSource[];
  verdict?: "allow" | "deny" | "warn" | "forwarded" | "dropped";
  start?: string;
  end?: string;
  actionType?: string;
  process?: string;
  namespace?: string;
  pod?: string;
  entity?: string;
  principalId?: string;
  sessionId?: string;
  endpointAgentId?: string;
  runtimeAgentId?: string;
  limit?: number;
  cursor?: string;
}
```

### 7.2 Search response

```typescript
export interface HuntQueryResponse {
  events: HuntEvent[];
  total: number;
  nextCursor?: string;
}
```

### 7.3 Timeline response

```typescript
export interface HuntTimelineResponse {
  events: HuntEvent[];
  entity?: string;
  groupedBy?: "principal" | "session" | "endpoint" | "runtime";
}
```

## 8. Correlation and IOC APIs

### 8.1 Correlation

```text
POST /api/v1/hunt/correlate
GET  /api/v1/hunt/jobs/{id}
```

The request should accept:

- inline rules
- stored rule references
- a query filter
- output mode

### 8.2 IOC matching

```text
POST /api/v1/hunt/ioc/match
GET  /api/v1/hunt/jobs/{id}
```

The request should accept:

- text IOC feeds
- STIX bundles
- stored feed references
- a query filter or saved hunt reference

## 9. Graph API

The hunt backend should eventually expose graph traversal directly.

```text
POST /api/v1/hunt/graph/query
```

Initial supported pivots:

- principal -> sessions
- principal -> grants
- principal -> delegated children
- session -> events
- response action -> affected principals/events

## 10. Saved Hunt API

```text
GET    /api/v1/hunt/saved
POST   /api/v1/hunt/saved
GET    /api/v1/hunt/saved/{id}
PATCH  /api/v1/hunt/saved/{id}
DELETE /api/v1/hunt/saved/{id}
POST   /api/v1/hunt/saved/{id}/run
```

## 11. Ingestion Pipeline

The backend should ingest from the same source families that the CLI already
understands:

- Tetragon envelopes
- Hubble envelopes
- receipt envelopes
- scan envelopes

The ingest path should:

1. read raw signed envelope
2. verify signature when configured
3. persist raw envelope
4. normalize into `hunt_events`
5. enrich with principal/session/grant joins
6. expose to query, timeline, and graph APIs

## 12. Relationship to Current CLI

The hunt backend should preserve CLI parity where possible.

| Current CLI capability | Backend equivalent |
|---|---|
| `hunt query` | `POST /api/v1/hunt/query` |
| `hunt timeline` | `POST /api/v1/hunt/timeline` |
| `hunt correlate` | `POST /api/v1/hunt/correlate` |
| `hunt ioc` | `POST /api/v1/hunt/ioc/match` |
| `hunt watch` | streaming detection or live correlation service |

The CLI should eventually become a client of this service for connected mode,
while preserving offline local workflows.

For the canonical event and detection contracts that should sit under this
service, see the [Normalized Fleet Event Envelope Spec](normalized-fleet-event-envelope.md)
and the [Detection and Rule Model Spec](detection-rule-model.md).

## 13. Open Questions

- Should the hunt backend live inside `control-api` first, or be a dedicated service from the start?
- Should graph storage be relational at first, or backed by a dedicated graph engine?
- How much source-specific raw structure should be promoted into first-class normalized columns versus left in JSON metadata?
