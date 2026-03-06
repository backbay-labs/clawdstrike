# Fleet Console Read Model Spec

> **Status:** Draft | **Date:** 2026-03-06
>
> This specification defines the backend read models and stream contract needed
> to turn the existing control console into a real fleet console.

## 1. Objective

The current control console is useful, but it is still mostly shaped around the
local desktop agent and `hushd` API surface. To support fleet operations, the
console needs a backend contract that projects directory, response, hunt, and
graph data in UI-friendly shapes.

This spec defines that read model.

## 2. Existing Anchors

- Current console API client:
  `apps/control-console/src/api/client.ts`
- Current shared SSE context:
  `apps/control-console/src/context/SSEContext.tsx`
- Current SSE hook and event shape:
  `apps/control-console/src/hooks/useSSE.ts`
- Current force-graph view:
  `apps/control-console/src/components/advanced/ForceGraph.tsx`
- Local desktop-agent API proxy:
  `apps/agent/src-tauri/src/api_server.rs`
- Current cloud SSE route:
  `crates/services/control-api/src/routes/events.rs`

## 3. Current Mismatch

Today the console is wired primarily to local endpoints such as:

- `/api/v1/audit`
- `/api/v1/audit/stats`
- `/api/v1/agents/status`
- `/api/v1/policy`
- `/api/v1/events`

Those are local `hushd`-style surfaces exposed through the desktop agent.

The cloud control API currently differs in important ways:

- directory resources do not yet exist as first-class routes
- cloud SSE is exposed at `/api/v1/events/stream`
- the cloud stream currently bridges raw tenant NATS envelope payloads rather
  than the normalized JSON event shape the console expects

The read model must close that gap without breaking local endpoint workflows.

## 4. Design Invariants

- one console can support both local endpoint mode and fleet cloud mode
- view models should be optimized for operators, not raw table mirroring
- every list and detail view must be tenant-scoped
- fleet views should key on `principal_id`, not only `agent_id`
- streaming payloads must already be normalized for frontend consumption
- local endpoint pages remain valid during migration

## 5. Console Modes

Recommended top-level console modes:

```typescript
export type ConsoleMode = "local_endpoint" | "fleet_cloud";
```

### 5.1 Local endpoint mode

Purpose:

- inspect one endpoint and its local daemon state
- view local audit history and status
- troubleshoot policy drift and telemetry forwarding

### 5.2 Fleet cloud mode

Purpose:

- browse principals, swarms, and projects
- investigate alerts and hunt results across the fleet
- issue and monitor response actions
- inspect grant lineage and delegation graphs

The same application can host both modes, but they should not pretend to be the
same backend.

## 6. Read Model Families

The fleet console needs at least these read-model families:

- overview
- principal directory
- principal detail
- policy state
- response center
- investigation timeline
- delegation graph

CRUD APIs remain canonical for writes. These read models exist to reduce UI
composition complexity and overfetch.

## 7. Overview Read Model

Recommended route:

```text
GET /api/v1/console/overview
```

Recommended response:

```typescript
export interface FleetConsoleOverview {
  tenantId: string;
  generatedAt: string;
  counts: {
    principals: number;
    endpointAgents: number;
    runtimeAgents: number;
    swarms: number;
    projects: number;
    quarantinedPrincipals: number;
    stalePrincipals: number;
    activeResponseActions: number;
    openDetections: number;
  };
  postureSummary: Array<{
    lifecycleState: string;
    count: number;
  }>;
  livenessSummary: Array<{
    livenessState: string;
    count: number;
  }>;
  recentResponseActions: ConsoleResponseActionListItem[];
  recentDetections: ConsoleDetectionListItem[];
}
```

```typescript
export interface ConsoleDetectionListItem {
  detectionId: string;
  title: string;
  severity: string;
  status: string;
  createdAt: string;
  principalId?: string;
}
```

## 8. Principal Directory Read Model

Recommended routes:

```text
GET /api/v1/console/principals
GET /api/v1/console/principals/{id}
```

List response:

```typescript
export interface ConsolePrincipalListItem {
  principalId: string;
  principalType: string;
  displayName: string;
  stableRef: string;
  lifecycleState: string;
  livenessState: string;
  endpointPosture?: string;
  trustLevel: string;
  swarmNames: string[];
  projectNames: string[];
  capabilityGroupNames: string[];
  lastHeartbeatAt?: string;
  openResponseActionCount: number;
}
```

Detail response:

```typescript
export interface ConsolePrincipalDetail {
  principal: ConsolePrincipalListItem;
  metadata?: Record<string, unknown>;
  memberships: Array<{
    targetKind: string;
    targetId: string;
    targetName?: string;
    role?: string;
  }>;
  effectivePolicy: {
    checksumSha256: string;
    resolutionVersion: number;
    overlays: string[];
  };
  activeGrants: Array<{
    grantId: string;
    subjectPrincipalId: string;
    expiresAt: string;
    status: string;
  }>;
  recentSessions: Array<{
    sessionId: string;
    startedAt: string;
    endedAt?: string;
    posture?: string;
  }>;
}
```

## 9. Response Center Read Model

Recommended route:

```text
GET /api/v1/console/response-actions
```

Recommended item shape:

```typescript
export interface ConsoleResponseActionListItem {
  actionId: string;
  actionType: string;
  status: string;
  targetKind: string;
  targetId: string;
  targetDisplayName?: string;
  requestedAt: string;
  requestedBy: string;
  reason: string;
  sourceDetectionId?: string;
}
```

This lets the console render a fleet-wide response queue without stitching
several resource tables together in the browser.

## 10. Investigation Timeline Read Model

Recommended routes:

```text
GET /api/v1/console/timeline
GET /api/v1/console/principals/{id}/timeline
```

Recommended event shape:

```typescript
export interface ConsoleTimelineEvent {
  eventId: string;
  timestamp: string;
  tenantId: string;
  principalId?: string;
  sessionId?: string;
  grantId?: string;
  eventType: string;
  actionType?: string;
  severity?: string;
  allowed?: boolean;
  summary: string;
  metadata?: Record<string, unknown>;
}
```

This model should be derived from the hunt backend rather than directly from raw
SSE traffic.

## 11. Delegation Graph Read Model

Recommended route:

```text
GET /api/v1/console/principals/{id}/graph
```

Recommended response:

```typescript
export interface ConsoleGraphView {
  rootPrincipalId: string;
  nodes: Array<{
    id: string;
    kind: "principal" | "session" | "grant" | "approval" | "response_action";
    label: string;
    state?: string;
  }>;
  edges: Array<{
    id: string;
    from: string;
    to: string;
    kind: string;
  }>;
  generatedAt: string;
}
```

This replaces the current event-derived force graph that only links `agent_id`
to `session_id` and has no durable notion of grants, principals, or response
actions.

## 12. Stream Contract

The fleet console needs a single normalized stream contract.

Recommended route:

```text
GET /api/v1/console/stream
```

Recommended payload:

```typescript
export interface ConsoleStreamEvent {
  id: string;
  kind:
    | "principal_state_changed"
    | "effective_policy_updated"
    | "response_action_updated"
    | "detection_created"
    | "timeline_event"
    | "graph_updated";
  tenantId: string;
  principalId?: string;
  sessionId?: string;
  grantId?: string;
  responseActionId?: string;
  timestamp: string;
  payload: Record<string, unknown>;
}
```

Normalization rule:

- local endpoint mode may adapt local `/api/v1/events` into this shape
- fleet cloud mode should publish this shape directly
- the console should not be responsible for parsing raw Spine envelopes

## 13. Query and Filter Contract

Every list-oriented endpoint should support:

- pagination
- text search
- state filters
- sort field and direction
- stable cursors where the result volume is large

Examples:

```text
GET /api/v1/console/principals?lifecycle_state=quarantined&q=planner
GET /api/v1/console/response-actions?status=queued&target_kind=principal
GET /api/v1/console/timeline?principal_id=pri_123&from=2026-03-01T00:00:00Z
```

## 14. Local Endpoint Compatibility

The console should keep local endpoint pages for:

- local audit
- endpoint health and drift
- local policy view
- local integration settings

Those pages should be clearly scoped as endpoint-local views. Fleet cloud mode
should not proxy them as if they were the authoritative tenant-wide record.

## 15. Rollout Sequence

Recommended sequence:

1. add a console data-source abstraction for `local_endpoint` vs `fleet_cloud`
2. add normalized `console/stream` support
3. ship overview and principal directory read models
4. ship principal detail and response center read models
5. replace the current graph view with principal/grant graph data
6. move investigation pages to hunt-backed timeline queries

## 16. Implementation Notes

This spec is meant to pair with:

- [Directory API Contract Spec](directory-api-contract.md)
- [Response Action Contract Spec](response-action-contract.md)
- [Hunt Backend API and Data Model Spec](hunt-backend.md)
- [Grants and Delegation Graph Contract Spec](grants-delegation-graph.md)
