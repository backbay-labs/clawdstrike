# Code and Artifact Map

This document maps the current repository artifacts to the fleet-security
architecture.

## Runtime and Endpoint Surface

| Concern | Current artifacts | Notes |
|---|---|---|
| Desktop agent shell | `apps/agent` | Tauri desktop agent with local daemon and control surfaces |
| Local authenticated API | `apps/agent/src-tauri/src/api_server.rs` | Proxies local console calls to `hushd` and agent services |
| Enrollment | `apps/agent/src-tauri/src/enrollment.rs` | Enterprise enrollment handshake and local persistence |
| Policy sync | `apps/agent/src-tauri/src/policy_sync.rs` | NATS KV policy distribution to local cache |
| Posture commands | `apps/agent/src-tauri/src/posture_commands.rs` | Handles signed cloud commands locally |
| Approval sync | `apps/agent/src-tauri/src/approval_sync.rs` | Cloud approval request and response flow |
| Telemetry heartbeat | `apps/agent/src-tauri/src/telemetry_publisher.rs` | JetStream heartbeat publication |

## Local Enforcement and Identity Semantics

| Concern | Current artifacts | Notes |
|---|---|---|
| Daemon API router | `crates/services/hushd/src/api/mod.rs` | Central local API surface |
| Local RBAC | `crates/services/hushd/src/api/rbac.rs` | Rich role and assignment model |
| Scoped policy | `crates/services/hushd/src/api/policy_scoping.rs` | Organization, team, project, role, user scopes |
| Runtime and endpoint liveness | `crates/services/hushd/src/api/agent_status.rs` | Strong local status model |
| Session lifecycle | `crates/services/hushd/src/api/session` | Session posture and termination surfaces |

## Cloud Control Plane

| Concern | Current artifacts | Notes |
|---|---|---|
| Main service | `crates/services/control-api` | Cloud control-plane service |
| Tenant routes | `crates/services/control-api/src/routes/tenants.rs` | Includes enrollment token creation |
| Agent routes | `crates/services/control-api/src/routes/agents.rs` | Register, list, get, heartbeat, enroll |
| Policy deploy | `crates/services/control-api/src/routes/policies.rs` | Tenant-wide active policy and KV fanout |
| Approval routes | `crates/services/control-api/src/routes/approvals.rs` | Pending approval resolution and signed responses |
| Event stream | `crates/services/control-api/src/routes/events.rs` | Tenant-scoped NATS to SSE bridge |
| Alert routes | `crates/services/control-api/src/routes/alerts.rs` | Alert configuration CRUD |
| Schema | `crates/services/control-api/migrations/*.sql` | Current cloud data model |

## Multi-Agent Trust

| Concern | Current artifacts | Notes |
|---|---|---|
| Delegation token model | `crates/libs/hush-multi-agent/src/token.rs` | Attenuation, expiry, redelegation, audience |
| Revocation store | `crates/libs/hush-multi-agent/src/revocation.rs` | In-memory and SQLite-backed revocation |
| Identity registry | `crates/libs/hush-multi-agent/src/identity_registry.rs` | Registry abstraction, currently in-memory |

## Hunt and Investigation

| Concern | Current artifacts | Notes |
|---|---|---|
| Hunt CLI | `crates/services/hush-cli/src/hunt.rs` | Query, timeline, correlate, watch, IOC |
| Query engine | `crates/libs/hunt-query` | Structured query, timeline, local replay |
| Correlation | `crates/libs/hunt-correlate` | Rule engine, watch mode, IOC matching, reports |
| Inventory scan | `crates/libs/hunt-scan` | MCP and client inventory scanning |
| Hunt docs | `docs/src/hunt/*.md` | Existing hunt architecture and command docs |

## Telemetry Bridges

| Concern | Current artifacts | Notes |
|---|---|---|
| Linux kernel runtime | `crates/bridges/tetragon-bridge` | Tetragon gRPC to signed Spine envelopes |
| Network flow | `crates/bridges/hubble-bridge` | Hubble flow pipeline |
| Kubernetes audit | `crates/bridges/k8s-audit-bridge` | K8s audit events to Spine |
| Linux audit | `crates/bridges/auditd-bridge` | Host audit telemetry |
| macOS host telemetry | `crates/bridges/darwin-telemetry-bridge` | Process, FSEvents, unified log |

## UI and Operator Surface

| Concern | Current artifacts | Notes |
|---|---|---|
| Control console | `apps/control-console` | Current operator UI |
| Console API client | `apps/control-console/src/api/client.ts` | Currently aligned more with local daemon routes than fleet cloud routes |
| Shared SSE stream | `apps/control-console/src/context/SSEContext.tsx` | Event stream abstraction for UI |
| Agent/session graph | `apps/control-console/src/components/advanced/ForceGraph.tsx` | Lightweight graph visualization seed |

## Supporting Docs and Artifacts

These repo artifacts should inform later iterations of this section:

- `docs/src/guides/enterprise-enrollment.md`
- `docs/src/hunt/architecture.md`
- `docs/src/concepts/adaptive-architecture.md`
- `docs/plans/siem-soar/overview.md`
- `docs/src/roadmap.md`

## Missing Artifact Classes

The following artifacts do not yet exist as first-class repo outputs for this
initiative and should be added in later passes:

- Directory ERD for tenant, swarm, project, principal, and grant objects
- Response-action schema and command contract
- Hunt backend API contract
- Provenance graph schema
- Fleet evidence bundle format
- Operator journey docs for investigation and response
