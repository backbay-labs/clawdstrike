# Current State

This document captures what already exists in the repository that supports the
fleet-security direction, and where the biggest product and architecture gaps
still are.

## Summary

Clawdstrike already has strong raw material for the category:

- Connected desktop agents with enrollment and NATS-backed control flows
- Signed identity, delegation, receipts, and approval workflows
- Local RBAC and scoped policy semantics in `hushd`
- Threat-hunting libraries and a real hunt CLI
- Telemetry bridges for Linux kernel, Kubernetes, network flow, and macOS

The main gap is not lack of primitives. The gap is lack of unification into a
single fleet platform model.

## Pillar Status

| Pillar | Current state | Main gap |
|---|---|---|
| Fleet EDR | Strong at tool-boundary enforcement and signed telemetry | Incomplete host coverage and limited fleet response backend |
| Directory / policy plane | Real enrollment, keys, policy sync, approvals, local RBAC/scoping | No durable cloud directory graph or inherited fleet policy model |
| Threat hunting | Real CLI query/timeline/correlate/watch/IOC stack | No indexed fleet hunt service or investigation backend |

## What Already Exists

### Connected agent lifecycle

The desktop agent already supports enterprise enrollment and connected operation.

- Agent enrollment handshake: `apps/agent/src-tauri/src/enrollment.rs`
- Cloud enrollment route: `crates/services/control-api/src/routes/agents.rs`
- Tenant enrollment token flow: `crates/services/control-api/src/routes/tenants.rs`
- Agent-side policy KV sync: `apps/agent/src-tauri/src/policy_sync.rs`
- Agent-side posture and kill-switch commands: `apps/agent/src-tauri/src/posture_commands.rs`
- Agent-side approval response sync: `apps/agent/src-tauri/src/approval_sync.rs`
- Agent-side heartbeat telemetry publisher: `apps/agent/src-tauri/src/telemetry_publisher.rs`

### Cloud control-plane substrate

The `control-api` service already has real, production-shaped surfaces, even
though it still describes itself as a scaffold in `crates/services/control-api/src/main.rs`.

Implemented areas include:

- Tenants and enrollment tokens
- Agent registration, listing, lookup, and heartbeat
- Pending approval intake and resolution
- Tenant-wide policy deployment and active-policy persistence
- Tenant-scoped event streaming over SSE from NATS
- Alert configuration CRUD
- Compliance export and retention paths

Primary routes and services:

- `crates/services/control-api/src/routes/mod.rs`
- `crates/services/control-api/src/routes/agents.rs`
- `crates/services/control-api/src/routes/policies.rs`
- `crates/services/control-api/src/routes/approvals.rs`
- `crates/services/control-api/src/routes/events.rs`
- `crates/services/control-api/src/services/agent_heartbeat_consumer.rs`

### Local directory and policy semantics

`hushd` already contains richer identity and policy concepts than the cloud
control plane currently exposes.

- Scoped policy hierarchy: `crates/services/hushd/src/api/policy_scoping.rs`
- RBAC roles and assignments: `crates/services/hushd/src/api/rbac.rs`
- Endpoint and runtime liveness tracking: `crates/services/hushd/src/api/agent_status.rs`
- Session posture transitions and session lifecycle: `crates/services/hushd/src/api/mod.rs`

This is important because it means the core semantics are already being worked
out in code, just not yet unified into a fleet-wide source of truth.

### Delegation, attestation, and revocation

Multi-agent trust primitives are already implemented.

- Delegation claims and attenuation ceilings: `crates/libs/hush-multi-agent/src/token.rs`
- Revocation stores and replay protection: `crates/libs/hush-multi-agent/src/revocation.rs`
- Identity registry abstraction: `crates/libs/hush-multi-agent/src/identity_registry.rs`

The weakness today is not cryptographic capability. It is the absence of a
durable, cloud-backed directory and provenance graph around those primitives.

### Hunt and investigation substrate

Threat hunting is not hypothetical. The hunt subsystem is already present and
documented.

- Hunt docs: `docs/src/hunt/index.md`, `docs/src/hunt/architecture.md`
- Hunt CLI orchestration: `crates/services/hush-cli/src/hunt.rs`
- Structured query and timeline model: `crates/libs/hunt-query`
- Correlation and IOC matching: `crates/libs/hunt-correlate`
- MCP and inventory scanning: `crates/libs/hunt-scan`

The current model is CLI-first and NATS-or-local-data driven. It does not yet
constitute a fleet investigation service.

### Telemetry bridges

The repo already includes multiple telemetry bridges.

- Linux kernel runtime telemetry: `crates/bridges/tetragon-bridge`
- Kubernetes audit telemetry: `crates/bridges/k8s-audit-bridge`
- Network flow telemetry: `crates/bridges/hubble-bridge`
- Linux audit telemetry: `crates/bridges/auditd-bridge`
- macOS telemetry: `crates/bridges/darwin-telemetry-bridge`

This is enough to anchor a serious cross-layer story, but not yet enough to
claim broad endpoint EDR parity.

## Biggest Gaps

### 1. No cloud directory graph

The current control-plane schema mostly stops at `tenants`, `users`, `agents`,
`approvals`, `alert_configs`, and `tenant_active_policies` in:

- `crates/services/control-api/migrations/001_init.sql`
- `crates/services/control-api/migrations/002_adaptive_sdr_schema.sql`
- `crates/services/control-api/migrations/003_adaptive_sdr_token_and_approval_flow.sql`
- `crates/services/control-api/migrations/004_adaptive_sdr_active_policy.sql`

Missing first-class entities include:

- Swarms
- Teams and projects
- Capability groups
- Run and mission objects
- Delegation edges
- Inherited policy attachments
- Fleet response actions and state

### 2. UI and backend are not yet aligned around fleet operations

The current control console talks primarily to local daemon-style routes such as
`/api/v1/audit`, `/api/v1/agents/status`, `/api/v1/policy`, and `/api/v1/events`
through `apps/control-console/src/api/client.ts`, and the desktop agent proxies
those through `apps/agent/src-tauri/src/api_server.rs`.

That is useful for local and single-endpoint operation, but it is not yet a
true fleet console backed end-to-end by `control-api`.

### 3. No fleet-native hunt backend

The hunt stack can already query, correlate, and watch events. What is missing
is a service that turns those capabilities into operator workflows:

- Indexed search across tenants and fleets
- Saved hunts and detection rules
- Investigation cases
- Provenance graph queries
- Fleet evidence bundles

### 4. Response is only partially surfaced in the cloud

Agents can receive `set_posture`, `kill_switch`, and `request_policy_reload`,
but the cloud control API does not yet expose a complete operator-facing
response plane for publishing and auditing those actions.

### 5. Endpoint coverage is uneven

The repo contains strong tool-boundary telemetry and some host/kernel coverage,
but the example EDR loop under `examples/bb-edr/README.md` explicitly states
that it is not OS-level telemetry. Windows-specific endpoint telemetry is also
not yet present as a first-class bridge.

## Immediate Documentation Implication

The architecture docs for this initiative should treat the current repo as a
collection of converging subsystems:

- local enforcement and desktop operation
- cloud enrollment and policy distribution
- multi-agent trust primitives
- telemetry bridges
- hunt libraries and CLI

The design task is to define how those become one coherent fleet product rather
than parallel feature tracks.
