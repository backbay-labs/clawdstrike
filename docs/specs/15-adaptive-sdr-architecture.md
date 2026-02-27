# Spec 15: Adaptive Local <-> Enterprise Architecture

> **Status:** Draft | **Date:** 2026-02-26
> **Author:** Spec Agent (architect)
> **Effort Estimate:** 15-20 engineer-days
> **Dependencies:** Spec 09 (Helm Chart), Spec 14 (ClawdStrike Cloud), spine crate, adapter-core, hushd-engine, hush-cli-engine, desktop agent

---

## 1. Overview

This specification defines the **Adaptive SDR (Security Decision Runtime)** architecture that enables ClawdStrike agents to operate across three deployment modes: standalone (local-only), connected (local + enterprise), and headless (enterprise-only). The architecture provides seamless promotion and demotion between modes, policy synchronization from enterprise to local agents, telemetry publication from agents to enterprise, fleet management via heartbeat and enrollment protocols, and approval escalation for human-in-the-loop workflows.

### 1.1 Scope

- Three deployment modes with well-defined transitions
- NATS-based transport for policy sync, telemetry, heartbeat, and commands
- HTTP-based enrollment protocol for agent-to-enterprise binding
- Heartbeat and stale-agent detection
- Policy sync (enterprise to agent) via NATS KV
- Telemetry push (agent to enterprise) via NATS JetStream with store-and-forward
- Posture commands including kill switch
- Approval escalation with fail-closed timeout
- hushd integration with Spine receipt publication

### 1.2 Relationship to Other Specs

| Spec | Relationship |
|------|--------------|
| Spec 09 (Helm Chart) | Defines the Kubernetes deployment topology for enterprise-side components (NATS, Spine, hushd). This spec defines how agents connect to that topology. |
| Spec 14 (ClawdStrike Cloud) | Defines the multi-tenant SaaS control plane. This spec defines the agent-side protocols that communicate with that control plane: enrollment, heartbeat, policy sync, telemetry, commands. |
| IAM Plans (`docs/plans/identity-access/`) | Define OIDC/SAML, RBAC, and policy scoping. This spec references IAM for enrollment token validation and agent identity but does not depend on full IAM implementation. |

### 1.3 Design Invariants

- **`PolicyEngineLike` contract is frozen.** The adaptive engine wraps existing engines; it does not modify the interface.
- **Fail-closed everywhere.** Every error path denies. Connectivity loss triggers degraded mode with local enforcement, not open access.
- **NATS auth aligns with `NatsAuthConfig`.** Agents authenticate via token, creds file, or NKey seed (enrollment returns token-based auth material by default).
- **Envelope format uses `build_signed_envelope()` from `spine/src/envelope.rs`.**
- **Desktop agent port 9878 (default, configurable).** The local API server port is configurable via `agent_api_port` in `${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike/agent.json`.
- **No breaking changes to existing adapters.** All framework adapters (`openclaw`, `vercel-ai`, `langchain`, etc.) continue to work unchanged.

---

## 2. Deployment Modes

### 2.1 Mode 1 -- Standalone

The agent operates entirely locally with no network dependency on enterprise infrastructure.

```
+-------------------------------------------------------+
|                    Developer Machine                    |
|                                                        |
|  +------------------+    +-------------------------+   |
|  |  Agent Runtime   |    |  Desktop Agent          |   |
|  |  (Claude, etc.)  |    |  localhost:9878         |   |
|  |                  |    |                         |   |
|  |  +-----------+   |    |  +-------------------+  |   |
|  |  | adapter   |---+--->|  | API Server        |  |   |
|  |  | (openclaw |   |    |  | /api/v1/eval      |  |   |
|  |  |  etc.)    |   |    |  +--------+----------+  |   |
|  |  +-----------+   |    |           |             |   |
|  +------------------+    |  +--------v----------+  |   |
|                          |  | hush-cli-engine   |  |   |
|                          |  | (local policy     |  |   |
|                          |  |  evaluation)      |  |   |
|                          |  +-------------------+  |   |
|                          |                         |   |
|                          |  +-------------------+  |   |
|                          |  | Local Policy      |  |   |
|                          |  | Files (YAML)      |  |   |
|                          |  +-------------------+  |   |
|                          +-------------------------+   |
+-------------------------------------------------------+
```

**Characteristics:**

- Local `hushd` or `hush-cli-engine` evaluates policies from local YAML files
- No network dependency; air-gap compatible
- Desktop agent exposes API on `127.0.0.1:9878`
- CLI engine spawns `hush policy eval <policyRef>` as child process
- Decisions are logged locally; no enterprise audit trail
- Posture is managed locally via `session.rs`

**Configuration:**

```json
// ${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike/agent.json (standalone)
{
  "policy_path": "/Users/<you>/.config/clawdstrike/policy.yaml",
  "daemon_port": 9876,
  "agent_api_port": 9878,
  "enabled": true
}
```

### 2.2 Mode 2 -- Connected

The agent connects to enterprise infrastructure for centralized policy management, telemetry collection, and fleet oversight, while maintaining local evaluation capability as a fallback.

```
+--------------------------------------------------------+     +----------------------------------+
|                    Developer Machine                    |     |         Enterprise (K8s)          |
|                                                        |     |                                  |
|  +------------------+    +-------------------------+   |     |  +----------------------------+  |
|  |  Agent Runtime   |    |  Desktop Agent          |   |     |  |  NATS JetStream Cluster    |  |
|  |  (Claude, etc.)  |    |  localhost:9878         |   |     |  |                            |  |
|  |                  |    |                         |   |     |  |  KV: policy.sync           |  |
|  |  +-----------+   |    |  +-------------------+  |   |     |  |  Stream: telemetry         |  |
|  |  | adapter   |---+--->|  | API Server        |  |   |     |  |  Subj: heartbeat           |  |
|  |  +-----------+   |    |  +--------+----------+  |   |     |  |  Subj: posture.command     |  |
|  +------------------+    |           |             |   |     |  |  Subj: approval            |  |
|                          |  +--------v----------+  |   |     |  +-------------+--------------+  |
|                          |  | engine-adaptive   |  |   |     |                |                 |
|                          |  | (mode manager)    |  |   |     |  +-------------v--------------+  |
|                          |  +--+------+------+--+  |   |     |  |  hushd (enterprise)        |  |
|                          |     |      |      |     |   |     |  |  Policy evaluation         |  |
|                          |     v      |      v     |   |     |  |  Receipt signing            |  |
|                          |  +-----+ +---+ +-----+  |   |     |  +----------------------------+  |
|                          |  |local| |N  | |hushd|  |   |     |                                  |
|                          |  |cli  | |A  | |remo-|--+---+---->|  +----------------------------+  |
|                          |  |eng. | |T  | |te   |  |   |     |  |  Spine Services            |  |
|                          |  +-----+ |S  | |eng. |  |   |     |  |  Checkpointer + Witness    |  |
|                          |          |   | +-----+  |   |     |  |  Proofs API                |  |
|                          |          |   |          |   |     |  +----------------------------+  |
|                          |          +---+----------+---+---->|                                  |
|                          |  +-------------------+  |   |     |  +----------------------------+  |
|                          |  | Local Policy      |  |   |     |  |  Cloud API (Spec 14)       |  |
|                          |  | Cache (synced)    |  |   |     |  |  Fleet management          |  |
|                          |  +-------------------+  |   |     |  |  Dashboard                 |  |
|                          |                         |   |     |  +----------------------------+  |
|                          |  +-------------------+  |   |     +----------------------------------+
|                          |  | Offline Receipt   |  |
|                          |  | Queue (store &    |  |
|                          |  | forward)          |  |
|                          |  +-------------------+  |
|                          +-------------------------+
+--------------------------------------------------------+
```

**Characteristics:**

- `engine-adaptive` wraps both local (`hush-cli-engine`) and remote (`hushd-engine`) evaluators
- Primary evaluation via enterprise `hushd` (remote engine)
- Automatic fallback to local engine on connectivity loss (degraded mode)
- Policy sync: enterprise pushes policies to agent via NATS KV watch
- Telemetry: agent publishes signed receipts to enterprise via NATS JetStream
- Heartbeat: agent sends periodic status to enterprise (30s interval)
- Posture commands: enterprise can remotely adjust agent posture
- Approval escalation: denied actions can be escalated to SOC analyst
- Store-and-forward: offline decisions queued for later submission (addresses Gap G7)
- Graceful promotion/demotion between connected and degraded sub-modes

**Sub-modes within Connected:**

| Sub-mode | Description | Evaluation Path |
|----------|-------------|-----------------|
| `connected` | Full enterprise connectivity | Remote hushd via HTTP |
| `degraded` | Enterprise unreachable, local fallback active | Local hush-cli with synced policy cache |
| `reconnecting` | Attempting to restore enterprise connectivity | Local hush-cli; probing enterprise |

**Configuration:**

```json
// ${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike/agent.json (connected)
{
  "daemon_port": 9876,
  "agent_api_port": 9878,
  "nats": {
    "enabled": true,
    "nats_url": "nats://nats.acme.clawdstrike.cloud:4222",
    "token": "nats-acme-...",
    "tenant_id": "2f9f15f9-...",
    "agent_id": "agent-2f6dbe4b-...",
    "nats_account": "tenant-acme",
    "subject_prefix": "tenant-acme.clawdstrike"
  },
  "enrollment": {
    "enrolled": true,
    "agent_uuid": "f37df9b7-...",
    "tenant_id": "2f9f15f9-..."
  }
}
```

### 2.3 Mode 3 -- Headless (Enterprise-Only)

No local agent process. The agent runtime integrates directly with enterprise hushd via `hushd-engine`. Used in CI/CD pipelines, serverless functions, and managed compute environments.

```
+-------------------------------+     +----------------------------------+
|  Compute Environment          |     |         Enterprise (K8s)          |
|  (CI runner, Lambda, etc.)    |     |                                  |
|                               |     |  +----------------------------+  |
|  +-------------------------+  |     |  |  hushd (enterprise)        |  |
|  |  Agent Runtime          |  |     |  |  /api/v1/eval             |  |
|  |                         |  |     |  +----------------------------+  |
|  |  +-----------+          |  |     |                                  |
|  |  | adapter   |          |  |     |  +----------------------------+  |
|  |  | (any)     |          |  |     |  |  NATS JetStream            |  |
|  |  +-----+-----+         |  |     |  +----------------------------+  |
|  |        |                |  |     |                                  |
|  |  +-----v-----------+   |  |     |  +----------------------------+  |
|  |  | hushd-engine    |---+--+---->|  |  Spine + Cloud API         |  |
|  |  | (remote only)   |   |  |     |  +----------------------------+  |
|  |  +-----------------+   |  |     +----------------------------------+
|  +-------------------------+  |
+-------------------------------+
```

**Characteristics:**

- No local hushd, no desktop agent, no local policy files
- Direct HTTP calls to enterprise hushd via `hushd-engine`
- `offlineFallback: false` -- no local fallback; fail-closed on connectivity loss
- Authentication via API key or short-lived JWT
- All telemetry is server-side (hushd publishes directly to Spine)
- No enrollment needed; identified by API key / service account

**Configuration:**

```yaml
# Environment variables (headless)
CLAWDSTRIKE_MODE=headless
CLAWDSTRIKE_HUSHD_URL=https://hushd.acme.clawdstrike.cloud
CLAWDSTRIKE_API_KEY=cs_live_...
CLAWDSTRIKE_OFFLINE_FALLBACK=false
```

---

## 3. Component Architecture

### 3.1 Component Diagram (All Modes)

```
                          STANDALONE           CONNECTED            HEADLESS
                         +----------+    +------------------+    +-----------+
                         |          |    |                  |    |           |
Agent Runtime            |  Agent   |    |  Agent Runtime   |    |  Agent    |
                         |  Runtime |    |                  |    |  Runtime  |
                         +----+-----+    +--------+---------+    +-----+----+
                              |                   |                     |
                              v                   v                     v
Adapter Layer           +-----------+    +-----------------+    +-----------+
                        |  adapter  |    |  adapter        |    |  adapter  |
                        |  (any)    |    |  (any)          |    |  (any)    |
                        +-----+-----+    +--------+--------+    +-----+----+
                              |                   |                     |
                              v                   v                     v
Engine Layer            +-----------+    +-----------------+    +-----------+
                        | hush-cli  |    | engine-adaptive |    | hushd-    |
                        | -engine   |    | (new)           |    | engine    |
                        +-----------+    +--+-----------+--+    +-----------+
                              |             |           |              |
                              v             v           v              v
Evaluation              +-----------+  +--------+ +----------+  +----------+
                        | hush CLI  |  | hush   | | hushd    |  | hushd    |
                        | (local)   |  | CLI    | | -engine  |  | (remote) |
                        +-----------+  | (local)| | (remote) |  +----------+
                                       +--------+ +----+-----+
                                                       |
Transport                              +-----------+   |
(Connected only)                       | NATS      |<--+
                                       | Client    |
                                       +-----+-----+
                                             |
                                             v
Enterprise                    +-----------------------------+
                              | NATS JetStream | hushd      |
                              | Spine          | Cloud API  |
                              +-----------------------------+
```

### 3.2 Component Inventory

| Component | Location | Mode(s) | Purpose |
|-----------|----------|---------|---------|
| `engine-adaptive` | `packages/adapters/clawdstrike-engine-adaptive/` (new) | Connected | Wraps local + remote engines; manages mode transitions |
| `hush-cli-engine` | `packages/adapters/clawdstrike-hush-cli-engine/` | Standalone, Connected (fallback) | Local policy evaluation via `hush` binary |
| `hushd-engine` | `packages/adapters/clawdstrike-hushd-engine/` | Connected, Headless | Remote policy evaluation via hushd HTTP API |
| Desktop Agent | `apps/agent/` | Standalone, Connected | Local API server (port 9878), session management, NATS client |
| `hushd` | `crates/services/hushd/` | All (enterprise-side) | Policy evaluation daemon, receipt signing |
| Spine | `crates/libs/spine/` | Connected, Headless (enterprise-side) | Signed envelope format, NATS transport, KV/stream helpers |
| NATS transport | `crates/libs/spine/src/nats_transport.rs` | Connected | `NatsAuthConfig`, `connect_with_auth`, `ensure_kv`, `ensure_stream` |
| Cloud API | `crates/services/cloud-api/` (Spec 14) | Connected, Headless (enterprise-side) | Tenant management, fleet management, dashboard backend |
| Framework adapters | `packages/adapters/clawdstrike-{openclaw,vercel-ai,...}/` | All | Agent runtime integrations; unchanged by this spec |

---

## 4. Data Flow

### 4.1 Standalone Mode -- Policy Evaluation

```
Agent Runtime        Desktop Agent (9878)      hush CLI
     |                      |                     |
     |  POST /api/v1/eval   |                     |
     |  { event }           |                     |
     |--------------------->|                     |
     |                      |  spawn: hush        |
     |                      |  policy eval <ref>  |
     |                      |  stdin: event JSON  |
     |                      |-------------------->|
     |                      |                     |  evaluate guards
     |                      |                     |  sign receipt
     |                      |  stdout: decision   |
     |                      |<--------------------|
     |  { decision }        |                     |
     |<---------------------|                     |
```

### 4.2 Connected Mode -- Policy Evaluation (Enterprise Online)

```
Agent Runtime     engine-adaptive       hushd-engine      Enterprise hushd
     |                  |                    |                    |
     | evaluate(event)  |                    |                    |
     |----------------->|                    |                    |
     |                  | mode=connected     |                    |
     |                  | delegate to remote |                    |
     |                  |------------------->|                    |
     |                  |                    | POST /api/v1/eval  |
     |                  |                    |------------------->|
     |                  |                    |                    | evaluate
     |                  |                    |                    | sign receipt
     |                  |                    |    { decision }    | publish to Spine
     |                  |                    |<-------------------|
     |                  |    { decision }    |                    |
     |                  |<-------------------|                    |
     |  { decision }    |                    |                    |
     |<-----------------|                    |                    |
     |                  |                    |                    |
     |                  | async: publish receipt to NATS telemetry stream
     |                  |-------------------------------------------->
```

### 4.3 Connected Mode -- Degraded Fallback

```
Agent Runtime     engine-adaptive       hushd-engine      hush-cli-engine
     |                  |                    |                    |
     | evaluate(event)  |                    |                    |
     |----------------->|                    |                    |
     |                  | delegate to remote |                    |
     |                  |------------------->|                    |
     |                  |                    | POST /api/v1/eval  |
     |                  |                    |----X (ECONNREFUSED)|
     |                  |                    |                    |
     |                  | isConnectivityError|                    |
     |                  |<---- error --------|                    |
     |                  |                    |                    |
     |                  | mode -> degraded   |                    |
     |                  | delegate to local  |                    |
     |                  |------------------------------------------->|
     |                  |                    |                    | spawn hush
     |                  |                    |                    | evaluate
     |                  |                    |  { decision +      |
     |                  |<-------------------------------------------| provenance:
     |  { decision,     |                    |    degraded }      |   degraded
     |    provenance:   |                    |                    |
     |    degraded }    |                    |                    |
     |<-----------------|                    |                    |
     |                  |                    |                    |
     |                  | queue receipt in offline store-and-forward
```

### 4.4 Decision Flow Summary

```
PolicyEvent arrives
        |
        v
+------------------+
| engine-adaptive  |
| check mode       |
+--------+---------+
         |
    +----+----+----+
    |         |    |
    v         v    v
standalone connected headless
    |         |    |
    v         |    v
 hush-cli     |  hushd-engine
 -engine      |  (remote, no fallback)
              |
         +----+----+
         |         |
         v         v
    enterprise  connectivity
    reachable?  error?
         |         |
         v         v
    hushd-engine  hush-cli-engine
    (remote)      (local, degraded)
         |         |
         v         v
    +----+---------+----+
    |    Decision        |
    +----+---------------+
         |
         v
    Sign receipt (Spine envelope)
         |
         v
    +----+----+
    |         |
    v         v
  online    offline
    |         |
    v         v
  Publish   Queue for
  to NATS   store-and-
  telemetry forward
```

---

## 5. NATS Channel Schema

### 5.1 Naming Convention

All NATS subjects follow the pattern:

```
<subject_prefix>.<domain>.<action>[.<qualifier>]
```

Where:
- `<subject_prefix>` -- tenant-scoped prefix provisioned at enrollment (for example `tenant-acme.clawdstrike`)
- `<domain>` -- functional domain (`policy`, `telemetry`, `agent`, `posture`, `approval`)
- `<action>` -- specific operation within the domain
- `<qualifier>` -- optional agent-specific or resource-specific suffix

**Tenant isolation** is enforced by both NATS account boundaries and the enrollment-provisioned `subject_prefix` that all publishers/subscribers derive from.

### 5.2 Subject Inventory

| Subject Pattern | Type | Direction | Purpose |
|----------------|------|-----------|---------|
| `<subject_prefix>.policy.update` | Subject | Enterprise -> Agent | Policy deployment signal |
| `<subject_prefix>.receipts.eval` | JetStream subject | Agent -> Enterprise | Audit receipt envelopes |
| `<subject_prefix>.agent.heartbeat.<agent-id>` | Subject | Agent -> Enterprise | Periodic agent status |
| `<subject_prefix>.posture.command.<agent-id>` | Subject | Enterprise -> Agent | Remote posture commands |
| `<subject_prefix>.approval.response.<agent-id>` | Subject | Enterprise -> Agent | Approval resolution responses |

### 5.3 KV Bucket: Policy Sync

```
Bucket:   <sanitized_subject_prefix>-policy-sync-<agent-id>
Purpose:  Per-agent policy distribution consumed by the desktop PolicySync watcher
History:  1 revision (latest value only)
Replicas: 1 (current implementation default)
TTL:      0 (no expiry; explicit deletion only)

Key Schema:
  "policy.yaml" -> raw YAML policy payload
```

`<sanitized_subject_prefix>` replaces non `[A-Za-z0-9_-]` bytes with `-` so bucket names remain valid JetStream stream identifiers.

Tenant-level active policy versioning/metadata is persisted in the cloud database (`tenant_active_policies`) and backfilled to agent buckets on deploy/enroll/heartbeat reconciliation.

**Entry format (`policy.yaml` value):**

```yaml
version: "1.0.0"
rules:
  - guard: ForbiddenPathGuard
    config:
      paths:
        - "/etc/ssh"
```

### 5.4 JetStream Stream: Telemetry Receipts

```
Stream:     <sanitized_subject_prefix>-telemetry-<agent-id>
Subjects:   ["<subject_prefix>.telemetry.>", "<subject_prefix>.agent.heartbeat.>"]
Storage:    File
Retention:  Limits (max_age based on tenant retention_days from Spec 14)
Replicas:   3
Max Age:    tenant.retention_days (default 30d for Team, configurable for Enterprise)
Dedup:      Window 5m (by Nats-Msg-Id header = envelope_hash)
```

**Message format:** Spine signed envelope (see Section 13) with `Nats-Msg-Id` header set to `envelope_hash` for deduplication.

### 5.5 Heartbeat Subject

```
Subject:  <subject_prefix>.agent.heartbeat.<agent-id>
Pattern:  Publish only (fire-and-forget)
Rate:     Every 30 seconds per agent
```

**Payload:** See Section 8 for heartbeat message format.

### 5.6 Posture Command Subject

```
Subject:   <subject_prefix>.posture.command.<agent-id>
Pattern:   Request/Reply
Timeout:   10 seconds (agent must ACK within this window)
```

**Payload:** See Section 11 for posture command format.

### 5.7 Approval Subjects

```
Response:  <subject_prefix>.approval.response.<agent-id>
Pattern:   Publish (enterprise -> agent)
Timeout:   5 minutes (default; configurable per tenant)
```

**Payload:** See Section 12 for approval escalation format.

---

## 6. Security Model and Trust Boundaries

### 6.1 Trust Zones

```
+----------------------------+     +----------------------------+
|     Agent Trust Zone       |     |   Enterprise Trust Zone    |
|                            |     |                            |
|  - Agent process           |     |  - hushd                   |
|  - Local policy cache      |     |  - Cloud API               |
|  - Local hush CLI          |     |  - Spine services          |
|  - Offline receipt queue   |     |  - NATS JetStream          |
|  - Ed25519 agent keypair   |     |  - PostgreSQL              |
|                            |     |  - Ed25519 server keypair  |
+-------------+--------------+     +-------------+--------------+
              |                                   |
              |         +------------------+      |
              +-------->| NATS Transport   |<-----+
                        | (Trust Boundary) |
                        +------------------+
                        | mTLS / NKey auth |
                        | Per-tenant       |
                        | account isolation|
                        +------------------+
```

### 6.2 Authentication

**NATS Connection Authentication:**

Agents authenticate to NATS using one of three methods from `NatsAuthConfig`:

| Method | Use Case | Priority |
|--------|----------|----------|
| Credentials file (`.creds`) | Optional/manual provisioning path | 1 (highest) |
| Token | Default enrollment output for desktop agents; also usable in headless mode | 2 |
| NKey seed | Development; manual provisioning | 3 |

Priority order matches the existing `connect_with_auth` implementation in `spine/src/nats_transport.rs`: first non-None field wins.

**hushd HTTP Authentication:**

- Bearer token in `Authorization` header (existing pattern)
- Tokens are API keys issued per-tenant via Cloud API (Spec 14)
- Desktop agent forwards `x-hushd-authorization` from clients (existing pattern)

### 6.3 Enrollment Token Lifecycle

```
                  Enterprise Admin
                        |
                        v
              +---------+---------+
              | Generate one-time |
              | enrollment token  |
              | (Cloud API or CLI)|
              +--------+----------+
                       |
          Out-of-band  |  (email, CLI output, dashboard copy)
          delivery     |
                       v
              +--------+----------+
              | Agent receives    |
              | enrollment token  |
              +--------+----------+
                       |
                       v
              +--------+----------+
              | Agent presents    |
              | token to          |
              | enrollment API    |
              +--------+----------+
                       |
                       v
              +--------+----------+
              | Enterprise        |
              | validates token   |
              | provisions creds  |
              | registers agent   |
              +--------+----------+
                       |
                       v
              +--------+----------+
              | Token consumed    |
              | (single-use)      |
              | Agent receives    |
              | NATS credentials  |
              +-------------------+
```

- Enrollment tokens are single-use, time-limited (default: 24 hours)
- Cloud persists only `token_hash` (salted SHA-256 derived from token format), `expires_at`, and `consumed_at`
- Expired or consumed tokens are rejected; fail-closed

### 6.4 Agent Identity Binding

At enrollment, the agent:

1. Generates a fresh Ed25519 keypair (or presents an existing one)
2. Sends the public key as part of the enrollment request
3. The enterprise registers the public key and binds it to the tenant + agent record
4. All subsequent receipts are signed with this keypair
5. The enterprise can verify receipt signatures against the registered public key

This aligns with the existing `AgentIdentity` from `hush-multi-agent` (Ed25519 public key, role, trust level, capabilities).

### 6.5 NATS Account Isolation and Subject ACLs

Per Spec 14, each tenant gets a dedicated NATS account:

- Account name: `tenant-<slug>`
- Isolated JetStream storage limits
- Cross-account access denied by NATS server configuration
- System account (`SYS`) used only by enterprise internal services

**Intra-tenant subject ACLs:**

Within a tenant's NATS account, two credential classes exist with distinct permissions:

| Credential | Publish | Subscribe |
|------------|---------|-----------|
| **Agent credential** | `<subject_prefix>.agent.heartbeat.<own-agent-id>`, `<subject_prefix>.approval.request.<own-agent-id>`, `<subject_prefix>.receipts.eval` | `<subject_prefix>.posture.command.<own-agent-id>`, `<subject_prefix>.approval.response.<own-agent-id>` |
| **Enterprise service** | `<subject_prefix>.posture.command.>`, `<subject_prefix>.approval.response.>` | `<subject_prefix>.>` |

Key restrictions:
- Agents **cannot** publish to `<subject_prefix>.posture.command.*` -- prevents spoofed command injection
- Agents **cannot** publish to `<subject_prefix>.approval.response.*` -- prevents forged approval responses
- Agents can only publish heartbeats to their own agent-id subject, not to other agents' heartbeat subjects
- Enterprise services maintain policy sync via per-agent JetStream KV bucket writes (`policy.yaml`)

### 6.6 Fail-Closed Guarantees

| Boundary | Failure Mode | Behavior |
|----------|-------------|----------|
| Agent -> Enterprise hushd | Connectivity error | Degrade to local engine |
| Agent -> Enterprise hushd | HTTP 4xx/5xx | Fail closed (deny) |
| Agent -> NATS | Connectivity loss | Queue receipts locally; continue local evaluation |
| Agent -> NATS | Disconnect during initial policy fetch (no cache) | Use local `policy_ref` from config (standalone behavior) |
| Enterprise -> Agent (posture command) | No ACK within 10s | Mark agent unresponsive; retry 3x |
| Approval request | No response within 5m | Default deny |
| Approval response | Malformed JSON or invalid signature | Treat as timeout (deny) |
| Approval response | Arrives after timeout | Discard; log warning |
| Enrollment | Crash between credential write and mode transition | Startup recovery (see Section 7.6) |
| Enrollment token | Expired or invalid | Reject enrollment |
| Local engine | Evaluation error | Fail closed (`ADC_GUARD_ERROR`) |
| Policy sync | Corrupt or invalid policy | Reject; keep last known good policy |
| Receipt queue | Overflow (max entries exceeded) | Evict oldest; log alert |

---

## 7. Enrollment Protocol

### 7.1 Overview

Enrollment is the process by which a standalone agent becomes a connected agent, bound to a specific enterprise tenant. Enrollment is a one-time operation per agent-tenant pair.

### 7.2 Prerequisites

- Enterprise admin has generated an enrollment token via Cloud API or CLI
- Agent has HTTPS access to the Cloud API endpoint (e.g., `https://api.clawdstrike.cloud`)
- Agent has the enrollment token (delivered out-of-band)

**Note:** Enrollment is HTTP-only. The agent does not have NATS credentials before enrollment -- that is precisely what enrollment provisions. The agent connects to NATS only after receiving credentials in the enrollment response.

### 7.3 Protocol Sequence

```
Agent                              Cloud API (HTTPS)
  |                                         |
  |  1. Generate Ed25519 keypair            |
  |  (if not already present)               |
  |                                         |
  |  2. POST /api/v1/agents/enroll          |
  |  {                                      |
  |    enrollment_token: "cset_...",        |
  |    public_key: "<hex>",                 |
  |    hostname: "dev-macbook",             |
  |    version: "0.1.2"                     |
  |  }                                      |
  |---------------------------------------->|
  |                                         |  3. Validate token:
  |                                         |     - Not expired
  |                                         |     - Not consumed
  |                                         |     - Hash exists
  |                                         |     - Tenant active
  |                                         |
  |                                         |  4. Check agent limit
  |                                         |     (tenant.agent_limit)
  |                                         |
  |                                         |  5. Register agent:
  |                                         |     - Store public_key
  |                                         |     - Create NATS credentials
  |                                         |     - Mark token consumed
  |                                         |
  |  6. HTTP 201 Enrollment Response        |
  |  {                                      |
  |    status: "enrolled",                  |
  |    agent_uuid: "<uuid>",                |
  |    tenant_id: "<tenant-uuid>",          |
  |    nats_token: "<opaque token>",        |
  |    nats_url: "nats://...",              |
  |    nats_subject_prefix: "tenant-...",   |
  |    agent_id: "agent-..."                |
  |  }                                      |
  |<----------------------------------------|
  |                                         |
  |  7. Agent persists enrollment + NATS    |
  |     settings in agent.json              |
  |                                         |
  |  8. Agent marks enrolled=true and       |
  |     requests restart                    |
  |                                         |
  |  9. Agent starts heartbeat,             |
  |     policy sync watch,                  |
  |     telemetry publisher                 |
```

The enrollment endpoint (`POST /api/v1/agents/enroll`) is the client-facing API. It internally calls the agent registration logic from Spec 14 (`register_agent`), combining enrollment token validation with agent provisioning in a single operation.

### 7.4 Enrollment Token Format

Tokens are generated as opaque `cset_...` values. Cloud stores only:

- `token_hash` (SHA-256)
- `expires_at`
- `consumed_at`

This keeps enrollment validation server-side and prevents plaintext token recovery from DB rows.

### 7.5 Credential Types

The enrollment response provides tenant-scoped NATS connection material (`nats_url`, `nats_token`, `nats_subject_prefix`, `agent_id`, `nats_account`) that is persisted in `agent.json`.

### 7.6 Enrollment Atomicity and Recovery

The enrollment flow (steps 7-9) involves sequential local mutations: key write, settings update, and service startup. If the agent crashes mid-enrollment, inconsistent flags must be detected and resolved on next startup.

**Recovery protocol:**

On startup, the agent checks for enrollment inconsistency:

1. If `enrollment.enrollment_in_progress=true` on startup:
   - **Interrupted enrollment** -- crash happened mid-handshake.
   - Recovery: clear the in-progress flag and require retry.

2. If `enrollment.enrolled=true` but required `nats.*` fields are missing:
   - **Incomplete connected config** -- settings are inconsistent.
   - Recovery: clear `enrollment` + `nats` blocks and remain local-only until re-enrollment.

3. If `enrollment.enrolled=true` and required `nats.*` fields are present:
   - **Normal connected startup.** Validate by connecting to NATS and starting background enterprise services.

This ensures the agent always reaches a consistent state on startup, regardless of where a previous crash occurred.

### 7.7 Revocation

The enterprise can revoke an agent's enrollment at any time:

1. Cloud API or CLI issues a revocation for the agent
2. Agent's NATS credentials are deleted from the NATS account
3. Next NATS operation by the agent fails with auth error
4. Agent detects auth failure and transitions to standalone mode
5. Agent clears cached enterprise credentials

---

## 8. Heartbeat Mechanism

### 8.1 Heartbeat Message Format

```json
{
  "agent_id": "a1b2c3d4-...",
  "timestamp": "2026-02-26T12:00:30Z",
  "posture": "standard",
  "version": "0.1.2",
  "mode": "connected",
  "budget_used": 45,
  "budget_limit": 100,
  "last_policy_version": 42,
  "os": "darwin",
  "uptime_secs": 3600
}
```

### 8.2 Timing

| Parameter | Value | Notes |
|-----------|-------|-------|
| Interval | 30 seconds | Aligns with existing `session.rs` heartbeat loop |
| Stale threshold | 120 seconds | 4 missed heartbeats |
| Dead threshold | 300 seconds | 10 missed heartbeats |

### 8.3 Enterprise Agent Registry

The enterprise maintains an agent registry (PostgreSQL `agents` table from Spec 14) with:

- `last_heartbeat_at` -- updated on each heartbeat
- `status` -- `active`, `stale`, `dead`, `revoked`
- `metadata` -- last heartbeat payload (JSONB)

### 8.4 Stale Agent Actions

| Condition | Action |
|-----------|--------|
| `now - last_heartbeat_at > 120s` | Status -> `stale`; alert if configured |
| `now - last_heartbeat_at > 300s` | Status -> `dead`; alert; optionally revoke |
| Manual revocation | Status -> `revoked`; delete NATS credentials |

Stale detection runs as a periodic job in the Cloud API (every 60 seconds). The Cloud API default keeps this worker enabled (`STALE_DETECTOR_ENABLED=true`) so stale/dead lifecycle transitions occur unless explicitly disabled.

### 8.5 Heartbeat Publishing

The agent publishes heartbeats as fire-and-forget NATS messages (not JetStream; heartbeats are ephemeral). The enterprise subscribes to `<subject_prefix>.agent.heartbeat.>` within the tenant's NATS account to receive all agent heartbeats for that tenant.

### 8.6 Session Posture Extraction (G9 Fix)

The existing session manager (`session.rs`) extracts posture from a deeply-nested JSON path: `state["posture"]["current_state"]`. This is fragile -- changes to the hushd session response format would silently break posture tracking.

**Required fix:** The agent must validate the hushd session response against a defined schema before extracting posture. If the expected fields are missing or have unexpected types:

1. Log a warning with the raw response structure
2. Default posture to `"unknown"` (not a crash or silent failure)
3. Report `posture: "unknown"` in the heartbeat so the enterprise can detect the mismatch

The enterprise dashboard should alert when agents report `posture: "unknown"`, indicating a schema mismatch between agent and hushd versions.

---

## 9. Policy Sync (Enterprise -> Agent)

### 9.1 Mechanism

Policy sync uses NATS KV watch on a per-agent bucket:

- Bucket name: `<sanitized_subject_prefix>-policy-sync-<agent-id>`
- Key: `policy.yaml`
- Value: raw YAML policy payload

The agent establishes a watcher at startup and receives updates in real time when the enterprise writes `policy.yaml` for that agent.

### 9.2 Sync Flow

```
Enterprise Admin         Cloud API            NATS KV              Agent
     |                      |                    |                    |
     | Update policy        |                    |                    |
     |--------------------->|                    |                    |
     |                      | PUT key="policy.yaml"                 |
     |                      | val="<raw policy yaml>"               |
     |                      |------------------->|                    |
     |                      |                    |  KV watch fires    |
     |                      |                    |------------------->|
     |                      |                    |                    |
     |                      |                    |    1. Write to local
     |                      |                    |       policy file
     |                      |                    |    2. Trigger hushd
     |                      |                    |       restart/reload
     |                      |                    |                    |
     |                      |                    |    ACK (implicit   |
     |                      |                    |    via next        |
     |                      |                    |    heartbeat with  |
     |                      |                    |    last_policy_version) |
```

### 9.3 Version Tracking

- Cloud persists tenant-level active policy metadata in `tenant_active_policies` (including monotonic `version`).
- Agent health/heartbeat includes `last_policy_version` from hushd state for observability.
- On reconnect/startup, the agent reads current `policy.yaml`; if missing, it keeps the last local policy (fail-closed).

### 9.4 Local Cache

```
${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike/
  policy-cache.yaml   # Last synced policy payload from hushd
```

- Cache is used during degraded mode when enterprise is unreachable
- Cache staleness is tracked via `synced_at` timestamp
- If the cache is older than a configurable threshold (default: 24 hours), the agent logs a warning in heartbeat and in decision provenance

### 9.5 Policy Validation

Current validation path:

1. Cloud validates policy YAML at deploy time before writing to KV.
2. Agent writes `policy.yaml` payload atomically to local disk.
3. Agent restarts/reloads hushd; hushd parsing/enforcement is the final validation gate.

If apply/reload fails, the previous effective policy remains in force and errors are logged (fail-closed).

---

## 10. Telemetry Push (Agent -> Enterprise)

### 10.1 Mechanism

Agents publish decision receipts as signed Spine envelopes to a NATS JetStream stream. This provides durable, ordered, deduplicated audit telemetry.

### 10.2 Envelope Format

Telemetry envelopes use `build_signed_envelope()` from `spine/src/envelope.rs`:

```json
{
  "schema": "aegis.spine.envelope.v1",
  "issuer": "aegis:ed25519:<agent-public-key-hex>",
  "seq": 1042,
  "prev_envelope_hash": "0x<previous-hash>",
  "issued_at": "2026-02-26T12:00:30Z",
  "capability_token": null,
  "fact": {
    "type": "clawdstrike.decision.v1",
    "agent_id": "a1b2c3d4-...",
    "session_id": "sess-5678",
    "event_type": "file_write",
    "decision": "deny",
    "reason_code": "FORBIDDEN_PATH",
    "policy_ref": "strict",
    "policy_version": 42,
    "target": "/etc/passwd",
    "mode": "connected",
    "evaluated_at": "2026-02-26T12:00:30Z"
  },
  "envelope_hash": "0x<sha256-hash>",
  "signature": "0x<ed25519-signature>"
}
```

### 10.3 Publishing

- **Online:** Receipts are published immediately to `<subject_prefix>.receipts.eval`
- **NATS message header:** `Nats-Msg-Id: <envelope_hash>` for server-side deduplication (5-minute window)
- **Batch mode:** Agent buffers receipts and flushes every `flush_interval_ms` (default: 5000ms) or when the buffer reaches 100 envelopes, whichever comes first

### 10.4 Store-and-Forward (Offline Decisions)

When the agent is in degraded mode (enterprise unreachable), decisions are queued in the local in-memory audit queue until hushd connectivity is restored.

**Queue properties:**

| Property | Value |
|----------|-------|
| Max entries | 10,000 (configurable) |
| Eviction | Oldest first when full |
| Persistence | File-based; survives agent restart |
| Format | One signed envelope per file |
| Naming | `<seq>-<envelope_hash>.json` for ordering |

**Drain on reconnect:**

When the agent transitions from degraded to connected mode:

1. Agent sorts queued envelopes by `seq` (monotonic)
2. Publishes each envelope to the JetStream stream
3. Server-side deduplication by `envelope_hash` prevents duplicate processing
4. Successfully published envelopes are deleted from the local queue
5. Chain integrity is preserved: `prev_envelope_hash` links are maintained

This addresses **Gap G7** from the research brief.

---

## 11. Posture Commands (Enterprise -> Agent)

### 11.1 Command Format

```json
{
  "command_id": "cmd-uuid-...",
  "command": "<command_type>",
  "issued_at": "2026-02-26T12:01:00Z",
  "issued_by": "admin@acme.com",
  "params": { }
}
```

### 11.2 Command Types

| Command | Description | Params |
|---------|-------------|--------|
| `set_posture` | Transition agent to a specified posture | `{ "posture": "restricted" }` |
| `kill_switch` | Kill switch: immediately transition active session posture to `locked` | `{ "reason": "Incident response" }` |
| `request_policy_reload` | Request immediate hushd restart/policy reload | `{}` |

### 11.3 Protocol

```
Enterprise            NATS                    Agent
    |                   |                       |
    | Publish command   |                       |
    | to posture.       |                       |
    | command.<agent-id>|                       |
    |------------------>|                       |
    |                   | Deliver to agent      |
    |                   |---------------------->|
    |                   |                       |
    |                   |                       | Process command
    |                   |                       |
    |                   |  ACK response         |
    |                   |<----------------------|
    |  Reply received   |                       |
    |<------------------|                       |
```

Uses NATS request/reply pattern. The enterprise publishes to `<subject_prefix>.posture.command.<agent-id>` with a reply inbox. The agent subscribes to its own command subject and replies with an ACK.

### 11.4 ACK Format

```json
{
  "status": "ok",
  "message": "Posture set to restricted"
}
```

Current implementation returns a minimal ACK payload with `status` and optional `message`.
Possible status values: `ok`, `error`.

### 11.5 Kill Switch (`kill_switch`)

The kill switch is the highest-priority posture command:

1. Agent immediately transitions posture to `locked`
2. In `locked` posture, all actions except `heartbeat` and `posture.command` are denied
3. The agent continues sending heartbeats (so the enterprise knows it is alive and locked down)
4. The locked state persists until the enterprise sends a `set_posture` command to restore normal operation
5. If the agent loses connectivity while locked, it remains locked (fail-closed)

### 11.6 Timeout and Unresponsive Agents

- Agent must ACK posture commands within 10 seconds
- If no ACK is received, the enterprise marks the agent as `unresponsive` in the fleet registry
- The enterprise retries the command up to 3 times with exponential backoff (10s, 20s, 40s)
- After 3 failed attempts, the enterprise alerts (if configured) and logs the failure

---

## 12. Approval Escalation

### 12.1 Overview

When a local policy evaluation results in a `deny` for an action that supports escalation, the agent can publish an approval request to the enterprise. A SOC analyst (or automated system) reviews the request and responds with an approval or denial.

### 12.2 Request Flow

```
Agent Runtime     engine-adaptive      NATS              SOC Dashboard
     |                  |                |                     |
     | evaluate(event)  |                |                     |
     |----------------->|                |                     |
     |                  | decision=deny  |                     |
     |                  | escalation=    |                     |
     |                  | allowed        |                     |
     |                  |                |                     |
     |                  | Publish to     |                     |
     |                  | approval.      |                     |
     |                  | request        |                     |
     |                  |--------------->|                     |
     |                  |                |-------------------->|
     |                  |                |                     |
     |                  | Subscribe to   |                     | Analyst reviews
     |                  | approval.      |                     |
     |                  | response.      |                     |
     |                  | <request-id>   |                     |
     |                  |                |                     |
     |                  |                |  Publish response   |
     |                  |                |<--------------------|
     |                  |<---------------|                     |
     |                  |                |                     |
     |  { decision }    |                |                     |
     |<-----------------|                |                     |
```

### 12.3 Request Format

```json
{
  "request_id": "apr-uuid-...",
  "agent_id": "a1b2c3d4-...",
  "session_id": "sess-5678",
  "timestamp": "2026-02-26T12:02:00Z",
  "event": {
    "eventId": "evt-...",
    "eventType": "file_write",
    "timestamp": "2026-02-26T12:01:59Z",
    "data": { "type": "file", "path": "/etc/hosts", "content": "..." }
  },
  "decision": {
    "status": "deny",
    "reason_code": "FORBIDDEN_PATH",
    "details": { "guard": "ForbiddenPathGuard" }
  },
  "context": {
    "hostname": "dev-macbook",
    "posture": "standard",
    "policy_version": 42,
    "mode": "connected"
  }
}
```

### 12.4 Response Format

Approval responses **must** be wrapped in a Spine signed envelope, signed by the enterprise service's keypair. This prevents forgery by any entity within the tenant's NATS account that has publish permission on the approval response subject.

The agent **must** verify the envelope signature using `verify_envelope()` before accepting the response. Responses with invalid or missing signatures are treated as if no response was received (timeout -> deny).

Cloud API runtime defaults are aligned with this requirement: `APPROVAL_SIGNING_ENABLED=true` by default. If `APPROVAL_SIGNING_KEYPAIR_PATH` is unset or unreadable, cloud-api generates an ephemeral signing keypair and logs a warning.

**Envelope fact payload:**

```json
{
  "type": "approval.response",
  "request_id": "apr-uuid-...",
  "approval_id": "db-row-uuid-...",
  "resolution": "approved",
  "resolved_by": "analyst@acme.com"
}
```

Possible `resolution` values:

| Resolution | Description |
|--------|-------------|
| `approved` | Action is allowed |
| `denied` | Action remains denied |

`timeout` is generated locally by the agent when no valid response arrives in time.

### 12.5 Timeout Behavior

- Default timeout: 5 minutes (configurable per tenant)
- If no response is received within the timeout, the agent generates a `timeout` response locally
- Timeout = deny (fail-closed)
- The pending action is not retried; the agent runtime receives a deny decision
- Timeout telemetry is published as a receipt with `escalation_outcome: "timeout"`

### 12.6 Late Response Handling

If an approval response arrives after the timeout has already fired:

- The agent **discards** the late response. The timeout deny decision has already been issued to the agent runtime and cannot be revoked.
- The agent logs a warning: `approval response received after timeout for request_id=<id>`.
- The late response is published as a telemetry event with `escalation_outcome: "late_response_discarded"` for audit visibility.
- This prevents a race condition where a late approval could retroactively authorize an action that was already denied.

### 12.7 Malformed Response Handling

If the approval response NATS message contains malformed JSON or an invalid Spine envelope signature:

- The agent treats it as if no response was received (equivalent to timeout).
- The agent logs an error and publishes a telemetry event with `escalation_outcome: "invalid_response"`.
- Fail-closed: malformed = deny.

---

## 13. hushd -> Spine Receipt Publication

### 13.1 Overview

Enterprise hushd publishes all policy evaluation decisions as signed Spine envelopes. This creates a tamper-evident audit ledger of all enforcement decisions across the fleet.

### 13.2 Integration Point

After hushd evaluates a `PolicyEvent` and produces a `Decision`, the decision response path is extended to:

1. Construct a `fact` value containing the decision, policy reference, agent context
2. Call `build_signed_envelope()` from `spine/src/envelope.rs`
3. Publish the signed envelope to the NATS JetStream telemetry stream

### 13.3 Envelope Fact Schema

```json
{
  "type": "clawdstrike.decision.v1",
  "decision": "deny",
  "reason_code": "FORBIDDEN_PATH",
  "policy_ref": "strict",
  "policy_version": 42,
  "agent_id": "a1b2c3d4-...",
  "session_id": "sess-5678",
  "event_type": "file_write",
  "target": "/etc/passwd",
  "mode": "connected",
  "evaluated_at": "2026-02-26T12:00:30Z",
  "guards_triggered": ["ForbiddenPathGuard"]
}
```

### 13.4 Chain Integrity

- hushd maintains a per-tenant envelope sequence counter (`seq`) and `prev_envelope_hash`
- Each new envelope links to the previous one, forming an append-only hash chain
- Spine checkpointer periodically creates Merkle tree checkpoints over the envelope chain
- Spine witness co-signs checkpoints for non-repudiation
- Proofs API serves inclusion proofs for individual envelopes

### 13.5 Dual Publication

In connected mode, both the agent and hushd may publish envelopes for the same decision:

- **Agent envelope:** Contains the agent's view of the decision, signed by the agent's keypair
- **hushd envelope:** Contains the server's view, signed by the server's keypair

Server-side deduplication by `Nats-Msg-Id` (envelope_hash) prevents true duplicates, but agent and server envelopes are different envelopes (different issuers, different signatures) and both are retained. This provides dual-attestation: the agent's receipt proves what the agent saw, and the server's receipt proves what the server decided.

---

## 14. engine-adaptive Design

### 14.1 Interface

`engine-adaptive` implements `PolicyEngineLike` (frozen contract). It is a drop-in replacement for `hush-cli-engine` or `hushd-engine` that manages mode transitions internally.

**Design decision:** `AdaptiveEngineOptions` accepts **pre-constructed `PolicyEngineLike` instances**, not raw configuration. This preserves the frozen contract by keeping engine construction outside the adaptive wrapper. The caller creates the local and remote engines using their respective `createStrikeCell()` factories, then passes them in. The adaptive engine has no knowledge of how sub-engines are configured -- only that they implement `PolicyEngineLike`.

The remote engine should be created with `offlineFallback: false` since the adaptive layer manages fallback itself.

```typescript
import type { PolicyEngineLike, Decision, PolicyEvent } from '@clawdstrike/adapter-core';

export interface AdaptiveEngineOptions {
  /** Pre-constructed local engine for standalone/fallback evaluation. */
  local: PolicyEngineLike;
  /** Pre-constructed remote engine for enterprise evaluation. */
  remote: PolicyEngineLike;
  /** Initial mode. Default: 'connected'. */
  initialMode?: 'standalone' | 'connected' | 'headless';
  /** Interval (ms) to probe enterprise availability in degraded mode. Default: 30000. */
  probeIntervalMs?: number;
  /** Callback invoked on mode transitions. */
  onModeChange?: (from: string, to: string, reason: string) => void;
}

export function createAdaptiveEngine(options: AdaptiveEngineOptions): PolicyEngineLike;
```

### 14.2 Mode Transition State Machine

```
                  enrollment
  STANDALONE  ------------------>  CONNECTED
      ^                               |
      |                               |  connectivity
      |  revocation /                 |  error
      |  manual disconnect            v
      |                           DEGRADED
      |                               |
      |  enterprise                   |  enterprise
      |  unreachable                  |  reachable
      |  for > 24h                    |  (probe success)
      +<------------------------------+
      |                               |
      |                           CONNECTED
      |
  HEADLESS (no transitions; fail-closed on connectivity loss)
```

**Transition triggers:**

| From | To | Trigger |
|------|-----|---------|
| Standalone | Connected | Successful enrollment |
| Connected | Degraded | Connectivity error during evaluation |
| Degraded | Connected | Successful probe to enterprise hushd |
| Degraded | Standalone | Enterprise unreachable for > 24h (configurable) |
| Connected | Standalone | Agent revoked or manual disconnect |

### 14.3 Enriched Provenance

Decisions from `engine-adaptive` include enriched provenance metadata (addressing **Gap G6**):

```typescript
{
  provenance: {
    mode: 'degraded',
    reason: 'ECONNREFUSED',
    local_policy_ref: 'default',
    local_policy_version: 42,
    local_policy_age_secs: 3600,
    capabilities_lost: ['approval_escalation', 'posture_commands']
  }
}
```

**Merge semantics for `decision.details`:**

The `Decision` type defines `details` as `unknown`. The adaptive engine shallow-merges provenance into it:

```typescript
decision.details = {
  ...(typeof decision.details === 'object' && decision.details !== null
    ? decision.details
    : {}),
  provenance: { ... },  // always set by engine-adaptive
};
```

The **`provenance` key within `decision.details` is reserved for the adaptive engine.** Upstream engines (hush-cli-engine, hushd-engine) and framework adapters must not set a `provenance` key in `decision.details`. If an upstream engine returns a `details` object that already contains a `provenance` key, the adaptive engine overwrites it. The adaptive engine's provenance is the authoritative source for mode and evaluation context metadata.

---

## 15. Monitoring and Observability

### 15.1 Metrics

The adaptive SDR components expose the following metrics for monitoring:

| Metric | Type | Source | Description |
|--------|------|--------|-------------|
| `clawdstrike_engine_mode` | Gauge (label: mode) | engine-adaptive | Current engine mode (standalone=0, connected=1, degraded=2, headless=3) |
| `clawdstrike_mode_transitions_total` | Counter (labels: from, to) | engine-adaptive | Mode transition count |
| `clawdstrike_probe_latency_ms` | Histogram | engine-adaptive | Enterprise probe response time |
| `clawdstrike_probe_failures_total` | Counter | engine-adaptive | Failed enterprise probes |
| `clawdstrike_offline_queue_depth` | Gauge | telemetry publisher | Pending envelopes in store-and-forward queue |
| `clawdstrike_offline_queue_evictions_total` | Counter | telemetry publisher | Envelopes evicted due to queue overflow |
| `clawdstrike_telemetry_publish_total` | Counter (labels: status) | telemetry publisher | Envelopes published (success/failure) |
| `clawdstrike_heartbeat_failures_total` | Counter | heartbeat loop | Consecutive heartbeat publish failures |
| `clawdstrike_policy_sync_version` | Gauge | policy sync | Current synced policy version |
| `clawdstrike_policy_sync_age_secs` | Gauge | policy sync | Seconds since last successful policy sync |
| `clawdstrike_approval_escalations_total` | Counter (labels: outcome) | approval handler | Escalation outcomes (approved/denied/timeout) |

### 15.2 Recommended Alerting Thresholds

| Condition | Severity | Threshold |
|-----------|----------|-----------|
| Agent in degraded mode | Warning | > 5 minutes continuous |
| Offline queue depth | Warning | > 5,000 envelopes |
| Offline queue evictions | Critical | Any eviction (audit loss) |
| Policy sync age | Warning | > 1 hour since last sync |
| Consecutive heartbeat failures | Warning | > 5 consecutive |

### 15.3 Structured Logging

All adaptive SDR components emit structured logs (JSON) with the following standard fields: `agent_id`, `mode`, `component`, `timestamp`. Mode transitions are logged at `INFO` level. Probe failures and fallback activations at `WARN`. Fail-closed denials at `ERROR`.

---

## 16. File Changes

### 16.1 New Files

| Path | Description |
|------|-------------|
| `packages/adapters/clawdstrike-engine-adaptive/src/index.ts` | Adaptive engine wrapper |
| `packages/adapters/clawdstrike-engine-adaptive/src/mode-machine.ts` | Mode transition state machine |
| `packages/adapters/clawdstrike-engine-adaptive/src/probe.ts` | Enterprise availability probing |
| `packages/adapters/clawdstrike-engine-adaptive/src/types.ts` | Adaptive engine types |
| `packages/adapters/clawdstrike-engine-adaptive/package.json` | Package manifest |
| `packages/adapters/clawdstrike-engine-adaptive/tsconfig.json` | TypeScript config |
| `apps/agent/src-tauri/src/nats_client.rs` | NATS client for connected mode |
| `apps/agent/src-tauri/src/enrollment.rs` | Enrollment protocol implementation |
| `apps/agent/src-tauri/src/policy_sync.rs` | NATS KV policy sync watcher |
| `apps/agent/src-tauri/src/telemetry_publisher.rs` | JetStream telemetry publisher (receipts + heartbeats) |
| `apps/agent/src-tauri/src/nats_subjects.rs` | Canonical subject/stream naming helpers |
| `apps/agent/src-tauri/src/posture_commands.rs` | Posture command subscriber |
| `apps/agent/src-tauri/src/approval.rs` | Approval escalation protocol |

### 16.2 Modified Files

| Path | Change |
|------|--------|
| `apps/agent/src-tauri/src/session.rs` | Add heartbeat payload to include `last_policy_version`, `mode`; add schema validation for posture extraction (G9 fix) |
| `apps/agent/src-tauri/src/api_server.rs` | Add enrollment endpoint, mode status endpoint; make port configurable via config (G8 fix) |
| `crates/services/hushd/src/eval.rs` | Wire `build_signed_envelope()` into decision response path |
| `packages/adapters/clawdstrike-hushd-engine/src/strike-cell.ts` | (No changes; engine-adaptive wraps it) |
| `packages/adapters/clawdstrike-hush-cli-engine/src/strike-cell.ts` | (No changes; engine-adaptive wraps it) |
| `Cargo.toml` | (No changes needed; new Rust modules are within existing crates) |
| `package.json` | Add `clawdstrike-engine-adaptive` to workspaces |

---

## 17. Testing Strategy

### Unit Tests

- **engine-adaptive:** Mode transitions, fallback delegation, provenance enrichment, probe scheduling
- **Enrollment:** Token validation, credential generation, agent registration
- **Policy sync:** KV watch handling, checksum validation, cache management
- **Telemetry:** Envelope construction, batch publishing, offline queue FIFO ordering
- **Posture commands:** Command parsing, ACK generation, lockdown enforcement
- **Approval:** Request/response formatting, timeout behavior, fail-closed

### Integration Tests

- **Enrollment flow:** Generate token -> agent enrolls -> receives credentials -> connects to NATS
- **Policy sync:** Publish policy update -> agent receives via KV watch -> applies new policy
- **Telemetry:** Agent publishes receipt -> enterprise receives in JetStream stream
- **Mode transitions:** Simulate connectivity loss -> verify degraded mode -> restore -> verify reconnection
- **Store-and-forward:** Make decisions offline -> reconnect -> verify receipts drained to JetStream
- **Kill switch:** Send kill_switch -> verify agent transitions session posture to locked -> send set_posture -> verify recovery
- **Approval escalation:** Agent denies action -> escalation request published -> response approves -> action allowed

### Load Tests

- 100 agents, 30s heartbeat interval = ~3 heartbeats/second
- 100 agents, 10 decisions/minute each = ~17 telemetry envelopes/second
- Target: < 50ms p99 latency for NATS publish operations
- Target: < 500ms policy sync propagation (KV watch latency)

---

## 18. Rollback Plan

1. **engine-adaptive is opt-in.** Existing adapters continue to use `hush-cli-engine` or `hushd-engine` directly. No adapter is forced to use the adaptive engine.
2. **Connected mode is opt-in.** Agents default to standalone mode. The `connected` mode requires explicit enrollment.
3. **NATS components are additive.** New NATS subjects and streams do not affect existing Spine infrastructure.
4. **hushd Spine publication is behind a feature flag.** If Spine receipt publication causes issues, it can be disabled without affecting core evaluation.
5. **Policy sync cache is a fallback, not a replacement.** If policy sync is disabled, the agent uses its local `policy_ref` (existing behavior).

---

## 19. Dependencies

| Dependency | Status | Notes |
|------------|--------|-------|
| `adapter-core` (PolicyEngineLike) | Exists | Frozen contract; no changes needed |
| `hush-cli-engine` | Exists | Used as local engine in standalone/connected |
| `hushd-engine` | Exists | Used as remote engine; fallback pattern already implemented |
| `spine` crate | Exists | `build_signed_envelope()`, `NatsAuthConfig`, `ensure_kv`, `ensure_stream` |
| Desktop agent (`apps/agent/`) | Exists | Extended with NATS client, enrollment, sync, telemetry |
| `hushd` | Exists | Extended with Spine receipt publication |
| Spec 09 (Helm Chart) | Draft | Enterprise-side deployment topology |
| Spec 14 (ClawdStrike Cloud) | Draft | Multi-tenant control plane, agent fleet management |
| NATS JetStream | Runtime | Required for connected mode |
| IAM Plans | Unimplemented | Enrollment token validation can use simple HMAC initially; full IAM integration deferred |

---

## 20. Open Questions

1. **Envelope schema namespace migration:** The current envelope schema uses `aegis.spine.envelope.v1` and `aegis:ed25519:` issuer prefix (see Contradiction C6 in research brief). Should Spec 15 mandate migration to `clawdstrike.spine.envelope.v2`? **Recommendation:** Defer to a separate spec. Accept both prefixes during a transition period.

2. **TypeScript session awareness:** The TypeScript `hushd-engine` StrikeCell is stateless (Contradiction C2). Should `engine-adaptive` add session ID to remote evaluation requests? **Recommendation:** Yes, extend the eval request with an optional `session_id` field. The hushd-engine can pass it as a header or query parameter without changing `PolicyEngineLike`.

3. **Policy sync granularity:** Should policy sync support incremental updates (diffs) or always full replacement? **Recommendation:** Start with full replacement (simpler, more reliable). Add incremental sync as an optimization when policy sizes justify it.

4. **Approval escalation scope:** Which guards and event types should support escalation? **Recommendation:** Escalation is opt-in per guard via policy configuration. Start with `ForbiddenPathGuard` and `EgressAllowlistGuard`. Other guards can be added later.

5. **Desktop agent port configurability:** ~~Resolved.~~ Port is configurable via `agent_api_port` in `${XDG_CONFIG_HOME:-$HOME/.config}/clawdstrike/agent.json` (default: 9878). Agent must detect port conflicts at startup and fail with a clear error message if the configured port is in use.

---

## 21. Acceptance Criteria

- [ ] Agent can operate in standalone mode with no enterprise dependency
- [ ] Agent can enroll with an enterprise tenant using a one-time enrollment token
- [ ] After enrollment, agent transitions to connected mode and evaluates via enterprise hushd
- [ ] On enterprise connectivity loss, agent falls back to local evaluation (degraded mode)
- [ ] On enterprise reconnect, agent restores connected mode within one probe interval
- [ ] Policy updates published to NATS KV propagate to connected agents within 1 second
- [ ] Agent validates policy checksums and rejects corrupt updates
- [ ] Agent publishes decision receipts as signed Spine envelopes to JetStream
- [ ] Offline decisions are queued and drained to JetStream on reconnect
- [ ] JetStream deduplication prevents duplicate receipt processing
- [ ] Heartbeats are published every 30 seconds with correct agent status
- [ ] Enterprise detects stale agents within 2 minutes of connectivity loss
- [ ] Enterprise can send posture commands and receive ACKs within 10 seconds
- [ ] Kill switch (`kill_switch`) immediately transitions active session posture to `locked`
- [ ] Approval escalation requests are published and responses received within timeout
- [ ] No response within approval timeout results in deny (fail-closed)
- [ ] hushd publishes all decisions as signed Spine envelopes
- [ ] `engine-adaptive` passes all `PolicyEngineLike` contract tests
- [ ] All error paths result in deny decisions (fail-closed)
- [ ] No breaking changes to existing adapters

---

## References

- [Research Brief](../plans/clawdstrike/adaptive-sdr-research-brief.md) -- Codebase analysis grounding this spec
- [Spec 09: Helm Chart](./09-helm-chart.md) -- Enterprise Kubernetes deployment
- [Spec 14: ClawdStrike Cloud](./14-clawdstrike-cloud.md) -- Multi-tenant SaaS control plane
- [IAM Plans](../plans/identity-access/) -- Identity and access management architecture
- `packages/adapters/clawdstrike-adapter-core/src/engine.ts` -- Frozen `PolicyEngineLike` contract
- `packages/adapters/clawdstrike-hushd-engine/src/strike-cell.ts` -- Remote engine with fallback
- `packages/adapters/clawdstrike-hush-cli-engine/src/strike-cell.ts` -- Local CLI engine
- `apps/agent/src-tauri/src/session.rs` -- Session manager with heartbeat
- `apps/agent/src-tauri/src/api_server.rs` -- Desktop agent API server
- `crates/libs/spine/src/envelope.rs` -- Signed envelope format and `build_signed_envelope()`
- `crates/libs/spine/src/nats_transport.rs` -- NATS auth and JetStream helpers
