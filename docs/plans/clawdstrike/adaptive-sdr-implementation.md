# Adaptive Local-Enterprise SDR -- Implementation Plan

> **Date:** 2026-02-26
> **Author:** planner agent (T4)
> **Status:** Complete
> **Prerequisite:** [Codebase Research Brief (D1)](./adaptive-sdr-research-brief.md)
> **Audience:** Implementation team, spec reviewers

---

## Overview

This plan delivers the adaptive local-enterprise Security Decision Runtime in five phases.
Each phase is self-contained: it can be merged, tested, and deployed independently, and each
subsequent phase only depends on the artifacts of its predecessor.

**Key invariants across all phases:**

- `PolicyEngineLike` contract is frozen -- no interface changes.
- Fail-closed everywhere: errors during evaluation produce a deny decision.
- NATS auth aligns with the existing `NatsAuthConfig` (creds file > token > NKey seed).
- Desktop agent local API port defaults to `9878`.
- No breaking changes to existing adapter packages.

---

## Phase 1 -- engine-adaptive (New Package)

### Goal

Create a new TypeScript adapter package `@clawdstrike/engine-adaptive` that wraps
pre-constructed local and remote `PolicyEngineLike` engines, automatically selecting the best
available engine at runtime (remote > local) and managing transitions between modes
(`standalone` / `connected` / `degraded`) with observability, enriched provenance, and
store-and-forward queuing for offline receipts.

Addresses research brief gaps: **G1** (mode negotiation), **G2** (graceful promotion/demotion),
**G3** (unified config), **G6** (enriched provenance), **G7** (audit bridge for offline decisions).

### File Change Table

| File Path | Action | Description |
|-----------|--------|-------------|
| `packages/adapters/clawdstrike-engine-adaptive/package.json` | create | Package manifest; depends on `@clawdstrike/adapter-core` (engines are caller-provided) |
| `packages/adapters/clawdstrike-engine-adaptive/tsconfig.json` | create | TypeScript config extending workspace base |
| `packages/adapters/clawdstrike-engine-adaptive/vitest.config.ts` | create | Test runner configuration |
| `packages/adapters/clawdstrike-engine-adaptive/src/index.ts` | create | Public API barrel export |
| `packages/adapters/clawdstrike-engine-adaptive/src/types.ts` | create | `AdaptiveEngineOptions`, `EngineMode`, `ModeChangeEvent`, `EnrichedProvenance`, `QueuedReceipt` types |
| `packages/adapters/clawdstrike-engine-adaptive/src/probe.ts` | create | Health-check probe logic: `probeRemoteEngine()` |
| `packages/adapters/clawdstrike-engine-adaptive/src/mode-machine.ts` | create | Mode state machine: `standalone` -> `connected` -> `degraded` -> `standalone` |
| `packages/adapters/clawdstrike-engine-adaptive/src/adaptive-engine.ts` | create | `createAdaptiveEngine()` implementing `PolicyEngineLike` by wrapping pre-constructed local and remote engines with auto-probe, mode transitions, and provenance enrichment |
| `packages/adapters/clawdstrike-engine-adaptive/src/receipt-queue.ts` | create | In-memory store-and-forward queue for offline decisions with optional JSONL persistence; drain on reconnect |
| `packages/adapters/clawdstrike-engine-adaptive/src/adaptive-engine.test.ts` | create | Unit tests for mode transitions, fallback, provenance enrichment |
| `packages/adapters/clawdstrike-engine-adaptive/src/probe.test.ts` | create | Unit tests for probe logic with mocked fetch |
| `packages/adapters/clawdstrike-engine-adaptive/src/mode-machine.test.ts` | create | State machine transition tests |
| `packages/adapters/clawdstrike-engine-adaptive/src/receipt-queue.test.ts` | create | Queue behavior tests (enqueue, drain, capacity limits, JSONL persistence round-trip) |
| `packages/adapters/clawdstrike-engine-adaptive/README.md` | create | Package documentation |

### Dependencies

- `@clawdstrike/adapter-core` (existing -- frozen `PolicyEngineLike` interface)

The adaptive engine accepts pre-constructed `PolicyEngineLike` instances, so it has no direct
dependency on specific engine packages. Callers bring their own engines (e.g., from
`@clawdstrike/engine-local` or `@clawdstrike/engine-remote`).

### Implementation Details

#### AdaptiveEngineOptions

The adaptive engine receives **pre-constructed** `PolicyEngineLike` instances rather than raw
configuration. This aligns with Spec 15 Section 14.1 and preserves the principle that the
adaptive engine is a **wrapper** around existing engines -- it does not construct them internally.
Callers are responsible for creating each engine via their respective factory functions
(`createStrikeCell`, `createLocalEngine`, etc.) and passing them in.

```typescript
export interface AdaptiveEngineOptions {
  // Pre-constructed local engine (always available as last-resort fallback).
  // Typically created via createStrikeCell() from @clawdstrike/engine-local.
  local: PolicyEngineLike;

  // Pre-constructed remote engine (optional; used in connected/enterprise mode).
  // Typically created via createStrikeCell() from @clawdstrike/engine-remote.
  remote?: PolicyEngineLike;

  // Initial mode hint (default: 'standalone')
  initialMode?: 'standalone' | 'connected' | 'degraded';

  // Probe configuration for auto-promotion/demotion
  probe?: {
    remoteHealthUrl?: string;   // default: inferred from remote engine baseUrl + '/api/v1/health'
    intervalMs?: number;        // default: 30_000
    timeoutMs?: number;         // default: 5_000
  };

  // Queue config for offline decisions
  receiptQueue?: {
    maxSize?: number;        // default: 1000
    persistPath?: string;    // optional fs path for durable queue (JSONL format)
  };

  // Mode change callback
  onModeChange?: (event: ModeChangeEvent) => void;
}
```

#### Mode State Machine

Aligned with Spec 15 Section 14.2 -- three modes, matching the spec's deployment modes:

```
States: standalone | connected | degraded

Transitions:
  standalone  --[remote engine healthy]---> connected
  connected   --[connectivity error]------> degraded
  degraded    --[remote engine healthy]---> connected (drain receipt queue)
  degraded    --[timeout]-----------------> standalone
```

Priority order: `connected` (remote engine) > `standalone` (local engine).
The `degraded` state uses the local engine while queuing receipts for later replay.

#### Auto-Probe Logic

1. On `createAdaptiveEngine()`: if a `remote` engine is provided, immediately probe its health endpoint.
2. Remote probe: `GET ${probe.remoteHealthUrl}` with configurable timeout (default 5s).
3. If remote is healthy: start in `connected` mode. If unhealthy: start in `standalone` mode.
4. Start periodic background probe at configured interval (default 30s).
5. On probe success when in `standalone` or `degraded`: promote to `connected` (drain queue on promotion from `degraded`).
6. On probe failure when in `connected`: demote to `degraded`.

#### Enriched Provenance (addresses G6)

```typescript
export interface EnrichedProvenance {
  mode: 'standalone' | 'connected' | 'degraded';
  engine: 'local' | 'remote';
  reason?: string;              // why this engine was selected
  localPolicyRef?: string;      // which local policy was used (standalone/degraded)
  localPolicyAge?: string;      // ISO-8601 age of local policy
  capabilitiesLost?: string[];  // features unavailable in current mode
  timestamp: string;            // ISO-8601
}
```

#### Store-and-Forward Queue (addresses G7)

- Decisions made in `degraded` or `standalone` mode are enqueued as `QueuedReceipt` objects.
- On promotion to `connected` mode, the queue is drained: each receipt is POSTed to
  the remote engine's replay endpoint (Phase 5: `POST /api/v1/receipts/replay`).
- Queue has a configurable max size (default 1000); oldest entries are evicted on overflow.
- Optional disk persistence via a JSONL (JSON Lines) append-only file for crash resilience.
  JSONL is preferred over file-per-envelope to avoid macOS directory listing performance
  degradation with large queues (see Item #15 from review).

### Acceptance Criteria

- [ ] `createAdaptiveEngine()` returns a valid `PolicyEngineLike` implementation.
- [ ] When no remote engine is provided or remote is unreachable, mode is `standalone` and local engine is used.
- [ ] When remote engine is healthy, mode is `connected` and requests route to the remote engine.
- [ ] On remote connectivity error, mode transitions to `degraded` and local engine is used.
- [ ] All decisions include `EnrichedProvenance` in `decision.details.provenance`.
- [ ] `onModeChange` callback fires on every mode transition with old/new mode and reason.
- [ ] Offline decisions are queued; queue respects max size with FIFO eviction.
- [ ] Queue drains on promotion to `connected` mode.
- [ ] All error paths produce fail-closed deny decisions.

### Test Strategy

- **Unit tests:** Mock `fetch` to simulate health endpoints. Test all state machine transitions.
  Pass mock `PolicyEngineLike` instances for local and remote to verify delegation.
- **Integration tests:** Start a lightweight HTTP server (similar to session.rs test pattern)
  to verify end-to-end probe -> evaluate -> provenance flow.
- **Edge cases:** Concurrent mode transitions during evaluation; probe timeout during evaluate;
  queue overflow; fallback engine throws.

### LOC Estimate

~900 new lines (TypeScript) + ~500 test lines = **~1,400 total**

---

## Phase 2 -- NATS Bidirectional Sync (Desktop Agent)

### Goal

Add NATS connectivity to the desktop agent for bidirectional communication with the enterprise
plane: subscribe to policy updates via NATS KV watch, publish receipts and telemetry via
JetStream.

Addresses research brief gap: **G5** (policy sync / cache-ahead).

### File Change Table

| File Path | Action | Description |
|-----------|--------|-------------|
| `apps/agent/src-tauri/src/nats_client.rs` | create | NATS connection manager: connect with auth, reconnect with backoff, expose `Client` and `JetStream` context |
| `apps/agent/src-tauri/src/policy_sync.rs` | create | KV watch subscriber: watch `policies.<tenant_id>.<agent_id>` bucket, write updates to local policy file, emit events |
| `apps/agent/src-tauri/src/telemetry_publisher.rs` | create | JetStream publisher: publish receipts to `telemetry.<tenant_id>.<agent_id>.receipts`, publish heartbeats to `telemetry.<tenant_id>.<agent_id>.heartbeat` |
| `apps/agent/src-tauri/src/settings.rs` | modify | Add `NatsSettings` struct: `nats_url`, `nats_auth` (creds_file/token/nkey_seed), `tenant_id`, `agent_id`, `nats_enabled` |
| `apps/agent/src-tauri/src/main.rs` | modify | Wire NATS client, policy sync, and telemetry publisher into agent lifecycle; respect shutdown signal |
| `apps/agent/src-tauri/src/daemon.rs` | modify | On policy file change from NATS sync, signal hushd reload |
| `apps/agent/src-tauri/Cargo.toml` | modify | Add dependency on `spine` crate (workspace member) for `NatsAuthConfig`, `connect_with_auth`, `ensure_kv`, `ensure_stream` |

### Dependencies

- **No dependency on Phase 1.** Phase 2 is Rust-only (desktop agent) and Phase 1 is TypeScript-only
  (`engine-adaptive`). They share no code and can run in parallel.
- `crates/libs/spine` (existing -- provides `NatsAuthConfig`, `connect_with_auth`, `ensure_kv`, `ensure_stream`)

### Implementation Details

#### NatsSettings (added to settings.rs)

```rust
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NatsSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub nats_url: Option<String>,         // e.g., "nats://enterprise.example.com:4222"
    #[serde(default)]
    pub creds_file: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub nkey_seed: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
}
```

Add `nats: NatsSettings` field to the existing `Settings` struct.

#### Subject Namespace

```
policies.<tenant_id>.<agent_id>       # KV bucket for policy documents
telemetry.<tenant_id>.<agent_id>.receipts    # JetStream stream for signed receipts
telemetry.<tenant_id>.<agent_id>.heartbeat   # JetStream stream for heartbeat events
commands.<tenant_id>.<agent_id>              # Request/reply for posture commands (Phase 4)
```

#### nats_client.rs

- `NatsClient::connect(settings: &NatsSettings) -> Result<Self>`
- Internally converts `NatsSettings` to `spine::NatsAuthConfig` and calls `spine::connect_with_auth`.
- Exposes `client()` and `jetstream()` accessors.
- Reconnect logic relies on `async-nats` built-in reconnect with configurable max attempts.
- `start_connection_monitor(shutdown_rx)`: watches connection status, emits events on disconnect/reconnect.

#### policy_sync.rs

- `PolicySyncWorker::new(js: JetStream, tenant_id, agent_id, policy_path: PathBuf)`
- `start(shutdown_rx)`: calls `ensure_kv` for the policy bucket, then `kv.watch_all()`.
- On KV entry update: write policy YAML to `policy_path`, emit `PolicyUpdated` event.
- On KV delete: no-op (keep last known policy -- fail-closed means keeping a policy is safer than having none).

#### telemetry_publisher.rs

- `TelemetryPublisher::new(js: JetStream, tenant_id, agent_id)`
- `publish_receipt(receipt: serde_json::Value) -> Result<()>`: publish to receipts stream.
- `publish_heartbeat(session_state: &SessionState) -> Result<()>`: publish to heartbeat stream.
- Uses `ensure_stream` to lazily create streams on first publish.

### Acceptance Criteria

- [ ] Agent connects to NATS when `nats.enabled = true` and `nats_url` is set.
- [ ] Policy updates via KV watch are written to the local policy file.
- [ ] hushd is signaled to reload on policy file change.
- [ ] Receipts are published to the correct JetStream subject.
- [ ] NATS connection loss does not crash the agent; reconnection is automatic.
- [ ] All NATS features are no-op when `nats.enabled = false`.
- [ ] Settings file migration is backwards-compatible (new fields have defaults).

### Test Strategy

- **Unit tests:** Mock `async-nats` client. Test policy_sync writes, telemetry_publisher subject formatting.
- **Integration tests:** Use embedded NATS server (nats-server binary in test harness) for
  end-to-end KV watch -> file write and publish -> consume verification.
- **Manual test:** Configure agent with a local NATS server, push a policy update via `nats kv put`,
  verify agent reloads.

### LOC Estimate

~600 new Rust lines + ~150 modified lines + ~400 test lines = **~1,150 total**

---

## Phase 3 -- Enrollment + Heartbeat

### Goal

Implement agent enrollment flow: the desktop agent authenticates to the enterprise cloud-api,
receives NATS credentials, and establishes a NATS-based heartbeat. The enterprise side gains
stale agent detection.

Addresses research brief gap: **G11** (fleet discovery / registration).

### File Change Table

| File Path | Action | Description |
|-----------|--------|-------------|
| `apps/agent/src-tauri/src/enrollment.rs` | create | Enrollment flow: generate Ed25519 keypair, POST to cloud-api `/agents`, store NATS credentials, persist enrollment state |
| `apps/agent/src-tauri/src/settings.rs` | modify | Add `EnrollmentState` and extend `NatsSettings` (token/account/subject_prefix/agent_id) for enrollment persistence |
| `apps/agent/src-tauri/src/session.rs` | modify | Extend heartbeat to also publish via NATS `telemetry_publisher` when enrolled |
| `apps/agent/src-tauri/src/api_server.rs` | modify | Add `POST /api/v1/enroll` and `GET /api/v1/enrollment-status` routes |
| `apps/agent/src-tauri/src/main.rs` | modify | On startup, check enrollment state; if enrolled, init NATS with stored credentials |
| `crates/services/cloud-api/src/routes/agents.rs` | modify | Add `POST /agents/enroll` endpoint that accepts enrollment token + public key, returns full NATS credentials |
| `crates/services/cloud-api/src/services/mod.rs` | modify | Add `stale_agent_detector` service module reference |
| `crates/services/cloud-api/src/services/stale_agent_detector.rs` | create | Background task: query agents where `last_heartbeat_at` < threshold, update status to `stale` |
| `crates/services/cloud-api/src/models/agent.rs` | modify | Add `EnrollmentRequest`/`EnrollmentResponse` types with structured NATS connection fields |

### Dependencies

- Phase 2 complete (NATS client and telemetry publisher exist in the desktop agent).
- `crates/services/cloud-api` (existing -- already has `register_agent`, `heartbeat` routes).

### Implementation Details

#### Enrollment Flow

```
1. Admin generates enrollment token via cloud-api dashboard/API
2. User enters enrollment token in desktop agent UI (or config file)
3. Agent generates Ed25519 keypair (using hush-core::Keypair::generate)
4. Agent POSTs to cloud-api:
   POST /api/v1/agents/enroll
   {
     "enrollment_token": "...",
     "public_key": "<hex>",
     "hostname": "...",
     "version": "..."
   }
5. cloud-api validates token, creates agent record, provisions NATS account credentials
6. cloud-api responds:
   {
     "agent_uuid": "...",
     "tenant_id": "...",
     "agent_id": "...",
     "nats_url": "...",
     "nats_account": "...",
     "nats_subject_prefix": "...",
     "nats_token": "..."
   }
7. Agent stores private signing key at ~/.config/clawdstrike/agent.key
8. Agent updates settings with enrollment + NATS connection state in `agent.json`
9. Agent initializes NATS client with new credentials
```

#### enrollment.rs

- `EnrollmentManager::enroll(cloud_api_url: &str, enrollment_token: &str) -> Result<EnrollmentResult>`
- Generates keypair, stores private key securely in `~/.config/clawdstrike/agent.key`.
- Stores NATS token/account/prefix/url directly in `Settings::nats`.
- Updates `Settings` with `EnrollmentState { enrolled: true, agent_uuid, tenant_id, ... }`.
- `is_enrolled(settings: &Settings) -> bool` -- checks if valid enrollment state exists.

#### NATS Heartbeat Extension

Extend `session.rs` heartbeat loop: after each successful HTTP heartbeat to hushd, also call
`telemetry_publisher.publish_heartbeat()` if NATS is connected. This provides the enterprise
with real-time agent liveness independent of the HTTP session.

#### Stale Agent Detection

Thresholds are aligned with Spec 15 Section 8.4:
- **Stale:** 120 seconds since last heartbeat (agent may be temporarily unreachable)
- **Dead:** 300 seconds since last heartbeat (agent is considered offline)

```rust
// stale_agent_detector.rs
const STALE_THRESHOLD_SECS: u64 = 120;
const DEAD_THRESHOLD_SECS: u64 = 300;

pub async fn run(db: PgPool, interval: Duration, shutdown_rx: Receiver<()>) {
    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => break,
            _ = tokio::time::sleep(interval) => {
                // Mark active agents as stale after 120s
                sqlx::query(
                    "UPDATE agents SET status = 'stale'
                     WHERE status = 'active'
                     AND last_heartbeat_at < now() - interval '120 seconds'"
                )
                .execute(&db)
                .await
                .ok();

                // Mark stale agents as dead after 300s
                sqlx::query(
                    "UPDATE agents SET status = 'dead'
                     WHERE status = 'stale'
                     AND last_heartbeat_at < now() - interval '300 seconds'"
                )
                .execute(&db)
                .await
                .ok();
            }
        }
    }
}
```

### Acceptance Criteria

- [ ] Agent can enroll using a valid enrollment token.
- [ ] Invalid/expired enrollment tokens are rejected with a clear error.
- [ ] NATS credentials are stored securely and used for subsequent connections.
- [ ] Agent heartbeat publishes to both HTTP (hushd) and NATS (enterprise) when enrolled.
- [ ] Stale agent detector marks agents as `stale` after 120s and `dead` after 300s (per Spec 15 Section 8.4).
- [ ] Re-enrollment overwrites previous credentials cleanly.
- [ ] Enrollment state persists across agent restarts.
- [ ] `/api/v1/enrollment-status` returns current enrollment state.

### Test Strategy

- **Unit tests:** Mock HTTP for cloud-api enrollment endpoint. Test keypair generation,
  credential storage, settings update.
- **Integration tests:** cloud-api + embedded PostgreSQL: full enrollment flow, heartbeat recording,
  stale detection trigger.
- **Edge cases:** Double enrollment, enrollment with expired token, NATS connection failure
  after successful enrollment, agent restart with stale credentials.

### LOC Estimate

~500 new Rust lines (agent) + ~200 modified lines + ~150 new Rust lines (cloud-api) + ~400 test lines = **~1,250 total**

---

## Phase 4 -- Posture Commands + Approval Escalation

### Goal

Enable bidirectional enterprise control: the enterprise can issue posture commands (mode change,
kill switch) to agents via NATS request/reply, and agents can escalate approval requests to the
enterprise for centralized decision-making.

### File Change Table

| File Path | Action | Description |
|-----------|--------|-------------|
| `apps/agent/src-tauri/src/posture_commands.rs` | create | NATS request subscriber: listen on `commands.<tenant_id>.<agent_id>`, handle `set_posture`, `kill_switch`, `request_policy_reload` commands |
| `apps/agent/src-tauri/src/approval.rs` | modify | Add NATS-based approval escalation: when local approval queue has pending items and enterprise is connected, publish to `approvals.<tenant_id>.<agent_id>.request` |
| `apps/agent/src-tauri/src/main.rs` | modify | Wire posture command subscriber into agent lifecycle |
| `apps/agent/src-tauri/src/events.rs` | modify | Add event types for posture command received, approval escalation sent/resolved |
| `crates/services/cloud-api/src/routes/agents.rs` | modify | Add `POST /agents/{id}/command` route for sending posture commands via NATS |
| `crates/services/cloud-api/src/routes/mod.rs` | modify | Register new approval routes |
| `crates/services/cloud-api/src/routes/approvals.rs` | create | `GET /approvals` (list pending), `POST /approvals/{id}/resolve` (approve/deny), NATS subscriber for incoming escalations |
| `crates/services/cloud-api/src/models/mod.rs` | modify | Register approval model |
| `crates/services/cloud-api/src/models/approval.rs` | create | `Approval` model: id, tenant_id, agent_id, event_type, event_data, status (pending/approved/denied), resolved_by, resolved_at |

### Dependencies

- Phase 3 complete (enrollment + NATS connectivity established).
- Existing `apps/agent/src-tauri/src/approval.rs` (local approval queue).

### Implementation Details

#### Posture Command Protocol

```
Subject: commands.<tenant_id>.<agent_id>
Request payload:
{
  "command": "set_posture" | "kill_switch" | "request_policy_reload",
  "params": { ... },
  "issued_by": "admin@example.com",
  "issued_at": "2026-02-26T..."
}

Reply payload:
{
  "status": "ok" | "error",
  "message": "...",
  "agent_state": { posture, session_id, ... }
}
```

#### Kill Switch

The `kill_switch` command:
1. Immediately sets posture to `locked` (deny-all).
2. Terminates the hushd session.
3. Disables all policy evaluation (everything denied).
4. Publishes confirmation to NATS.
5. Can only be reversed by a `set_posture` command with admin authorization.

#### Approval Escalation

When a policy evaluation results in a decision requiring approval (`reason_code` contains
`APPROVAL_REQUIRED`):
1. Agent adds to local approval queue (existing behavior).
2. If NATS is connected, agent publishes escalation to `approvals.<tenant_id>.<agent_id>.request`.
3. Enterprise cloud-api receives escalation, stores in database, notifies admin dashboard.
4. Admin resolves via dashboard/API.
5. Resolution is published to `approvals.<tenant_id>.<agent_id>.response`.
6. Agent receives resolution, updates local approval queue.

### Acceptance Criteria

- [ ] Agent subscribes to posture commands on NATS when enrolled.
- [ ] `set_posture` command changes agent posture and confirms via reply.
- [ ] `kill_switch` command immediately locks the agent and deny-all decisions.
- [ ] `request_policy_reload` triggers a policy file re-read and hushd reload.
- [ ] Approval escalations are published to NATS and stored in cloud-api database.
- [ ] Admin can list and resolve approval requests via cloud-api REST routes.
- [ ] Resolution is delivered back to agent via NATS.
- [ ] All commands are authenticated (NATS account isolation + command signing).
- [ ] Agent handles commands gracefully when NATS disconnects mid-operation.

### Test Strategy

- **Unit tests:** Mock NATS subscription. Test command parsing, posture state transitions,
  kill switch behavior, approval escalation publish.
- **Integration tests:** Full NATS request/reply cycle with embedded NATS server.
  Verify command -> posture change -> confirmation flow.
- **Security tests:** Verify commands from wrong tenant are rejected. Verify kill switch
  cannot be bypassed by local API.

### LOC Estimate

~450 new Rust lines (agent) + ~200 modified lines + ~350 new Rust lines (cloud-api) + ~400 test lines = **~1,400 total**

---

## Phase 5 -- hushd-to-Spine Integration

### Goal

Wire the Spine signed envelope system into the hushd decision flow so that every policy
evaluation produces a cryptographically signed, chained attestation record that is published
to NATS for enterprise audit consumption.

### File Change Table

| File Path | Action | Description |
|-----------|--------|-------------|
| `crates/services/hushd/src/spine_publisher.rs` | create | Spine envelope publisher: wraps `build_signed_envelope()`, maintains sequence counter and chain hash, publishes to NATS JetStream |
| `crates/services/hushd/src/api/eval.rs` | modify | After eval decision, call `spine_publisher.publish_eval_receipt()` with decision, event, and policy context |
| `crates/services/hushd/src/config.rs` | modify | Add `SpineConfig` struct: `enabled`, `nats_url`, `nats_auth`, `keypair_path`, `stream_name` |
| `crates/services/hushd/src/lib.rs` | modify | Initialize `SpinePublisher` on startup when `spine.enabled = true` |
| `crates/services/hushd/src/api/mod.rs` | modify | Add `POST /api/v1/receipts/replay` endpoint for store-and-forward receipt ingestion from adaptive engine (Phase 1) |
| `crates/libs/spine/src/lib.rs` | modify | Re-export `build_signed_envelope`, `verify_envelope` for ergonomic access |
| `crates/services/cloud-api/src/services/audit_consumer.rs` | create | NATS JetStream consumer: subscribe to `spine.receipts.*`, store envelopes in audit ledger (PostgreSQL), verify chain integrity |
| `crates/services/cloud-api/src/services/mod.rs` | modify | Register audit_consumer service |

### Dependencies

- Phase 2 complete (NATS infrastructure). This is the only phase dependency -- Phase 5 operates
  on hushd and cloud-api, which are independent of Phase 3 (enrollment) and Phase 4 (posture
  commands). Phase 5 can therefore run in parallel with Phase 3.
- `crates/libs/spine` (existing -- `build_signed_envelope`, `verify_envelope`, `NatsAuthConfig`).
- `crates/services/hushd` (existing -- eval endpoint at `api/eval.rs`).

### Implementation Details

#### Spine Publisher (spine_publisher.rs)

```rust
pub struct SpinePublisher {
    js: async_nats::jetstream::Context,
    keypair: hush_core::Keypair,
    seq: AtomicU64,
    prev_hash: Mutex<Option<String>>,
    subject_prefix: String,
}

impl SpinePublisher {
    pub async fn new(config: &SpineConfig, js: JetStream) -> Result<Self>;

    pub async fn publish_eval_receipt(
        &self,
        decision: &serde_json::Value,
        event: &serde_json::Value,
        policy_ref: &str,
        session_id: Option<&str>,
    ) -> Result<()> {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let prev_hash = self.prev_hash.lock().await.clone();

        let fact = json!({
            "type": "policy.eval",
            "decision": decision,
            "event_type": event.get("eventType"),
            "event_id": event.get("eventId"),
            "policy_ref": policy_ref,
            "session_id": session_id,
        });

        let envelope = build_signed_envelope(
            &self.keypair,
            seq,
            prev_hash,
            fact,
            now_rfc3339(),
        )?;

        let hash = envelope.get("envelope_hash")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // Publish to JetStream
        let subject = format!("{}.receipts.eval", self.subject_prefix);
        self.js.publish(subject, serde_json::to_vec(&envelope)?.into()).await?;

        // Update chain
        *self.prev_hash.lock().await = Some(hash);

        Ok(())
    }
}
```

#### Envelope Fact Schema for Eval Decisions

```json
{
  "type": "policy.eval",
  "decision": {
    "status": "allow|warn|deny",
    "reason_code": "...",
    "guard": "...",
    "severity": "..."
  },
  "event_type": "file_write",
  "event_id": "evt-uuid",
  "policy_ref": "strict",
  "session_id": "sess-uuid"
}
```

#### Receipts Replay Endpoint

`POST /api/v1/receipts/replay` accepts an array of signed envelopes from the adaptive engine's
store-and-forward queue. Each envelope is verified (`verify_envelope`), then published to the
same Spine JetStream subject. Replayed envelopes carry a `replayed: true` metadata flag.

#### Audit Consumer (cloud-api)

- Subscribes to `spine.receipts.>` on JetStream.
- For each message: `verify_envelope`, extract fact, insert into `audit_log` table.
- Chain integrity check: verify `prev_envelope_hash` matches the last stored envelope hash
  for that issuer. Log a chain-break warning if mismatched (do not reject -- offline receipts
  may arrive out of order).

### Acceptance Criteria

- [ ] Every hushd eval produces a signed Spine envelope.
- [ ] Envelopes are correctly chained via `prev_envelope_hash`.
- [ ] Envelopes are published to JetStream and consumable by cloud-api.
- [ ] `verify_envelope()` succeeds for all published envelopes.
- [ ] Receipts replay endpoint accepts and re-publishes offline envelopes.
- [ ] Replayed envelopes are tagged with `replayed: true`.
- [ ] Audit consumer stores envelopes in PostgreSQL with chain integrity checks.
- [ ] Spine publisher is no-op when `spine.enabled = false`.
- [ ] Sequence numbers are monotonically increasing per hushd instance.
- [ ] Publisher handles NATS disconnection gracefully (log warning, skip publish, do not block eval).

### Test Strategy

- **Unit tests:** Test envelope construction, chain linking, fact schema.
  Mock JetStream publish to verify subject and payload format.
- **Integration tests:** hushd with embedded NATS: eval -> publish -> consume -> verify chain.
  Test replay endpoint with pre-signed envelopes.
- **Property tests:** Use `proptest` to verify that arbitrary fact values produce valid
  envelopes that pass `verify_envelope`.
- **Chain integrity tests:** Publish N envelopes, verify chain is unbroken.
  Simulate out-of-order replay and verify consumer handles gracefully.

### LOC Estimate

~400 new Rust lines (hushd) + ~200 modified lines + ~300 new Rust lines (cloud-api consumer) + ~350 test lines = **~1,250 total**

---

## Summary

| Phase | Package/Crate | New Files | Modified Files | Est. LOC | Gaps Addressed |
|-------|--------------|-----------|----------------|----------|----------------|
| 1 | `clawdstrike-engine-adaptive` (TS) | 12 | 0 | ~1,400 | G1, G2, G3, G6, G7 |
| 2 | Desktop agent (Rust) | 3 | 4 | ~1,150 | G5 |
| 3 | Desktop agent + cloud-api (Rust) | 2 | 5 | ~1,250 | G11 |
| 4 | Desktop agent + cloud-api (Rust) | 3 | 5 | ~1,400 | -- |
| 5 | hushd + spine + cloud-api (Rust) | 2 | 4 | ~1,250 | -- |
| **Total** | | **22** | **18** | **~6,450** | |

### Sequencing

```
Phase 1 (engine-adaptive, TS)  ────────────────────────────►
Phase 2 (NATS sync, Rust)  ────────────────────────────────►
                                 Phase 3 (enrollment)  ────────────────►
                                 Phase 5 (spine)  ─────────────────────►
                                                        Phase 4 (commands)  ──────►
```

- Phases 1 and 2 can run in parallel (TypeScript vs. Rust, no shared code).
- Phase 5 can run in parallel with Phase 3: both depend only on Phase 2 (NATS).
  Phase 5 operates on hushd + cloud-api audit consumer, which are independent of
  desktop agent enrollment (Phase 3) and posture commands (Phase 4).
- Phase 4 depends on Phase 3 (requires enrollment + NATS connectivity).

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| NATS server unavailability during testing | Embed `nats-server` binary in CI; provide docker-compose for local dev |
| Envelope schema migration (`aegis` -> `clawdstrike` prefix, C6) | Phase 5 uses existing `aegis.spine.envelope.v1` schema; namespace migration is a separate follow-up |
| IAM dependency (G10) | Phases use API key auth throughout; full IAM (OIDC/SAML) is a separate workstream per R6 |
| Agent port conflicts (G8) | Phase 1 probe uses configurable `baseUrl`; port configurability is out of scope |
| Concurrent mode transitions | Phase 1 mode machine uses a mutex to serialize transitions |
