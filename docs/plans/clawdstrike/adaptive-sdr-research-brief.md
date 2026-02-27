# Adaptive Local ↔ Enterprise Architecture — Codebase Research Brief

> **Date:** 2026-02-26
> **Author:** research agent (T1)
> **Status:** Complete
> **Audience:** Spec-15 authors, implementation team

---

## 1. Executive Summary

The clawdstrike-remote codebase already implements a two-tier policy evaluation architecture: a **local CLI engine** (`hush-cli-engine`) that spawns the `hush` binary and a **remote daemon engine** (`hushd-engine`) that posts to a running `hushd` HTTP service. Both engines implement the frozen `PolicyEngineLike` contract from `adapter-core`. The remote engine includes a fallback mechanism that delegates to any `PolicyEngineLike` (typically the local engine) when the daemon is unreachable, tagging decisions with `{ mode: 'degraded' }` provenance.

The desktop agent (`apps/agent`) exposes a local API server on port **9878** with routes for policy checks, OpenClaw gateway management, session lifecycle, OTA updates, and approval workflows. The agent maintains a session with `hushd` via a 30-second heartbeat loop with exponential-backoff retry.

The Spine attestation layer uses NATS JetStream for transport with three auth modes (creds file, token, NKey seed) and Ed25519-signed envelopes with SHA-256 chaining.

Existing specs cover Helm-chart deployment (Spec 09) and multi-tenant SaaS (Spec 14). IAM plans define a comprehensive identity architecture (OIDC/SAML bridge, RBAC with 10 roles, policy scoping, session context) but remain unimplemented. Several gaps exist between the current code and the planned architecture, most notably: no runtime mode negotiation protocol, no graceful promotion/demotion between local and enterprise modes, and no unified configuration surface for the adaptive behavior.

---

## 2. Interface Inventory

### 2.1 PolicyEngineLike (Frozen Contract)

**File:** `packages/adapters/clawdstrike-adapter-core/src/engine.ts`

```typescript
export interface PolicyEngineLike {
  evaluate(event: PolicyEvent): Promise<Decision> | Decision;
  redactSecrets?(value: string): string;
}
```

- Return type is `Promise<Decision> | Decision` — allows both sync and async implementations.
- `redactSecrets` is optional; only local engines currently implement it.
- **Frozen**: all engines must conform. Any new capability must be expressed through `PolicyEvent.metadata` or `Decision.details`, not new interface methods.

### 2.2 Decision Type

**File:** `packages/adapters/clawdstrike-adapter-core/src/types.ts`

```typescript
export type DecisionStatus = 'allow' | 'warn' | 'deny';

export type Decision =
  | (DecisionBase & { status: 'allow'; reason_code?: DecisionReasonCode })
  | (DecisionBase & { status: 'warn' | 'deny'; reason_code: DecisionReasonCode });
```

Key invariant: `reason_code` is **required** for `warn` and `deny` statuses, optional for `allow`.

### 2.3 PolicyEvent & EventType

**File:** `packages/adapters/clawdstrike-adapter-core/src/types.ts`

```typescript
export type EventType =
  | 'file_read' | 'file_write' | 'command_exec' | 'network_egress'
  | 'tool_call' | 'patch_apply' | 'secret_access' | 'custom'
  | 'remote.session.connect' | 'remote.session.disconnect'
  | 'remote.session.reconnect' | 'input.inject'
  | 'remote.clipboard' | 'remote.file_transfer' | 'remote.audio'
  | 'remote.drive_mapping' | 'remote.printing' | 'remote.session_share';

export interface PolicyEvent {
  eventId: string;
  eventType: EventType;
  timestamp: string;
  sessionId?: string;
  data: EventData;
  metadata?: Record<string, unknown>;
}
```

EventData is a discriminated union on `type`: `file`, `command`, `network`, `tool`, `patch`, `secret`, `custom`, `cua`.

### 2.4 Response Parsing & Fail-Closed

**File:** `packages/adapters/clawdstrike-adapter-core/src/engine-response.ts`

```typescript
export function parsePolicyEvalResponse(raw: string, source: string): PolicyEvalParsed;
export function failClosed(error: unknown): Decision;
// failClosed returns: { status: 'deny', reason_code: 'ADC_GUARD_ERROR', ... }
```

- `parsePolicyEvalResponse` expects `{ version: 1, command: 'policy_eval', decision }`.
- `parseDecision` handles both the current `status` field and legacy boolean fields (`allowed`, `denied`, `warn`).
- `failClosed` always returns a deny with reason code `ADC_GUARD_ERROR`.

### 2.5 StrikeCellOptions — Local (hush-cli-engine)

**File:** `packages/adapters/clawdstrike-hush-cli-engine/src/strike-cell.ts`

```typescript
export interface StrikeCellOptions {
  hushPath?: string;    // default: 'hush'
  policyRef: string;    // required — policy file or built-in name
  resolve?: boolean;    // --resolve flag for policy inheritance
  timeoutMs?: number;   // default: 10_000
}
```

- Spawns `hush policy eval <policyRef> - --json` as a child process.
- Pipes the `PolicyEvent` as JSON to stdin; reads JSON decision from stdout.
- Exit codes 0 (ok), 1 (warn), 2 (blocked) are non-fatal; codes < 0 or > 2 throw.
- Stderr is captured and appended to error messages (truncated to 2048 chars).

### 2.6 StrikeCellOptions — Remote (hushd-engine)

**File:** `packages/adapters/clawdstrike-hushd-engine/src/strike-cell.ts`

```typescript
export interface StrikeCellOptions {
  baseUrl: string;           // required — hushd URL
  token?: string;            // Bearer token
  timeoutMs?: number;        // default: 10_000
  fallback?: PolicyEngineLike;     // optional fallback engine
  offlineFallback?: boolean;       // default: true
}
```

- Posts to `${baseUrl}/api/v1/eval` with `{ event }` body.
- Uses `AbortController` for timeout enforcement.
- Bearer token sent in `Authorization` header when provided.
- Response body truncated to 2048 chars in error messages.

### 2.7 Adapter-Core Public API Surface

**File:** `packages/adapters/clawdstrike-adapter-core/src/index.ts`

Exports: `PolicyEngineLike`, all types from `types.ts`, `parsePolicyEvalResponse`, `failClosed`, `parseDecision`, `createDecision`, `allowDecision`, `denyDecision`, `warnDecision`.

---

## 3. Pattern Analysis

### 3.1 Fallback / Degraded-Mode Pattern

**File:** `packages/adapters/clawdstrike-hushd-engine/src/strike-cell.ts` (lines 41-62)

The remote engine wraps the primary evaluation in a try/catch. On connectivity errors (and only connectivity errors), it optionally delegates to a fallback engine:

```typescript
if (offlineFallback && fallback && isConnectivityError(error)) {
  const decision = await fallback.evaluate(event);
  return {
    ...decision,
    details: { ...decision.details, provenance: { mode: 'degraded' } },
  };
}
return failClosed(error);
```

**Connectivity error detection** (`isConnectivityError`):
- `ECONNREFUSED`, `ECONNRESET`, `ENOTFOUND`, `fetch failed`, `network`, `abort`, `timeout`, `ETIMEDOUT`
- Notably: HTTP 4xx/5xx responses are **not** treated as connectivity errors — they fail closed.

**Provenance constant:** `{ mode: 'degraded' as const }`

**Key design decisions:**
- `offlineFallback` defaults to `true` — fallback is opt-out, not opt-in.
- If the fallback engine itself throws, the outer catch returns `failClosed(fallbackError)`.
- The provenance tag is shallow-merged into `decision.details`, preserving any existing details from the fallback engine.

### 3.2 Authentication Patterns

#### 3.2.1 Desktop Agent Auth

**File:** `apps/agent/src-tauri/src/api_server.rs`

- Local API server binds to `127.0.0.1:9878` (localhost only).
- Client authentication via Bearer token in cookie `clawdstrike_agent_auth`.
- Daemon auth forwarding: the desktop agent reads `x-hushd-authorization` from incoming requests and forwards it to hushd.
- `AgentApiServerDeps` includes `auth_token: Option<String>`.

#### 3.2.2 hushd Auth

**File:** `crates/services/hushd/src/config.rs`

```rust
pub struct AuthConfig {
    pub enabled: bool,
    pub api_keys: Vec<ApiKeyConfig>,
}

pub struct ApiKeyConfig {
    pub name: String,
    pub key: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<String>,
}
```

Supports:
- API key auth with named keys, scopes, and expiration.
- Identity providers: OIDC (issuer URL, client ID/secret, JWKS), Okta, Auth0, SAML.
- RBAC with enabled flag and group-to-role mapping.
- Policy scoping with cache (TTL + max entries) and escalation prevention.

#### 3.2.3 NATS Transport Auth

**File:** `crates/libs/spine/src/nats_transport.rs`

```rust
pub struct NatsAuthConfig {
    pub creds_file: Option<String>,
    pub token: Option<String>,
    pub nkey_seed: Option<String>,
}
```

Three mutually-exclusive auth modes: credentials file, token string, or NKey seed. The `connect_with_auth` function selects the first non-None field in priority order: creds_file > token > nkey_seed.

Helpers: `ensure_kv(js, bucket)` and `ensure_stream(js, name, subjects)` for JetStream resource provisioning.

### 3.3 Signed Envelope Format

**File:** `crates/libs/spine/src/envelope.rs`

```
Schema:  "aegis.spine.envelope.v1"
Issuer:  "aegis:ed25519:<64-char-hex-public-key>"
```

Fields:
| Field | Type | Purpose |
|-------|------|---------|
| `schema` | string | Version identifier |
| `issuer` | string | Ed25519 public key URN |
| `seq` | u64 | Monotonic sequence number |
| `prev_envelope_hash` | Option<String> | SHA-256 of previous envelope (chain integrity) |
| `issued_at` | string | ISO-8601 timestamp |
| `capability_token` | Option<String> | Authorization context |
| `fact` | serde_json::Value | Arbitrary payload |
| `envelope_hash` | string | SHA-256 of canonical JSON (excluding hash + sig) |
| `signature` | string | Ed25519 signature of envelope_hash |

Signing process:
1. Serialize envelope fields (excluding `envelope_hash` and `signature`) to canonical JSON (RFC 8785).
2. SHA-256 hash the canonical bytes → `envelope_hash`.
3. Ed25519 sign the `envelope_hash` → `signature`.

Verification: `verify_envelope()` re-derives the hash from canonical JSON and validates the Ed25519 signature against the issuer's public key.

Chain integrity: `prev_envelope_hash` links envelopes into an append-only chain.

### 3.4 Session Manager & Heartbeat

**File:** `apps/agent/src-tauri/src/session.rs`

```
Session State:
  session_id: String
  posture: String         (extracted from state["posture"]["current_state"])
  budget_used: u64
  budget_limit: u64

Heartbeat:
  Interval: 30 seconds
  Endpoint: GET /api/v1/session/{id}
  Outcomes: NoSession | Updated | Invalidated

Session Creation:
  Endpoint: POST /api/v1/session
  Body: { client, version, hostname }
  Retry: exponential backoff 250ms → 10s max
```

Lifecycle management:
- A lifecycle lock serializes create/replace/terminate operations to prevent races.
- Invalidation: HTTP 404, 401, or 403 responses clear the local session state.
- The `ensure_session` loop retries with exponential backoff when creation fails.
- Posture is nested: `response.state.posture.current_state` — this deeply-nested extraction is fragile.

---

## 4. Existing Spec Summary

### 4.1 Spec 09 — Helm Chart

**File:** `docs/specs/09-helm-chart.md`

Defines the Kubernetes deployment of the full SDR (Security Decision Runtime) stack:
- **Components:** NATS cluster, Spine services, hushd, bridge DaemonSets.
- **OCI publishing:** Helm chart to GHCR at `ghcr.io/backbay/clawdstrike-helm`.
- **CI/CD:** `helm lint`, `helm template`, integration tests.
- **Open item:** hushd Dockerfile does not yet exist; spec calls for its creation.
- **Relevance to Spec 15:** Defines the enterprise deployment topology that the adaptive architecture must target.

### 4.2 Spec 14 — ClawdStrike Cloud (Managed SaaS)

**File:** `docs/specs/14-clawdstrike-cloud.md`

Multi-tenant managed service architecture:
- **Tiers:** Team ($15-25/agent/month), Enterprise ($5K+/month), Verified Publisher.
- **Isolation:** Per-tenant NATS account isolation; PostgreSQL control plane.
- **Services:** `cloud-api` (Rust/Axum), web dashboard (React SPA), Stripe billing.
- **Key architectural decisions:**
  - Tenant isolation via NATS accounts, not separate clusters.
  - Control plane in PostgreSQL; data plane in NATS JetStream.
  - Dashboard serves as management UI for policies, audit logs, and fleet.
- **Relevance to Spec 15:** The cloud tier is the enterprise endpoint that local agents connect to. Spec 15 must define how a local agent discovers, authenticates to, and synchronizes with a cloud tenant.

---

## 5. IAM Plan Summary

**Source:** `docs/plans/identity-access/` (6 documents)

### 5.1 Overview (`overview.md`)

Defines `IdentityPrincipal` (TS + Rust) and `EnhancedGuardContext`. Token flow: IdP → IdentityBridge → claim mapping → PolicyEngineLike evaluation with identity context. Four-phase implementation plan (foundations → RBAC → scoping → advanced).

### 5.2 RBAC (`rbac.md`)

10 built-in roles: `super-admin`, `org-admin`, `team-admin`, `policy-author`, `policy-reviewer`, `security-analyst`, `auditor`, `agent-operator`, `viewer`, `session-manager`.

Permission model: `Permission = { resource: Resource, action: Action, constraints: Constraint[] }`. Scope hierarchy: global → org → team → project → user. Constraint types: scope, attribute, time-based, approval-required.

### 5.3 OIDC/SAML (`oidc-saml.md`)

`IdentityBridge` trait with `authenticate(token) → IdentityPrincipal`. OIDC: standard discovery + JWKS caching. SAML: attribute mapping, signature validation. Multi-tenant issuer isolation. Replay protection via nonce/jti tracking.

### 5.4 Okta/Auth0 (`okta-auth0.md`)

Platform-specific adapters: `OktaAdapter`, `Auth0Adapter`. Group-to-role mapping. Webhook handlers for user lifecycle (deprovisioning). Auth0 organization-based multi-tenancy.

### 5.5 Policy Scoping (`policy-scoping.md`)

Identity-based policy resolution: `PolicyScope` hierarchy. `ScopeCondition` evaluation against identity claims. Policy merge strategies: `replace`, `merge`, `deep_merge`. Escalation prevention (cannot grant broader permissions than own scope). Cache with configurable TTL and max entries.

### 5.6 Session Context (`session-context.md`)

`SessionContext` and `SessionManager` interfaces. Session binding to identity. CSRF protection. Org isolation (session cannot cross org boundary). Per-user rate limiting.

### 5.7 IAM Implementation Status

**None of the IAM plans are implemented.** The hushd config structs (`AuthConfig`, `IdentityConfig`, `RbacConfig`, `PolicyScopingConfig`) define the configuration surface but the actual OIDC/SAML bridge, RBAC enforcement, and policy scoping logic are not present in the current codebase.

---

## 6. Gap Analysis

### G1 — No Mode Negotiation Protocol
There is no protocol for a local agent to discover whether an enterprise hushd is available, negotiate capabilities, or agree on a communication mode. The current fallback is purely reactive (catches connectivity errors after they occur).

### G2 — No Graceful Promotion/Demotion
The transition between local-only and enterprise-connected modes is binary: the remote engine either reaches hushd or falls back. There is no staged promotion (e.g., local → cached-enterprise-policy → full-enterprise) or graceful demotion with policy state preservation.

### G3 — No Unified Adaptive Configuration
The local and remote `StrikeCellOptions` are separate types with no shared configuration surface. An adaptive engine would need a combined configuration that specifies both local and remote parameters plus mode-selection preferences.

### G4 — Missing hushd Session API in TypeScript
The session manager exists only in Rust (`session.rs`). The TypeScript adapter packages have no session concept — the `hushd-engine` StrikeCell makes stateless HTTP calls with no session binding.

### G5 — No Policy Sync / Cache-Ahead
When the remote engine is available, there is no mechanism to pre-cache or sync policies for offline use. The fallback engine must independently load its own policy (via `policyRef` in the CLI engine).

### G6 — Degraded Provenance Is Shallow
The `{ mode: 'degraded' }` provenance tag is the only signal of offline operation. There is no indication of: why the fallback was triggered, how stale the local policy is, whether the decision would differ under enterprise evaluation, or what capabilities are lost.

### G7 — No Audit Bridge for Offline Decisions
Decisions made during offline/degraded mode are not queued for later submission to the enterprise audit ledger. The Spine envelope system could support this but no "store-and-forward" pattern exists.

### G8 — Desktop Agent Port Hardcoded
Port 9878 appears hardcoded in `api_server.rs`. No configuration mechanism for port selection or conflict resolution.

### G9 — Session Posture Extraction Is Fragile
The session manager extracts posture from `state["posture"]["current_state"]` — a deeply nested JSON path with no schema validation. Changes to the hushd session response format would silently break posture tracking.

### G10 — IAM Plans Are Entirely Unimplemented
The identity-access plans define a comprehensive architecture (OIDC/SAML bridge, 10-role RBAC, policy scoping, session context) but none of it exists in code. The hushd config structs define the shape but not the behavior.

### G11 — No Fleet Discovery / Registration
Spec 14 mentions fleet management but there is no agent-side registration or discovery protocol. The desktop agent connects to a pre-configured hushd URL with no mechanism for fleet enrollment or tenant association.

### G12 — hushd Dockerfile Missing
Spec 09 explicitly calls out that a hushd Dockerfile needs to be created but does not yet exist.

---

## 7. Contradictions & Conflicts

### C1 — Fallback Default vs. Fail-Closed Philosophy
The `offlineFallback` option defaults to `true`, meaning the system prefers availability (using a potentially staler local policy) over strict fail-closed behavior. This contradicts the project's stated "fail-closed" design philosophy. The reconciliation is that the local engine itself fails closed — but the *mode selection* is fail-open.

### C2 — Session Manager vs. Stateless StrikeCell
The desktop agent maintains a session with heartbeat, posture, and budget tracking (`session.rs`), but the TypeScript `hushd-engine` StrikeCell makes stateless `/api/v1/eval` calls with no session binding. This means TypeScript-based adapters (used in Node.js agent runtimes) cannot participate in session-scoped policies or budget enforcement.

### C3 — Auth Token Forwarding Ambiguity
The desktop agent forwards `x-hushd-authorization` headers from clients to hushd, but also has its own `auth_token` in `AgentApiServerDeps`. It is unclear which auth context takes precedence when both are present, and how this interacts with the IAM plan's session-bound identity.

### C4 — Spec 14 Tenant Isolation vs. Current NATS Auth
Spec 14 specifies per-tenant NATS account isolation, but `nats_transport.rs` has a single `NatsAuthConfig` with no tenant-scoping concept. The current NATS transport assumes a single-tenant connection.

### C5 — EventType Remote Events Not Consumed
The `EventType` union includes remote desktop events (`remote.session.connect`, `remote.clipboard`, `remote.file_transfer`, etc.) and CUA events (`input.inject`), but no guard or policy rule in the current codebase evaluates these event types. They are defined but dead.

### C6 — Envelope Schema Namespace
The envelope uses `"aegis.spine.envelope.v1"` as its schema identifier, but the project has been rebranded from "aegis" to "clawdstrike". The issuer URN also uses the `aegis:` prefix. This will create confusion if not migrated.

---

## 8. Recommendations

### R1 — Define a Mode Negotiation Handshake
Introduce a lightweight discovery endpoint (e.g., `GET /api/v1/capabilities`) that returns the hushd version, supported features, and tenant context. The adaptive engine should probe this at startup and on reconnection rather than relying solely on connectivity error detection.

### R2 — Introduce an Adaptive Engine Wrapper
Create a new package (or extend `adapter-core`) with an `AdaptiveStrikeCell` that:
- Accepts both local and remote `StrikeCellOptions`.
- Manages mode transitions (local → enterprise → degraded → local).
- Emits mode-change events for observability.
- Preserves the `PolicyEngineLike` contract (no interface changes).

### R3 — Add Session Awareness to TypeScript StrikeCell
Extend the `hushd-engine` StrikeCellOptions with an optional `sessionId` that gets attached to eval requests. This bridges the gap between the Rust session manager and TypeScript adapters.

### R4 — Implement Store-and-Forward Audit
Leverage the Spine envelope format to queue decisions made during degraded mode. On reconnection, replay the signed envelopes to the enterprise audit ledger. The `prev_envelope_hash` chaining already supports append-only integrity.

### R5 — Enrich Degraded Provenance
Extend the provenance metadata to include: `reason` (why fallback triggered), `local_policy_ref` (which policy was used), `local_policy_age` (staleness), and `capabilities_lost` (what enterprise features were unavailable).

### R6 — Prioritize IAM Phase 1
The IAM plans are well-designed but entirely unimplemented. Spec 15 should either depend on IAM Phase 1 (identity bridge + basic RBAC) or explicitly define a minimal auth contract that can be replaced by the full IAM system later.

### R7 — Migrate Envelope Schema Namespace
Update `"aegis.spine.envelope.v1"` to `"clawdstrike.spine.envelope.v1"` (or v2) and the `aegis:ed25519:` issuer prefix to `clawdstrike:ed25519:`. Include a migration path for existing signed envelopes.

### R8 — Make Desktop Agent Port Configurable
Add port configuration to the agent settings (with 9878 as default) and implement port-conflict detection at startup.
