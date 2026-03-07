# Origin Enclaves — Architecture & Codebase Index

> Status: Research complete, roadmap drafted, critic review applied (v0.2)
> Branch: feat/enclaves
> Date: 2026-03-07

This document maps the Origin Enclaves product spec to the existing Clawdstrike codebase, identifying every integration point, extension surface, and dependency.

---

## 1. Existing Primitives Summary

Origin Enclaves builds on top of — not alongside — these existing systems:

| Primitive | Status | Location | Relevance to Enclaves |
|-----------|--------|----------|----------------------|
| Policy schema v1.1.0–1.3.0 | Shipped | `crates/libs/clawdstrike/src/policy.rs:24-29` | New `origins` top-level field at v1.4.0 |
| Policy `extends` + merge | Shipped | `policy.rs:1044-1150` | Enclave profiles inherit from base rulesets |
| Guard trait + pipeline | Shipped | `guards/mod.rs:275-286`, `engine.rs:350-431` | Enclaves feed into existing guard stack |
| McpToolGuard | Shipped | `guards/mcp_tool.rs:20-314` | Enclave projects filtered tool surface into mcp_tool |
| Posture state machine | Shipped | `posture.rs:30-599` | Enclaves set initial posture per origin |
| Posture transitions | Shipped | `posture.rs:74-110` | UserApproval, CriticalViolation, BudgetExhausted |
| Signed receipts | Shipped | `hush-core/src/receipt.rs:154-294` | Extend `metadata` with origin fields |
| Spine envelopes | Shipped | `spine/src/envelope.rs:77-163` | Transport for origin-enriched receipts |
| GuardContext | Shipped | `guards/mod.rs:170-254` | **Proposed:** add `origin: Option<OriginContext>` field |
| IdentityPrincipal | Shipped | `identity.rs:28-80` | Actor identity for origin resolution |
| OrganizationContext | Shipped | `identity.rs:91-99` | Tenant scoping |
| RequestContext | Shipped | `identity.rs` | IP, geo, VPN — supplementary trust signals |
| Approval queue (DB) | Shipped | `control-api/src/models/approval.rs` | Reuse for origin-bound approvals |
| Approval outbox | Shipped | `control-api/src/services/approval_resolution_outbox.rs` | Durable delivery of approval resolutions |
| NATS transport | Shipped | `spine/src/nats_transport.rs` | Subject-scoped messaging per tenant |
| GenericInboundMessage | Shipped | `adapter-core/src/adapter.ts` | Proto-OriginContext: has source, channel, chatType |
| SecurityContext | Shipped | `adapter-core/src/context.ts` | Session state for TS adapters |
| OpenClaw inbound hook | Shipped | `clawdstrike-openclaw/src/hooks/inbound-message/` | First integration point for origin data |
| Fleet delegation graph | Shipped | `control-api/migrations/014_grants_delegation_graph.sql` | Grant lineage for cross-origin bridges |
| Response actions | Shipped | `control-api/src/routes/response_actions.rs` | TransitionPosture, KillSwitch per origin |
| Console + SSE | Shipped | `control-api/src/routes/console.rs` | Add enclave views |
| Detection rules | Shipped | `control-api/src/routes/alerts.rs` | Origin-aware detection rules |
| Cases & evidence | Shipped | `control-api/src/routes/cases.rs` | Origin-tagged evidence bundles |
| Webhook handlers | Shipped | `hushd/src/api/webhooks.rs` | Okta/Auth0; pattern for Slack/GitHub webhooks |
| Slack/Teams plans | Planned | `docs/plans/siem-soar/slack-teams.md` | Alerting integration (not origin ingestion yet) |

---

## 2. Codebase Insertion Points

### 2.1 Policy Schema Extension (v1.4.0)

**Files to modify:**
- `crates/libs/clawdstrike/src/policy.rs`
  - Add `"1.4.0"` to `POLICY_SUPPORTED_SCHEMA_VERSIONS` (line 29)
  - Add `origins: Option<OriginsConfig>` to `Policy` struct (after line 207)
  - Add `OriginsConfig`, `OriginProfile`, `OriginMatch` structs
  - Add merge logic in `GuardConfigs::merge_with()` for origin profiles
  - Add version gate: `policy_version_supports_origins()` requiring >= 1.4.0

**New types needed:**
```
OriginsConfig { default_behavior, profiles: Vec<OriginProfile> }
OriginProfile {
  id, match_rules: OriginMatch, posture, explanation,
  mcp: OriginMcpPolicy,          // allow, block, require_approval, default_action
  egress: OriginEgressPolicy,     // allow, block, default_action
  data: OriginDataPolicy,         // allow_external_sharing, redact_before_send, block_sensitive_outputs
  budgets: OriginBudgets,         // mcp_tool_calls, egress_calls, shell_commands
  bridge: OriginBridgePolicy,     // allow_cross_origin, allowed_targets, require_approval
}
OriginMatch { provider, tenant_id, space_id, space_type, thread_id, visibility, external_participants, tags, sensitivity, actor_role, provenance_confidence }
```

**Note on `data` policy:** The `OriginDataPolicy` struct covers spec section 12.2's `dataPolicy`:
- `allow_external_sharing: bool` — controls whether agent can send data to external participants
- `redact_before_send: bool` — force redaction of sensitive content before sending to origin
- `block_sensitive_outputs: bool` — block outputs containing PII/secrets from reaching origin

### 2.2 Origin Context (Core Type)

**New file:** `crates/libs/clawdstrike/src/origin.rs`
- `OriginContext` struct (Rust equivalent of spec's TS type)
- `OriginProvider` enum (Slack, Teams, GitHub, Jira, Email, Discord, Webhook, Custom)
- `SpaceType` enum (Channel, Group, Dm, Thread, Issue, Ticket, EmailThread, Custom)
- `Visibility` enum (Private, Internal, Public, ExternalShared, Unknown)
- `ProvenanceConfidence` enum (Strong, Medium, Weak, Unknown)

**Modify:** `crates/libs/clawdstrike/src/guards/mod.rs`
- Add `origin: Option<OriginContext>` to `GuardContext` (line ~180)

### 2.3 Enclave Resolver (New Module)

**New file:** `crates/libs/clawdstrike/src/enclave.rs`
- `EnclaveResolver` — matches `OriginContext` to `OriginProfile`
- Match priority: exact space_id > tag+visibility > provider > default > fail-closed
- `EnclaveProfile` — resolved runtime struct with projected tool surface
- `resolve(origin: &OriginContext, policy: &Policy) -> Result<EnclaveProfile>`

### 2.4 Capability Projector

**Modify:** `crates/libs/clawdstrike/src/engine.rs`
- Before guard pipeline (lines 363-364, after early error returns, before guard categorization), if origin is present:
  1. Resolve enclave from origin + policy
  2. Project tool surface from enclave profile
  3. Compile projected `McpToolConfig` into guard context
  4. Set posture from enclave if specified
- This is the "outer resolution layer feeding the current guard model"

### 2.5 Receipt Extension

**Modify:** `crates/libs/hush-core/src/receipt.rs`
- Add origin fields to receipt metadata (not struct — use existing `metadata: Option<JsonValue>`)
- Convention: `receipt.metadata.origin = { provider, tenant_id, space_id, ... }`
- Convention: `receipt.metadata.enclave = { id, resolution_path }`
- Convention: `receipt.metadata.approval = { required, grant_id }`
- Use existing `merge_metadata()` for composability

### 2.6 Trust Adapter Framework (TS)

**New package:** `packages/adapters/clawdstrike-origin-core/`
- `TrustAdapter` interface (required methods):
  - `validate(event) -> ProvenanceResult`
  - `normalize(event) -> OriginContext`
  - `renderApprovalRequest(request) -> ProviderPayload`
  - `consumeApprovalResponse(response) -> Decision`
  - `deriveTags(context) -> string[]`
- Optional methods (for advanced integrations):
  - `enrichIdentity?(context) -> EnrichedContext`
  - `listSpaces?(tenant) -> Space[]`
  - `syncMetadata?(provider) -> ProviderMetadata`

**New packages (per provider):**
- `packages/adapters/clawdstrike-origin-slack/`
- `packages/adapters/clawdstrike-origin-github/`
- (Teams, Jira in later phases)

### 2.7 Adapter Core Extension

**Modify:** `packages/adapters/clawdstrike-adapter-core/src/adapter.ts`
- Extend `GenericInboundMessage` → map to `OriginContext`
- Current fields already present: `source`, `channel`, `chatType`, `senderId`, `senderName`, `metadata`
- Add: `visibility`, `externalParticipants`, `tags`, `sensitivity`, `provenanceConfidence`
- Or: add `origin?: OriginContext` to `SecurityContext`

### 2.8 Approval Broker Extension

**Modify:** `crates/services/control-api/src/models/approval.rs`
- Add origin fields to `event_data` JSON (already JSONB, no schema change needed)
- Add origin filter to `GET /api/v1/approvals` query

**New routes:**
- `POST /api/v1/origins/resolve` — test origin resolution
- `POST /api/v1/origins/explain` — explain resolution path
- `GET /api/v1/origins/profiles` — list active profiles

### 2.9 Bridge Model

**Modify:** `crates/libs/clawdstrike/src/engine.rs`
- Before cross-origin action, check `bridge_policy` on enclave
- Emit bridge receipt with source_origin + target_origin
- Reuse delegation graph for bridge authorization chain

### 2.10 CLI Commands

**Modify:** `crates/services/hush-cli/`
- `clawdstrike origin resolve --provider slack --space-id C123`
- `clawdstrike origin explain --provider github --space-type issue --space-id 88`
- `clawdstrike origin list-profiles`
- `clawdstrike origin simulate policy.yaml origin-event.json`

---

## 3. Existing TS Adapter Architecture (How Origin Data Flows)

Current flow (from Agent 7 findings):

```
External Input (Slack, webhook, MCP, etc.)
    |
adapter.interceptInboundMessage() / interceptToolCall()
    |
GenericInboundMessage { source, channel, chatType, senderId, metadata }
    |
SecurityContext { sessionId, userId, metadata, policy }
    |
PolicyEvent { eventType, data, metadata }
    |
GuardContext { identity, organization, request, roles, session }
    |
Guard pipeline: FastPath -> StdPath -> Custom -> Extra -> DeepPath
    |
GuardResult -> Decision -> Receipt
```

**Origin Enclaves extends this to:**

```
External Input (Slack, GitHub, Teams, Jira, ...)
    |
TrustAdapter.validate(event) -> provenance check
TrustAdapter.normalize(event) -> OriginContext
    |
EnclaveResolver.resolve(origin, policy) -> EnclaveProfile
    |
CapabilityProjector.project(enclave) -> filtered McpToolConfig + posture
    |
[existing pipeline continues with projected surface]
    |
Guard pipeline with origin-enriched GuardContext
    |
Receipt with origin + enclave metadata
```

---

## 4. Database Schema Extensions (Control API)

New migration needed (e.g., `016_origin_enclaves.sql`):

```sql
-- Origin profiles are policy-driven (YAML), not DB-stored.
-- DB stores: origin-aware approvals (already in event_data JSONB),
-- origin-scoped grants, and origin telemetry.

-- Add origin columns to existing tables for query efficiency:
ALTER TABLE approvals ADD COLUMN origin_provider TEXT;
ALTER TABLE approvals ADD COLUMN origin_space_id TEXT;
ALTER TABLE approvals ADD COLUMN enclave_id TEXT;

-- Index for origin-based queries:
CREATE INDEX idx_approvals_origin ON approvals(tenant_id, origin_provider, origin_space_id);
CREATE INDEX idx_approvals_enclave ON approvals(tenant_id, enclave_id);

-- Temporary grants (TTL-scoped capability releases):
CREATE TABLE origin_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    enclave_id TEXT NOT NULL,
    origin_provider TEXT NOT NULL,
    space_id TEXT,
    thread_id TEXT,
    actor_id TEXT,
    approved_by TEXT NOT NULL,
    scope_server TEXT NOT NULL,
    scope_tool TEXT NOT NULL,
    argument_hash TEXT,
    ttl_seconds INTEGER NOT NULL,
    reason TEXT,
    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

CREATE INDEX idx_origin_grants_lookup
    ON origin_grants(tenant_id, enclave_id, origin_provider, space_id)
    WHERE revoked_at IS NULL AND expires_at > now();
```

---

## 5. NATS Subject Extensions

New subjects under existing tenant prefix:

```
tenant-{slug}.clawdstrike.origin.resolve.{agent_id}     # Origin resolution requests
tenant-{slug}.clawdstrike.origin.grant.{agent_id}       # Temporary grant issuance
tenant-{slug}.clawdstrike.origin.bridge.{agent_id}      # Bridge authorization
tenant-{slug}.clawdstrike.origin.telemetry.>             # Origin telemetry events
```

---

## 6. Key Docs & Specs Referenced

| Document | Path | Relevance |
|----------|------|-----------|
| Policy schema reference | `docs/src/reference/policy-schema.md` | Schema extension target |
| Posture schema reference | `docs/src/reference/posture-schema.md` | Posture integration |
| Fleet architecture | `docs/src/fleet/architecture.md` | Six-plane model alignment |
| Slack/Teams alerting | `docs/plans/siem-soar/slack-teams.md` | Provider integration patterns |
| Multi-agent delegation | `docs/plans/multi-agent/delegation-tokens.md` | Cross-origin bridge model |
| Identity & access | `docs/plans/identity-access/session-context.md` | Session context propagation |
| Custom guards plugin | `docs/plans/decisions/0005-custom-guards-plugin-model.md` | Plugin model for adapters |
| ADR: schema convergence | `docs/plans/decisions/0002-policy-schema-convergence.md` | Version strategy |
| Spec: SPIRE identity | `docs/specs/06-spire-identity-binding.md` | Identity binding patterns |
| Spec: Cloud SaaS | `docs/specs/14-clawdstrike-cloud.md` | Multi-tenant NATS architecture |
| OpenClaw hooks | `packages/adapters/clawdstrike-openclaw/src/hooks/*/HOOK.md` | Hook integration model |
| Threat model | `THREAT_MODEL.md` | Trust boundary analysis |

---

## 7. Risk & Gap Analysis

### Low Risk (Clean Extensions)
- Policy schema v1.4.0 — follows established version pattern (1.1→1.2→1.3→1.4)
- Receipt metadata — existing `merge_metadata()` is purpose-built for this
- GuardContext enrichment — `origin` field is additive, no breaking change
- Approval model — `event_data` is already JSONB, origin fields are metadata
- NATS subjects — new subjects under existing tenant prefix

### Medium Risk (Requires Careful Design)
- Enclave resolver match semantics — ordering/priority must be deterministic and documented
- Capability projection into McpToolGuard — must compose correctly with existing allow/block/require_confirmation
- Posture interaction — enclave sets initial posture, but posture transitions are session-scoped
- Bridge model — cross-origin isolation is novel; delegation graph may need extension
- TS adapter extension — GenericInboundMessage already has some fields; avoid breaking existing adapters

### High Risk (Architecture Decisions Needed)
- **Where do origin profiles live?** Top-level policy objects (proposed) vs compiled guard-level structures
- **Bridge rules location:** Part of origin profile (proposed) vs separate policy section
- **Provider metadata in receipts:** Full copy vs reference-by-ID — storage vs verifiability tradeoff
- **DM default behavior:** Deny vs tiny read-only profile — **DECISION NEEDED before Phase 0.3**
- **Tool projection location:** Adapter layer vs engine core — spec says centrally, but TS adapters need it too
- **McpToolConfig composition semantics:** Enclave mcp + policy mcp must compose; "most restrictive wins" needs formal definition for allow/block/require_confirmation interactions

### Architectural Decisions Taken
- **Origin profiles** are top-level policy objects in `Policy.origins`, not guard-level
- **Bridge rules** are part of the origin profile (`OriginProfile.bridge_policy`)
- **Receipt metadata** uses full copy convention (`receipt.metadata.origin = {...}`)
- **Tool projection** happens in engine core (Rust), TS adapters pass origin context through
- **Schema version:** v1.4.0 following posture v1.2.0 precedent with `policy_version_supports_origins()`
- **`deny_unknown_fields` safe:** Adding `Option<T>` with `#[serde(default)]` is proven safe by posture and Spider Sense additions
- **Feature gating:** Follow Spider Sense pattern — types always compiled, async guards behind `#[cfg(feature = "full")]`
- **OSS/Enterprise split:** Use existing `auth.plan` runtime gating in control-api (not separate crates)

### Spec Coverage Gaps (From Critic Review)
- **dataPolicy:** Now addressed (see section 2.1 `OriginDataPolicy`)
- **argumentHash in ApprovalGrant:** `origin_grants.argument_hash` column exists in migration (section 4) — approval broker (Phase 5.1) must implement hash computation and matching
- **Telemetry query schema:** Needs formal spec in Phase 5.6 — query fields, aggregations, time-series structure
- **Provider inventory console view:** Add `GET /api/v1/console/origins/providers` endpoint in Phase 5.4
- **Optional adapter methods:** Now listed in section 2.6 — implemented in Phase 7 (advanced)
- **Go/Python SDK OriginContext types:** Not in current roadmap — add as Phase 7 work item
- **WASM compatibility:** `origin.rs` and `enclave.rs` must compile under `wasm32-unknown-unknown` (no std::time::Instant, no fs)
