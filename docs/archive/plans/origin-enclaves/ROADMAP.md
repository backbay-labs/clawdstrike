# Origin Enclaves — End-to-End Implementation Roadmap

> Status: Draft v0.2 (critic review applied)
> Branch: feat/enclaves
> Date: 2026-03-07

This roadmap sequences the Origin Enclaves implementation into phased work items, mapping each to concrete codebase changes. Dependencies are explicit. Each phase has a clear "done" definition.

**Revised timeline:** 14 weeks (Phases 0-6), extendable for Phase 7. With 2 developers and parallelization, calendar time ~10-12 weeks.

---

## Phase 0: Foundation Types & Schema (Week 1-2)

**Goal:** Core Rust types, policy schema v1.4.0, and enclave resolver — no adapters yet.

### 0.0 Bridge Model Design Sketch
- Draft `BridgePolicy` and `BridgeRequest` type shapes before `OriginProfile` is finalized
- This is a design doc, not implementation — ensures `OriginProfile.bridge_policy` is correctly shaped from the start
- Decide DM default behavior: deny vs minimal read-only profile
- Define McpToolConfig composition semantics: how enclave mcp + policy mcp interact
- **Depends on:** nothing
- **Output:** Design note in `docs/plans/origin-enclaves/bridge-design.md`

### 0.1 Origin Context Types
- **New file:** `crates/libs/clawdstrike/src/origin.rs`
- Define `OriginContext`, `OriginProvider`, `SpaceType`, `Visibility`, `ProvenanceConfidence`
- All types: `#[derive(Debug, Clone, Serialize, Deserialize)]`, `deny_unknown_fields`
- Must compile under `--target wasm32-unknown-unknown` (no std::time::Instant, no fs)
- Property tests for serialization roundtrip
- **Depends on:** nothing
- **Tests:** unit tests for serde, Display, Default

### 0.2 Policy Schema v1.4.0
- **Modify:** `crates/libs/clawdstrike/src/policy.rs`
  - Add `"1.4.0"` to `POLICY_SUPPORTED_SCHEMA_VERSIONS`
  - Add `OriginsConfig` struct with `default_behavior: OriginDefaultBehavior` (Deny | MinimalProfile) and `profiles: Vec<OriginProfile>`
  - Add `OriginProfile` with `id`, `match_rules: OriginMatch`, `posture`, `mcp` (reuse McpToolConfig shape), `egress`, `data: OriginDataPolicy` (allow_external_sharing, redact_before_send, block_sensitive_outputs), `budgets`, `bridge_policy`, `explanation`
  - Add `OriginMatch` with all match fields from spec section 13.2
  - Add `origins: Option<OriginsConfig>` to `Policy` struct
  - Gate on `policy_version_supports_origins()` requiring >= 1.4.0
  - Add merge logic: child profiles replace base profiles by ID, or append
- **Depends on:** 0.1
- **Tests:** YAML parse roundtrip, version gating, merge with extends, reject unknown fields

### 0.3 Enclave Resolver
- **New file:** `crates/libs/clawdstrike/src/enclave.rs`
- `EnclaveResolver::resolve(origin: &OriginContext, origins_config: &OriginsConfig) -> Result<ResolvedEnclave>`
- Match priority (deterministic):
  1. Exact `space_id` match
  2. Tag + visibility + provider match (most specific wins by field count)
  3. Provider-only match
  4. Default profile (if defined)
  5. `default_behavior` (deny or minimal)
- `ResolvedEnclave` contains: profile ID, effective McpToolConfig, effective posture, egress policy, resolution path (for explainability)
- **Depends on:** 0.1, 0.2
- **Tests:** match priority ordering, fail-closed on no match, tag intersection, wildcard, boolean match

### 0.4 GuardContext Extension
- **Modify:** `crates/libs/clawdstrike/src/guards/mod.rs`
  - Add `origin: Option<OriginContext>` to `GuardContext` (~line 180)
  - Add `enclave: Option<ResolvedEnclave>` to `GuardContext`
- **Modify:** `GuardContext::builder()` or constructor to accept origin
- Non-breaking: field is Option, all existing code unaffected
- **Depends on:** 0.1, 0.3
- **Tests:** existing guard tests still pass, new tests with origin populated

### 0.5 Built-in Ruleset
- **New file:** `crates/libs/clawdstrike/rulesets/origin-enclaves-example.yaml`
- Example policy demonstrating incident-room and external-chat profiles
- Register in `RuleSet::list()` and `yaml_by_name()`
- **Depends on:** 0.2
- **Tests:** loads and validates without error

**Phase 0 Done When:**
- `cargo test --workspace` passes
- `cargo clippy --workspace -- -D warnings` passes
- New types serialize/deserialize correctly
- Origin types compile under `--target wasm32-unknown-unknown`
- Policy v1.4.0 with `origins` block loads, validates, and merges
- Policy v1.4.0 with `origins` block is **rejected** by runtimes aware only of v1.3.0
- Policy v1.3.0 without `origins` loads without error on v1.4.0-aware runtime
- Enclave resolver matches correctly with deterministic priority
- Enclave resolver performance: < 1ms for 50 profiles
- Example ruleset loads
- Bridge model design sketch reviewed (Phase 0.0)

---

## Phase 1: Engine Integration & Receipts (Week 2-4)

**Goal:** Engine uses enclave resolution to project tool surfaces and enrich receipts.

> **Critic note:** Extended from 1 week to 2 weeks. Capability projection (1.1) modifies the hottest code path in `engine.rs` and McpToolConfig composition ("most restrictive wins") requires extensive testing. Cross-origin isolation (1.4) is split into Phase 1b.

### 1.1 Capability Projection in Engine
- **Modify:** `crates/libs/clawdstrike/src/engine.rs`
- Before guard pipeline (lines 363-364 in `check_action_report()`, after early error returns, before guard categorization):
  1. If `guard_context.origin` is `Some`:
     - Resolve enclave via `EnclaveResolver`
     - Project `McpToolConfig` from enclave into effective guard config
     - If enclave specifies posture, set as initial posture (if no session posture exists)
     - If enclave specifies egress policy, merge into effective egress config
  2. Store `ResolvedEnclave` in engine state for receipt enrichment
- Projection composites: enclave mcp + policy mcp, most restrictive wins
  - Enclave allows + policy blocks = **blocked**
  - Enclave blocks + policy allows = **blocked**
  - Both allow = **allowed**
  - Either require_confirmation = **require_confirmation**
  - Note: existing `McpToolConfig::merge_with()` has complex additional_*/remove_* semantics; enclave projection should NOT use merge — it should compute an intersection
- Edge case: if enclave specifies a posture state not in policy's PostureConfig → fail-closed with error
- **Depends on:** 0.3, 0.4, 0.5 (need example policy for meaningful tests)
- **Tests:** origin-aware check with tool allowed by policy but blocked by enclave, and vice versa; all 4 composition cases; posture state mismatch error

### 1.2 Receipt Origin Enrichment
- **Modify:** `crates/libs/clawdstrike/src/engine.rs` (in `create_receipt()` / `create_signed_receipt()`)
- If origin is present, merge into receipt metadata:
  ```json
  {
    "origin": { "provider": "slack", "space_id": "C456", "visibility": "internal", ... },
    "enclave": { "id": "incident-room", "resolution_path": ["provider=slack", "tag=incident"] }
  }
  ```
- Uses existing `receipt.merge_metadata()` — no receipt struct changes needed
- **Depends on:** 1.1
- **Tests:** receipt contains origin metadata, metadata merges correctly with existing fields

### 1.3 Posture Integration
- **Modify:** `crates/libs/clawdstrike/src/engine.rs`
- When enclave specifies `posture`:
  - If session has no posture state yet → initialize from enclave's posture
  - If session already has posture → validate compatibility, do not override (fail-closed if conflict)
- Transitions reuse existing: `UserApproval`, `CriticalViolation`, `BudgetExhausted`
- **Depends on:** 1.1
- **Tests:** enclave sets posture, posture transitions work within enclave context

### 1b. Cross-Origin Isolation Check (Week 3-4, can overlap with Phase 2)
- **Modify:** `crates/libs/clawdstrike/src/engine.rs`
- Track `session_origin: Option<OriginContext>` in `EngineState` (private struct, lines 111-122)
- On subsequent checks within same session:
  - If new origin differs from session origin → check `bridge_policy`
  - If bridge not allowed → deny with `cross_origin_violation`
  - If bridge requires approval → escalate
- **Depends on:** 1.1
- **Tests:** same-origin passes, different-origin without bridge blocked, bridge with approval escalates

**Phase 1 Done When:**
- Engine projects enclave tool surface into guard evaluation
- Capability projection unit-tested for all 4 composition cases
- Receipts contain origin + enclave metadata under `clawdstrike.origin` and `clawdstrike.enclave` keys
- Posture initialization from enclave works; invalid posture state reference fails closed
- Cross-origin isolation: denies when bridge_policy absent, escalates when approval required, allows when unconditional
- All existing tests still pass (non-breaking)
- Enclave resolution < 1ms for 50 profiles (benchmark)

---

## Phase 2: CLI & Local Experience (Week 3-5, parallel with Phase 1b)

**Goal:** Operators can resolve, explain, and simulate origin policies locally.

### 2.1 CLI: `origin resolve`
- **Modify:** `crates/services/hush-cli/`
- `clawdstrike origin resolve --provider slack --space-id C123 --visibility internal --tags incident`
- Loads policy, builds OriginContext from flags, runs EnclaveResolver, prints result
- Output: enclave ID, posture, allowed tools, blocked tools, resolution path
- **Depends on:** Phase 0

### 2.2 CLI: `origin explain`
- `clawdstrike origin explain --provider github --space-type issue --space-id 88`
- Shows step-by-step match evaluation: which profiles were considered, why each matched or didn't
- Human-readable output with optional `--json` flag
- **Depends on:** Phase 0

### 2.3 CLI: `origin list-profiles`
- `clawdstrike origin list-profiles [policy.yaml]`
- Lists all origin profiles with their match rules and effective tool surfaces
- Table output showing profile ID, match criteria, posture, tool count
- **Depends on:** Phase 0

### 2.4 CLI: `origin simulate`
- `clawdstrike origin simulate policy.yaml origin-event.json`
- Takes a full origin event JSON, resolves enclave, then simulates a set of tool calls
- Reports: which tools allowed, which blocked, which need approval
- **Depends on:** Phase 1

### 2.5 Policy Validation Extension
- **Modify:** policy validation in `policy.rs`
- Validate origin profiles: no duplicate IDs, valid match fields, valid posture references
- Validate bridge policies: target profiles exist
- Warn on overlapping match rules with different outcomes
- **Depends on:** 0.2

**Phase 2 Done When:**
- All 4 CLI commands work end-to-end
- Policy validation catches invalid origin configs
- `clawdstrike origin simulate` produces accurate allow/deny/ask results

---

## Phase 3: Trust Adapter Framework & Slack Adapter (Week 1-6)

**Goal:** Generic adapter contract + first production adapter (Slack).

> **Critic note:** Phase 3.1 (adapter interface design) starts in Week 1 parallel with Phase 0, not Week 4. The TrustAdapter contract is an architectural decision that affects all downstream phases. Implementation (3.3-3.5) starts Week 4 once Phase 0 types are stable.

### 3.1 Trust Adapter Core (TS) — Start Week 1, parallel with Phase 0
- **New package:** `packages/adapters/clawdstrike-origin-core/`
- `TrustAdapter` interface:
  ```typescript
  interface TrustAdapter {
    provider: string;
    validate(event: ProviderEvent): Promise<ProvenanceResult>;
    normalize(event: ProviderEvent): Promise<OriginContext>;
    renderApprovalRequest(request: ApprovalRequest): Promise<ProviderPayload>;
    consumeApprovalResponse(response: ProviderResponse): Promise<ApprovalDecision>;
    deriveTags(context: OriginContext): string[];
    // Optional advanced methods
    enrichIdentity?(context: OriginContext): Promise<OriginContext>;
    listSpaces?(tenantId: string): Promise<Space[]>;
    syncMetadata?(): Promise<ProviderMetadata>;
  }
  ```
- `OriginContext` TypeScript type mirroring Rust struct
- `ProvenanceResult` with confidence level
- TS package setup: ESM-first, tsc + vitest + biome (follow existing adapter pattern)
- **Depends on:** 0.1 (type parity — TS type can be drafted before Rust types are final)
- **Tests:** interface compliance tests, type tests

### 3.2 Adapter Core Integration
- **Modify:** `packages/adapters/clawdstrike-adapter-core/src/context.ts`
  - Add `origin?: OriginContext` to `SecurityContext`
- **Modify:** `packages/adapters/clawdstrike-adapter-core/src/adapter.ts`
  - Add optional `resolveOrigin?: (message: GenericInboundMessage) => OriginContext` to `AdapterConfig`
  - In `interceptInboundMessage()`: if resolver present, build OriginContext and attach to SecurityContext
- **Modify:** `packages/adapters/clawdstrike-adapter-core/src/types.ts`
  - Add origin fields to `PolicyEvent.metadata`
- Non-breaking: all new fields optional
- **Depends on:** 3.1
- **Tests:** existing adapter tests pass, new tests with origin resolution

### 3.3 Slack Trust Adapter
- **New package:** `packages/adapters/clawdstrike-origin-slack/`
- Validates Slack request signatures (HMAC-SHA256 with signing secret)
- Normalizes Slack events to OriginContext:
  - `provider: "slack"`
  - `tenantId` from `team_id`
  - `spaceId` from `channel`
  - `spaceType`: channel → "channel", im → "dm", mpim → "group", thread_ts → "thread"
  - `threadId` from `thread_ts`
  - `actorId` from `user`
  - `actorType`: bot_id present → "bot", else "human"
  - `visibility`: `is_private` → "private", `is_shared` → "external_shared", else "internal"
  - `externalParticipants`: derived from `is_ext_shared` or Slack Connect status
  - `tags`: derived from channel name patterns, bookmarks, canvas metadata
- Renders approval as Slack Block Kit interactive message
- Consumes button callbacks as approval decisions
- **Depends on:** 3.1
- **Tests:** Slack event fixtures, signature verification, normalization correctness

### 3.4 Slack Webhook Endpoint
- **Modify:** `crates/services/hushd/src/api/webhooks.rs` (follow Okta/Auth0 pattern)
- Add `.route("/api/v1/webhooks/slack", post(webhooks::slack_webhook))` to public routes
- `POST /api/v1/webhooks/slack` — receive Slack Events API payloads
- Verify `X-Slack-Signature` header (HMAC-SHA256 with timestamp anti-replay, reject > 5 min)
- Handle `url_verification` challenge
- Route `message`, `app_mention`, `message.channels` events to adapter
- **Prerequisite:** Extend hushd config struct for Slack credentials (`config.origins.slack.signing_secret`)
- **Note:** Block Kit approval rendering deferred to Phase 5 (approval broker). Phase 3 focuses on origin context derivation only.
- **Depends on:** 3.3
- **Tests:** signature verification, challenge response, event routing, replay rejection

### 3.5 OpenClaw Integration
- **Modify:** `packages/adapters/clawdstrike-openclaw/src/hooks/inbound-message/handler.ts`
- If Slack adapter is configured, use it to derive OriginContext from inbound message
- Attach OriginContext to SecurityContext before policy evaluation
- Falls back to existing behavior if no origin adapter configured
- **Depends on:** 3.2, 3.3
- **Tests:** OpenClaw e2e with Slack origin context

**Phase 3 Done When:**
- Trust adapter contract is stable and documented
- Slack adapter normalizes real Slack events into OriginContext
- Slack signature verification rejects replayed requests older than 5 minutes
- Slack normalization correctly maps all 4 channel types (channel, im, mpim, thread_ts)
- OpenClaw inbound messages carry Slack origin context through the pipeline
- New TS packages have 80%+ test coverage
- Slack event test fixtures committed (real payloads, anonymized)

---

## Phase 4: GitHub Adapter & Bridge Model (Week 6-8)

**Goal:** Second adapter proves the abstraction. Bridge model for cross-origin workflows.

### 4.1 GitHub Trust Adapter
- **New package:** `packages/adapters/clawdstrike-origin-github/`
- Validates GitHub webhook signatures (HMAC-SHA256)
- Normalizes GitHub events:
  - PR thread → `spaceType: "thread"`, `spaceId: "PR#123"`
  - Issue → `spaceType: "issue"`, `spaceId: "ISSUE#456"`
  - PR review comment → threaded under PR
  - `visibility`: public repo → "public", private → "internal"
  - `actorType`: bot accounts → "bot", else "human"
  - `tags`: derived from labels, milestone, review state
- **Depends on:** 3.1
- **Tests:** GitHub event fixtures for PR, issue, review, comment events

### 4.2 GitHub Webhook Endpoint
- `POST /api/v1/webhooks/github` — receive GitHub webhook payloads
- Verify `X-Hub-Signature-256` header
- Route events: `pull_request`, `issues`, `issue_comment`, `pull_request_review`
- **Depends on:** 4.1

### 4.3 Bridge Implementation (Rust Core)
- **New file:** `crates/libs/clawdstrike/src/bridge.rs`
- `BridgeRequest { source_origin, target_origin, requested_capability }`
- `BridgePolicy { allow_cross_origin, allowed_targets, require_approval }`
- `BridgeResolver::check(request, policy) -> BridgeDecision`
- Bridge receipt: signs source + target origins + capability + decision
- **Depends on:** Phase 1 (cross-origin isolation)

### 4.4 Bridge Integration in Engine
- **Modify:** `crates/libs/clawdstrike/src/engine.rs`
- When cross-origin detected (1.4), invoke BridgeResolver
- If bridge allowed → proceed with target enclave's tool surface
- If bridge requires approval → escalate via existing approval queue
- Receipt chain: bridge receipt links source receipt to target receipt
- **Depends on:** 4.3

### 4.5 Delegation Graph Extension
- **Modify:** `crates/services/control-api/src/services/delegation_graph.rs`
- Update `validate_grant_type()` (line 1785) to accept `"bridge"` alongside delegation/approval/session_override
- Add `bridge` node/edge kinds to `DelegationGraphNodeKind` and `DelegationGraphEdgeKind`
- Bridge grants carry source_origin + target_origin metadata in grant context JSON
- Lineage queries show cross-origin paths
- **Depends on:** 4.3, 4.4, DB migration 016

**Phase 4 Done When:**
- GitHub adapter normalizes PR/issue events into OriginContext
- Slack + GitHub proves the adapter abstraction holds
- Cross-origin bridge model works with approval escalation
- Bridge events appear in delegation graph

---

## Phase 5: Enterprise Controls (Week 8-11)

**Goal:** Approval broker, Control Console views, and fleet-wide origin management.

> **Critic note:** Extended from 2 weeks to 3 weeks. Split into 5a (Week 8-9: approvals + grants + resolution API) and 5b (Week 10-11: console + detection + hunt).

### 5.1 Origin-Bound Approval Broker
- **Modify:** `crates/services/control-api/src/routes/approvals.rs`
- Add origin-aware fields to approval queries and resolution
- Support approval types from spec section 16.1:
  - Single-action, thread/run-scoped, time-bound, role-bound, argument-bound
- Approval must bind to narrow capability (deny-by-default, not "approve this bot")
- **Depends on:** Phase 3

### 5.2 Temporary Grant System
- **New routes in control-api:**
  - `POST /api/v1/origins/grants` — issue temporary grant with `argument_hash` binding
  - `GET /api/v1/origins/grants` — list active grants (lazy expiration: `WHERE expires_at > now()`)
  - `DELETE /api/v1/origins/grants/{id}` — revoke grant
- Grant scoped by: enclave, provider, space, thread, tool, actor, TTL, argument_hash
- Automatic expiration via `expires_at` column (lazy — checked at query time)
- Background cleanup task: `tokio::spawn` periodic job to archive expired grants (every 5 min)
- **Depends on:** 5.1, DB migration 016 (section 4 of INDEX)

### 5.3 Origin Resolution API
- **New routes:**
  - `POST /api/v1/origins/resolve` — resolve OriginContext to enclave
  - `POST /api/v1/origins/explain` — explain resolution path
  - `GET /api/v1/origins/profiles` — list profiles for tenant's active policy
- **Depends on:** Phase 0

### 5.4 Control Console: Origin Enclaves Views
- **Modify:** `crates/services/control-api/src/routes/console.rs`
- New console endpoints:
  - `GET /api/v1/console/enclaves` — enclave profile overview
  - `GET /api/v1/console/enclaves/{id}` — enclave detail (tool matrix, approval queue, recent denials)
  - `GET /api/v1/console/origins/unmatched` — origins that resolved to default/deny
  - `GET /api/v1/console/origins/providers` — provider inventory (connected providers, event counts)
  - `GET /api/v1/console/origins/heatmap` — origin posture heatmap data
  - `GET /api/v1/console/bridges` — bridge activity log
- **Depends on:** 5.1, 5.2, 5.3

### 5.5 Origin-Aware Detection Rules
- **Modify:** `crates/services/control-api/src/routes/alerts.rs`
- Preset detection rules:
  - Agent invoked from unknown external origin
  - Prod tools used from non-incident origin
  - Repeated bridge attempts between unrelated origins
  - Sudden increase in approval requests from one origin
  - Tool exposure drift for a sensitive profile
- **Depends on:** Phase 1 (receipt enrichment)

### 5.6 Origin-Aware Hunt Queries & Telemetry Schema
- **Modify:** `crates/services/control-api/src/routes/hunt.rs`
- Add origin fields as queryable dimensions:
  - Filter by provider, space_id, enclave_id, visibility
  - Aggregate denials by origin
  - Timeline filtered by origin
- Define telemetry event schema for origin events:
  - `origin.resolved` — enclave resolution with profile ID and resolution path
  - `origin.denied` — tool blocked by enclave policy
  - `origin.bridge.attempted` — cross-origin bridge request
  - `origin.grant.issued` / `origin.grant.expired` — temporary grant lifecycle
- **Depends on:** Phase 1 (receipt enrichment)

**Phase 5 Done When:**
- Origin-bound approvals with narrow capability binding (argument_hash verified)
- Temporary grants with TTL; test creates 1-second TTL grant and verifies expiration
- Grant cleanup background task runs without error
- Console endpoints return correct data for each view (tested with seeded data)
- Provider inventory shows connected providers with event counts
- Detection rules fire on origin anomalies (tested with synthetic events)
- Hunt queries filter and aggregate by origin fields
- Telemetry event schema documented

---

## Phase 6: Adapter Expansion (Week 11-13)

**Goal:** Teams and Jira adapters, proving tier-2 coverage.

### 6.1 Microsoft Teams Trust Adapter
- **New package:** `packages/adapters/clawdstrike-origin-teams/`
- Validate Bot Framework webhook tokens (JWT from Microsoft)
- Normalize Teams events:
  - Team → tenantId, Channel → spaceId
  - Chat types: channel, groupChat, personal
  - Visibility from team settings (public/private)
  - Tab/connector context metadata
- Render approval as Adaptive Card
- **Depends on:** 3.1

### 6.2 Jira Trust Adapter
- **New package:** `packages/adapters/clawdstrike-origin-jira/`
- Validate Jira webhook signatures
- Normalize: project → tenantId, issue → spaceId (spaceType: "ticket")
- Tags from issue labels, priority, components
- Visibility from project permissions
- **Depends on:** 3.1

### 6.3 Adapter Conformance Test Suite
- **New test package:** shared conformance tests every adapter must pass
- Tests: normalization correctness, provenance validation, approval rendering, tag derivation
- Run against all adapters: Slack, GitHub, Teams, Jira
- **Depends on:** 6.1, 6.2

**Phase 6 Done When:**
- Teams and Jira adapters pass conformance suite
- All 4 tier-1 adapters (Slack, Teams, GitHub, Jira) work end-to-end
- Adapter abstraction is validated across conversation + engineering + ticketing origins

---

## Phase 7: Advanced Features (Week 14+)

**Goal:** Drift detection, profile templates, adaptive posture.

### 7.1 Drift Detection
- Monitor origin profiles vs actual tool usage patterns
- Alert when enclave grants exceed observed usage (over-provisioned)
- Alert when denials increase (under-provisioned or abuse attempt)
- **Depends on:** Phase 5 (telemetry)

### 7.2 Profile Templates
- Pre-built templates: `incident-room`, `support-channel`, `code-review`, `external-chat`, `internal-dm`
- Templates as rulesets that can be `extends`-ed
- **Depends on:** 0.5

### 7.3 Recommended Profile Synthesis
- Analyze observed origin behavior patterns
- Suggest profiles based on tool usage frequency per origin type
- "We observed 95% of actions from this channel type are read-only — recommend read-only profile"
- **Depends on:** 7.1

### 7.4 Adaptive Posture by Origin Risk
- Runtime risk scoring: external_participants + public visibility + weak provenance → higher risk
- Auto-escalate posture for high-risk origins
- **Depends on:** Phase 1 posture integration

### 7.5 Go & Python SDK OriginContext Types
- Add `OriginContext` to hush-go and hush-py SDKs for cross-language parity
- Mirror Rust struct with language-idiomatic naming
- **Depends on:** 0.1

### 7.6 Optional Adapter Methods
- Implement `enrichIdentity`, `listSpaces`, `syncMetadata` on Slack and GitHub adapters
- Provider inventory sync for Control Console
- **Depends on:** Phase 6

---

## Dependency Graph

```
Week 1-2:  Phase 0 (Types + Schema + Resolver)  ||  Phase 3.1 (Adapter Interface Design)
              |                                          |
Week 2-4:  Phase 1a (Engine + Receipts + Posture)       |
              |                                          |
Week 3-5:  Phase 1b (Cross-Origin) || Phase 2 (CLI)     |
              |                                          |
Week 4-6:  Phase 4.3-4.4 (Bridge)                  Phase 3.3-3.5 (Slack) || Phase 4.1-4.2 (GitHub)
              |                                          |
Week 6-8:  Phase 4.5 (Delegation Graph)                  |
              |                                          |
Week 8-9:  Phase 5a (Approvals + Grants + Resolution API)
              |
Week 10-11: Phase 5b (Console + Detection + Hunt)
              |
Week 11-13: Phase 6 (Teams + Jira + Conformance)
              |
Week 14+:  Phase 7 (Drift + Templates + Go/Py SDK)
```

### Parallelization (2-developer model)

| Week | Developer A (Rust) | Developer B (TS) |
|------|-------------------|------------------|
| 1-2  | Phase 0 (all)     | Phase 3.1 (adapter interface design) |
| 2-4  | Phase 1a (engine projection + receipts) | Phase 3.1 finalize + 3.3 (Slack adapter) |
| 3-5  | Phase 1b (cross-origin) + 2.1-2.3 (CLI) | Phase 3.3-3.5 (Slack + OpenClaw) |
| 4-6  | Phase 2.4-2.5 + 3.4 (Slack webhook) | Phase 4.1-4.2 (GitHub adapter) |
| 6-8  | Phase 4.3-4.5 (bridge + delegation) | Phase 6.1 or docs |
| 8-9  | Phase 5a (approvals + grants) | Phase 5.3-5.4 (console) |
| 10-11 | Phase 5.5-5.6 (detection + hunt) | Phase 6 (conformance) |

---

## Cross-Cutting Work Items (Not Phase-Specific)

These items must be tracked alongside the phased work:

### Documentation
- Update `docs/src/reference/policy-schema.md` for v1.4.0 `origins` block (after Phase 0)
- Add `docs/src/reference/rulesets/origin-enclaves.md` (after Phase 0.5)
- Write adapter developer guide for custom `TrustAdapter` implementations (after Phase 3)
- Migration guide: upgrading from v1.3.0 to v1.4.0 policies (after Phase 0)
- API reference for new control-api routes (after Phase 5)

### Test Infrastructure
- Collect and anonymize real Slack webhook payloads as test fixtures (before Phase 3.3)
- Collect and anonymize real GitHub webhook payloads as test fixtures (before Phase 4.1)
- Add origin-aware test cases to `rulesets/tests/policy-torture/` (Phase 0)
- Add origin context vectors to `scripts/run-sdk-conformance.sh` (Phase 0)

### CI/CD
- New TS packages need: `package.json`, `tsconfig.json`, vitest config, integration into smoke checks
- Architecture guardrails update (`scripts/architecture-guardrails.sh`) for new modules
- DB migration rollback script for 016

### Performance
- Benchmark enclave resolution: target < 1ms for 50 profiles (Phase 0.3)
- Benchmark engine hot path with origin projection enabled vs disabled (Phase 1.1)

### Backward Compatibility
- v1.4.0 policies with `origins` block must be **rejected** by runtimes running v1.3.0 (verified by schema version check)
- v1.3.0 policies without `origins` must continue to work on v1.4.0-aware runtimes (Option<T> + serde(default))
- Error messages for origin-related failures must be clear and consistent across Rust and TS

---

## OSS vs Enterprise Split

| Component | License |
|-----------|---------|
| OriginContext types | OSS |
| Policy schema v1.4.0 origins block | OSS |
| EnclaveResolver | OSS |
| Capability projection in engine | OSS |
| Receipt origin metadata | OSS |
| Cross-origin isolation | OSS |
| Bridge model (core) | OSS |
| CLI resolve/explain/simulate | OSS |
| Trust Adapter SDK | OSS |
| Slack adapter (reference) | OSS |
| GitHub adapter (reference) | OSS |
| Temporary grant system | Enterprise |
| Approval broker (origin-bound) | Enterprise |
| Control Console views | Enterprise |
| Origin-aware detection rules | Enterprise |
| Origin-aware hunt queries | Enterprise |
| Drift detection | Enterprise |
| Profile synthesis | Enterprise |
| Teams adapter | Enterprise |
| Jira adapter | Enterprise |

---

## Success Criteria

### Phase 0-1 (Core)
- [ ] Policy v1.4.0 with origins block loads and validates
- [ ] v1.3.0 policies still load on v1.4.0-aware runtimes (backward compat)
- [ ] Enclave resolver matches with deterministic priority (property tested)
- [ ] Enclave resolver < 1ms for 50 profiles
- [ ] Engine projects enclave tool surface: enclave-allows + policy-blocks = blocked (and all 4 combos)
- [ ] Receipts contain `clawdstrike.origin` and `clawdstrike.enclave` metadata keys
- [ ] Cross-origin isolation: denies absent bridge, escalates approval-required bridge, allows unconditional bridge
- [ ] Posture state mismatch (enclave references nonexistent state) fails closed with clear error
- [ ] Origin types compile under `wasm32-unknown-unknown`
- [ ] All existing tests still pass (non-breaking)
- [ ] `cargo clippy --workspace -- -D warnings` clean

### Phase 2-3 (Usable)
- [ ] CLI `origin resolve` returns enclave ID, posture, and tool surface
- [ ] CLI `origin explain` shows step-by-step match evaluation
- [ ] Slack signature verification rejects replayed requests > 5 min old
- [ ] Slack normalization handles all 4 channel types correctly
- [ ] OpenClaw e2e: Slack message → origin resolution → tool check → signed receipt with origin
- [ ] New TS packages have 80%+ test coverage

### Phase 4-5 (Production)
- [ ] GitHub adapter normalizes PR/issue/review events into OriginContext
- [ ] Bridge model: cross-origin attempt without bridge_policy → deny
- [ ] Approval broker binds to exact origin + tool + argument_hash
- [ ] Temporary grants expire after TTL (tested with 1s grant)
- [ ] Console endpoints return correct data (tested with seeded data)
- [ ] Provider inventory shows connected providers
- [ ] Detection rules fire on synthetic origin anomaly events

### Phase 6-7 (Scale)
- [ ] 4 adapters pass conformance test suite
- [ ] Drift detection alerts on over-provisioned enclaves
- [ ] Profile templates cover: incident-room, support-channel, code-review, external-chat, internal-dm
