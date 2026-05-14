# Secret Broker -- Implementation Roadmap

> **Status:** Draft | **Date:** 2026-03-12
> **Audience:** implementation team and reviewers

## Overview

This roadmap delivers the brokered egress tier in additive phases. The key rule is to keep the
first release **explicit, provider-scoped, and fail-closed**.

## Current Hardening Slice

The current implementation now covers the first hardening wave beyond the baseline e2e path:

- non-loopback broker clients use a DPoP-like Ed25519 sender-constrained proof instead of a
  reusable bearer-style capability handoff
- `clawdstrike-brokerd` supports file-backed, environment-backed, and managed HTTP secret
  resolution
- `clawdstrike-brokerd` now executes both typed OpenAI requests and strict generic HTTPS requests,
  with private/link-local/loopback upstreams denied unless explicitly enabled
- streaming broker execution now emits explicit `started` and `completed` evidence phases with
  final body hash and chunk counts
- the desktop agent can bundle and supervise `brokerd` beside `hushd`, and it now materializes a
  persistent local hushd signing key so broker trust bootstrap survives restarts

## Global Invariants

1. `hushd` remains the policy authority.
2. Secrets are never returned in plaintext to the caller.
3. Broker execution without a valid capability is denied.
4. Existing adapter and engine behavior remains unchanged unless broker mode is explicitly enabled.
5. Output sanitization remains active on broker-returned content.

## Phase 0 -- Freeze the Protocol and Policy Surface

### Goal

Lock the public concepts before implementation:

- `CredentialRef`
- `BrokerCapability`
- `BrokerExecuteRequest`
- `BrokerExecutionEvidence`
- policy schema additions for broker rules
- next policy schema version for the new top-level `broker:` block

### File Change Table

| File Path | Action | Description |
| --- | --- | --- |
| `docs/specs/19-secret-broker-egress-tier.md` | create | formal spec |
| `docs/plans/clawdstrike/secret-broker/**` | create | planning set |
| `crates/libs/clawdstrike/src/policy.rs` | later modify | broker policy schema hooks |
| `packages/adapters/clawdstrike-adapter-core/src/adapter.ts` | later modify | broker config surface |
| `packages/adapters/clawdstrike-adapter-core/src/interceptor.ts` | later modify | optional broker directive/types if needed |
| `packages/adapters/clawdstrike-adapter-core/src/engine.ts` | ideally unchanged | keep `PolicyEngineLike` stable in v1 |

### Acceptance Criteria

- [ ] spec reviewed by daemon + adapter owners
- [ ] decision recorded on explicit-vs-transparent execution strategy
- [ ] v1 provider list agreed
- [ ] v1 integration choice recorded: wrapper-owned `replacementResult` path first, or a new explicit broker directive if required

## Phase 1 -- hushd Capability Issuance

### Goal

Teach `hushd` to authorize broker intents and mint short-lived capabilities after policy
evaluation.

### Candidate Files

| File Path | Action | Description |
| --- | --- | --- |
| `crates/services/hushd/src/api/broker.rs` | create | capability issuance + evidence ingestion endpoints |
| `crates/services/hushd/src/api/mod.rs` | modify | route wiring |
| `crates/services/hushd/src/api/v1.rs` | modify | response/error envelope reuse if needed |
| `crates/services/hushd/src/api/check.rs` | reference / maybe modify | reuse identity/session/origin request context patterns |
| `crates/services/hushd/src/state.rs` | modify | broker config and dependencies |
| `crates/services/hushd/src/config.rs` | modify | broker config and secret backend references |
| `crates/services/hushd/src/policy_event.rs` | modify | broker event/evidence shapes |
| `crates/libs/clawdstrike/src/policy.rs` | modify | broker policy schema |

### Notes

- Reuse existing identity fields from check requests
- Reuse current origin/posture/session semantics rather than inventing a second request context
- Capabilities should include policy hash, expiry, destination scope, and secret ref
- Start with signed envelopes issued by `hushd`
- Prefer a dedicated broker capability endpoint over widening the existing `Decision` payload from
  generic eval APIs
- For non-loopback broker deployments, bind the capability to the caller with a DPoP-like proof,
  mTLS, or workload identity rather than bearer-only transport
- If the capability envelope uses JWS/JWT, pin accepted algorithms and key handling explicitly
  rather than relying on generic library defaults

### Acceptance Criteria

- [ ] `hushd` can deny or issue a broker capability
- [ ] capabilities are destination-scoped and short-lived
- [ ] broker intents show up in audit events
- [ ] broker-required requests fail closed when `hushd` is unavailable, even if generic eval uses degraded/offline fallback
- [ ] remote broker capabilities are sender-constrained rather than reusable bearer tokens

## Phase 2 -- `clawdstrike-brokerd` Skeleton

### Goal

Stand up a minimal trusted execution service with:

- capability validation
- in-memory secret provider
- provider executor abstraction
- evidence emission

### Candidate Files

| File Path | Action | Description |
| --- | --- | --- |
| `crates/services/clawdstrike-brokerd/Cargo.toml` | create | new service crate |
| `crates/services/clawdstrike-brokerd/src/main.rs` | create | daemon entry point |
| `crates/services/clawdstrike-brokerd/src/api.rs` | create | `POST /v1/execute`, `GET /health` |
| `crates/services/clawdstrike-brokerd/src/capability.rs` | create | capability verification |
| `crates/services/clawdstrike-brokerd/src/provider/mod.rs` | create | provider executor trait |
| `crates/services/clawdstrike-brokerd/src/provider/openai.rs` | create | first typed executor |
| `crates/services/clawdstrike-brokerd/src/secret_provider/mod.rs` | create | secret provider trait |
| `crates/services/clawdstrike-brokerd/src/secret_provider/in_memory.rs` | create | dev/test provider |
| `crates/libs/hush-proxy/**` | optional reuse | DNS/SNI/domain helper reuse only where it reduces duplicate parsing logic |

### Acceptance Criteria

- [ ] broker rejects invalid or expired capabilities
- [ ] broker can execute a provider-scoped request with an in-memory secret backend
- [ ] broker emits evidence payloads to `hushd`
- [ ] broker never returns plaintext credential material to the caller

## Phase 3 -- TS Broker Client and Adapter-Core Hooks

### Goal

Add a client path that existing TS adapters can adopt without rewriting their interception model.

### Candidate Files

| File Path | Action | Description |
| --- | --- | --- |
| `packages/adapters/clawdstrike-broker-client/package.json` | create | client package |
| `packages/adapters/clawdstrike-broker-client/src/index.ts` | create | public API |
| `packages/adapters/clawdstrike-broker-client/src/client.ts` | create | capability request + execute calls |
| `packages/adapters/clawdstrike-adapter-core/src/broker-types.ts` | create | shared TS broker schemas |
| `packages/adapters/clawdstrike-adapter-core/src/adapter.ts` | modify | optional broker config |
| `packages/adapters/clawdstrike-adapter-core/src/interceptor.ts` | maybe modify | keep current contract or add explicit broker directive |
| `packages/adapters/clawdstrike-adapter-core/src/engine.ts` | ideally unchanged | avoid expanding `PolicyEngineLike` in v1 |
| `packages/adapters/clawdstrike-adapter-core/src/secure-tool-wrapper.ts` | modify | first broker-capable wrapper path |
| `packages/adapters/clawdstrike-adapter-core/src/framework-tool-boundary.ts` | modify | optional broker-aware execution hooks |
| `packages/adapters/clawdstrike-adapter-core/src/base-tool-interceptor.ts` | modify | broker intent plumbing |
| `packages/adapters/clawdstrike-adapter-core/tests/cross-adapter/**` | modify | extend existing cross-adapter conformance harness for broker mode |

### Notes

- Keep broker mode opt-in
- The adapter should be able to say "this outbound call must route through broker"
- Preserve existing fail-closed behavior
- Lowest-risk v1 path is interceptor-owned broker execution via `replacementResult`
- Only add a new explicit broker directive if multiple adapters make the v1 path too awkward

### Acceptance Criteria

- [ ] adapter-core can request capabilities and invoke brokerd
- [ ] broker mode is optional and off by default
- [ ] conformance tests prove deny-on-error behavior
- [ ] non-broker adapters do not require code changes to keep compiling
- [ ] broker-required operations never fall back to direct SDK execution on client or network error

## Phase 4 -- First Provider Integrations

### Goal

Prove product value with one typed executor and one real framework adoption path.

### First Adopters

1. `brokerd` OpenAI executor
2. `packages/adapters/clawdstrike-openai/` framework integration
3. `packages/adapters/clawdstrike-claude/` after the OpenAI path stabilizes

### Candidate Files

| File Path | Action | Description |
| --- | --- | --- |
| `crates/services/clawdstrike-brokerd/src/provider/openai.rs` | modify | productionize first typed executor |
| `packages/adapters/clawdstrike-openai/src/secure-tools.ts` | modify | broker-backed provider path |
| `packages/adapters/clawdstrike-openai/src/tool-boundary.ts` | modify | broker mode configuration |
| `packages/adapters/clawdstrike-openai/src/provider-conformance-runtime.test.ts` | modify | extend existing runtime conformance coverage |
| `packages/adapters/clawdstrike-claude/**` | later modify | Anthropic / Claude integration path |
| `packages/adapters/clawdstrike-opencode/**` | later modify | broader framework adoption after first success |

### Acceptance Criteria

- [ ] one typed provider executor ships end-to-end first
- [ ] one framework package can opt into broker mode without a bespoke app-level fork
- [ ] brokered responses still pass through output sanitization
- [ ] provider-specific evidence fields are captured
- [ ] streaming and non-streaming behavior are both accounted for in the integration design

## Phase 5 -- Secret Backends and Enterprise Packaging

### Goal

Make the broker practical outside a toy environment.

### Candidate Areas

| Area | Description |
| --- | --- |
| local secret backend | file, OS keychain, or agent-managed store |
| enterprise backend | external secret manager integration |
| agent packaging | run broker beside `hushd` for local developer or endpoint flows |
| cloud packaging | multi-tenant service topology and admin surfaces |

### Candidate Files

| File Path | Action | Description |
| --- | --- | --- |
| `apps/agent/src-tauri/src/settings.rs` | modify | optional local broker lifecycle management config |
| `apps/agent/scripts/prepare-bundled-hushd.sh` | modify | bundle `brokerd` beside `hushd` |
| `apps/agent/README.md` | modify | document local broker mode |
| `apps/control-console/**` or future cloud dashboard | later modify | broker config UI |
| `infra/docker/**` | later modify | broker deployment assets |
| `infra/deploy/**` | later modify | self-hosted packaging |

### Acceptance Criteria

- [ ] local developer mode exists
- [ ] one enterprise secret backend exists
- [ ] hosted deployment topology is documented
- [ ] local packaging makes it clear whether broker authority is local, remote, or hybrid

## Phase 6 -- Generic HTTPS Broker Mode

### Goal

Only after provider-scoped execution is stable, add a stricter generic HTTPS execution path for
non-provider outbound APIs.

### Constraints

- no transparent MITM
- strict destination and method matching
- no arbitrary header injection outside policy
- reuse existing fail-closed target normalization from `policy-event-factory.ts` and
  `network-target.ts`
- re-resolve and re-authorize redirects on every hop, or disable redirects entirely in v1
- deny private/link-local/loopback destinations unless explicitly allowed by policy and deployment
- pin execution to the validated target after DNS resolution instead of trusting a raw URL string

### Acceptance Criteria

- [ ] generic HTTPS mode cannot bypass provider-scoped controls
- [ ] malformed or hostless targets fail closed
- [ ] audit/evidence parity with provider mode

## Testing and Conformance

1. Rust unit tests for capability issuance, capability verification, and evidence ingestion
2. Broker executor tests with fixture upstream servers and malformed-destination cases
3. TS adapter conformance tests for `replacementResult`-based broker execution, built on the
   existing `packages/adapters/clawdstrike-adapter-core/tests/cross-adapter/**` harness
4. Offline/degraded-mode tests proving broker-required actions deny when authority is unavailable
5. Provider runtime conformance tests using the existing OpenAI adapter test surface before
   repeating the pattern in other frameworks
6. Agent packaging smoke test for bundled `hushd` + `brokerd` local mode

## Recommended Build Order

1. spec + policy schema
2. `hushd` capability issuance
3. broker daemon skeleton
4. TS broker client
5. OpenAI integration
6. secret backends
7. additional providers
8. generic HTTPS mode

## Major Risks

1. **Scope explosion into transparent proxying**
   Keep transparent interception out of v1.
2. **Second policy brain inside brokerd**
   Brokerd validates capabilities; it should not independently re-interpret policy.
3. **Leaky secret provider abstractions**
   Never expose plaintext secrets through debugging or client APIs.
4. **Receipt drift**
   Evidence must compose with existing receipt lineage rather than invent a disconnected trail.

## Exit Criteria For v1

The first release is good enough when:

- one provider integration is production-credible
- secrets never enter the covered agent runtime
- broker execution is bound to Clawdstrike identity and policy hash
- denial and error paths remain fail-closed
- evidence is visible in receipts and audit export

## Wave 4 -- Zero-Trust Action Plane

### Goal

Turn the broker from a secret-hiding egress shim into a product-visible action plane with:

- just-in-time credential leases from enterprise backends
- provider mesh routing across multiple LLM vendors
- typed SaaS executors for common operational systems
- origin-aware capability ceilings and human approval objects
- live operator surfaces for execution timelines, active capability inventory, replay, and revoke

### User-Facing Outcome

Wave 4 should make the broker feel like a control plane the user can trust and inspect, not just a
background daemon:

1. credentials are leased only when needed and expire automatically
2. provider outages or policy-driven routing changes do not force app rewrites
3. common GitHub and Slack actions have typed, auditable execution paths instead of generic HTTPS
4. public-vs-private origin context changes what can be executed and which secrets can be touched
5. operators can watch, replay, approve, revoke, and freeze broker activity in real time

### Non-Goals

- transparent MITM interception
- broad arbitrary SaaS coverage in the first Wave 4 cut beyond GitHub and Slack
- independent policy interpretation inside `brokerd`
- cloud/backend parity across every enterprise secret manager in one pass

### Milestones

| Milestone | Goal | Primary Lanes | Exit Criteria |
| --- | --- | --- | --- |
| `W4-M0` | Freeze contracts for leases, routing, approvals, and execution timeline events | `sb0` | shared schema, capability status model, approval object shape, and evidence/event additions are documented and accepted |
| `W4-M1` | Land lease and routing foundations | `sb6`, `sb7` | Vault and AWS Secrets Manager lease paths exist, lease revocation is modeled, and provider mesh routing can choose OpenAI / Anthropic / Azure OpenAI / local targets |
| `W4-M2` | Ship the first typed action plane | `sb8` | GitHub and Slack executors work end to end with typed request validation, scoped credentials, and provider-specific evidence |
| `W4-M3` | Bind origin and approval policy to broker execution | `sb9` | origin enclaves can reduce or widen broker ceilings, and risky actions can stop on an approval object instead of failing with a generic deny |
| `W4-M4` | Expose operator-grade broker surfaces | `sb10`, `sb11` | users can inspect active capabilities, watch execution phases live, replay old executions against current policy, and trigger revocation / freeze controls |

### Shared Files That Stay Orchestrator-Owned

These files are likely to see edits from more than one lane and should merge through `sb0`:

- `crates/libs/clawdstrike-broker-protocol/src/lib.rs`
- `crates/libs/clawdstrike/src/policy.rs`
- `crates/services/hushd/src/api/broker.rs`
- `crates/services/clawdstrike-brokerd/src/provider/mod.rs`
- `packages/adapters/clawdstrike-adapter-core/src/broker-types.ts`
- `docs/plans/clawdstrike/secret-broker/README.md`
- `docs/plans/clawdstrike/secret-broker/roadmap.md`
- `.codex/swarm/lanes.tsv`
- `.codex/swarm/waves.tsv`

### Lane Map

| Lane | Scope | Primary Ownership | Depends On | Verification Gate |
| --- | --- | --- | --- | --- |
| `sb6` | JIT leases and enterprise secret backends | `crates/services/clawdstrike-brokerd/src/secret_provider/**`, new `src/lease/**`, brokerd lease tests, backend config wiring | `W4-M0` | `cargo test -p clawdstrike-brokerd` |
| `sb7` | Provider mesh and routed execution policy | brokerd route selection, provider registry, latency/cost/failover policy, hushd capability routing hints | `W4-M0`, then merge after `sb6` | `cargo test -p clawdstrike-brokerd` and `npm --prefix packages/adapters/clawdstrike-openai test` |
| `sb8` | Typed GitHub and Slack executors | new brokerd typed provider modules, typed request validators, broker-client executor coverage | `sb6`, `sb7` | `cargo test -p clawdstrike-brokerd` and `npm --prefix packages/adapters/clawdstrike-broker-client test` |
| `sb9` | Origin-aware ceilings and approval objects | origin-enclave-aware broker policy, approval state transitions, hushd approval APIs, engine/origin conformance | `W4-M1`, then converge with `sb8` contracts | `cargo test -p clawdstrike`, `cargo test -p hushd --test broker` |
| `sb10` | Execution theater and capability wallet | `apps/control-console/src/**`, local broker status surfaces in agent/desktop apps, streamed timeline rendering | `sb8`, `sb9` | `npm --prefix apps/control-console test`, `npm --prefix apps/control-console run build`, `cargo check --manifest-path apps/agent/src-tauri/Cargo.toml` |
| `sb11` | Replay, revoke, freeze, and release hardening | broker admin/replay endpoints, kill-switch flows, chaos validation, final docs and platform gates | `sb8`, `sb9`, `sb10` | `mise run ci`, `bash scripts/test-platform.sh`, `cargo test --workspace` |

### Recommended Implementation Order

1. `sb0`: freeze the Wave 4 contract set first.
   That includes lease metadata, routed-provider fields, approval object shape, execution status APIs, and timeline event contracts.
2. `sb6`: ship the lease core next.
   Start with Vault and AWS Secrets Manager because they create immediate enterprise value and force the right revocation/TTL model.
3. `sb7`: layer the provider mesh on top of the lease core.
   Route selection should target OpenAI, Anthropic, Azure OpenAI, and a local executor path before adding more providers.
4. `sb8`: add typed GitHub executors first, then Slack.
   GitHub gives the strongest “agent can safely act in prod systems” demo; Slack then proves human-loop communications and approval callbacks.
5. `sb9`: bind origin enclaves and approval objects to those typed actions.
   This is where public-vs-private origin, external-shared spaces, and cross-origin transitions become first-class broker controls.
6. `sb10`: expose the operator experience once the actions are real.
   Add live execution theater, capability wallet, and lease/executor visibility in the control console and local agent surfaces.
7. `sb11`: finish with replay, revoke, freeze, and release-hardening.
   The kill-switch path and replay-against-current-policy flow should be the last merge because they depend on every earlier event and evidence shape staying stable.

### Merge Graph

- `MR-W4-0`: docs/spec/schema freeze through `sb0`
- `MR-W4-1`: `sb6` lease and backend primitives
- `MR-W4-2`: `sb7` provider mesh and routed execution
- `MR-W4-3`: `sb8` GitHub typed executor
- `MR-W4-4`: `sb8` Slack typed executor
- `MR-W4-5`: `sb9` origin-aware ceilings and approval objects
- `MR-W4-6`: `sb10` execution theater and capability wallet
- `MR-W4-7`: `sb11` replay, revoke, freeze, and full release validation

`sb8` and `sb9` can overlap only after `MR-W4-2` freezes the routed execution contract. `sb10`
should not start until the approval and typed-executor evidence fields are stable.

### First Concrete Ship Targets

The first credible Wave 4 release should explicitly target:

- enterprise backends: HashiCorp Vault and AWS Secrets Manager
- provider mesh targets: OpenAI, Anthropic, Azure OpenAI, and one local executor
- typed SaaS executors: GitHub issue/comment/check-run actions and Slack message/post/update flows
- operator surfaces: active capability wallet, live execution timeline, replay/simulate, and panic revoke

## Wave 5 -- Delegated Trust Fabric

### Goal

Build on the Wave 4 action plane and turn it into a delegated trust fabric with:

- just-in-time OAuth and cloud identity minting instead of mostly secret-material resolution
- typed intent preview objects that explain what an execution will touch before it runs
- parent/child multi-agent capability lineage with attenuation and chain-of-custody evidence
- time-travel replay against current policy, routing, and approval posture
- a mission-control operator surface with portable signed completion bundles

### User-Facing Outcome

Wave 5 should make brokered execution feel inspectable before, during, and after the action:

1. users can approve a typed intent card instead of a raw opaque action payload
2. child agents can act with reduced scopes without widening the parent agent's trust boundary
3. GitHub, Slack, and cloud actions run on freshly minted identities that expire automatically
4. operators can answer who acted, what they were allowed to do, which identity was minted, and whether today's policy would still allow it
5. signed completion bundles can travel into cases, audits, exports, and customer-facing evidence

### Non-Goals

- full IAM parity across every SaaS and cloud provider in the first Wave 5 cut
- replacing provider-native admin consoles or human approval systems
- replay that performs live mutations during simulation mode
- cross-tenant broker federation in the first Wave 5 release

### Milestones

| Milestone | Goal | Primary Lanes | Exit Criteria |
| --- | --- | --- | --- |
| `W5-M0` | Freeze contracts for minted identities, intent cards, lineage, and replay bundles | `sb0` | broker protocol, policy schema, approval object shape, lineage/evidence fields, and mission-control summary objects are documented and accepted |
| `W5-M1` | Ship just-in-time identity minting on the existing action plane | `sb12` | `brokerd` can mint short-lived GitHub App, Slack app, and AWS STS identities, lease expiry and revocation are modeled, and `hushd` records minted-identity metadata in capability state |
| `W5-M2` | Add explain-before-execute intent and approval previews | `sb13` | typed intent preview objects exist for GitHub, Slack, and routed LLM actions, approvals can target those objects directly, and policy can require preview or approval based on risk/data class |
| `W5-M3` | Bind delegated multi-agent lineage to broker execution | `sb14` | parent/child agents receive attenuated broker scopes, delegation chains are signed and verifiable, and capability/evidence views expose lineage per execution |
| `W5-M4` | Make replay and mission control operator-grade | `sb15`, `sb16` | users can replay historical executions against current policy and routing, and control-console exposes live mission-control views for active capabilities, blast radius, and lineage |
| `W5-M5` | Finish portable evidence and defensive hardening | `sb17` | signed completion bundles export cleanly, tripwire/deception controls can freeze or revoke on suspicious use, and full release gates pass on the integrated Wave 5 stack |

### Shared Files That Stay Orchestrator-Owned

These files are likely to see edits from more than one lane and should merge through `sb0`:

- `crates/libs/clawdstrike-broker-protocol/src/lib.rs`
- `crates/libs/clawdstrike/src/policy.rs`
- `crates/libs/hush_multi_agent/src/token.rs`
- `crates/services/hushd/src/api/broker.rs`
- `crates/services/hushd/src/broker_state.rs`
- `crates/services/clawdstrike-brokerd/src/api.rs`
- `crates/services/clawdstrike-brokerd/src/provider/mod.rs`
- `apps/control-console/src/api/client.ts`
- `packages/adapters/clawdstrike-adapter-core/src/broker-types.ts`
- `docs/plans/clawdstrike/secret-broker/README.md`
- `docs/plans/clawdstrike/secret-broker/roadmap.md`
- `.codex/swarm/lanes.tsv`
- `.codex/swarm/waves.tsv`

### Lane Map

| Lane | Scope | Primary Ownership | Depends On | Verification Gate |
| --- | --- | --- | --- | --- |
| `sb12` | JIT OAuth and cloud identity minting | `crates/services/clawdstrike-brokerd/src/secret_provider/**`, `src/lease/**`, typed provider auth exchangers, and hushd minted-identity metadata wiring | `W5-M0` | `cargo test -p clawdstrike-brokerd` |
| `sb13` | Intent preview cards and approval policy | broker protocol intent objects, `hushd` preview/approval APIs, policy risk hooks, and adapter-side preview request plumbing | `W5-M0`, then merge after `sb12` | `cargo test -p hushd --test broker`, `cargo test -p clawdstrike`, and `npm --prefix packages/adapters/clawdstrike-broker-client test` |
| `sb14` | Multi-agent lineage and delegated broker scopes | `crates/libs/hush_multi_agent/**`, `hushd` capability issuance with delegation claims, and adapter-core lineage headers/proofs | `sb12`, `sb13` | `cargo test -p hush_multi_agent`, `cargo test -p hushd --test broker`, and `npm --prefix packages/adapters/clawdstrike-adapter-core test` |
| `sb15` | Time-travel replay and policy-diff simulation | broker replay ledger, policy snapshot comparison, routed-provider diffing, and non-mutating simulation APIs in `hushd` | `sb13`, then converge with `sb14` evidence fields | `cargo test -p hushd --test broker` and `cargo test -p clawdstrike-brokerd` |
| `sb16` | Mission control UX and approval/lineage surfaces | `apps/control-console/src/**`, local broker status surfaces in agent apps, mission-control dashboards, preview cards, and lineage graphs | `sb13`, `sb14`, `sb15` | `npm --prefix apps/control-console test`, `npm --prefix apps/control-console run build`, and `cargo check --manifest-path apps/agent/src-tauri/Cargo.toml` |
| `sb17` | Completion bundles, deception controls, and release hardening | signed completion bundle export, tripwire/honey credential logic, freeze-on-suspicion flows, final docs, and platform validation | `sb14`, `sb15`, `sb16` | `mise run ci`, `bash scripts/test-platform.sh`, and `cargo test --workspace` |

### Recommended Implementation Order

1. `sb0`: freeze the Wave 5 contract set first.
   That includes minted-identity metadata, intent preview shape, approval object extensions, delegated lineage fields, replay result contracts, and mission-control summary objects.
2. `sb12`: ship just-in-time identity minting next.
   Start with GitHub App installation tokens, Slack app credentials, and AWS STS because they align directly with the typed executors and lease machinery that already exist.
3. `sb13`: layer explain-before-execute intent previews on top of minted identities.
   `hushd` should stay the approval and policy authority while `brokerd` computes typed plans, risk hints, and resource targets for each execution.
4. `sb14`: bind multi-agent lineage after the preview contract stabilizes.
   Reuse `hush_multi_agent` for attenuation and sender identity so parent/child broker scopes become first-class instead of out-of-band metadata.
5. `sb15`: add time-travel replay once preview, routing, and lineage data are in the evidence model.
   Replay should answer "would this still run now?" without performing live mutations.
6. `sb16`: expose mission control UX after the lineage and replay data model is stable.
   The control-console should combine active capabilities, intent previews, lineage graphs, spend/latency, and blast-radius summaries in one operator surface.
7. `sb17`: finish with portable completion bundles, deception controls, and release-hardening.
   Tripwire-triggered revoke or freeze behavior and evidence export should merge last because they depend on the final evidence and replay contracts staying stable.

### Merge Graph

- `MR-W5-0`: docs/spec/schema freeze through `sb0`
- `MR-W5-1`: `sb12` minted identity and JIT lease core
- `MR-W5-2`: `sb13` intent preview and approval object flow
- `MR-W5-3`: `sb14` multi-agent lineage and delegated scopes
- `MR-W5-4`: `sb15` time-travel replay and policy-diff simulation
- `MR-W5-5`: `sb16` mission control dashboards and approval UX
- `MR-W5-6`: `sb17` signed completion bundles, tripwires, and full release validation

`sb14` should not merge before `MR-W5-2` freezes how preview and approval metadata are represented in capability state. `sb16` should wait for both replay result contracts and lineage evidence shapes to stabilize.

### First Concrete Ship Targets

The first credible Wave 5 release should explicitly target:

- just-in-time identities: GitHub App installation tokens, Slack app credentials, and AWS STS assume-role sessions
- intent preview cards: target systems, action types, affected resources, data classes, egress path, estimated cost, and policy hash
- lineage: signed parent/child broker delegation, per-hop attenuation, and lineage-aware capability detail in `hushd`
- mission control: active capability map, live execution timeline, provider spend/latency, lineage graph, and blast-radius summary
- replay and evidence: replay-against-current-policy, routed-provider diffs, and exportable signed completion bundles
