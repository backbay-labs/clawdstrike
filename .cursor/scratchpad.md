# Background and Motivation
Sentinel Swarm is already partway through a transition from a local workbench concept into a signed, federated threat-intel and mission-coordination system. The target operating model is a hybrid federated network: compact signed envelopes over P2P/libp2p gossip, heavier evidence in content-addressed or hub-backed storage, and self-hostable swarm hubs for relay, replay, search, and moderation.

# Key Challenges and Analysis
GENIUS: Problem Framing

Core goal:
Deliver a production-ready Sentinel Swarm federation stack that preserves Clawdstrike's fail-closed trust model: transports distribute data, but signed envelopes and verified blobs are the trust root.

Constraints:
- Existing branch already contains active uncommitted work in mission-control, mission-store, mission-runtime, mission-manager, mission types, docs, and tests.
- The workbench has meaningful substrate already implemented: canonical sentinel/swarm/intel types, mission flow, signal/finding pipelines, intel signing helpers, swarm coordinator, Speakeasy bridge, swarm/sentinel UI routes, and local persistence.
- Current typecheck is red, including true model drift in mission files and broad test typing failures around jest-dom matcher types.
- `intel-forge.ts` and `speakeasy-bridge.ts` still contain placeholder or partial verification logic; crypto/transport semantics are not end-to-end hardened yet.
- Relevant reusable code already exists outside this repo in `backbay-sdk`: `@backbay/witness` for browser-side verification and `@backbay/notary` for IPFS upload plus optional attestation publishing and verification.

Non-goals:
- Do not make blockchain the primary transport or storage plane.
- Do not prioritize cosmetic doc cleanup over protocol, verification, and transport correctness.
- Do not ship giant evidence blobs through pubsub.

GENIUS: Frontier Scan

- Current branch already matches the right architectural direction: local-first stores, transport abstraction, topic routing, signed message helpers, and outbox/reconnect behavior are in place.
- The biggest gap is not "missing all swarm comms"; it is "missing a canonical federated protocol and a real end-to-end implementation behind the current scaffolding."
- `swarm-coordinator.ts` provides a usable abstraction boundary: `TransportAdapter`, `MessageOutbox`, topic helpers, and in-process bus exist and can be kept as the client-side orchestration surface.
- `speakeasy-bridge.ts` defines typed swarm/speakeasy messages and message verification structure, but the wire protocol still needs canonical object/versioning decisions, stronger verification, and real transport wiring.
- `intel-forge.ts` promotes and packages intel, but `signIntel()`/`verifyIntel()` still use placeholder verification behavior; this is not production trust.
- `@backbay/witness` is a strong candidate for the verification layer because it already exposes Ed25519 verification, canonical receipt hashing/serialization, Merkle proof verification, and optional Rekor/EAS/Solana attestation-chain verification.
- `@backbay/notary` is a strong candidate for the durable publish lane because it already models "upload artifact bundle to IPFS + mint external attestation + verify later" without forcing blockchain into the realtime transport path.
- Current `mission-control.test.ts` and `sentinel-manager.test.ts` pass, proving the branch has some executable substrate. Full workbench `typecheck` fails, proving the repo is not integration-ready yet.

GENIUS: Options (clearly distinct)

Option A - UI-first continuation
Trade-offs:
- Fastest visible progress in the workbench.
- Risks deepening drift between docs, stores, and actual wire protocol.
- Produces a demo, not a durable federation substrate.
Est. complexity: M
Fast experiment: finish intel store/UI plumbing and render local/swarm intel with mock transport only.

Option B - Protocol-first federation core
Trade-offs:
- Best path to a real Swarm Hub and trust-preserving federation.
- Requires slowing down UI feature work until protocol objects, blob model, replay, and verification are stable.
- Minimizes rework across client, hub, and future hosted/self-hosted modes.
Est. complexity: L
Fast experiment: define and round-trip `FindingEnvelope`, `FindingBlob`, `HeadAnnouncement`, `RevocationEnvelope`, and `HubConfig` through a mock transport + replay store with signature verification.

Option C - Hub-first vertical slice
Trade-offs:
- Strong demo value: real relay/replay/history early.
- Can validate federation ergonomics sooner.
- Risks locking in protocol mistakes if hub behavior is built before object model and verification contracts are frozen.
Est. complexity: L
Fast experiment: implement a thin append-only replay service over provisional envelope types and connect one workbench client through it.

GENIUS: Recommendation

Pick: Option B, then immediately execute a Hub-first vertical slice on top of the stabilized protocol.

Why:
- The current repo already has enough UI and store scaffolding.
- The real production risk is inconsistent models and placeholder trust logic, not lack of screens.
- A canonical protocol layer unlocks direct peer exchange, Swarm Hub replay, IPFS/hub blob fetch, trust lists, revocation, and future hosted federation without rewriting the client.
- Reusing `witness` and `notary` reduces reimplementation risk and keeps Sentinel Swarm aligned with the wider Backbay trust/attestation stack instead of inventing a second verification system.

Success criteria (provable):
- Workbench typecheck passes again.
- Protocol objects are canonicalized, versioned, signed, and verified in tests.
- A client can publish a signed finding envelope, another peer or mock hub can replay it, and the receiver can verify/fetch/blob-check it.
- Hub replay/head sync and revocation flow have unit/integration coverage.
- A dogfood flow demonstrates mission -> signals/findings -> promoted intel/finding envelope -> swarm publish -> replay/fetch/verify.

Handoff plan:

Planner tasks (T1..T10)
- T1 - Stabilize branch health and source-of-truth types
  Success: `apps/workbench` typecheck passes; mission model drift is resolved; test matcher typing is fixed.
- T2 - Freeze federation protocol objects
  Success: canonical TypeScript interfaces and serialization rules exist for `FindingEnvelope`, `FindingBlob`, `HeadAnnouncement`, `RevocationEnvelope`, and `HubConfig`, with explicit convergence points against `@backbay/witness` canonical hashing inputs and `@backbay/notary` publish metadata.
- T3 - Replace placeholder trust logic
  Success: `signIntel`/message signing and verification paths use real signing/verification semantics or an explicit production adapter boundary with tests, preferring `@backbay/witness` for verification rather than local placeholder logic.
- T4 - Add client-side durable intel/finding stores
  Success: local/swarm intel and shared findings are persisted and queryable outside placeholder component state.
- T5 - Implement anti-entropy and replay contracts
  Success: per-swarm/per-issuer head tracking, missing-range requests, and replay ingestion work in tests.
- T6 - Build Swarm Hub MVP
  Success: hub can bootstrap/relay, persist append-only envelope history, serve replay, and expose blob lookup/pinning hooks.
- T7 - Add blob retrieval lane
  Success: finding blobs/evidence bundles can be fetched by CID/content hash from hub-backed storage or a content-addressed adapter with verification, with `@backbay/notary` evaluated as the first optional publish/anchor backend.
- T8 - Wire trust, moderation, and revocation
  Success: trust lists, peer/hub allowlists, revocation/supersession, and basic moderation policy enforcement are implemented with tests.
- T9 - Dogfood end-to-end federation flow
  Success: scripted dogfood proves mission-driven findings can be shared, replayed, verified, and rendered across peers/hub.
- T10 - Production hardening
  Success: observability, failure-mode docs, migration/version handling, load/race tests, and packaging/runbooks exist.

Risks + mitigations
- Mission model drift continues while federation work lands.
  Mitigation: finish T1 before new protocol implementation spreads the inconsistency.
- Placeholder crypto accidentally ships.
  Mitigation: make placeholder paths impossible in production builds or behind explicit dev-only adapters, and prefer `@backbay/witness` as the production verification backend.
- Store/provider fragmentation causes duplicate truth sources.
  Mitigation: designate canonical stores for local intel, federated findings, replay heads, and trust state before UI expansion.
- Hub over-centralization leaks into trust semantics.
  Mitigation: keep validation local, treat replay/search as facilitation, and design every hub response as untrusted until verified.
- Notary anchoring starts to dominate protocol design.
  Mitigation: keep `@backbay/notary` strictly optional and post-verification; envelopes and blobs must remain valid and useful without any external attestation.

Rollback/alternative path
- If full hub delivery proves too large for the current wave, stop after T5 with a mock/local replay service and finish a trusted private-swarm beta before external federation.

GENIUS: References

- User architectural direction from prior chat transcript: signed envelopes + P2P gossip + optional Swarm Hubs + content-addressed storage.

# High-Level Task Breakdown
- [ ] Task #1 - Re-baseline `apps/workbench` health
  **Success:** `npm run typecheck` passes in `apps/workbench`; focused mission/sentinel tests still pass.
- [ ] Task #2 - Canonicalize federated protocol objects and schema versioning
  **Success:** shared types and tests cover envelope canonicalization, hashing, and version validation, with an explicit compatibility decision for `@backbay/witness` canonical hashing helpers.
- [ ] Task #3 - Implement real verification boundaries for intel and swarm messages
  **Success:** verification rejects malformed, stale, replayed, or bad-signature messages in tests, using `@backbay/witness` where feasible.
- [ ] Task #4 - Add persistent swarm intel/finding/head stores
  **Success:** client can persist and reload local + federated artifacts without placeholder component state.
- [ ] Task #5 - Implement anti-entropy sync and replay ingestion
  **Success:** client can recover missed envelopes from a replay source using seq/head tracking.
- [ ] Task #6 - Deliver Swarm Hub MVP
  **Success:** hub provides bootstrap/relay/replay/history interfaces and append-only persistence.
- [ ] Task #7 - Deliver blob retrieval and verification lane
  **Success:** heavy artifacts are fetched out-of-band by content hash/CID and validated locally, with `@backbay/notary` evaluated for optional IPFS publish + attestation workflows.
- [ ] Task #8 - Add trust list, moderation, revocation, and supersession flows
  **Success:** hub and client both enforce configured trust/moderation rules; revocations propagate and apply.
- [ ] Task #9 - End-to-end dogfood and operator validation
  **Success:** scripted dogfood proves publish, relay, replay, fetch, verify, and UI render across the full path.
- [ ] Task #10 - Production packaging and runbooks
  **Success:** deploy/dev docs, failure modes, observability, and hosted/self-hosted hub configs are documented and tested.

# Project Status Board
- ~~**In Progress:** Task #2 planning and execution sequencing~~
- ~~**In Progress:** Task #1 - Re-baseline `apps/workbench` health~~
- ~~**In Progress:** Task #2 - Canonicalize federated protocol objects and schema versioning~~
- ~~**In Progress:** Task #3 - Implement real verification boundaries for intel and swarm messages~~
- ~~**In Progress:** Task #4 - Add persistent swarm intel/finding/head stores~~
- ~~**In Progress:** Task #5 - Implement anti-entropy sync and replay ingestion~~
- ~~**In Progress:** Task #6 - Deliver Swarm Hub MVP~~
- ~~**In Progress:** Task #7 - Deliver blob retrieval and verification lane~~
- ~~**In Progress:** Awaiting validation to begin Task #8 - Add trust list, moderation, revocation, and supersession flows~~
- ~~**In Progress:** Task #8 - Add trust list, moderation, revocation, and supersession flows~~
- ~~**In Progress:** Task #8 slice two - revocation and supersession propagation~~
- **In Progress:** Task #9 - End-to-end dogfood and operator validation
- ~~**Blocked On:** None~~
- ~~**Blocked On:** User validation to begin Task #8~~
- **Blocked On:** None
- **Done:** Initial repo/doc/code assessment - 2026-03-13
- **Done:** Integrated `@backbay/witness` / `@backbay/notary` findings into federation plan - 2026-03-13
- **Done:** Execution kickoff using Cursor subagents - 2026-03-13
- **Done:** Task #1 - Re-baseline `apps/workbench` health - 2026-03-13
- **Done:** Task #2 - Canonicalize federated protocol objects and schema versioning - 2026-03-13
- **Done:** Task #3 - Implement real verification boundaries for intel and swarm messages - 2026-03-13
- **Done:** Task #4 - Add persistent swarm intel/finding/head stores - 2026-03-13
- **Done:** Task #5 - Implement anti-entropy sync and replay ingestion - 2026-03-13
- **Done:** Task #6 - Deliver Swarm Hub MVP - 2026-03-13
- **Done:** Task #7 - Deliver blob retrieval and verification lane - 2026-03-13
- **Done:** Task #8 slice one - durable trust-policy state and fail-closed finding enforcement - 2026-03-13
- **Done:** Task #8 - Add trust list, moderation, revocation, and supersession flows - 2026-03-13

# Current Status / Progress Tracking
- 2026-03-13 11:00 - Reviewed sentinel swarm plans, workbench stores, mission flow, swarm coordinator, intel forge, and Speakeasy bridge.
- 2026-03-13 11:00 - Confirmed focused tests pass: `mission-control.test.ts` and `sentinel-manager.test.ts`.
- 2026-03-13 11:00 - Confirmed `apps/workbench` typecheck currently fails due to both widespread jest-dom matcher typing gaps and real mission API/model drift in `mission-control.ts`, `mission-manager.ts`, `mission-runtime.ts`, and `mission-store.tsx`.
- 2026-03-13 11:00 - Selected plan direction: optimize for full federated rollout first, not a solo-first interim path.
- 2026-03-13 11:00 - Reviewed `backbay-sdk/packages/witness` and `backbay-sdk/packages/notary`; updated the plan to reuse `witness` for local verification and treat `notary` as an optional publish/anchor layer for blob-backed federation.
- 2026-03-13 11:10 - Began Executor phase using Cursor subagents rather than Codex swarm scripts. Task #1 is active.
- 2026-03-13 11:10 - Task #1 scope narrowed to two concrete baselines: restore Vitest/jest-dom typing in TypeScript and resolve mission model drift between `mission-types.ts`, `mission-control.ts`, `mission-store.tsx`, and the older `mission-manager.ts` / `mission-runtime.ts` files.
- 2026-03-13 11:42 - Task #1 completed via subagent-driven development. `apps/workbench` now passes `npm run typecheck` and focused mission/sentinel/store/manager tests (`13/13`).
- 2026-03-13 11:42 - Task #1 implementation details: added explicit Vitest/jest-dom types in `apps/workbench/tsconfig.json`; repaired mission-store persisted mission normalization into a canonical usable shape; added `buildMissionStagesForDriver()` in `mission-control.ts` to support repair; updated `mission-manager.executeMission()` to forward `MissionLaunchContext`; removed unsupported `targetRef` from the `mission-manager` compatibility facade; added regression tests for mission-store normalization and manager context/contract behavior.
- 2026-03-13 11:42 - Task #1 review status: spec review approved after repair-path test coverage was added; final code-quality review returned LGTM with residual coverage gaps limited to `mission-runtime.ts` and some legacy/openclaw compatibility paths.
- 2026-03-13 12:18 - Task #2 completed via subagent-driven development. Added `apps/workbench/src/lib/workbench/swarm-protocol.ts` and `swarm-protocol.test.ts` with versioned protocol schemas, fail-closed runtime guards, deterministic canonical JSON serialization, `0x`-prefixed SHA-256 hashing, signable field extraction, and derived `HeadAnnouncement` creation.
- 2026-03-13 12:18 - Task #2 protocol hardening details: publish metadata stripping is limited to known protocol slots, issuer identities are bound to `aegis:ed25519:<publicKey>`, runtime validators reject unknown keys and unsafe numeric ranges, and protocol compatibility is explicitly aimed at `@backbay/witness`.
- 2026-03-13 12:18 - Task #2 verification status: `apps/workbench` passes `npm run typecheck` and focused mission/protocol tests (`27/27`). Spec review approved the versioned-schema approach, and final code-quality review returned LGTM with only parity-vector follow-up notes for Task #3.
- 2026-03-13 12:55 - Task #3 completed via subagent-driven development. Added a narrow `signature-adapter.ts` boundary backed by the existing real Ed25519 implementation in `operator-crypto.ts` rather than pulling `@backbay/witness` directly into the workbench.
- 2026-03-13 12:55 - Task #3 verification details: `signIntel()` now performs real detached signing over the hashed canonical intel payload; `verifyIntel()` is async and verifies both the intel signature and its receipt signature; `verifyClawdstrikeMessage()` now verifies Ed25519 signatures against a canonical JSON hash of the full unsigned message payload and only tracks nonces after signature success.
- 2026-03-13 12:55 - Task #3 provenance hardening: receipt verification now binds `receipt.action.target`, `receipt.evidence.content_hash`, and `receipt.evidence.finding_ids` back to the recomputed intel artifact; `IntelShareMessage` now carries the full signable-intel hash plus `intelSignerPublicKey`, matching the actual signing semantics.
- 2026-03-13 12:55 - Task #3 verification status: `apps/workbench` passes `npm run typecheck` and focused mission/protocol/intel/speakeasy tests (`40/40`). Final spec review returned `SPEC OK`; final code review returned `LGTM` with residual follow-up gaps limited to extra negative-path regression coverage and future consumer-side intel-share validation helpers.
- 2026-03-13 13:41 - Task #4 completed via subagent-driven development. Added `intel-store.tsx` for durable local/swarm intel artifacts and `swarm-feed-store.tsx` for durable `FindingEnvelope` and `HeadAnnouncement` records with latest-seq selectors intended to become the substrate for Task #5 replay logic.
- 2026-03-13 13:41 - Task #4 UI/store wiring: `FindingsIntelPage` and `FindingDetailPage` now promote findings into the canonical intel store instead of page-local placeholder state; `IntelPageConnected` now reads local/swarm intel from the store; `IntelDetailPage` now renders the real `IntelDetail` component and shares through a real app path into `SwarmProvider`, `IntelStore`, and `SwarmFeedStore`.
- 2026-03-13 13:41 - Task #4 federation durability details: swarm intel provenance now preserves multiple `(swarmId, intel.id)` records instead of overwriting by intel ID alone; sharing intel now persists `IntelRef`, swarm intel payloads, a derived `FindingEnvelope`, and a `HeadAnnouncement`; durable feed/head issuer attribution now follows the current publishing operator when one re-shares intel signed by someone else.
- 2026-03-13 13:41 - Task #4 verification status: `apps/workbench` passes `npm run typecheck` and focused store/page/regression tests (`46/46`). Final spec review returned `SPEC OK`; final code review returned `LGTM` with residual follow-up gaps limited to missing unhappy-path share tests and the anti-entropy/history work intentionally deferred to Task #5.
- 2026-03-13 14:15 - Task #5 completed via subagent-driven development. Added `swarm-sync.ts` as the pure anti-entropy planner/validator layer and extended `swarm-feed-store.tsx` with `getFeedSyncState`, `deriveReplayRequest`, and reducer-based `ingestReplayBatch()` helpers built on the Task #4 durable feed store.
- 2026-03-13 14:15 - Task #5 replay hardening details: replay progress now tracks both the highest contiguous recovered sequence and the highest seen sequence; sparse high-seq batches no longer advance the durable tip or head; heads are rejected with `gap_incomplete` until the contiguous tip reaches the announced sequence; replay history is now append-only by `swarmId + feedId + issuerId + feedSeq` so repeated finding IDs and shared-feed cross-issuer collisions do not erase anti-entropy state.
- 2026-03-13 14:15 - Task #5 verification status: `apps/workbench` passes `npm run typecheck` and focused sync/store/regression tests (`56/56`). Final spec review returned `SPEC OK`; final code review returned `LGTM` with residual follow-up gaps limited to later retention/compaction, real hub/transport replay e2e coverage, and future migration handling.
- 2026-03-13 14:28 - Task #6 server-host decision confirmed: the Swarm Hub MVP should land in `crates/services/hushd`, not a new TypeScript service, because `hushd` already has the right Axum/router/auth shape plus reusable durable-state primitives.
- 2026-03-13 14:28 - Task #6 scope narrowed for testability: use `hushd` `ControlDb` SQLite as the canonical MVP store for append-only finding history, synthesized per-issuer heads, replay range responses, and blob lookup/pin audit hooks, while leaving Spine/NATS mirroring as an optional later extension instead of a merge blocker.
- 2026-03-13 15:15 - Task #6 completed via subagent-driven development. Added `crates/services/hushd/src/api/swarm_hub.rs` plus route wiring in `api/mod.rs`, new swarm tables and helpers in `control_db/schema.rs` / `control_db/mod.rs`, and an end-to-end `crates/services/hushd/tests/swarm_hub.rs` suite covering the first server-side Swarm Hub surfaces.
- 2026-03-13 15:15 - Task #6 Swarm Hub MVP details: `hushd` now serves hub config, append-only finding ingest, synthesized per-feed/per-issuer heads, bounded replay ranges, blob reference lookup, and blob-pin intent recording from SQLite-backed `ControlDb` state without requiring NATS/JetStream for correctness.
- 2026-03-13 15:15 - Task #6 protocol/persistence hardening: head responses now match the canonical `HeadAnnouncement` shape frozen in `apps/workbench/src/lib/workbench/swarm-protocol.ts`, head hashes strip finding/blob `publish` metadata before canonical SHA-256, and the old `(feed_id, issuer_id, finding_id)` uniqueness index is dropped so the same `findingId` can reappear at later `feedSeq` values in append-only history.
- 2026-03-13 15:15 - Task #6 verification status: `cargo build -p hushd --bin clawdstriked`, `cargo test -p hushd --test swarm_hub` (`16/16`), and `cargo test -p hushd control_db_new_drops_legacy_swarm_finding_identity_index` all pass. Final code review returned `LGTM`; final spec review returned `SPEC OK`; residual follow-up gaps are limited to extra malformed-input coverage and the later blob byte retrieval/workbench integration work intentionally deferred to Task #7+.
- 2026-03-13 15:15 - Task #7 exploration findings: the protocol layer already defines `FindingBlob`, `FindingBlobRef`, `isFindingBlob()`, and `hashProtocolPayload()` in `apps/workbench/src/lib/workbench/swarm-protocol.ts`, but the workbench has no blob client/store yet and the real share path in `sentinel-swarm-pages.tsx` still emits `blobRefs: []`.
- 2026-03-13 15:15 - Task #7 storage/verification direction: keep the lane consumer-first by resolving blob refs from the new `hushd` lookup endpoint, fetching artifact bytes out-of-band from `publish.uri` or a content-addressed adapter, verifying raw-byte SHA-256 locally, and only then optionally validating `FindingBlob` JSON payloads or richer receipt proofs.
- 2026-03-13 15:15 - Task #7 integration guidance from `backbay-sdk`: use `@backbay/witness` as the first local verification helper (WASM-backed SHA-256 / receipt verification) and keep `@backbay/notary` strictly optional and off the critical path because its current APIs are server-first, path-based, and EAS-centric rather than a clean browser blob transport.
- 2026-03-13 15:47 - Task #7 first implementation slice completed via subagent-driven development. Added `apps/workbench/src/lib/workbench/swarm-blob-client.ts` plus `swarm-blob-client.test.ts` to resolve hushd blob lookups, verify fetched `FindingBlob` protocol payloads against canonical `hashProtocolPayload()` digests, verify artifact raw bytes against `0x`-prefixed SHA-256 + byte length, and request hushd pin intent when bytes are unavailable.
- 2026-03-13 15:47 - Task #7 blob-client hardening: extracted shared URL validation into `apps/workbench/src/lib/workbench/fleet-url-policy.ts` so blob fetches inherit the same invalid-scheme / embedded-credentials / production SSRF guardrails as the existing fleet connection code instead of creating a parallel policy path.
- 2026-03-13 15:47 - Task #7 verification status for the current slice: `npm test -- src/lib/workbench/__tests__/swarm-blob-client.test.ts` passes (`12/12`), `npm run typecheck` passes in `apps/workbench`, final code review returned `LGTM`, and final spec review returned `SPEC OK`. Remaining work for Task #7 is consumer/store wiring so a real app surface can hydrate and display verified blob content on demand rather than leaving the blob client as a pure library boundary.
- 2026-03-13 17:10 - Task #7 completed via subagent-driven development. Added a real `Swarm Artifacts` consumer on the Intel detail route so saved swarm feed records can resolve blob refs through `hushd`, verify `FindingBlob` manifests, verify raw artifact bytes on demand, and record pin intent when bytes are unavailable.
- 2026-03-13 17:10 - Task #7 hardening details: blob verification now uses shared desktop-safe transport via `http-transport.ts`, aligns blob fetches with the existing Tauri/fleet HTTP path, verifies artifact payloads sequentially instead of unbounded `Promise.all(...)`, and fail-closes on oversized FindingBlob or artifact responses using metadata, `Content-Length`, and streamed byte-cap checks.
- 2026-03-13 17:10 - Task #7 verification status: `npm test -- --run src/lib/workbench/__tests__/http-transport.test.ts` (`3/3`), `npm test -- src/lib/workbench/__tests__/swarm-blob-client.test.ts` (`14/14`), `npm test -- src/components/workbench/intel/__tests__/intel-detail-page.test.tsx` (`8/8`), `npm test -- --run src/lib/workbench/__tests__/fleet-client.test.ts` (`111/111`), and `npm run typecheck` all pass. Final spec review returned `SPEC OK`; code review found no remaining lane-local blockers after the transport and size-limit repairs.
- 2026-03-13 17:10 - Residual cross-cutting follow-up: `validateFleetUrl()` still blocks embedded credentials and literal private/loopback IPs, but hostname-to-private-IP resolution for untrusted remote hosts remains a broader shared transport/policy hardening gap rather than a Task #7-only contract defect.
- 2026-03-13 17:32 - Task #7 final hardening closeout: untrusted blob and artifact fetches now reject redirects, the shared URL policy rejects the `localhost.` trailing-dot loopback alias in production, and the blob client route tests plus shared URL-policy tests were extended to prove those regressions stay closed.
- 2026-03-13 17:32 - Task #7 final verification status: `npm test -- --run src/lib/workbench/__tests__/http-transport.test.ts` (`3/3`), `npm test -- src/lib/workbench/__tests__/swarm-blob-client.test.ts` (`16/16`), `npm test -- src/components/workbench/intel/__tests__/intel-detail-page.test.tsx` (`8/8`), `npm test -- --run src/lib/workbench/__tests__/fleet-client.test.ts` (`112/112`), and `npm run typecheck` all pass. Final code review returned `LGTM`; final spec gate returned `SPEC OK`.
- 2026-03-13 17:45 - Task #8 began via fresh exploration across `apps/workbench`, `crates/services/hushd`, and the sentinel-swarm docs/protocol layer. The repo already models `HubTrustPolicy` and `RevocationEnvelope`, but neither the client ingress path nor the hub currently enforces issuer trust rules or persists revocation/supersession state.
- 2026-03-13 17:45 - Task #8 scope is intentionally split into two slices. Slice one is durable trust-policy state plus fail-closed trust enforcement for findings on hub publish and client ingest/replay. Slice two follows with revocation/supersession propagation and projection once the trust-policy substrate exists.
- 2026-03-13 17:45 - Task #8 slice-one success target: persisted trust policy on both hub and client; `blockedIssuers`, `trustedIssuers`, `allowedSchemas`, `requireAttestation`, and `requireWitnessProofs` enforced on finding publish and replay/ingest; tests prove rejected findings never reach durable feed state and blocked issuers cannot publish through `hushd`.
- 2026-03-13 21:40 - Task #8 slice one completed via subagent-driven development. The hub and client now persist `HubTrustPolicy`, enforce issuer/schema/attestation/witness rules fail-closed on publish and ingest/replay, quarantine strict-policy persisted feed/head data on reload, and block live hushd-backed sharing until hub trust hydration succeeds from the first saved-URL render.
- 2026-03-13 21:40 - Task #8 slice-one verification status: `npm exec vitest run src/components/workbench/intel/__tests__/intel-detail-page.test.tsx src/lib/workbench/__tests__/swarm-feed-store.test.tsx src/lib/workbench/__tests__/swarm-trust-policy.test.ts` (`37/37`), `npm run typecheck`, and the final spec gate all pass. Final code review returned `LGTM` with only a non-blocking note about missing malformed-`control_metadata` regression parity in `hushd`.
- 2026-03-13 21:40 - Task #8 slice-two exploration kickoff: `swarm-protocol.ts` already defines `RevocationEnvelope` plus supersede targets, but neither `swarm-feed-store.tsx` nor `crates/services/hushd/src/api/swarm_hub.rs` currently persists revocation/supersession history or projects it into active feed/head state.
- 2026-03-13 23:36 - Task #8 completed after a final policy-flip repair in `swarm-feed-store.tsx`: runtime `setTrustPolicy()` changes now repartition active vs quarantined finding/head/revocation state, pending finding digest hydration can no longer resurrect quarantined findings into active state, duplicate guards now check both active and quarantined partitions, and replay progress treats quarantined finding sequences as already seen.
- 2026-03-13 23:36 - Task #8 final verification status: `npm exec vitest run src/lib/workbench/__tests__/swarm-feed-store.test.tsx src/components/workbench/intel/__tests__/intel-detail-page.test.tsx` (`46/46`) and `npm run typecheck` both pass. Final targeted code review returned `LGTM`; remaining notes are non-blocking partition asymmetries for head announcements plus the intentionally fail-closed exact-default-policy restoration behavior.
- 2026-03-13 23:58 - Task #9 root-cause investigation found two live dogfood blockers on the current branch: a new clean-session operator-identity prompt that the Playwright scripts did not satisfy, and a dev-proxy auth gap that caused proxied hushd fleet status calls to return `401`, collapsing Mission Control OpenClaw readiness to `0 agents`.
- 2026-03-14 04:09 - Task #9 mission-control slice now passes again after patching both dogfood scripts to bootstrap an operator identity and patching the workbench dev proxy + script startup env so proxied hushd auth works during dogfood runs. Verified with `WORKBENCH_MISSION_DOGFOOD_START_DEV=0 WORKBENCH_MISSION_DOGFOOD_TIMEOUT_SECS=60 npm --prefix apps/workbench run dogfood:missions`, which produced `output/playwright/workbench-mission-control-dogfood/20260314T040923Z/summary.json` with Claude `blocked`, OpenClaw `finding_links: 1`, `endpoints_after: 26`, and `online_after: 1`.
- 2026-03-14 04:09 - Task #9 remaining gap is now sharply scoped: the live mission dogfood proves mission creation and runtime evidence again, and the network trace shows proxied hushd fleet status calls succeeding, but no live browser harness yet exercises `/_proxy/hushd/api/v1/swarm/...` publish, replay, hub-config hydration, or blob verification. That federation tail remains the next validation slice.
- 2026-03-14 06:14 - Task #9 federation-tail exploration confirmed a deeper blocker behind the missing browser coverage: the workbench live share path hydrates hub config and can verify blobs, but `IntelDetailPage.handleShareToSwarm` still never calls the hushd publish endpoints, and no app code currently exercises hushd head/replay routes. The next execution slice therefore starts with real hub publish integration rather than dogfood-script-only work.
- 2026-03-14 06:14 - Began the next Task #9 repair slice: add a workbench fleet-client publish helper plus fail-closed `Share to Swarm` hub publishing, then extend the dogfood flow to create a swarm, promote a mission-produced finding, and drive a real `/_proxy/hushd/api/v1/swarm/feeds/.../findings` publish through the UI.
- 2026-03-14 06:18 - Task #9 publish slice landed in the workbench: `fleet-client.ts` now exposes a fail-closed `publishSwarmFinding()` helper with runtime response validation, and `IntelDetailPage.handleShareToSwarm` now publishes to hushd before mutating local durable swarm state when a saved hushd connection exists.
- 2026-03-14 06:18 - Task #9 publish-slice verification status: `npm --prefix apps/workbench run typecheck` passed, `npm exec vitest run src/components/workbench/intel/__tests__/intel-detail-page.test.tsx` passed (`15/15`), and `ReadLints` reported no diagnostics on the touched files. New route regressions prove the live share path hits `/_proxy/hushd/api/v1/swarm/feeds/.../findings` on success and leaves no partial local swarm state behind when hushd returns an invalid publish response.
- 2026-03-14 06:28 - Post-implementation review found one easy fail-closed gap and one larger follow-up. The easy gap is now fixed: `publishSwarmFinding()` rejects semantically bad `200 OK` bodies (`accepted: false` or mismatched head feed/issuer/seq), and the route regression now proves the share path stays empty when hushd returns `accepted: false`. The larger remaining follow-up is remote `feedSeq` reconciliation against hushd head state before publish, which stays in Task #9’s replay/sync slice.
- 2026-03-14 06:28 - Final publish-slice verification status: reran `npm --prefix apps/workbench run typecheck` and `npm exec vitest run src/components/workbench/intel/__tests__/intel-detail-page.test.tsx` (`15/15`) after the review fix; both passed, and `ReadLints` still reported no diagnostics.

# Executor's Feedback or Assistance Requests
- ~~Best next step: switch to Executor mode and start with Task #1, then fold `@backbay/witness` into Task #3 before implementing hub replay/blob lanes.~~
- Current next step: complete Task #1 with fresh verification evidence, then move to Task #2 and freeze the canonical federation protocol objects before any hub implementation.
- Current execution focus: Task #2 should produce the canonical `FindingEnvelope`, `FindingBlob`, `HeadAnnouncement`, `RevocationEnvelope`, and `HubConfig` types plus tests and an explicit compatibility choice for `@backbay/witness` hashing/canonicalization.
- ~~Current execution focus: Task #3 should replace placeholder intel and swarm-message verification with protocol-aware, test-backed verification paths, preferably reusing `@backbay/witness` primitives where they fit cleanly.~~
- ~~Current execution focus: Task #4 should make the hardened protocol objects and verification outputs durable by adding persistent swarm intel/finding/head stores and wiring them into the workbench state model.~~
- ~~Current execution focus: Task #5 should build on the new durable feed/head stores to track per-swarm/per-publisher heads, detect missing ranges, ingest replay batches, and prove catch-up behavior in tests before any hub networking layer lands.~~
- ~~Current execution focus: Task #6 should add a first `hushd` Swarm Hub surface with `GET /api/v1/swarm/hub/config`, publish/head/replay endpoints per feed+issuer, and blob lookup/pin hooks backed by append-only SQLite state rather than making JetStream mandatory for correctness.~~
- ~~Current execution focus: Task #7 should build on the new `hushd` hub by adding a real blob retrieval and verification lane that can fetch heavy artifacts by digest/CID, verify them locally against the federated protocol contract, and keep `@backbay/notary` optional rather than mandatory for the first usable path.~~
- ~~Current execution focus: Task #7 should start with a workbench-side hub/blob client and verification module before UI/storage expansion: resolve blob refs from `hushd`, fetch bytes via `publish.uri`, verify raw-byte digests locally, validate `FindingBlob` JSON when present, and expose pin intent only when bytes are unavailable.~~
- ~~Current execution focus: Task #7 now needs the smallest real consumer path on top of the verified blob client, likely in a swarm-aware route or store that can use the saved fleet connection plus `SwarmFeedStore` blob refs to fetch and render verification state on demand.~~
- 2026-03-13 15:45 - Reviewer pass on Task #7 blob retrieval/verification slice returned `LGTM` against the stated MVP contract. Non-blocking follow-ups: align the new blob client with the existing fleet transport abstraction before UI wiring, and add a few extra malformed-response regression tests for lookup/blob/pin failure paths.
- ~~2026-03-13 17:10 - Task #7 is ready for user validation. On confirmation, the next execution slice is Task #8: trust lists, moderation, revocation, and supersession flows across the client and hub.~~
- ~~2026-03-13 17:45 - Current execution focus: Task #8 slice one should add persisted `HubTrustPolicy`-shaped state to the hub and client, then enforce that policy fail-closed for finding publish and finding replay/ingest before any revocation or supersession projection work starts.~~
- ~~2026-03-13 21:40 - Current execution focus: Task #8 slice two should add append-only revocation/supersession persistence on the hub and client, replay/head propagation, and local projection so revoked findings are suppressed and superseded findings point to their replacement with regression coverage.~~
- 2026-03-13 23:36 - Current execution focus: Task #9 should run the full workbench dogfood path end to end using the real route-level federation flow, existing hushd/workbench live fixtures, and scripted validation of publish, policy hydration, replay, artifact verification, and rendered UI state.
- 2026-03-14 04:09 - Current execution focus: keep Task #9 in progress and build or extend a browser dogfood slice for the missing federation tail: mission-produced finding/intel promotion, share into the hub, second-session replay/hydration, and blob verification or pin fallback through the real `Sentinel Swarm` UI path.
- 2026-03-14 06:14 - Current execution focus: first close the client gap that blocks the live federation tail by wiring `Share to Swarm` to hushd publish fail-closed with regression coverage, then resume the browser dogfood expansion on top of the real publish path.
- 2026-03-14 06:18 - Current execution focus: extend the live dogfood/browser slice to create a swarm in a clean session, promote a mission-produced finding into intel, drive the real hushd-backed `Share to Swarm` path, and capture publish-network evidence before tackling replay/hydration.

# Lessons
- 2026-03-13 - The branch already has more federation substrate than the UI suggests; the main gap is protocol and verification hardening, not lack of initial scaffolding.
- 2026-03-13 - Always check full typecheck before calling the branch integration-ready; focused tests alone hide significant model drift.
- 2026-03-13 - `@backbay/witness` and `@backbay/notary` cover important parts of the trust stack already, so the plan should converge on them instead of duplicating verification and publish logic inside Sentinel Swarm.
- 2026-03-13 - Compatibility shims must either preserve semantics all the way through execution or explicitly reject unsupported fields; silent façade-only options create future runtime traps.
- 2026-03-13 - A protocol task is only really frozen once hashing, schema validation, and issuer binding are fail-closed enough to survive skeptical code review; permissive guards just defer the cost to later tasks.
- 2026-03-13 - Real signature verification is not enough by itself; provenance objects like receipts and transport wrappers must be cryptographically bound back to the artifact they describe or they become swappable trust veneers.
- 2026-03-13 - Durable stores only count as real federation substrate once a live app path actually writes into them; store scaffolding without ingress and provenance-aware keys just creates another layer of dead state.
- 2026-03-13 - Anti-entropy logic cannot use “highest sequence ever seen” as a synonym for “caught up”; replay has to be driven by the highest contiguous recovered prefix or sparse batches will silently strand gaps forever.
- 2026-03-13 - For a first self-hostable Swarm Hub lane, `hushd` plus SQLite-backed append-only state is a better merge target than making Spine/NATS infrastructure mandatory before the replay contract exists end-to-end.
- 2026-03-13 - Shared protocol contracts need explicit cross-runtime regression tests; otherwise a server lane can look locally correct while silently drifting on field names or hash inputs from the frozen TypeScript contract.
- 2026-03-13 - Append-only feed history must be keyed by sequence, not by artifact identity; uniqueness on `findingId` seems intuitive at first but breaks legitimate re-emission and anti-entropy semantics later.
- 2026-03-13 - Blob verification needs two distinct digest rules: protocol objects use canonical JSON hashes with `publish` metadata stripped, while fetched artifacts/files should verify against raw-byte SHA-256 unless a richer proof format is explicitly defined.
- 2026-03-13 - Blob and artifact verification lanes need explicit response byte caps and bounded verification concurrency; otherwise a single untrusted fetch can turn correctness code into a denial-of-service path.
- 2026-03-13 - Desktop workbench network code must reuse the shared Tauri-aware transport boundary rather than silently falling back to browser fetch, or packaged-app behavior will drift from dev/test behavior.
- 2026-03-13 - Hostname validation and literal private-IP blocking are not the same as DNS-aware private-network protection; untrusted remote URI fetches still need a deeper resolver/allowlist story in later hardening work.
- 2026-03-13 - URL validation before an untrusted fetch is not sufficient by itself; the client also needs redirect rejection and host normalization so public-looking URLs cannot bounce into local services through alias tricks.
- 2026-03-13 - Live fail-closed federation logic must key off saved hub configuration, not just a later `connected` flag, or bootstrap windows reopen strict share paths before trust-policy hydration lands.
- 2026-03-13 - Once swarm feed data can move between active and quarantined partitions, every async updater and duplicate/replay guard has to stay partition-aware or a later strict policy flip will silently resurrect moderated history.
- 2026-03-14 - Browser dogfood scripts are part of the product contract too: if they clear local state, they must recreate any new mandatory bootstrap state such as operator identity before they drive later workflow surfaces.
- 2026-03-14 - The workbench dev proxy needs explicit auth available at startup for live dogfood against hushd/control-api; otherwise the UI can look “connected” while fleet-backed readiness silently degrades to empty-state behavior.
