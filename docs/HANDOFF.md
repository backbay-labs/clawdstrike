# ClawdStrike SDR — Team Handoff

> **Date:** 2026-02-07
> **Branch:** `feat/sdr-execution` → `main`
> **PR:** [#40 — feat: Swarm Detection & Response (SDR) platform](https://github.com/backbay-labs/clawdstrike/pull/40)

---

## What This Branch Contains

PR #40 adds the Swarm Detection & Response (SDR) platform to ClawdStrike — a runtime security pipeline that flows from Kubernetes kernel events through signed transparency logs to a desktop SOC UI. The branch has **21 commits** on top of `main`.

### Key commits (chronological):

1. `2643377e` — **SDR foundation**: `crates/libs/spine/` (signed envelopes, checkpoints, NATS transport, Merkle proofs), `crates/bridges/tetragon-bridge/` (Tetragon gRPC → Spine)
2. `60daed38` — **Wave 2**: `crates/bridges/hubble-bridge/` (Cilium Hubble → Spine), `crates/libs/spine/src/bin/` services (checkpointer, proofs API)
3. `132d240b` — **Wave 3**: Dockerfiles, `spine-cli`, NATS wiring in desktop Tauri app
4. `b12cf65a` — **Wave 4**: Live data pipeline, proof verification, L7 enrichment
5. `38187bd7` — **30 bug fixes** from PR review (4 critical, 8 high, 10 medium, 8 low)
6. `e23ddd93` — **14 implementation specs** for the next roadmap phases (`docs/specs/01-14`)

### What's uncommitted right now

6 spec files have been updated to reference `@backbay/notary`, `@backbay/witness`, and `@backbay/speakeasy` SDK package reuse (see "SDK Reuse" section below). These should be committed before any other work:

```
docs/specs/05-npm-publishing.md
docs/specs/07-aegisnet-notary-replacement.md
docs/specs/08-marketplace-spine-unification.md
docs/specs/10-ipfs-distribution.md
docs/specs/12-reticulum-adapter.md
docs/specs/13-eas-onchain-anchoring.md
```

---

## Architecture at a Glance

```
Kubernetes Cluster                    NATS JetStream               Desktop / CLI
┌─────────────────┐                ┌──────────────────┐         ┌──────────────────┐
│ Tetragon         │──gRPC──────►  │ tetragon-bridge   │──pub──► │                  │
│ (kernel events)  │               │ (ProcessExec,     │         │  Spine envelopes │
│                  │               │  ProcessExit,     │         │  in JetStream    │
│ Hubble           │──gRPC──────►  │  ProcessKprobe)   │         │                  │
│ (network flows)  │               │                   │         │  ┌────────────┐  │
└─────────────────┘               │ hubble-bridge     │         │  │Checkpointer│  │
                                   │ (L3/L4/L7 flows)  │         │  │ Merkle tree│  │
                                   └──────────────────┘         │  │ witnesses  │  │
                                                                 │  └────────────┘  │
                                                                 │  ┌────────────┐  │
                                                                 │  │ Proofs API │  │
                                                                 │  │ /v1/proofs │  │
                                                                 │  └────────────┘  │
                                                                 └──────────────────┘
                                                                          │
                                                                          ▼
                                                                 ┌──────────────────┐
                                                                 │ Desktop Tauri App │
                                                                 │ • SOC dashboard   │
                                                                 │ • Marketplace     │
                                                                 │ • Proof verify    │
                                                                 └──────────────────┘
```

### Crate map (Rust)

| Crate | Purpose | Status |
|-------|---------|--------|
| `hush-core` | Ed25519, SHA-256, Keccak-256, Merkle trees, RFC 8785 canonical JSON | alpha |
| `clawdstrike` | Policy engine, guards, receipts, marketplace feed | alpha |
| `spine` | Signed envelopes, checkpoints, NATS transport, trust bundles, proofs API | alpha |
| `tetragon-bridge` | Tetragon gRPC → Spine envelopes | alpha |
| `hubble-bridge` | Hubble gRPC → Spine envelopes | alpha |
| `hushd` | HTTP daemon for centralized enforcement | alpha |
| `hush-multi-agent` | Delegation tokens, agent identity, revocation | alpha |
| `hush-cli` | CLI binary | alpha |

### Key conventions

- **Fail-closed**: `#[must_use]`, config errors bubble up, `deny_unknown_fields` on all serde types
- **Clippy**: `unwrap_used = "deny"`, `expect_used = "deny"` — use `ok_or_else` / `map_err`
- **Canonical JSON**: RFC 8785 (JCS) everywhere for cross-language determinism
- **NATS subjects**: `clawdstrike.spine.envelope.>` (NOT `aegis.spine.envelope.>` — research docs use the old name)
- **Envelope schema constant**: `ENVELOPE_SCHEMA_V1 = "aegis.spine.envelope.v1"` (this is the schema *value*, not a NATS subject)
- **Issuer format**: `"aegis:ed25519:<64-char-hex-pubkey>"`
- **KV buckets**: `CLAWDSTRIKE_LOG_INDEX`, `CLAWDSTRIKE_CHECKPOINTS`, `CLAWDSTRIKE_ENVELOPES`, `CLAWDSTRIKE_FACT_INDEX`

---

## The 14 Specs

All specs are in `docs/specs/`. They were cross-referenced against the actual codebase for accuracy (every file path, struct name, API endpoint, NATS subject verified). Total: ~9,700 lines.

### Phase A — Core Infrastructure

| # | Spec | Effort | Summary |
|---|------|--------|---------|
| 01 | Tracing Policy CRDs | 3-4d | 6 Tetragon TracingPolicy YAML manifests for process, file, network, crypto, container, kernel monitoring |
| 02 | Cilium Network Policies | 3-4d | 10 CiliumNetworkPolicy manifests for SDR pod network isolation |
| 03 | Multi-Curator Marketplace | 5-7d | Extend existing `curator_config.rs` with multi-curator trust, weighted quorum, role separation |
| 04 | Apache 2.0 License | 2-3d | MIT → Apache 2.0 migration plan (headers, NOTICE, Cargo.toml, package.json) |
| 05 | npm Publishing | 3d | Publish 11 TS packages to npm under `@backbay/` scope |

### Phase B — Identity & Trust

| # | Spec | Effort | Summary |
|---|------|--------|---------|
| 06 | SPIRE Identity Binding | 5-7d | Bind SPIFFE SVIDs to Spine envelope issuers, node attestation facts |
| 07 | AegisNet Notary Replacement | 6d | Replace centralized notary with Spine Merkle inclusion proofs |
| 08 | Marketplace-Spine Unification | 12d | Policy bundles as Spine envelopes, feed updates as head announcements |

### Phase C — Deployment & Distribution

| # | Spec | Effort | Summary |
|---|------|--------|---------|
| 09 | Helm Chart | 5-7d | Full Helm chart for SDR stack (bridges, checkpointer, proofs API, NATS) |
| 10 | IPFS Distribution | 4-6d | IPFS-first policy bundle distribution with Pinata + gateway fallback |
| 11 | Open Source Governance | 3-5d | CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md, RFC process |

### Phase D — Advanced

| # | Spec | Effort | Summary |
|---|------|--------|---------|
| 12 | Reticulum Adapter | 8-10d | Python sidecar for off-grid envelope distribution over LoRa/packet radio |
| 13 | EAS On-Chain Anchoring | 3-5d | Ethereum Attestation Service on Base L2 for blockchain timestamps |
| 14 | ClawdStrike Cloud | 15-20d | Managed SaaS with multi-tenant NATS, Stripe billing, SSE streaming |

### Dependency graph

```
Phase A (parallel):  01, 02, 03, 04, 05
Phase B (after A):   06 → 07 → 08
Phase C (after A):   09, 10, 11
Phase D (after B+C): 12, 13, 14
```

Specs 01-05 can all be done in parallel. Spec 08 depends on 07. Spec 14 depends on most earlier specs. Specs 09-11 are independent of Phase B.

---

## SDK Reuse — backbay-sdk Packages

Three packages from `standalone/backbay-sdk/packages/` have significant overlap with planned clawdstrike work. The specs have been updated to reference these:

### @backbay/notary

- **IPFS uploads** via w3up-client: `uploadFile()`, `uploadDirectory()`, `checkAvailability()`
- **EAS attestations**: `createAttestation()`, `createOnchainAttestation()`, `verifyAttestation()`
- **RFC 8785 canonical JSON**: `canonicalize()`, `hashObject()`, `sha256()`
- **Used by:** Spec 10 (IPFS), Spec 13 (EAS) — extend with `spine-eas.ts` module

### @backbay/witness + witness-react

- **Ed25519 verification (WASM)**: Same primitives as `hush-core`
- **Merkle proof verification**: `verifyMerkleProof()` — same algorithm as `hush_core::MerkleProof`
- **EAS verification**: `fetchers/eas.ts` with multi-chain GraphQL queries
- **React components**: `VerificationBadge`, `VerificationDetails`
- **Used by:** Spec 07 (notary replacement), Spec 13 (EAS) — add `fetchers/spine.ts` and `fetchers/spine-eas.ts`

### @backbay/speakeasy

- **Ed25519 identity** with BIP39 recovery, same curve as Spine
- **libp2p Gossipsub** P2P transport (WebRTC/WebSocket)
- **Used by:** Spec 12 (open question — alternative to Reticulum for browser-native nodes)

### Key decision

Instead of creating new `packages/eas-utils/` in clawdstrike, extend `@backbay/notary` with a `spine-eas.ts` module for attestation creation and extend `@backbay/witness` with `fetchers/spine-eas.ts` for verification. This avoids duplicating EAS SDK initialization, signer management, and canonical JSON.

---

## Research Docs

6 research documents in `docs/research/` informed the specs:

| Document | Focus |
|----------|-------|
| `architecture-vision.md` | Full-stack vision, multi-plane transport, deployment layers |
| `tetragon-integration.md` | Tetragon TracingPolicy patterns, gRPC integration |
| `cilium-network-security.md` | CiliumNetworkPolicy patterns, L7 enrichment |
| `marketplace-trust-evolution.md` | Trust delegation chains, EAS, community curation |
| `open-source-strategy.md` | Licensing, npm publishing, governance, Helm |
| `reticulum-sdr-transport.md` | Off-grid mesh networking, priority scheduling, CBOR encoding |

---

## Build & Test Commands

```bash
# Full workspace build
cargo build --workspace

# Full test suite
cargo test --workspace

# Lint (CI-level)
cargo fmt --all -- --check && cargo clippy --workspace -- -D warnings

# Test specific SDR crates
cargo test -p spine
cargo test -p tetragon-bridge
cargo test -p hubble-bridge

# TypeScript
npm install --workspace=packages/sdk/hush-ts
npm run build --workspace=packages/sdk/hush-ts
npm test --workspace=packages/sdk/hush-ts
```

**Note:** `cargo test --workspace` compiles heavy wasmtime deps and needs ~20GB disk. If space is tight, test individual crates.

---

## Known Issues / Gotchas

1. **NATS namespace**: Research docs say `aegis.spine.envelope.*` but all code uses `clawdstrike.spine.envelope.*`. The specs are corrected. Don't regress.

2. **`ed25519-blake2b` is WRONG**: Uses BLAKE2b (not SHA-512), producing incompatible signatures with `ed25519-dalek`. Spec 12 now uses `PyNaCl`. Don't use `ed25519-blake2b`.

3. **`canonicaljson` Python package is WRONG**: Implements RFC 7159, not RFC 8785. Use `rfc8785` (Trail of Bits).

4. **`deny_unknown_fields`**: All serde structs use this. Adding new fields to existing types requires making them `Option` with `skip_serializing_if` for backward compat.

5. **Checkpoint `witnesses` field**: The actual checkpoint fact field is `"witnesses"` (not `"witness_signatures"`).

6. **hushd endpoints**: `/health` (not `/healthz`), `/api/v1/audit` (not `/api/v1/receipts`).

7. **Multiple crypto backends in hushd**: ring + rustls + openssl all present. The `ring` CryptoProvider must be explicitly installed (commit `9209ade0` fixes this).

8. **Tetragon bridge**: Supports `ProcessExec`, `ProcessExit`, `ProcessKprobe` — does NOT support `ProcessLsm`.

---

## Immediate Next Steps

1. **Commit the 6 uncommitted spec updates** (SDK reuse references)
2. **Merge PR #40** when ready — it's the SDR foundation + 30 bug fixes + 14 specs
3. **Start Phase A** — specs 01-05 are all parallelizable and have no dependencies on each other
4. **Spec 04 (Apache 2.0)** should be decided early since it affects every published package
5. **Spec 05 (npm publish)** unblocks external consumers of `@backbay/*` packages
