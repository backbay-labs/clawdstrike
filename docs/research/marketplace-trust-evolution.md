# Marketplace Trust Evolution: From Centralized Curator to Decentralized Attestation

> Research document for evolving ClawdStrike's policy marketplace trust model.
>
> **Status:** Draft | **Date:** 2026-02-07

---

## Table of Contents

1. [Current Trust Model Analysis](#1-current-trust-model-analysis)
2. [Multi-Curator Trust](#2-multi-curator-trust)
3. [AegisNet as Notary Replacement](#3-aegisnet-as-notary-replacement)
4. [On-Chain Attestation (EAS)](#4-on-chain-attestation-eas)
5. [IPFS + Content Addressing](#5-ipfs--content-addressing)
6. [P2P Discovery Enhancements](#6-p2p-discovery-enhancements)
7. [Trust Delegation Chains](#7-trust-delegation-chains)
8. [Community Curation Model](#8-community-curation-model)
9. [Policy Versioning & Revocation](#9-policy-versioning--revocation)
10. [Competitive Landscape](#10-competitive-landscape)
11. [Comparison Matrix](#11-comparison-matrix)
12. [Open Questions](#12-open-questions)
13. [Recommended Phased Roadmap](#13-recommended-phased-roadmap)

---

## 1. Current Trust Model Analysis

### Architecture

ClawdStrike's marketplace currently uses a **single-curator, signed-feed** model implemented across three layers:

**Layer 1 -- Feed Signing** (`marketplace_feed.rs`)
- A `MarketplaceFeed` contains entries, a monotonic `seq` number, and schema version.
- The feed is canonicalized (RFC 8785 canonical JSON) and signed with an Ed25519 keypair.
- `SignedMarketplaceFeed::verify_trusted()` accepts a `&[PublicKey]` array, iterating through trusted keys until one verifies. This already supports N trusted keys in the verification path, but the list is currently compiled-in or passed from a fixed config.

**Layer 2 -- Bundle Signing** (`policy_bundle.rs`)
- Each `PolicyBundle` wraps a compiled `Policy` plus its SHA-256 content hash.
- Bundles are independently signed (Ed25519) producing a `SignedPolicyBundle`.
- Verification requires either an embedded public key or explicit trusted key.

**Layer 3 -- Provenance / Notary** (`MarketplaceProvenance`)
- Each marketplace entry can optionally carry an `attestation_uid` and `notary_url`.
- The desktop frontend (`MarketplaceView.tsx`) calls `verifyMarketplaceAttestation(notaryUrl, uid)` to check provenance against a centralized notary HTTP endpoint.
- Users can toggle "Verified only" mode and configure trusted attesters.

**Layer 4 -- P2P Discovery** (`marketplace_discovery.rs`)
- libp2p gossipsub + mDNS for discovering feed URIs.
- Discovery is explicitly **low-trust**: it only gossips URIs (ipfs:// or https://). All signature verification happens after fetch.
- Announcements carry optional `signer_public_key` and `seq` for freshness hints.

### Cryptographic Primitives (hush-core)

| Primitive | Implementation | Notes |
|-----------|---------------|-------|
| Signing | Ed25519 (ed25519-dalek) | 32-byte seeds, 64-byte signatures |
| Hashing | SHA-256 | Policy content addressing |
| Serialization | RFC 8785 canonical JSON | Key-order-independent verification |
| Key format | Hex-encoded (0x-optional) | Serde transparent wrappers |

### Strengths

- **Fail-closed**: Invalid versions, missing keys, and bad signatures are hard errors.
- **Content-addressed policies**: `policy_hash` (SHA-256 of canonical JSON) pins bundle contents.
- **Canonical JSON**: Immune to key-ordering differences in JSON serialization.
- **Layered signatures**: Feed signature and bundle signature are independent; a curator signs the feed, a different author can sign the bundle.
- **Discovery separation**: Gossip layer is explicitly untrusted; verification is deferred.

### Limitations

- **Single point of trust**: One curator keypair controls the entire feed. Key compromise means total trust failure.
- **No key rotation story**: Replacing the curator key requires all clients to update their trusted key list.
- **Centralized notary**: The `/verify/{uid}` endpoint is a single HTTP service. If it goes down, provenance verification fails.
- **No community curation**: Third parties cannot publish or co-sign policies without access to the curator key.
- **No revocation mechanism**: Once a policy is in the feed, there is no way to revoke it without publishing a new feed version that omits it.
- **Static trust configuration**: Trusted attesters and notary URLs are stored in localStorage on the desktop client.

---

## 2. Multi-Curator Trust

The simplest evolutionary step: support multiple independent feed curators without recompiling.

### Approach A: Config-File Key Registry

```toml
# ~/.clawdstrike/trusted_curators.toml

[[curator]]
name = "clawdstrike-official"
public_key = "0xabc123..."
trust_level = "full"    # full | audit-only

[[curator]]
name = "acme-security-team"
public_key = "0xdef456..."
trust_level = "full"

[[curator]]
name = "community-experimental"
public_key = "0x789012..."
trust_level = "audit-only"   # show in UI but require explicit user approval
```

**Pros**: Dead simple. No network dependency. Users control their own trust roots.
**Cons**: Manual distribution of config files. No discoverability. Key rotation requires config updates across all clients.

### Approach B: On-Chain Curator Registry

A smart contract (EAS schema or dedicated registry) stores curator public keys with metadata:

```solidity
struct CuratorEntry {
    bytes32 publicKey;
    string  feedId;
    string  name;
    uint256 addedAt;
    bool    revoked;
}
```

Clients query the registry contract (or a cached gateway) to discover trusted curators. New curators go through an on-chain governance vote.

**Pros**: Decentralized discoverability. Transparent governance. Immutable audit trail.
**Cons**: Requires chain interaction (cost, latency). Bootstrapping problem (who seeds the initial registry?).

### Approach C: SPIRE-Issued Curator Identities

If ClawdStrike runs within a SPIFFE/SPIRE-enabled environment (like AegisNet's k8s deployment), curator identities can be SPIFFE IDs:

```
spiffe://clawdstrike.io/curator/official
spiffe://clawdstrike.io/curator/acme-security
```

SPIRE issues short-lived X.509 SVIDs bound to workload attestation. The curator's signing key is derived from or attested by the SVID.

**Pros**: Automatic key rotation. Strong workload identity. No manual key management.
**Cons**: Requires SPIRE infrastructure. Only works in environments with SPIRE agents. Not suitable for standalone desktop use cases unless bridged.

### Approach D: Web of Trust (PGP-style)

Curators sign each other's keys, building a trust graph. Users configure a trust depth (e.g., "trust keys signed by at least 2 curators I already trust").

**Pros**: Fully decentralized. No infrastructure dependency.
**Cons**: Complex UX for non-technical users. Trust graph maintenance burden. Susceptible to Sybil attacks without additional constraints.

### Recommendation

**Phase 1**: Approach A (config-file registry) -- unblocks multi-curator immediately with zero infrastructure cost. The `verify_trusted()` function already accepts `&[PublicKey]`; the only change is loading keys from a TOML/JSON config instead of hardcoding.

**Phase 2**: Approach B (on-chain registry) -- once EAS integration is live, curator registration becomes a specific attestation schema.

**Phase 3**: Approach C (SPIRE) -- for server-side/k8s deployments where AegisNet is present.

---

## 3. AegisNet as Notary Replacement

### Current Notary Model

The marketplace currently points to an opaque HTTP notary:
```
notary_url: "https://notary.example.com"
attestation_uid: "0x..."
```

The frontend calls `GET /verify/{uid}` and receives a `NotaryVerifyResult` with `valid`, `attester`, and `attested_at` fields.

### AegisNet Proofs API Mapping

AegisNet already provides the infrastructure to replace this centralized notary:

| Notary Concept | AegisNet Equivalent |
|---------------|---------------------|
| Notary endpoint | `aegisnet-proofs-api` service |
| Attestation UID | Envelope hash (0x-prefixed SHA-256) |
| Verification | `GET /v1/proofs/inclusion?envelope_hash=0x...` |
| Attester identity | `issuer` field in signed envelope (`aegis:ed25519:<pubkey>`) |
| Timestamp | `issued_at` in envelope + `checkpoint.issued_at` |
| Trust anchor | Log operator key + witness co-signatures |

### Proposed Attestation Schema

When a curator publishes a policy bundle to the marketplace, they also submit a signed envelope to AegisNet:

```json
{
  "schema": "aegis.spine.envelope.v1",
  "issuer": "aegis:ed25519:<curator-pubkey>",
  "seq": 42,
  "prev_envelope_hash": "0x...",
  "issued_at": "2026-02-07T12:00:00Z",
  "capability_token": null,
  "fact": {
    "schema": "clawdstrike.marketplace.policy_attestation.v1",
    "fact_id": "pa_<uuid>",
    "bundle_id": "<policy-bundle-id>",
    "bundle_hash": "0x<sha256-of-canonical-bundle-json>",
    "feed_id": "clawdstrike-official",
    "feed_seq": 15,
    "entry_id": "hipaa-compliance-v2",
    "policy_hash": "0x<sha256-of-canonical-policy-json>",
    "curator_public_key": "0x<ed25519-pubkey>",
    "attestation_type": "curator_approval",
    "metadata": {
      "review_notes": "Reviewed for HIPAA compliance requirements",
      "review_date": "2026-02-06"
    }
  },
  "envelope_hash": "0x...",
  "signature": "0x..."
}
```

### Verification Flow (Replacing Notary)

```
1. Client fetches marketplace feed
2. For each entry with provenance:
   a. Extract bundle_hash from entry
   b. Query AegisNet: GET /v1/proofs/inclusion?envelope_hash=<attestation_envelope_hash>
   c. Receive inclusion proof (audit_path, checkpoint_seq, tree_size)
   d. Verify inclusion proof locally (RFC 6962 Merkle verification)
   e. Verify checkpoint signature (log operator key)
   f. Verify witness co-signature(s)
   g. Extract fact.bundle_hash from the envelope
   h. Confirm fact.bundle_hash matches the downloaded bundle's hash
3. Display verification status in UI
```

### AegisNet Provenance Schema for MarketplaceEntry

```json
{
  "provenance": {
    "attestation_uid": "0x<envelope_hash>",
    "notary_url": "https://proofs-api.aegisnet.internal:8080",
    "type": "aegisnet_inclusion",
    "log_id": "aegis:ed25519:<log-operator-pubkey>",
    "checkpoint_seq": 123
  }
}
```

### Benefits Over Centralized Notary

- **Cryptographic verifiability**: RFC 6962 Merkle proofs are locally verifiable without trusting the server.
- **Append-only log**: Attestations cannot be silently removed or altered.
- **Independent witness**: The witness co-signs checkpoints with a separate key, providing split-trust.
- **Auditability**: Anyone can monitor the log for unexpected or malicious attestations.
- **Timestamps are anchored**: Checkpoint timestamps are part of the signed statement.

### Challenges

- **Latency**: Inclusion proofs are only available after a checkpoint is emitted (every 5-10 seconds by default). Real-time verification has a small delay.
- **Infrastructure dependency**: Requires running AegisNet services (or having access to a public instance).
- **Offline verification**: The proofs API must be reachable. For offline scenarios, the inclusion proof and checkpoint can be bundled with the feed (see Section 7).

---

## 4. On-Chain Attestation (EAS)

### How EAS Works

The Ethereum Attestation Service provides two core contracts:

1. **SchemaRegistry.sol** -- Registers attestation schemas defining the structure of attestation data.
2. **EAS.sol** -- Creates attestations referencing registered schemas.

Attestations can be **on-chain** (stored in the contract, gas-costly but maximally trustless) or **off-chain** (encoded in a URI fragment, optionally timestamped on-chain for minimal cost).

### ClawdStrike Policy Attestation Schema

```
Schema: "bytes32 bundleHash, string feedId, string entryId, string curatorKey, uint64 feedSeq, string policyVersion"
Resolver: 0x0 (no on-chain resolver -- verification is client-side)
Revocable: true
```

**Example on-chain attestation:**

| Field | Value |
|-------|-------|
| `bundleHash` | `0x<sha256>` |
| `feedId` | `"clawdstrike-official"` |
| `entryId` | `"hipaa-compliance-v2"` |
| `curatorKey` | `"0x<ed25519-pubkey>"` |
| `feedSeq` | `15` |
| `policyVersion` | `"1.1.0"` |

### On-Chain vs Off-Chain Attestations

| Dimension | On-Chain | Off-Chain |
|-----------|----------|-----------|
| **Storage** | EVM state | IPFS, client-side, or URI fragment |
| **Cost** | ~$0.50-$5 per attestation (L2) | Free (timestamp: ~$0.10 on L2) |
| **Verifiability** | Contract state query | Client reconstructs from URI + optional timestamp check |
| **Revocation** | On-chain revoke tx | Requires on-chain revocation record |
| **Latency** | Block confirmation (~2-12s) | Instant (timestamp delayed) |
| **Censorship resistance** | High (blockchain consensus) | Medium (depends on storage) |

### Cost Analysis

For a marketplace with 100 policies, updated monthly:

| Approach | Monthly Cost (Ethereum L1) | Monthly Cost (Base/Optimism L2) |
|----------|---------------------------|--------------------------------|
| On-chain attestation per policy | ~$500 | ~$5-$10 |
| Off-chain + on-chain timestamp | ~$10 | ~$0.50-$1 |
| Batch timestamp (1 tx for N attestations) | ~$5 | ~$0.10-$0.50 |

**Recommendation**: Off-chain attestations with batched on-chain timestamps on an L2. This gives blockchain-backed timestamps at negligible cost while keeping the actual attestation data in IPFS or the feed itself.

### Integration Point

The `MarketplaceProvenance` struct already has `attestation_uid` and `notary_url`. For EAS:

```json
{
  "provenance": {
    "attestation_uid": "0x<eas-attestation-uid>",
    "notary_url": "https://easscan.org",
    "type": "eas",
    "chain_id": 8453,
    "schema_uid": "0x<schema-uid>"
  }
}
```

The desktop client would use the EAS SDK to verify the attestation either on-chain or via the EAS GraphQL API.

---

## 5. IPFS + Content Addressing

### Current State

The marketplace already supports `ipfs://` URIs in `bundle_uri` fields and the discovery layer validates `ipfs://` as a supported scheme. This is an excellent foundation.

### Content-Addressed Distribution Model

```
┌──────────────┐     ┌──────────┐     ┌──────────────┐
│ Curator signs │────>│ Pin to   │────>│ Feed entry   │
│ policy bundle │     │ IPFS     │     │ references   │
│               │     │ (Pinata) │     │ ipfs://<CID> │
└──────────────┘     └──────────┘     └──────────────┘
                                             │
                         ┌───────────────────┘
                         v
┌──────────────┐     ┌──────────────┐
│ ClawdStrike  │<────│ Fetch via    │
│ desktop      │     │ IPFS gateway │
│ verifies sig │     │ or local     │
└──────────────┘     │ IPFS node    │
                     └──────────────┘
```

### Dual-CID Strategy

Each marketplace entry carries two content identifiers:

```json
{
  "entry_id": "hipaa-compliance-v2",
  "bundle_uri": "ipfs://bafybeie5gq4jxvq...",
  "bundle_hash": "0x<sha256>",
  "content_ids": {
    "ipfs_cid": "bafybeie5gq4jxvq...",
    "sha256": "0x<sha256-of-canonical-json>"
  }
}
```

- **IPFS CID**: Content-addressed by IPFS's own hashing (typically SHA-256 under CIDv1). Used for fetching.
- **SHA-256 (policy_hash)**: ClawdStrike's own content hash of the canonical JSON. Used for signature verification.

The client can verify that the fetched IPFS content matches the expected SHA-256 hash, providing defense-in-depth against IPFS gateway compromise.

### Pinning Strategies

| Service | Tier | Redundancy | Cost | Notes |
|---------|------|------------|------|-------|
| **Pinata** | Pro | 3x replication, edge caching | $20/mo for 50GB | Market leader, dedicated gateways |
| **web3.storage** | Free tier | Filecoin + IPFS | Free for 5GB | Filecoin deals for long-term storage |
| **Self-hosted** | DIY | Configurable | Infrastructure cost | Full control, no third-party dependency |
| **Hybrid** | Mixed | Multi-provider | Varies | Pin to 2+ services for redundancy |

**Recommendation**: Hybrid pinning (Pinata primary + self-hosted backup). For critical policy bundles, the curator pins to both services. The feed lists multiple gateway hints:

```json
{
  "bundle_uri": "ipfs://bafybeie5gq4jxvq...",
  "gateway_hints": [
    "https://gateway.pinata.cloud/ipfs/",
    "https://ipfs.clawdstrike.io/ipfs/",
    "https://dweb.link/ipfs/"
  ]
}
```

### Feed Itself on IPFS

The signed marketplace feed can also be pinned to IPFS, making the feed itself content-addressed and decentrally distributed:

```
Feed CID: bafybeif...
├── feed.json (signed marketplace feed)
├── bundles/
│   ├── hipaa-compliance-v2.bundle.json
│   ├── soc2-baseline.bundle.json
│   └── ...
```

P2P discovery gossips the feed CID. Clients fetch and verify the entire feed in one IPFS retrieval.

---

## 6. P2P Discovery Enhancements

### Current Discovery Architecture

The existing `marketplace_discovery.rs` uses:
- libp2p gossipsub for message dissemination
- mDNS for local peer discovery
- Static bootstrap multiaddrs for WAN connectivity
- Single gossipsub topic per feed

### Enhancement 1: DHT-Based Feed Discovery

Replace or supplement gossipsub with Kademlia DHT for more reliable feed discovery:

```
Topic: /clawdstrike/marketplace/v1/feeds/<feed_id>
Key:   SHA-256(feed_id)
Value: DiscoveryRecord {
    feed_uri: "ipfs://...",
    seq: 42,
    signer_public_key: "0x...",
    published_at: "2026-02-07T12:00:00Z",
    ttl_sec: 3600
}
```

DHT provides:
- **Persistent discovery**: Records survive peer disconnections.
- **Content routing**: Find peers that have specific feeds without flooding.
- **Bootstrap independence**: Any DHT participant can serve as entry point.

### Enhancement 2: Reputation Scoring for Peers

Track peer behavior to prioritize reliable sources:

```rust
struct PeerReputation {
    peer_id: PeerId,
    /// Feeds announced that verified successfully.
    valid_announcements: u32,
    /// Feeds announced that failed verification.
    invalid_announcements: u32,
    /// Freshness: average lag between seq announcement and actual feed publication.
    avg_freshness_ms: u64,
    /// Last seen timestamp.
    last_seen: DateTime<Utc>,
}
```

Score = `valid / (valid + invalid * 10)` with decay over time. Peers below threshold are deprioritized.

### Enhancement 3: Multi-Topic Channels

Instead of a single discovery topic, use category-specific topics:

```
clawdstrike/marketplace/v1/discovery             # general
clawdstrike/marketplace/v1/discovery/compliance   # compliance policies
clawdstrike/marketplace/v1/discovery/ai-safety    # AI safety policies
clawdstrike/marketplace/v1/discovery/enterprise   # enterprise policies
```

Clients subscribe only to categories they care about, reducing gossip noise.

### Enhancement 4: Relay Nodes for NAT Traversal

Add libp2p circuit relay v2 support for peers behind NAT:

```rust
// In discovery config
pub struct MarketplaceDiscoveryConfig {
    // ... existing fields ...
    /// Relay nodes for NAT traversal.
    #[serde(default)]
    pub relays: Vec<String>,
    /// Enable AutoNAT detection.
    #[serde(default = "default_true")]
    pub auto_nat: bool,
}
```

This enables desktop clients behind home routers to participate in discovery without manual port forwarding.

### Enhancement 5: Feed Freshness Protocol

Extend announcements with proof of freshness:

```json
{
  "v": 2,
  "feed_uri": "ipfs://...",
  "feed_id": "clawdstrike-official",
  "seq": 42,
  "signer_public_key": "0x...",
  "feed_hash": "0x<sha256-of-signed-feed>",
  "checkpoint_ref": {
    "log_id": "aegis:ed25519:...",
    "checkpoint_seq": 123,
    "envelope_hash": "0x..."
  }
}
```

The `checkpoint_ref` lets peers verify that the announced feed was attested in AegisNet before a specific checkpoint, providing a verifiable freshness bound.

---

## 7. Trust Delegation Chains

### The Full Chain

```
Author signs PolicyBundle
    └─> Curator attests bundle in signed MarketplaceFeed
        └─> Curator submits attestation envelope to AegisNet
            └─> Checkpointer includes envelope in Merkle tree
                └─> Witness co-signs checkpoint
                    └─> (Optional) Checkpoint hash timestamped on-chain via EAS
```

### Multi-Hop Trust Verification

The client verifies the chain bottom-up:

```
1. VERIFY: EAS on-chain timestamp matches checkpoint hash
   └─ Trust anchor: blockchain consensus
2. VERIFY: Witness co-signature on checkpoint
   └─ Trust anchor: witness Ed25519 key
3. VERIFY: Checkpoint signature (log operator)
   └─ Trust anchor: log operator Ed25519 key
4. VERIFY: Inclusion proof (envelope in Merkle tree)
   └─ Trust anchor: RFC 6962 math
5. VERIFY: Envelope signature (curator)
   └─ Trust anchor: curator Ed25519 key in trusted registry
6. VERIFY: Feed signature (same or different curator)
   └─ Trust anchor: curator Ed25519 key
7. VERIFY: Bundle signature (author)
   └─ Trust anchor: author Ed25519 key (embedded or trusted)
8. VERIFY: Bundle policy_hash matches SHA-256 of canonical policy
   └─ Trust anchor: cryptographic hash
```

### Portable Proof Bundle

For offline verification, package the entire proof chain alongside the policy:

```json
{
  "schema": "clawdstrike-portable-proof-v1",
  "signed_bundle": { "...": "..." },
  "feed_entry": { "...": "..." },
  "attestation_envelope": { "...": "..." },
  "inclusion_proof": {
    "audit_path": ["0x...", "0x..."],
    "checkpoint_seq": 123,
    "tree_size": 456,
    "log_index": 455
  },
  "checkpoint": {
    "statement": { "...": "..." },
    "log_signature": "0x...",
    "witness_signatures": [
      { "witness_node_id": "aegis:ed25519:...", "signature": "0x..." }
    ]
  },
  "eas_timestamp": {
    "chain_id": 8453,
    "attestation_uid": "0x...",
    "block_number": 12345678,
    "block_hash": "0x..."
  }
}
```

This portable proof can be verified entirely offline given only the trusted root keys (log operator, witness, curator).

---

## 8. Community Curation Model

### Roles

| Role | Capability | Trust Level |
|------|-----------|-------------|
| **Author** | Creates and signs policy bundles | Self-certified (anyone) |
| **Reviewer** | Reviews policy content for correctness | Reputation-based |
| **Curator** | Includes policies in a signed feed | Key-holder (registered) |
| **Witness** | Co-signs AegisNet checkpoints | Infrastructure operator |
| **User** | Installs and runs policies | Configures trust preferences |

### Submission Flow

```
1. AUTHOR creates PolicyBundle, signs it, pins to IPFS
2. AUTHOR submits proposal to community review channel
   - Proposal = { bundle_cid, bundle_hash, author_pubkey, description }
3. REVIEWERS evaluate the policy:
   - Automated: lint checks, schema validation, conflict detection
   - Manual: security review, intent verification
4. REVIEWERS co-sign a review attestation (via AegisNet envelope):
   {
     schema: "clawdstrike.marketplace.review_attestation.v1",
     fact: {
       bundle_hash: "0x...",
       reviewer: "aegis:ed25519:<reviewer-pubkey>",
       verdict: "approve" | "reject" | "needs-changes",
       review_notes: "...",
       conditions: ["requires-monitoring", "time-limited-30d"]
     }
   }
5. CURATOR checks review attestations (threshold: M-of-N reviewers approved)
6. CURATOR adds entry to marketplace feed, signs, and publishes
7. CURATOR submits curator attestation to AegisNet
8. Policy appears in marketplace with full provenance chain
```

### Reputation System

```rust
struct ContributorReputation {
    /// Number of policies authored that are currently in active feeds.
    active_policies: u32,
    /// Number of review attestations submitted.
    reviews_submitted: u32,
    /// Policies authored that were later revoked for issues.
    revoked_policies: u32,
    /// Time-weighted score.
    reputation_score: f64,
}
```

Reputation is derived from on-chain/AegisNet attestation data -- not self-reported. The trust graph is:
- New authors start with score 0.
- Each approved policy adds score.
- Each revoked policy heavily penalizes score.
- Review attestations from high-reputation reviewers count more.

### Moderation & Revocation

- **Feed-level revocation**: Curator publishes new feed with higher `seq` omitting the revoked entry.
- **Attestation-level revocation**: Curator submits a revocation envelope to AegisNet:
  ```json
  {
    "schema": "clawdstrike.marketplace.revocation.v1",
    "fact": {
      "bundle_hash": "0x...",
      "reason": "security-vulnerability",
      "revoked_at": "2026-02-07T18:00:00Z",
      "superseded_by": "0x<new-bundle-hash>"  // optional
    }
  }
  ```
- **EAS revocation**: If the attestation was on-chain, call `revoke()` on the EAS contract.
- **Client behavior**: ClawdStrike clients check revocation status before installing. Already-installed policies show a warning if their attestation is revoked.

---

## 9. Policy Versioning & Revocation

### Versioning Strategy

The current model uses `seq` (monotonic sequence number) at the feed level and `bundle_id` (UUID) + `compiled_at` at the bundle level. This can be extended:

```json
{
  "entry_id": "hipaa-compliance",
  "version": "2.1.0",
  "version_chain": {
    "previous_version": "2.0.0",
    "previous_bundle_hash": "0x...",
    "change_type": "minor",
    "changelog": "Added PHI de-identification rules"
  }
}
```

### Revocation Mechanisms

| Mechanism | Speed | Decentralization | Complexity |
|-----------|-------|------------------|------------|
| **Feed omission** (new feed without entry) | Slow (next feed publish) | Centralized (curator) | Low |
| **Revocation list** (signed JSON of revoked hashes) | Medium (periodic fetch) | Centralized (curator) | Medium |
| **AegisNet revocation envelope** | Fast (seconds) | Semi-decentralized | Medium |
| **EAS on-chain revocation** | Fast (block time) | Decentralized | High |
| **Time-bound attestations** | Automatic | N/A | Low |

### Time-Bound Attestations

Attestations can include an expiration:

```json
{
  "fact": {
    "schema": "clawdstrike.marketplace.policy_attestation.v1",
    "bundle_hash": "0x...",
    "valid_from": "2026-02-07T00:00:00Z",
    "valid_until": "2026-08-07T00:00:00Z",
    "auto_renew": false
  }
}
```

Clients automatically reject policies with expired attestations. Curators must re-attest to keep policies active. This provides a natural revocation mechanism without explicit revoke transactions.

### Recommended Approach

Combine time-bound attestations (automatic expiry) with AegisNet revocation envelopes (immediate revocation for emergencies). The client checks:

1. Is the attestation within its validity window?
2. Is there a revocation envelope in AegisNet for this bundle hash?
3. (Optional) Is the EAS attestation revoked on-chain?

---

## 10. Competitive Landscape

### Sigstore / Cosign

**What it does**: Keyless signing for container images and artifacts using ephemeral keys bound to OIDC identity. Rekor provides a transparency log.

**Relevance to ClawdStrike**:
- Sigstore's keyless model (ephemeral keys + OIDC identity + transparency log) maps well to a curator who authenticates via GitHub/Google and gets a short-lived certificate.
- Rekor's transparency log is functionally similar to AegisNet's append-only log with Merkle proofs.
- Cosign's in-toto attestation support could be used to attest policy bundles.

**Gaps**: Sigstore is container/artifact-focused. ClawdStrike's policies are JSON documents, not OCI images. The OIDC-based identity model may not fit all deployment scenarios (e.g., air-gapped environments).

**Integration potential**: ClawdStrike could publish policy bundles as OCI artifacts and sign them with cosign, leveraging the existing Sigstore ecosystem. However, this adds a dependency on the OCI registry model.

### TUF (The Update Framework)

**What it does**: Secure software update distribution with role separation (root, targets, snapshot, timestamp) and threshold signing.

**Relevance to ClawdStrike**:
- TUF's role separation maps cleanly to ClawdStrike's trust model:
  - `root` = Master key that bootstraps trust
  - `targets` = Curator key(s) that sign policy bundles
  - `snapshot` = Feed integrity (the signed feed itself)
  - `timestamp` = Freshness guarantee (seq + published_at)
- TUF's key rotation protocol (root key delegates to new root key) solves ClawdStrike's key rotation gap.
- TUF's threshold signing (M-of-N) enables multi-curator governance.
- TUF's compromise-resilience design is exactly what ClawdStrike needs as it decentralizes.

**Gaps**: TUF is designed for software updates, not policy marketplaces. The metadata overhead (multiple JSON files for each role) may be heavy for a policy feed with frequent updates.

**Integration potential**: High. Adopting TUF's metadata structure for the marketplace feed would bring battle-tested key rotation, threshold signing, and compromise resilience. The `verify_trusted()` function could be extended to implement TUF's delegation model.

### OPA Gatekeeper

**What it does**: Kubernetes admission controller that enforces OPA policies on cluster resources.

**Relevance to ClawdStrike**:
- Gatekeeper distributes policies as Kubernetes CRDs (ConstraintTemplates + Constraints).
- Multi-cluster distribution uses OCM (Open Cluster Management) policies.
- OPA's Bundle feature downloads policies from remote HTTP servers.

**Gaps**: Gatekeeper is Kubernetes-specific. It has no built-in signing, attestation, or trust model for policies. Policy distribution relies on the Kubernetes API server's RBAC for access control, not cryptographic verification.

**Integration potential**: ClawdStrike policies could be distributed alongside Gatekeeper constraints for environments that use both. The policy bundle format could include an OPA/Rego translation for k8s-native enforcement.

### Notary v2 (Notation)

**What it does**: Signing and verification for OCI artifacts, successor to Docker Content Trust.

**Relevance to ClawdStrike**: Notation's trust policy model (configurable trust stores with scoped verification) is similar to what ClawdStrike needs for multi-curator trust. Notation supports plugin-based key management (KMS, hardware tokens).

**Gaps**: OCI-specific. Not designed for arbitrary JSON policy documents.

### in-toto Attestation Framework

**What it does**: Generates verifiable claims about software supply chain steps. Provides a `layout` defining expected steps and trusted actors.

**Relevance to ClawdStrike**:
- in-toto's layout model maps to ClawdStrike's policy review workflow:
  - Step 1: Author creates policy (in-toto link)
  - Step 2: Reviewer reviews policy (in-toto link)
  - Step 3: Curator approves and publishes (in-toto link)
- The layout can enforce that all three steps happened, by authorized parties, in order.
- SLSA provenance levels (L1-L4) provide a graduated trust model.

**Integration potential**: ClawdStrike could adopt the in-toto attestation format for its review/approval workflow, providing interoperability with the broader supply chain security ecosystem. The `fact` field in AegisNet envelopes could carry in-toto predicates.

---

## 11. Comparison Matrix

| Dimension | Current Model | Multi-Curator (Config) | AegisNet Notary | EAS On-Chain | TUF-Based | Sigstore/Cosign | Full Decentralized |
|-----------|--------------|----------------------|-----------------|-------------|-----------|-----------------|-------------------|
| **Trust roots** | 1 hardcoded key | N config keys | Log + witness keys | Blockchain + schema | Root + delegated roles | OIDC + Rekor | Web of trust + chain |
| **Key rotation** | Recompile | Edit config | SPIRE auto-rotate | Contract upgrade | Built-in delegation | Keyless (ephemeral) | Cross-signing |
| **Revocation** | Feed omission | Feed omission | Revocation envelope | on-chain revoke() | Metadata expiry | Rekor entry | Multi-mechanism |
| **Offline verify** | Ed25519 only | Ed25519 only | Portable proof bundle | No (needs RPC) | Yes (cached metadata) | No (needs Rekor) | Portable proofs |
| **Decentralization** | None | Low | Medium | High | Medium-High | Medium | High |
| **Infrastructure** | None | None | AegisNet k8s | EVM node/gateway | TUF repository | Fulcio + Rekor | All of the above |
| **UX complexity** | Simple | Simple | Medium | Medium-High | Medium | Low (keyless) | High |
| **Cost** | $0 | $0 | Infrastructure | L2 gas | Infrastructure | Free (public) | Mixed |
| **Community curation** | No | No | With review flow | With governance | With delegation | With OIDC groups | Full DAO |
| **Maturity** | Production | Trivial change | AegisNet exists | EAS production | CNCF graduated | CNCF graduated | Research phase |
| **Auditability** | Feed seq only | Feed seq only | Merkle proofs | Block explorer | Snapshot metadata | Rekor transparency | Full chain |

---

## 12. Open Questions

### Architecture Decisions

1. **On-chain vs off-chain attestations?**
   - On-chain provides maximum censorship resistance but costs gas.
   - Off-chain with on-chain timestamps provides a middle ground.
   - AegisNet provides Merkle-proof-based verifiability without blockchain costs.
   - **Recommendation**: AegisNet as primary, EAS as optional anchoring layer for high-value attestations.

2. **What's the right balance of decentralization vs usability?**
   - Full DAO governance for policy approval is too slow for security-sensitive updates.
   - Single curator is too centralized.
   - **Recommendation**: Multi-curator with configurable trust (users choose which curators to trust) + AegisNet for auditability.

3. **How do you bootstrap trust in a new network?**
   - The first curator key must be distributed out-of-band (embedded in the binary, published on the website, etc.).
   - Subsequent curators are attested by existing curators (trust delegation).
   - **Recommendation**: Ship with 1 official curator key. Provide a `trusted_curators.toml` for users to add more.

4. **What's the key rotation story?**
   - TUF's root rotation protocol is the gold standard.
   - For ClawdStrike: the current curator signs a "key rotation" envelope attesting the new key, publishes it to AegisNet, and updates the feed metadata.
   - Clients that see a valid rotation attestation from the old key automatically trust the new key.

5. **Should the marketplace support competing feeds?**
   - Yes. Different organizations should be able to run their own feeds (e.g., "acme-corp-internal", "owasp-community").
   - The desktop client should support multiple feed sources, each with its own trust configuration.
   - This is already partially supported via `loadMarketplaceFeedSources()` returning an array.

### Implementation Priorities

6. **Which integration comes first: AegisNet or EAS?**
   - AegisNet, because the infrastructure already exists in the Aegis deployment and uses the same Ed25519 primitives as ClawdStrike.

7. **Should IPFS be required or optional?**
   - Optional but strongly encouraged. HTTPS URLs must remain supported for enterprise environments with firewall restrictions.

8. **How do we handle feed divergence in P2P discovery?**
   - The `seq` number provides a total order. Clients always prefer the highest `seq` from a trusted curator.
   - If two curators publish conflicting feeds, the client shows both with clear curator attribution.

---

## 13. Recommended Phased Roadmap

### Phase 1: Multi-Curator + Config (Weeks)

- Load trusted curator keys from `~/.clawdstrike/trusted_curators.toml` instead of hardcoding.
- The `verify_trusted()` function already supports this; the change is in key loading.
- Add UI in Settings for managing trusted curator keys.
- **Risk**: None. Fully backward-compatible.

### Phase 2: AegisNet Integration (1-2 Months)

- Define `clawdstrike.marketplace.policy_attestation.v1` fact schema.
- Curator tooling submits attestation envelopes to AegisNet on feed publish.
- Replace notary HTTP calls with AegisNet proofs API queries.
- Add RFC 6962 Merkle proof verification to the desktop client (Rust side).
- Store inclusion proofs alongside feed entries for offline verification.
- **Risk**: Medium. Requires AegisNet availability. Fallback to direct Ed25519 verification.

### Phase 3: IPFS-First Distribution (1-2 Months, parallelizable with Phase 2)

- Curator tooling pins signed feeds and bundles to IPFS (Pinata + self-hosted).
- Feed entries use `ipfs://` CIDs as primary `bundle_uri`.
- P2P discovery gossips feed CIDs instead of HTTPS URLs.
- Add IPFS gateway fallback chain to the desktop client.
- **Risk**: Low. IPFS is already supported in URI validation.

### Phase 4: Community Review Workflow (2-3 Months)

- Implement review attestation schema.
- Build reviewer submission flow (CLI + desktop UI).
- Curator tooling checks M-of-N review attestations before including a policy.
- Reputation tracking based on attestation history.
- **Risk**: Medium. UX design for review workflow needs careful thought.

### Phase 5: EAS Anchoring (1-2 Months)

- Register ClawdStrike attestation schema on EAS (Base L2).
- Curator tooling optionally timestamps attestation UIDs on-chain.
- Desktop client verifies EAS timestamps for policies with `type: "eas"` provenance.
- **Risk**: Low. Optional layer on top of existing verification.

### Phase 6: TUF Metadata Structure (2-3 Months)

- Adopt TUF's root/targets/snapshot/timestamp role structure for marketplace metadata.
- Implement key rotation protocol (root delegates to new root).
- Implement threshold signing (M-of-N curators must sign for feed updates).
- **Risk**: High. Significant refactor of feed signing and verification.

---

## References

- [Ethereum Attestation Service](https://attest.org/) -- EAS protocol and SDK
- [EAS Documentation](https://docs.attest.org/) -- Schema registry, on-chain/off-chain attestations
- [Sigstore](https://docs.sigstore.dev/) -- Keyless signing and transparency
- [The Update Framework (TUF)](https://theupdateframework.io/) -- Compromise-resilient software updates
- [in-toto](https://in-toto.io/) -- Supply chain attestation framework
- [Pinata](https://pinata.cloud/) -- IPFS pinning service
- [W3C Verifiable Credentials 2.0](https://www.w3.org/press-releases/2025/verifiable-credentials-2-0/) -- Decentralized identity standard
- [W3C Decentralized Identifiers v1.1](https://www.w3.org/TR/did-1.1/) -- DID specification
- [OPA Gatekeeper](https://github.com/open-policy-agent/gatekeeper) -- Kubernetes policy controller
- [AegisNet Architecture](../../apps/aegis/services/aegisnet/ARCHITECTURE.md) -- Internal verifiable log system
- [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962) -- Certificate Transparency
- [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) -- JSON Canonicalization Scheme
