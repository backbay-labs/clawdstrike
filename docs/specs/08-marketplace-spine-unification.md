# Spec 08: Marketplace-to-Spine Protocol Unification

> **Status:** Draft | **Date:** 2026-02-07
> **Effort:** ~12 engineer-days
> **Phase:** B (Spine Unification) | **Priority:** Medium-High
> **Dependencies:** Spec 07 (AegisNet notary replacement), Spine crate, P2P discovery, Reticulum research

---

## Summary / Objective

Unify the ClawdStrike marketplace protocol with the Aegis Spine protocol. Today,
the marketplace maintains a parallel trust infrastructure (feed signing, notary
verification, libp2p gossip for discovery) that is structurally equivalent to --
but separate from -- the Spine protocol (signed envelopes, Merkle proofs, head
announcements, multi-plane transport). This spec makes the marketplace a native
Spine application:

- **Policy bundles become Spine envelope facts** rather than standalone signed objects.
- **Feed updates become Spine head announcements** rather than separate signed feed JSON blobs.
- **Discovery gossip carries Spine head semantics** (issuer, seq, head_hash) for anti-entropy.
- **Revocations propagate on all transport planes** including future Reticulum (Plane A-R).
- **Desktop subscribes to curator heads via Spine sync** rather than polling HTTP/IPFS for feeds.

The end result: a single trust infrastructure (Spine envelope signing +
AegisNet Merkle proofs + witness co-signatures) replaces the marketplace's
separate signing/notary/gossip systems. Policy updates reach disconnected nodes
via Reticulum. Feed freshness is cryptographically verifiable via checkpoint
references.

---

## Current State

### Marketplace Protocol (Parallel Trust Infrastructure)

The marketplace uses four independent systems:

**1. Feed Signing** (`crates/clawdstrike/src/marketplace_feed.rs`):
- `MarketplaceFeed` with `feed_id`, monotonic `seq`, `published_at`, `entries[]`
- Signed with Ed25519 via `SignedMarketplaceFeed::sign()` over RFC 8785 canonical JSON
- Verified via `verify_trusted(&[PublicKey])` against a set of trusted curator keys
- Keys loaded from `~/.config/clawdstrike/trusted_curators.toml` via `CuratorTrustSet`

**2. Bundle Signing** (via `SignedPolicyBundle` in clawdstrike crate):
- Each policy bundle is independently signed with Ed25519
- Bundle carries its own `public_key` for embedded verification
- Content-addressed by `policy_hash` (SHA-256 of canonical policy JSON)

**3. Notary Verification** (`apps/desktop/src-tauri/src/commands/marketplace.rs`):
- `marketplace_verify_attestation`: calls `GET {notary_url}/verify/{uid}` (centralized HTTP)
- `marketplace_verify_spine_proof`: calls Proofs API for Merkle inclusion proof (partially implemented)
- `MarketplaceProvenance` carries `attestation_uid`, `notary_url`, `spine_envelope_hash`

**4. P2P Discovery** (`apps/desktop/src-tauri/src/marketplace_discovery.rs`):
- libp2p gossipsub + mDNS on topic `clawdstrike/marketplace/v1/discovery`
- Gossips `MarketplaceDiscoveryAnnouncement`: `{ v, feed_uri, feed_id?, seq?, signer_public_key? }`
- Low-trust: only gossips URIs, verification is deferred to fetch time
- Desktop emits `marketplace_discovery` Tauri events to the frontend

### Spine Protocol (Target Trust Infrastructure)

The Spine crate (`crates/spine/src/`) provides:
- `SignedEnvelope` with `issuer`, `seq`, `prev_envelope_hash`, `fact`, `envelope_hash`, `signature`
- `TrustBundle` with allowlists for log IDs, witness node IDs, receipt signers
- Checkpoint statements with witness co-signatures
- Proofs API with RFC 6962 Merkle inclusion proofs
- NATS JetStream as Plane B transport

### Structural Equivalence

The research doc (`docs/research/reticulum-sdr-transport.md`, Section 3) maps
each marketplace construct to its Spine equivalent:

| Marketplace | Spine | Status |
|------------|-------|--------|
| `SignedMarketplaceFeed` (canonical JSON, monotonic `seq`, Ed25519 signed) | Issuer chain (monotonic `seq`, `prev_envelope_hash`, Ed25519 signed) | **Same crypto, different schema** |
| `SignedPolicyBundle` | `SignedEnvelope` wrapping a `policy_bundle` fact | **Same crypto, different schema** |
| Feed `seq` for freshness | Spine `(issuer, seq)` for append-only ordering | **Identical concept** |
| `MarketplaceProvenance` (notary verification) | AegisNet inclusion proof | **Notary is centralized approximation** |
| libp2p gossipsub discovery | Spine head announcements + gossip | **Same transport, different semantics** |
| `verify_trusted(&[PublicKey])` | Spine TrustBundle | **Same verification model** |

### Existing SDK Packages (backbay-sdk)

The `@backbay/notary` package already implements RFC 8785 canonical JSON + SHA-256 hashing for the marketplace's `RunReceipt` attestation pipeline. Its `canonicalize()` and `hashObject()` functions use the same deterministic JSON algorithm as `hush_core::canonicalize_json()`. When unifying marketplace with Spine, the notary's canonical JSON and EAS attestation modules can be reused rather than ported to a new package.

The `@backbay/witness` package verifies Ed25519 signatures and Merkle proofs in the browser via WASM -- the same primitives Spine uses server-side. Extending witness with a Spine verification backend (Spec 07) means the unified marketplace can verify provenance client-side without new crypto code.

---

## Target State

After this spec is implemented:

1. **Policy bundles as Spine facts**: A new `clawdstrike.marketplace.policy_bundle.v1`
   fact schema wraps policy bundle content inside a Spine envelope. The curator's
   feed sequence maps to the Spine `seq`. The curator's Ed25519 key is the
   envelope `issuer`. Existing `SignedPolicyBundle` format continues to work
   during the transition period.

2. **Feed updates as head announcements**: When a curator publishes a new feed
   version, they emit a Spine `head_announcement` carrying `(issuer, seq,
   head_hash, signature)`. Peers that see a higher `seq` can request catch-up
   via Spine sync.

3. **Discovery gossip carries Spine head semantics**: The
   `MarketplaceDiscoveryAnnouncement` is extended with Spine head fields
   (`head_hash`, `checkpoint_ref`) enabling anti-entropy: peers know when they
   are behind and can request missing envelopes.

4. **Desktop subscribes to curator heads via NATS**: Instead of polling HTTP
   endpoints for feed updates, the desktop (via hushd or direct NATS connection)
   subscribes to curator head announcements on
   `clawdstrike.spine.envelope.clawdstrike.marketplace.>`.

5. **Revocations propagate via Spine**: Revocation facts published to NATS
   propagate through all connected planes. When Reticulum (Plane A-R) is
   deployed (future), revocations automatically traverse the radio mesh with
   highest priority.

6. **The existing marketplace HTTP protocol continues to work** during the
   transition. Spine-backed verification is additive. Desktop clients prefer
   Spine when available but fall back to HTTP feed loading.

---

## Implementation Plan

### Step 1: Define Spine Fact Schemas for Marketplace Objects

Create `crates/spine/src/marketplace_spine.rs`:

```rust
use serde::{Deserialize, Serialize};

pub const POLICY_BUNDLE_FACT_SCHEMA: &str =
    "clawdstrike.marketplace.policy_bundle.v1";
pub const HEAD_ANNOUNCEMENT_SCHEMA: &str =
    "clawdstrike.marketplace.head_announcement.v1";
pub const FEED_ENTRY_FACT_SCHEMA: &str =
    "clawdstrike.marketplace.feed_entry.v1";

/// A marketplace feed entry wrapped as a Spine fact.
///
/// This replaces the standalone `MarketplaceEntry` when the marketplace
/// is running in Spine-unified mode. The entry content is identical;
/// only the wrapping changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedEntryFact {
    pub schema: String,
    pub fact_id: String,
    /// Feed identifier (e.g., "clawdstrike-official").
    pub feed_id: String,
    /// Feed sequence at time of publication.
    pub feed_seq: u64,
    /// Entry identifier within the feed.
    pub entry_id: String,
    /// Location of the policy bundle.
    pub bundle_uri: String,
    /// SHA-256 hash of the canonical policy bundle.
    pub bundle_hash: String,
    /// SHA-256 hash of the canonical policy JSON.
    pub policy_hash: String,
    /// Entry metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
}

/// Head announcement fact for a marketplace curator feed.
///
/// Published when a curator updates their feed (new entries, removals,
/// revocations). Peers compare their local `(issuer, seq)` state against
/// announced heads and initiate sync for missing ranges.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadAnnouncement {
    pub schema: String,
    pub fact_id: String,
    /// Feed identifier.
    pub feed_id: String,
    /// Curator's Spine issuer (redundant with envelope issuer, but explicit for clarity).
    pub curator_issuer: String,
    /// Current head sequence number.
    pub head_seq: u64,
    /// Envelope hash of the head envelope.
    pub head_envelope_hash: String,
    /// Number of entries in the feed at this head.
    pub entry_count: u64,
    /// Checkpoint reference for verifiable freshness.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_ref: Option<CheckpointRef>,
}

/// Reference to a Spine checkpoint for verifiable freshness.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRef {
    pub log_id: String,
    pub checkpoint_seq: u64,
    pub envelope_hash: String,
}

/// Sync request from a peer that is behind on a curator's feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncRequest {
    pub schema: String,
    /// Curator issuer to sync.
    pub curator_issuer: String,
    /// Inclusive start of the missing range.
    pub from_seq: u64,
    /// Inclusive end of the missing range.
    pub to_seq: u64,
}

/// Sync response containing a batch of envelopes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncResponse {
    pub schema: String,
    pub curator_issuer: String,
    /// Envelopes in the requested range, ordered by seq.
    pub envelopes: Vec<serde_json::Value>,
}
```

Source: Reticulum SDR Transport Section 3 (marketplace unification mapping),
Architecture Vision Section 4.6 (marketplace-to-Spine unification).

### Step 2: Curator Feed-to-Spine Conversion Tooling

Extend `marketplace_feed_gen` with a `--spine-mode` flag. When set:

1. For each feed entry, build a `FeedEntryFact` and wrap it in a `SignedEnvelope`
   using the curator's keypair, with monotonically increasing `seq` and
   `prev_envelope_hash` chaining.

2. After all entry envelopes, build a `HeadAnnouncement` fact referencing the
   last envelope's hash and `seq`.

3. Publish all envelopes to NATS subject
   `clawdstrike.spine.envelope.clawdstrike.marketplace.v1`.

4. Publish the head announcement to NATS subject
   `clawdstrike.spine.envelope.clawdstrike.marketplace.head.v1`.

5. Optionally, also generate the legacy `SignedMarketplaceFeed` for
   backward compatibility (`--emit-legacy-feed`).

CLI interface:
```
marketplace-feed-gen \
  --input feed.yaml \
  --key-seed 0x... \
  --spine-mode \
  --nats-url nats://localhost:4222 \
  --emit-legacy-feed feed.signed.json
```

For offline environments:
```
marketplace-feed-gen \
  --input feed.yaml \
  --key-seed 0x... \
  --spine-mode \
  --spine-output spine-envelopes.jsonl \
  --head-output head-announcement.json
```

### Step 3: Extend P2P Discovery with Spine Head Semantics

Modify `MarketplaceDiscoveryAnnouncement` in
`apps/desktop/src-tauri/src/marketplace_discovery.rs`:

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarketplaceDiscoveryAnnouncement {
    #[serde(default = "default_discovery_version")]
    pub v: u8,
    pub feed_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feed_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_public_key: Option<String>,
    // --- New Spine-aware fields ---
    /// Spine head hash for anti-entropy (peers compare to local state).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_hash: Option<String>,
    /// Spine issuer ID of the curator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spine_issuer: Option<String>,
    /// Checkpoint reference for verifiable freshness bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_ref: Option<CheckpointRefDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointRefDto {
    pub log_id: String,
    pub checkpoint_seq: u64,
    pub envelope_hash: String,
}
```

Bump the protocol version to `2` and handle both v1 (existing) and v2
(Spine-aware) announcements:

```rust
const DISCOVERY_PROTOCOL_VERSION: u8 = 2;

// In handle_gossipsub_message:
if announcement.v != 1 && announcement.v != 2 {
    return;
}
```

When the desktop receives a v2 announcement with `spine_issuer` and `seq`, it
compares against its local state for that curator. If the announced `seq` is
higher, the desktop initiates a sync (see Step 5).

Source: Marketplace Trust Evolution Section 6 (feed freshness protocol),
Reticulum SDR Transport Section 3.2 (head announcements in gossip).

### Step 4: NATS-Based Head Subscription for Desktop

Add a new subscription path in hushd (or directly in the desktop's Tauri
backend) for marketplace head announcements:

**NATS subject**: `clawdstrike.spine.envelope.clawdstrike.marketplace.head.v1`

When a head announcement arrives:

1. Verify the envelope signature.
2. Check that the issuer is a trusted curator (via `CuratorTrustSet`).
3. Compare `head_seq` against the desktop's last-known seq for this curator.
4. If behind, initiate sync for the missing envelope range.
5. Emit a Tauri event to the frontend: `marketplace_feed_update` with the new
   head info.

For the desktop, this replaces feed polling. Instead of periodically fetching
`feed.signed.json` from HTTP/IPFS, the desktop learns about feed updates in
real time via NATS head announcements.

**Fallback**: When NATS is not available (standalone desktop mode), the existing
HTTP/IPFS feed polling continues to work. The desktop tries NATS first, falls
back to HTTP/IPFS.

### Step 5: Spine Sync for Missing Envelopes

Implement a lightweight sync protocol for the desktop to catch up on missed
marketplace envelopes:

1. Desktop determines it is behind: `local_seq < announced_head_seq` for a
   trusted curator.
2. Desktop sends a `SyncRequest` to the Proofs API (or a dedicated sync
   endpoint):
   ```
   GET /v1/marketplace/sync?issuer={curator_issuer}&from_seq={local_seq+1}&to_seq={head_seq}
   ```
3. The API returns the missing envelopes as a JSON array.
4. Desktop validates each envelope (signature, seq monotonicity,
   prev_envelope_hash chaining).
5. Desktop updates its local state and processes new feed entries.

Add to the Proofs API (`crates/spine/src/bin/proofs_api.rs`):

```rust
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncQuery {
    issuer: String,
    from_seq: u64,
    to_seq: u64,
}

async fn v1_marketplace_sync(
    State(state): State<Arc<AppState>>,
    Query(q): Query<SyncQuery>,
) -> Result<Json<Value>, ApiError> {
    // Validate range (max 100 envelopes per request)
    // Look up envelope hashes by issuer+seq in fact_index_kv
    // Return array of envelopes
}
```

Route:
```rust
.route("/v1/marketplace/sync", get(v1_marketplace_sync))
```

### Step 6: Revocation Propagation via Spine

Revocations (defined in Spec 07 as `clawdstrike.marketplace.revocation.v1`)
are already Spine envelopes. For multi-plane propagation:

1. When a curator publishes a revocation, it is submitted to NATS:
   `clawdstrike.spine.envelope.clawdstrike.marketplace.revocation.v1`

2. The desktop subscribes to revocation subjects and processes them
   immediately:
   - Remove the revoked bundle from the marketplace UI
   - Show a warning if the bundle is currently installed
   - Persist the revocation in local state to prevent reinstallation

3. When Reticulum (Plane A-R) is deployed, the translation gateway forwards
   revocations with highest priority (priority 1 per the transport profile).
   No additional work is needed beyond the gateway's standard envelope
   forwarding -- revocations are just envelopes with a specific fact schema.

4. Fact indexing for revocations (from Spec 07, Step 6):
   ```
   Key:   policy_revocation.<bundle_hash>
   Value: <envelope_hash>
   ```

### Step 7: Desktop State Machine for Dual-Mode Operation

The desktop must operate in both modes during the transition:

**Mode A (Legacy)**: Load feed from HTTP/IPFS, verify feed signature, load
bundles, verify bundle signatures. This is the current behavior.

**Mode B (Spine)**: Subscribe to curator head announcements via NATS, sync
missing envelopes, extract feed entries from envelope facts, verify envelope
signatures. Bundles are still fetched by URI from the entry but provenance is
Spine-backed.

The desktop should prefer Mode B when NATS is available and the curator has a
Spine issuer configured. Mode A remains the fallback.

Implementation in `apps/desktop/src-tauri/src/commands/marketplace.rs`:

```rust
#[tauri::command]
pub async fn marketplace_list_policies(
    app: AppHandle,
    sources: Option<Vec<String>>,
    state: State<'_, AppState>,
) -> Result<MarketplaceListResponse, String> {
    let trust_set = load_curator_trust_set()?;
    let sources = sources.unwrap_or_else(|| vec!["builtin".to_string()]);

    // Try Spine-mode first if NATS is configured
    if let Some(nats_url) = state.nats_url.as_ref() {
        if let Ok(response) = load_spine_feed(&trust_set, nats_url).await {
            return Ok(response);
        }
        // Fall through to legacy mode
    }

    // Legacy mode (existing implementation)
    load_legacy_feed(&app, &state, &sources, &trust_set).await
}
```

### Step 8: Fact Index Keys for Marketplace Sync

The checkpointer must index marketplace envelopes for the sync endpoint:

For `clawdstrike.marketplace.feed_entry.v1`:
```
Key:   marketplace_entry.<issuer_hex>.<seq>
Value: <envelope_hash>
```

For `clawdstrike.marketplace.head_announcement.v1`:
```
Key:   marketplace_head.<issuer_hex>
Value: <envelope_hash>  (latest head only, overwritten on each update)
```

This enables the sync endpoint to look up envelopes by `(issuer, seq)` range.

### Step 9: Portable Spine Feed Export

For offline/disconnected environments, add a CLI command to export a curator's
Spine feed as a portable bundle:

```bash
clawdstrike marketplace export \
  --nats-url nats://localhost:4222 \
  --curator-issuer aegis:ed25519:<hex> \
  --output feed-bundle.jsonl \
  --include-proofs
```

The export contains:
- All `feed_entry.v1` envelopes for the curator
- The latest `head_announcement.v1` envelope
- Any `revocation.v1` envelopes
- Optionally, inclusion proofs for each envelope
- The relevant checkpoint(s) with witness signatures

This bundle can be imported on a disconnected node:
```bash
clawdstrike marketplace import --input feed-bundle.jsonl
```

The import validates all signatures, checks seq monotonicity, and detects forks.

Source: Reticulum SDR Transport Section 4.3 (USB sneakernet for air-gapped
facilities).

---

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `crates/spine/src/marketplace_spine.rs` | **Create** | `FeedEntryFact`, `HeadAnnouncement`, `CheckpointRef`, `SyncRequest`, `SyncResponse` types |
| `crates/spine/src/lib.rs` | **Modify** | Add `pub mod marketplace_spine;` and re-exports |
| `crates/clawdstrike/src/bin/marketplace_feed_gen.rs` | **Modify** | Add `--spine-mode`, `--spine-output`, `--head-output`, `--emit-legacy-feed` flags |
| `apps/desktop/src-tauri/src/marketplace_discovery.rs` | **Modify** | Extend `MarketplaceDiscoveryAnnouncement` with `head_hash`, `spine_issuer`, `checkpoint_ref`; bump protocol version to 2 |
| `apps/desktop/src-tauri/src/commands/marketplace.rs` | **Modify** | Add Spine-mode feed loading path, NATS head subscription, sync logic, dual-mode state machine |
| `crates/spine/src/bin/proofs_api.rs` | **Modify** | Add `/v1/marketplace/sync` endpoint for envelope range sync |
| `apps/desktop/src/services/marketplaceSettings.ts` | **Modify** | Add `natsUrl` and `preferSpineMode` settings |
| `crates/spine/tests/marketplace_spine_test.rs` | **Create** | Serde roundtrip, envelope wrapping, head announcement, sync tests |

---

## Testing Strategy

### Unit Tests

- `FeedEntryFact`, `HeadAnnouncement`, `CheckpointRef` serde roundtrip with `deny_unknown_fields`
- `SyncRequest`, `SyncResponse` serde roundtrip
- Discovery announcement v1 -> v2 backward compatibility: v1 announcements without Spine fields still parse
- Head comparison logic: `local_seq < announced_seq` triggers sync

### Integration Tests

- Build a sequence of `FeedEntryFact` envelopes with chained `prev_envelope_hash`, verify the chain integrity
- Build a `HeadAnnouncement` referencing the last entry, verify it matches
- Simulate sync: store 10 envelopes in mock KV, request range [5..10], verify returned envelopes are correct and ordered
- Revocation: publish a revocation for an entry, verify the sync endpoint includes it and the desktop filters it out
- Dual-mode fallback: when NATS is unreachable, verify the desktop falls back to legacy HTTP feed loading

### End-to-End Manual Testing

1. Run `marketplace_feed_gen --spine-mode` against a local NATS
2. Verify `feed_entry.v1` envelopes appear in NATS
3. Verify `head_announcement.v1` appears in NATS
4. Start the desktop with NATS configured
5. Verify the desktop receives the head announcement and loads policies
6. Add a new entry, verify the desktop receives the update in real time
7. Publish a revocation, verify the desktop removes the entry
8. Disconnect NATS, verify the desktop falls back to legacy mode
9. Export a feed bundle, import on a fresh desktop, verify all entries load

---

## Rollback Plan

1. **Discovery protocol**: v2 announcements are backward-compatible with v1.
   Peers running old code ignore the new fields. Reverting does not break
   existing discovery.

2. **Marketplace commands**: The dual-mode state machine tries Spine first and
   falls back to legacy. Reverting removes the Spine path, leaving the existing
   legacy path unchanged.

3. **Proofs API**: The `/v1/marketplace/sync` endpoint is additive and does
   not modify existing routes.

4. **Feed generation**: The `--spine-mode` flag is opt-in. The existing
   `marketplace_feed_gen` usage is unchanged without the flag.
   `--emit-legacy-feed` ensures the legacy feed format is always available.

5. **NATS subjects**: New subjects (`clawdstrike.spine.envelope.clawdstrike.marketplace.*`)
   are additive and do not conflict with existing subjects.

Rollback procedure: revert the commit, redeploy. Curators continue publishing
legacy feeds. Desktop falls back to legacy mode. No data migration needed.

---

## Dependencies

| Dependency | Status | Notes |
|-----------|--------|-------|
| Spec 07 (AegisNet Notary Replacement) | Required | Defines `PolicyAttestation`, `PolicyRevocation` fact schemas and Spine provenance infrastructure |
| `spine` crate | Exists | Envelope signing, verification, checkpoint, trust |
| Proofs API | Exists | KV-backed endpoint with inclusion proofs |
| Marketplace feed | Exists | `marketplace_feed.rs`, `marketplace_feed_gen` binary |
| P2P Discovery | Exists | `marketplace_discovery.rs` with libp2p gossipsub |
| Desktop marketplace commands | Exists | `commands/marketplace.rs` with feed loading, bundle verification, notary/Spine verification |
| NATS JetStream | Deployed | Plane B transport for head announcements and sync |
| Reticulum (Plane A-R) | Not deployed | Future transport for offline revocation propagation. This spec does not require Reticulum but is designed so revocations "just work" when Reticulum gateways are deployed. |

---

## Acceptance Criteria

- [ ] `FeedEntryFact` compiles, serializes, roundtrips with `deny_unknown_fields`
- [ ] `HeadAnnouncement` compiles, serializes, roundtrips with `deny_unknown_fields`
- [ ] `marketplace_feed_gen --spine-mode` produces valid Spine envelopes for
      each feed entry and a head announcement
- [ ] Spine envelopes have correct `prev_envelope_hash` chaining and monotonic `seq`
- [ ] Each Spine envelope passes `spine::verify_envelope()`
- [ ] Head announcement `head_envelope_hash` matches the last entry's `envelope_hash`
- [ ] `--emit-legacy-feed` produces a valid `SignedMarketplaceFeed` alongside
      Spine envelopes
- [ ] Discovery announcement v2 includes `head_hash`, `spine_issuer`,
      `checkpoint_ref` when available
- [ ] Discovery announcement v1 (without new fields) still parses correctly
      (backward compat)
- [ ] Proofs API `GET /v1/marketplace/sync?issuer=...&from_seq=...&to_seq=...`
      returns the correct envelope range
- [ ] Desktop loads policies from Spine envelopes when NATS is available
- [ ] Desktop falls back to legacy HTTP/IPFS feed loading when NATS is
      unavailable
- [ ] Desktop receives real-time head announcements and updates the policy list
- [ ] Desktop processes revocation envelopes and removes revoked entries
- [ ] `clawdstrike marketplace export` produces a valid portable bundle
- [ ] `clawdstrike marketplace import` validates and loads a portable bundle
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo test --workspace` passes

---

## Migration Strategy

The migration from the parallel marketplace protocol to Spine-unified mode is
**additive and non-breaking**:

**Phase 1 (This Spec)**: Implement dual-mode operation. Curators can publish
in both formats simultaneously (`--emit-legacy-feed`). Desktop tries Spine
first, falls back to legacy.

**Phase 2 (Future)**: Once Spine mode is validated in production for one full
release cycle, deprecate the legacy feed format. Curators publish only Spine
envelopes. Legacy feed generation is removed from the CLI. Desktop removes the
legacy feed loading path.

**Phase 3 (Future)**: When Reticulum gateways are deployed, revocations and
policy deltas automatically propagate to disconnected nodes. No additional
marketplace-specific work is required -- the gateway forwards Spine envelopes
regardless of their fact schema.

This phasing follows the Architecture Vision's recommendation (Section 4.6):
"Spine-backed verification is additive, not a breaking change."

---

## References

- Architecture Vision, Section 4.6: marketplace-to-Spine unification mapping table
- Architecture Vision, Section 6.7: Phase 6 Reticulum transport and Spine unification workstreams
- Reticulum SDR Transport, Section 3: marketplace unification (the incomplete Spine)
- Reticulum SDR Transport, Section 3.1: mapping marketplace constructs to Spine objects
- Reticulum SDR Transport, Section 3.2: what unification looks like (code examples)
- Reticulum SDR Transport, Section 3.3: why this matters for Reticulum
- Reticulum SDR Transport, Section 4.3: USB sneakernet (portable bundle export)
- Marketplace Trust Evolution, Section 6: P2P discovery enhancements
  (feed freshness protocol with checkpoint_ref)
- `crates/clawdstrike/src/marketplace_feed.rs`: `MarketplaceFeed`, `SignedMarketplaceFeed`, `MarketplaceProvenance`
- `apps/desktop/src-tauri/src/marketplace_discovery.rs`: `MarketplaceDiscoveryAnnouncement`, P2P gossip
- `apps/desktop/src-tauri/src/commands/marketplace.rs`: `marketplace_list_policies`, `marketplace_verify_spine_proof`, `marketplace_verify_attestation`
- `apps/desktop/src/services/marketplaceSettings.ts`: feed source configuration
- `crates/spine/src/envelope.rs`: `build_signed_envelope()`, `verify_envelope()`, issuer format
- `crates/spine/src/bin/proofs_api.rs`: existing API endpoints, KV patterns
