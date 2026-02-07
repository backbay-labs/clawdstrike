# Spec 10: IPFS-First Policy Bundle Distribution

> **Status:** Draft | **Date:** 2026-02-07
> **Author:** Phase C Spec Agent
> **Effort estimate:** 4-6 engineer-days
> **Dependencies:** None (can be done in parallel with other marketplace work)

---

## Summary / Objective

Evolve ClawdStrike's policy marketplace distribution from HTTPS-only to an IPFS-first model with Pinata as managed pinning, a self-hosted IPFS node as backup, and an HTTPS fallback gateway chain. Policy bundles and signed feeds become content-addressed IPFS objects, providing censorship-resistant, verifiable, and decentralized distribution. Clients fetch bundles via IPFS CID with defense-in-depth SHA-256 verification against the existing `policy_hash`.

---

## Current State

### Marketplace feed and bundle signing (Rust)

The marketplace uses a three-layer signed model implemented in:

**`crates/clawdstrike/src/marketplace_feed.rs`:**
- `MarketplaceFeed` has a `entries: Vec<MarketplaceEntry>` where each entry has a `bundle_uri: String`
- `bundle_uri` accepts `https://...`, `ipfs://...`, and `builtin://...` schemes (documented in the struct comment on line 52)
- `MarketplaceProvenance` has optional `attestation_uid`, `notary_url`, and `spine_envelope_hash` fields
- `SignedMarketplaceFeed::verify_trusted()` already accepts `&[PublicKey]` for multi-curator verification
- Feed content is canonicalized via RFC 8785 (`hush_core::canonical::canonicalize`) before signing

**`crates/clawdstrike/src/policy_bundle.rs`:**
- `PolicyBundle` computes `policy_hash: Hash` as SHA-256 of the canonical JSON of the policy
- `SignedPolicyBundle` wraps a bundle with an Ed25519 signature
- `PolicyBundle::hash_sha256()` returns the SHA-256 of the canonical bundle JSON

### P2P discovery (desktop Tauri)

**`apps/desktop/src-tauri/src/marketplace_discovery.rs`:**
- libp2p gossipsub + mDNS for feed URI discovery
- `MarketplaceDiscoveryAnnouncement` carries `feed_uri: String` (comment on line 33: "recommended: `ipfs://<CID>`")
- Discovery is explicitly low-trust -- only gossips URIs; verification happens after fetch
- Static bootstrap multiaddrs for WAN connectivity

### Desktop settings (TypeScript)

**`apps/desktop/src/services/marketplaceSettings.test.ts`:**
- Tests confirm `ipfs://bafy...` is a valid feed source URI
- `loadMarketplaceFeedSources()` / `saveMarketplaceFeedSources()` store feed URIs in localStorage
- Settings UI (`SettingsView.tsx` line 337) documents that `ipfs://...` URIs are supported

**`apps/desktop/src/services/marketplaceProvenanceSettings.ts`:**
- `MarketplaceProvenanceSettings` tracks `requireVerified`, `trustedAttesters[]`, and `notaryUrl`

### Existing SDK Reuse

`@backbay/notary` (located at `standalone/backbay-sdk/packages/notary/src/lib/ipfs.ts`) already has a production IPFS upload pipeline built on `@web3-storage/w3up-client` v16.0.0. It provides:

- **`uploadFile(filePath)`** and **`uploadDirectory(dirPath)`** -- pin files/directories to IPFS via web3.storage
- **`checkAvailability(cid)`** -- verify a CID is retrievable from the IPFS network
- **`getIpfsGatewayUrl(cid)`** -- format gateway URLs for a given CID
- **Space management** -- `setupAuthentication(email)`, `listSpaces()`, `createSpace()`, `selectSpace()`
- **`isIpfsConfigured()`** -- check whether IPFS credentials are present (via `NOTARY_*` environment variables)

Additionally, `@backbay/notary` has its own RFC 8785 canonical JSON implementation (`canonicalize()`, `hashObject()`, `sha256()`), which overlaps with `hush-ts`'s canonical JSON support. These implementations can be shared or consolidated to avoid divergence.

### What is missing

- No IPFS fetching implementation (desktop or CLI) -- URIs are accepted but never resolved
- No pinning workflow for curators (no Pinata/self-hosted integration)
- No gateway fallback chain logic
- No dual-CID validation (IPFS CID vs SHA-256 policy_hash)
- No `content_ids` field on `MarketplaceEntry` for explicit CID tracking
- No feed-on-IPFS support (the feed itself pinned and distributed via IPFS)
- No CLI command for publishing bundles to IPFS

### Referenced research

From `docs/research/marketplace-trust-evolution.md` (section 5):
> The marketplace already supports `ipfs://` URIs in `bundle_uri` fields and the discovery layer validates `ipfs://` as a supported scheme. This is an excellent foundation.

Section 5 recommends:
- Dual-CID strategy (IPFS CID + SHA-256 policy_hash)
- Hybrid pinning (Pinata primary + self-hosted backup)
- Gateway hints in feed entries
- Feed itself pinned to IPFS

From `docs/research/open-source-strategy.md` (section 4.5, Phase 3):
> - Curator tooling pins signed feeds and bundles to IPFS (Pinata + self-hosted).
> - Feed entries use `ipfs://` CIDs as primary `bundle_uri`.
> - P2P discovery gossips feed CIDs instead of HTTPS URLs.
> - Add IPFS gateway fallback chain to the desktop client.

---

## Target State

1. **Curator publish workflow**: A CLI command `clawdstrike marketplace publish` signs a policy bundle, pins it to IPFS via Pinata API (and optionally a self-hosted node), and outputs the CID for inclusion in a feed entry.

2. **Feed-on-IPFS**: The entire signed feed (JSON) is pinned to IPFS. P2P discovery gossips the feed CID. Clients fetch the full feed in one IPFS retrieval.

3. **Extended MarketplaceEntry**: Each entry carries `content_ids` with both IPFS CID and SHA-256 hash, plus optional `gateway_hints` for fallback fetching.

4. **Client fetch pipeline**: Desktop and CLI resolve `ipfs://` bundle URIs via a configurable gateway chain, then verify the fetched content's SHA-256 matches `policy_hash` before accepting.

5. **Pinning management**: Curators can list, pin, and unpin bundles from their Pinata account or self-hosted node via CLI.

---

## Implementation Plan

### Step 1: Extend `MarketplaceEntry` with `content_ids` and `gateway_hints`

**File:** `crates/clawdstrike/src/marketplace_feed.rs`

Add two new optional fields to `MarketplaceEntry`:

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentIds {
    /// IPFS CIDv1 (base32, typically SHA-256 under the hood).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipfs_cid: Option<String>,
    /// SHA-256 of the canonical JSON of the signed bundle.
    pub sha256: String,
}

// In MarketplaceEntry:
/// Content identifiers for verifiable fetching.
#[serde(skip_serializing_if = "Option::is_none")]
pub content_ids: Option<ContentIds>,

/// Ordered list of IPFS gateway base URLs for fallback fetching.
#[serde(default, skip_serializing_if = "Vec::is_empty")]
pub gateway_hints: Vec<String>,
```

Since `MarketplaceEntry` uses `deny_unknown_fields`, this is a schema change. The `content_ids` and `gateway_hints` fields are optional, so existing feeds without them will continue to deserialize. Update the test in `marketplace_feed.rs` to include the new fields.

**Important:** The MARKETPLACE_FEED_SCHEMA_VERSION stays at `clawdstrike-marketplace-feed-v1` since the new fields are optional and backward-compatible. If strict schema versioning is desired, bump to `v2` and handle both in `validate_version()`.

### Step 2: Add IPFS pinning client module

> **Note:** The TypeScript side of IPFS upload should reuse `@backbay/notary`'s existing `ipfs.ts` module (w3up-client wrapper) rather than building a new one. The Rust `IpfsClient` in this step covers the Rust CLI and daemon use case; the desktop app's TypeScript layer should import from `@backbay/notary` or extract its IPFS module into a shared `@backbay/ipfs` package.

**New file:** `crates/clawdstrike/src/ipfs.rs`

A lightweight IPFS pinning client that supports:

1. **Pinata API** (remote pinning, managed):
   - `POST https://api.pinata.cloud/pinning/pinJSONToIPFS` -- pin JSON directly
   - `POST https://api.pinata.cloud/pinning/pinFileToIPFS` -- pin binary files
   - `GET https://api.pinata.cloud/data/pinList` -- list pinned items
   - `DELETE https://api.pinata.cloud/pinning/unpin/{hash}` -- remove pin
   - Authentication via `PINATA_JWT` environment variable

2. **IPFS HTTP API** (self-hosted, localhost:5001):
   - `POST /api/v0/add` -- add and pin content
   - `POST /api/v0/pin/ls` -- list pins
   - `POST /api/v0/pin/rm` -- remove pin

3. **Gateway fetch** (read-only):
   - `GET https://<gateway>/ipfs/<CID>` with fallback chain
   - SHA-256 verification of fetched content against expected hash

```rust
pub struct IpfsPinningConfig {
    /// Pinata JWT token (if using Pinata).
    pub pinata_jwt: Option<String>,
    /// Self-hosted IPFS API URL (e.g., "http://localhost:5001").
    pub ipfs_api_url: Option<String>,
    /// Ordered list of IPFS gateways for fetching.
    pub gateways: Vec<String>,
}

impl Default for IpfsPinningConfig {
    fn default() -> Self {
        Self {
            pinata_jwt: None,
            ipfs_api_url: None,
            gateways: vec![
                "https://gateway.pinata.cloud/ipfs/".to_string(),
                "https://dweb.link/ipfs/".to_string(),
                "https://ipfs.io/ipfs/".to_string(),
            ],
        }
    }
}

pub struct IpfsClient {
    config: IpfsPinningConfig,
    http: reqwest::Client,
}

impl IpfsClient {
    /// Pin JSON content and return the CIDv1.
    pub async fn pin_json(&self, json: &serde_json::Value, name: &str) -> Result<String>;

    /// Fetch content by CID, trying each gateway in order.
    /// Returns the content bytes after verifying SHA-256 if `expected_sha256` is provided.
    pub async fn fetch_verified(&self, cid: &str, expected_sha256: Option<&Hash>) -> Result<Vec<u8>>;

    /// List currently pinned items (Pinata or self-hosted).
    pub async fn list_pins(&self) -> Result<Vec<PinInfo>>;

    /// Unpin a CID.
    pub async fn unpin(&self, cid: &str) -> Result<()>;
}
```

Dependencies to add to `crates/clawdstrike/Cargo.toml`:
- `reqwest` (already in workspace) -- for HTTP calls to Pinata/gateway
- Feature-gate the IPFS module behind `ipfs` feature flag to keep the core library lean

### Step 3: CLI `marketplace publish` command

**File:** `crates/hush-cli/src/commands/marketplace.rs` (new subcommand)

```
clawdstrike marketplace publish \
    --policy strict.yaml \
    --signing-key ~/.clawdstrike/curator.key \
    --pin-to pinata \
    --pin-to self-hosted \
    --output-entry entry.json
```

Workflow:
1. Load and compile the policy YAML (resolve `extends`)
2. Create `PolicyBundle` with `policy_hash`
3. Sign the bundle with curator key -> `SignedPolicyBundle`
4. Serialize to canonical JSON
5. Pin canonical JSON to IPFS via configured backends (Pinata, self-hosted, or both)
6. Compute SHA-256 of the canonical JSON
7. Output a `MarketplaceEntry` fragment with:
   - `bundle_uri: "ipfs://<CID>"`
   - `content_ids: { ipfs_cid: "<CID>", sha256: "0x<hash>" }`
   - `gateway_hints: [...]` from config

```
clawdstrike marketplace publish-feed \
    --feed feed.yaml \
    --signing-key ~/.clawdstrike/curator.key \
    --pin-to pinata \
    --output signed-feed.json
```

Workflow:
1. Load entries (from individual entry JSON files or inline YAML)
2. Build `MarketplaceFeed` with current timestamp and incremented `seq`
3. Sign feed -> `SignedMarketplaceFeed`
4. Serialize to canonical JSON
5. Pin the signed feed JSON to IPFS
6. Output the feed CID for P2P discovery announcement

### Step 4: Gateway fetch pipeline for desktop client

> **Note:** The desktop app's TypeScript layer should use `@backbay/notary`'s `checkAvailability(cid)` for IPFS availability checks and `getIpfsGatewayUrl(cid)` for gateway URL formatting, while the Rust Tauri backend handles the actual fetch + SHA-256 verification.

**File:** `apps/desktop/src-tauri/src/commands/marketplace.rs`

Add an IPFS-aware bundle fetcher that the existing marketplace commands call:

```rust
async fn fetch_bundle(uri: &str, expected_hash: Option<&Hash>, config: &IpfsPinningConfig) -> Result<SignedPolicyBundle> {
    let bytes = if uri.starts_with("ipfs://") {
        let cid = uri.strip_prefix("ipfs://").unwrap_or(uri);
        let client = IpfsClient::new(config.clone());
        client.fetch_verified(cid, expected_hash).await?
    } else if uri.starts_with("https://") || uri.starts_with("http://") {
        let resp = reqwest::get(uri).await?;
        resp.bytes().await?.to_vec()
    } else if uri.starts_with("builtin://") {
        // existing built-in bundle loading
        load_builtin_bundle(uri)?
    } else {
        return Err(Error::ConfigError(format!("Unsupported bundle URI scheme: {uri}")));
    };

    // Defense-in-depth: verify SHA-256 matches policy_hash
    let bundle: SignedPolicyBundle = serde_json::from_slice(&bytes)?;
    if let Some(expected) = expected_hash {
        let actual = bundle.bundle.hash_sha256()?;
        if &actual != expected {
            return Err(Error::ConfigError(
                "Bundle SHA-256 does not match expected policy_hash".to_string(),
            ));
        }
    }
    Ok(bundle)
}
```

The `fetch_verified` method in `IpfsClient` tries gateways in order:
1. `gateway_hints` from the `MarketplaceEntry` (if present)
2. `gateways` from `IpfsPinningConfig` (user-configured defaults)
3. Hard-coded fallbacks: `dweb.link`, `ipfs.io`

Timeout per gateway: 10 seconds. Total timeout: 30 seconds.

### Step 5: Desktop settings for IPFS gateways

**File:** `apps/desktop/src/services/marketplaceSettings.ts`

Add IPFS gateway configuration to the marketplace settings:

```typescript
export interface IpfsGatewaySettings {
  /** Ordered list of IPFS gateway base URLs */
  gateways: string[];
  /** Timeout per gateway in ms */
  timeoutMs: number;
}

export const DEFAULT_IPFS_GATEWAY_SETTINGS: IpfsGatewaySettings = {
  gateways: [
    "https://gateway.pinata.cloud/ipfs/",
    "https://dweb.link/ipfs/",
    "https://ipfs.io/ipfs/",
  ],
  timeoutMs: 10000,
};
```

**File:** `apps/desktop/src/features/settings/SettingsView.tsx`

Add a settings section for IPFS gateways (below the existing "Feed Sources" section):

- Ordered list of gateway URLs (drag to reorder, add/remove)
- Per-gateway timeout
- "Test connectivity" button that fetches a known CID

### Step 6: CLI `marketplace pin-status` command

```
clawdstrike marketplace pin-status --backend pinata
```

Lists all pinned bundles/feeds with their CIDs, pin dates, and sizes. Useful for curators managing their IPFS content.

### Step 7: P2P discovery carries feed CID

**File:** `apps/desktop/src-tauri/src/marketplace_discovery.rs`

The `MarketplaceDiscoveryAnnouncement` already has `feed_uri: String` which can be an `ipfs://` URI. When a curator publishes a feed to IPFS:

1. The curator announces `{ feed_uri: "ipfs://<feed-CID>", feed_id: "clawdstrike-official", seq: 42 }` via gossipsub
2. Peers receiving the announcement fetch the feed via their gateway chain
3. After fetching, peers verify the feed signature against trusted curator keys
4. If valid and `seq` > local `seq`, the peer updates its local feed cache

No protocol changes needed -- the existing gossipsub format already supports this.

### Step 8: Tests

**Unit tests (Rust):**
- `ContentIds` serialization round-trip
- `MarketplaceEntry` with `content_ids` and `gateway_hints` serializes/deserializes correctly
- Existing `deny_unknown_fields` tests still pass (fields are optional)
- `IpfsClient::fetch_verified` with mock HTTP server (wiremock) -- verify SHA-256 check rejects tampered content
- Gateway fallback: first gateway 404s, second succeeds

**Unit tests (TypeScript):**
- `IpfsGatewaySettings` save/load round-trip
- Settings UI renders gateway list

**Integration tests:**
- Pin a test bundle to a local IPFS node (`ipfs daemon` in test), fetch via gateway, verify hash
- End-to-end: `clawdstrike marketplace publish` -> pin -> fetch -> verify

---

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `crates/clawdstrike/src/marketplace_feed.rs` | Modify | Add `ContentIds`, `content_ids`, `gateway_hints` to `MarketplaceEntry` |
| `crates/clawdstrike/src/ipfs.rs` | Create | IPFS pinning client (Pinata + self-hosted + gateway fetch) |
| `crates/clawdstrike/src/lib.rs` | Modify | Add `pub mod ipfs;` (feature-gated) |
| `crates/clawdstrike/Cargo.toml` | Modify | Add `ipfs` feature flag, optional reqwest dep |
| `crates/hush-cli/src/commands/marketplace.rs` | Create | `marketplace publish`, `marketplace publish-feed`, `marketplace pin-status` subcommands |
| `crates/hush-cli/src/commands/mod.rs` | Modify | Register `marketplace` subcommand |
| `crates/hush-cli/Cargo.toml` | Modify | Add `clawdstrike/ipfs` feature dep |
| `apps/desktop/src-tauri/src/commands/marketplace.rs` | Modify | Add IPFS-aware `fetch_bundle` function with gateway fallback chain |
| `apps/desktop/src/services/marketplaceSettings.ts` | Modify | Add `IpfsGatewaySettings` interface and storage |
| `apps/desktop/src/services/marketplaceSettings.test.ts` | Modify | Add tests for IPFS gateway settings |
| `apps/desktop/src/features/settings/SettingsView.tsx` | Modify | Add IPFS gateways section in settings UI |
| `packages/notary` (backbay-sdk) | Reference | Import IPFS upload functions; may extract to shared `@backbay/ipfs` package |

---

## Testing Strategy

### Unit tests

```bash
# Rust: marketplace_feed changes
cargo test -p clawdstrike marketplace_feed

# Rust: IPFS client (with mock server)
cargo test -p clawdstrike ipfs --features ipfs

# TypeScript: settings
npm test --workspace=apps/desktop -- --grep "ipfs"
```

### Integration test with local IPFS

```bash
# Start a local IPFS daemon
ipfs daemon &

# Pin a test bundle
clawdstrike marketplace publish \
    --policy rulesets/strict.yaml \
    --signing-key /tmp/test.key \
    --pin-to self-hosted \
    --ipfs-api http://localhost:5001 \
    --output-entry /tmp/entry.json

# Verify the entry has an ipfs:// URI
cat /tmp/entry.json | jq '.bundle_uri'

# Fetch via gateway and verify
curl -s "http://localhost:8080/ipfs/$(cat /tmp/entry.json | jq -r '.content_ids.ipfs_cid')" | sha256sum
```

### CI validation

The IPFS integration test is gated behind a `--features ipfs-integration-test` flag since it requires an IPFS daemon. It runs in a separate CI job with `ipfs` installed.

### Manual testing

1. Use Pinata free tier to pin a test bundle
2. Fetch via `gateway.pinata.cloud` and `dweb.link`
3. Verify content hash matches
4. Add the CID to a feed entry, sign the feed, announce via gossipsub
5. Verify another desktop client discovers and fetches the feed

---

## Rollback Plan

1. **Schema backward compatibility**: The `content_ids` and `gateway_hints` fields are optional. Removing them from `MarketplaceEntry` does not break existing feeds.
2. **Feature flag**: The IPFS module is behind the `ipfs` feature flag. Disabling it removes all IPFS code from the binary.
3. **HTTPS fallback**: All IPFS-distributed bundles also have HTTPS URLs. Removing IPFS support falls back to HTTPS fetching.
4. **No data migration**: IPFS pinning is additive. Existing HTTPS-hosted bundles continue to work. Curators can re-publish to HTTPS if IPFS is abandoned.
5. **Settings reset**: Desktop IPFS gateway settings can be cleared by resetting marketplace settings to defaults.

---

## Dependencies

| Dependency | Type | Notes |
|------------|------|-------|
| Pinata API account | External service | Free tier: 1GB storage, 100 pin requests/day. Pro: $20/mo for 50GB. |
| IPFS gateway availability | External service | Multiple public gateways for redundancy (Pinata, dweb.link, ipfs.io) |
| `reqwest` crate | Already in workspace | Used for Pinata API calls and gateway fetch |
| Spec 03 (Multi-curator config) | Soft | Curators need signing keys; currently manual key management |
| Spec 07 (AegisNet notary) | Soft | IPFS CIDs can be attested in AegisNet for additional trust |
| `@backbay/notary` IPFS module | Existing (backbay-sdk) | w3up-client wrapper for IPFS uploads; reuse for TS-side upload pipeline |

---

## Acceptance Criteria

- [ ] `MarketplaceEntry` accepts optional `content_ids: { ipfs_cid, sha256 }` and `gateway_hints: [...]` fields
- [ ] Existing feeds without `content_ids` / `gateway_hints` still deserialize (backward compatibility)
- [ ] `clawdstrike marketplace publish` pins a signed policy bundle to Pinata and outputs a `MarketplaceEntry` fragment with `ipfs://` URI
- [ ] `clawdstrike marketplace publish --pin-to self-hosted --ipfs-api http://localhost:5001` pins to a local IPFS node
- [ ] `clawdstrike marketplace publish-feed` pins the entire signed feed to IPFS and outputs the feed CID
- [ ] Desktop client resolves `ipfs://` bundle URIs via gateway fallback chain
- [ ] Fetched bundle content is verified against `policy_hash` SHA-256 (tampered content is rejected)
- [ ] Gateway fallback: if first gateway times out or 404s, the next gateway is tried
- [ ] Desktop Settings UI allows managing IPFS gateway list (add, remove, reorder)
- [ ] `clawdstrike marketplace pin-status` lists pinned items from Pinata or self-hosted IPFS
- [ ] P2P discovery announcements with `ipfs://` feed URIs are fetched and verified correctly
- [ ] All new Rust code passes `cargo clippy -- -D warnings` and `cargo fmt --check`
- [ ] Unit tests cover: ContentIds serde, gateway fallback, SHA-256 verification rejection, Pinata API mock
- [ ] IPFS module is feature-gated (`ipfs` feature) and does not increase default binary size
