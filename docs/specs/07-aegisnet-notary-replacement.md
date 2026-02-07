# Spec 07: AegisNet Notary Replacement -- Spine Inclusion Proofs for Marketplace

> **Status:** Draft | **Date:** 2026-02-07
> **Effort:** ~6 engineer-days
> **Phase:** B (Marketplace Trust) | **Priority:** High
> **Dependencies:** Spine crate (exists), Proofs API (exists), Marketplace feed + commands (exist)

---

## Summary / Objective

Replace the centralized HTTP notary verification path
(`GET /verify/{uid}` -> `NotaryVerifyResult`) with Spine inclusion proofs from
the AegisNet Proofs API (`GET /v1/proofs/inclusion?envelope_hash=0x...`). When a
curator publishes a policy bundle, they also submit a
`clawdstrike.marketplace.policy_attestation.v1` signed envelope to the Spine
log. Desktop clients verify provenance by fetching the RFC 6962 Merkle inclusion
proof and validating it locally, rather than trusting a centralized notary
server.

The end result: marketplace provenance verification is cryptographically
verifiable, append-only, independently witnessed, and works offline when
inclusion proofs are bundled with feed entries.

---

## Current State

### Notary Verification Path (Current)

The desktop app's `marketplace_verify_attestation` Tauri command
(`apps/desktop/src-tauri/src/commands/marketplace.rs:253-313`) implements the
current centralized notary model:

1. Takes `notary_url` and `uid` (attestation UID) as parameters
2. Calls `GET {notary_url}/verify/{uid}`
3. Expects a JSON response: `{ valid: bool, attester?: string, attested_at?: string }`
4. Returns a `NotaryVerifyResult` to the frontend

The `MarketplaceProvenance` struct (`crates/clawdstrike/src/marketplace_feed.rs:77-89`)
carries:
- `attestation_uid: Option<String>` -- opaque UID for the notary
- `notary_url: Option<String>` -- centralized notary endpoint
- `spine_envelope_hash: Option<String>` -- already present, for future Spine use

The frontend provenance settings (`apps/desktop/src/services/marketplaceProvenanceSettings.ts`)
store `notaryUrl`, `trustedAttesters`, and `requireVerified` in localStorage.

### Spine Proof Path (Partially Implemented)

The desktop already has a `marketplace_verify_spine_proof` Tauri command
(`apps/desktop/src-tauri/src/commands/marketplace.rs:599-690`) that:

1. Takes `proofs_api_url` and `envelope_hash`
2. Calls `GET {proofs_api_url}/v1/proofs/inclusion?envelope_hash={hash}`
3. Performs **local RFC 6962 Merkle proof verification** using `hush_core::MerkleProof`
4. Returns `SpineProofResult` with `included`, `log_id`, `checkpoint_seq`, `tree_size`, `log_index`, `proof_verified`

This path works end-to-end when an `envelope_hash` is known and the Proofs API
is reachable. What is missing:

- **Fact schema**: No `policy_attestation.v1` fact schema is defined
- **Curator tooling**: No tool to submit attestation envelopes when publishing a feed
- **Automatic verification**: The desktop must manually be told to use Spine vs notary
- **Provenance enrichment**: Feed entries do not carry inclusion proofs for offline use
- **Witness verification**: The desktop does not verify witness co-signatures

### Existing SDK Packages (backbay-sdk)

The `@backbay/witness` package (`standalone/backbay-sdk/packages/witness`) provides browser-side cryptographic verification that overlaps significantly with this spec's client verification needs:

- **Ed25519 verification (WASM):** Same primitives as `hush-core`, compiled to WASM for browser use
- **Merkle proof verification:** `verifyMerkleProof(leaf, proof, root)` — identical algorithm to `hush_core::MerkleProof::verify()`
- **RFC 8785 canonical JSON:** `getCanonicalJson()` for deterministic hashing
- **Multi-backend verification:** `fetchAndVerifyChain()` supports pluggable verification backends (currently Rekor, EAS, Solana)
- **React components:** `VerificationBadge` and `VerificationDetails` in `@backbay/witness-react` provide ready-made UI for verification status display

Rather than building new browser-side verification from scratch, this spec should extend `@backbay/witness` with a **Spine verification backend** (`fetchers/spine.ts`) that queries the Proofs API and verifies Merkle inclusion proofs using the existing WASM crypto.

### Proofs API

The Proofs API (`crates/spine/src/bin/proofs_api.rs`) exposes:
- `GET /v1/proofs/inclusion?envelope_hash=0x...` -- RFC 6962 inclusion proof
- `GET /v1/checkpoints/latest` -- latest checkpoint envelope
- `GET /v1/checkpoints/{seq}` -- checkpoint by sequence number
- `GET /v1/envelopes/{envelope_hash}` -- raw envelope lookup

All endpoints use KV buckets in NATS JetStream:
`CLAWDSTRIKE_LOG_INDEX`, `CLAWDSTRIKE_CHECKPOINTS`, `CLAWDSTRIKE_ENVELOPES`, `CLAWDSTRIKE_FACT_INDEX`.

---

## Target State

After this spec is implemented:

1. A `clawdstrike.marketplace.policy_attestation.v1` fact schema is defined and
   part of the Spine crate.

2. The `marketplace_feed_gen` CLI tool (or a new `clawdstrike attest` command)
   submits a signed attestation envelope to the Spine log when a curator
   publishes or updates a feed.

3. The `MarketplaceProvenance` struct supports a new `type` field that
   distinguishes between `"notary"` (legacy), `"spine"` (Spine inclusion
   proof), and `"eas"` (future on-chain). The `spine_envelope_hash` field is
   the primary identifier for Spine-backed entries.

4. The desktop client automatically prefers Spine verification when
   `spine_envelope_hash` is present, falling back to the legacy notary when it
   is not.

5. Feed entries can optionally carry pre-computed inclusion proofs for offline
   verification.

6. Witness co-signature verification is added to the desktop's Spine proof path.

---

## Implementation Plan

### Step 1: Define `policy_attestation.v1` Fact Schema

Create types in `crates/spine/src/marketplace_facts.rs`:

```rust
use serde::{Deserialize, Serialize};

pub const POLICY_ATTESTATION_SCHEMA: &str =
    "clawdstrike.marketplace.policy_attestation.v1";
pub const REVIEW_ATTESTATION_SCHEMA: &str =
    "clawdstrike.marketplace.review_attestation.v1";
pub const REVOCATION_SCHEMA: &str =
    "clawdstrike.marketplace.revocation.v1";

/// Curator attestation fact for a policy bundle in the marketplace.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAttestation {
    pub schema: String,
    pub fact_id: String,
    /// Policy bundle ID (UUID from SignedPolicyBundle).
    pub bundle_id: String,
    /// SHA-256 hash of the canonical JSON bundle content.
    pub bundle_hash: String,
    /// Feed identifier (e.g., "clawdstrike-official").
    pub feed_id: String,
    /// Feed sequence number at time of attestation.
    pub feed_seq: u64,
    /// Entry identifier within the feed.
    pub entry_id: String,
    /// SHA-256 hash of the canonical policy JSON.
    pub policy_hash: String,
    /// Curator public key (hex).
    pub curator_public_key: String,
    /// Type of attestation.
    pub attestation_type: String, // "curator_approval"
    /// Optional validity window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
    /// Optional metadata (review notes, etc.).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Community review attestation for a policy bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewAttestation {
    pub schema: String,
    pub fact_id: String,
    pub bundle_hash: String,
    pub reviewer: String, // "aegis:ed25519:<hex>"
    pub verdict: String,  // "approve" | "reject" | "needs-changes"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_notes: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<String>,
}

/// Revocation fact for a marketplace policy bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRevocation {
    pub schema: String,
    pub fact_id: String,
    pub bundle_hash: String,
    pub reason: String,
    pub revoked_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
}
```

Wire into `crates/spine/src/lib.rs`:
```rust
pub mod marketplace_facts;
pub use marketplace_facts::{
    PolicyAttestation, ReviewAttestation, PolicyRevocation,
    POLICY_ATTESTATION_SCHEMA, REVIEW_ATTESTATION_SCHEMA, REVOCATION_SCHEMA,
};
```

Source: Marketplace Trust Evolution Section 3 (AegisNet as Notary Replacement,
proposed attestation schema JSON), Section 8 (community curation model, review
attestation), Section 9 (revocation mechanisms).

### Step 2: Curator Attestation Tooling

Extend the `marketplace_feed_gen` binary
(`crates/clawdstrike/src/bin/marketplace_feed_gen.rs`) with a `--submit-attestation`
flag. When set, after signing the feed, the tool also:

1. For each feed entry, builds a `PolicyAttestation` fact with the entry's
   `bundle_hash`, `feed_seq`, `entry_id`, and `policy_hash`.
2. Wraps the fact in a `SignedEnvelope` using the curator's Ed25519 keypair.
3. Publishes the envelope to NATS subject
   `clawdstrike.spine.envelope.clawdstrike.policy.v1`.
4. Writes the `envelope_hash` back into the feed entry's
   `provenance.spine_envelope_hash` field.
5. Re-signs the feed with the updated provenance.

CLI interface:
```
marketplace-feed-gen \
  --input feed.yaml \
  --output feed.signed.json \
  --key-seed 0x... \
  --submit-attestation \
  --nats-url nats://localhost:4222
```

For environments without NATS access, the `--attestation-output` flag writes
the attestation envelopes to a JSONL file for later submission:
```
marketplace-feed-gen \
  --input feed.yaml \
  --output feed.signed.json \
  --key-seed 0x... \
  --attestation-output attestations.jsonl
```

### Step 3: Extend `MarketplaceProvenance` with Type Discriminator

Modify `MarketplaceProvenance` in
`crates/clawdstrike/src/marketplace_feed.rs`:

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarketplaceProvenance {
    /// Verification type: "notary", "spine", "eas".
    /// When absent, inferred from which fields are populated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notary_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spine_envelope_hash: Option<String>,
    /// Log operator ID for Spine verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_id: Option<String>,
    /// Checkpoint sequence for Spine verification (pin to a specific checkpoint).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_seq: Option<u64>,
    /// Pre-computed inclusion proof for offline verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<InclusionProofBundle>,
}

/// Pre-computed inclusion proof for offline Spine verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionProofBundle {
    /// RFC 6962 Merkle audit path (hex-encoded hashes).
    pub audit_path: Vec<String>,
    pub checkpoint_seq: u64,
    pub tree_size: u64,
    pub log_index: u64,
    pub merkle_root: String,
    /// Witness signatures on the checkpoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_signatures: Vec<WitnessSignatureRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSignatureRef {
    pub witness_node_id: String,
    pub signature: String,
}
```

The `type` field defaults to inference:
- If `spine_envelope_hash` is set -> `"spine"`
- Else if `attestation_uid` and `notary_url` are set -> `"notary"`
- Else -> no provenance

Add a helper method:
```rust
impl MarketplaceProvenance {
    pub fn effective_type(&self) -> Option<&str> {
        if let Some(t) = &self.r#type {
            return Some(t.as_str());
        }
        if self.spine_envelope_hash.is_some() {
            return Some("spine");
        }
        if self.attestation_uid.is_some() && self.notary_url.is_some() {
            return Some("notary");
        }
        None
    }
}
```

### Step 4: Desktop -- Automatic Spine-First Verification

Modify the `marketplace_verify_attestation` Tauri command or add routing logic
to prefer Spine when available. In practice, the frontend should call the
appropriate verification function based on `provenance.effective_type()`.

Add a new unified Tauri command
(`apps/desktop/src-tauri/src/commands/marketplace.rs`):

```rust
#[tauri::command]
pub async fn marketplace_verify_provenance(
    provenance: MarketplaceProvenance,
    proofs_api_url: Option<String>,
    state: State<'_, AppState>,
) -> Result<ProvenanceVerifyResult, String> {
    match provenance.effective_type() {
        Some("spine") => verify_spine_provenance(&provenance, &proofs_api_url, &state).await,
        Some("notary") => verify_notary_provenance(&provenance, &state).await,
        Some("eas") => Err("EAS verification not yet implemented".to_string()),
        _ => Ok(ProvenanceVerifyResult::unverified()),
    }
}
```

The `verify_spine_provenance` function:

1. If `inclusion_proof` is present in the provenance, verify locally first
   (offline path).
2. If online and `proofs_api_url` is configured, fetch a fresh proof from the
   Proofs API.
3. Verify the Merkle proof locally using `hush_core::MerkleProof`.
4. If `witness_signatures` are present, verify each using
   `spine::verify_witness_signature()`.
5. Return a `ProvenanceVerifyResult` with verification details.

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvenanceVerifyResult {
    pub verified: bool,
    pub method: String,        // "spine", "notary", "spine_offline", "none"
    pub log_id: Option<String>,
    pub checkpoint_seq: Option<u64>,
    pub witness_count: Option<usize>,
    pub error: Option<String>,
}
```

### Step 5: Witness Co-Signature Verification on Desktop

The desktop's `marketplace_verify_spine_proof` already does Merkle verification
but does not check witness signatures. Extend it:

1. After fetching the inclusion proof, fetch the associated checkpoint:
   `GET {proofs_api_url}/v1/checkpoints/{checkpoint_seq}`
2. The checkpoint envelope contains `fact.witness_signatures` (array of
   `{ witness_node_id, signature }` objects).
3. For each witness signature, call
   `spine::verify_witness_signature(&checkpoint_statement, witness_node_id, signature_hex)`.
4. Report the number of verified witnesses in the result.
5. Compare against the TrustBundle's `witness_quorum` if available.

### Step 6: Fact Indexing for Policy Attestations

The checkpointer must index `policy_attestation.v1` facts when they arrive.
Add indexing rules to the checkpointer:

For `clawdstrike.marketplace.policy_attestation.v1`:
```
Key:   policy_attestation.<bundle_hash>
Value: <envelope_hash>
```

For `clawdstrike.marketplace.revocation.v1`:
```
Key:   policy_revocation.<bundle_hash>
Value: <envelope_hash>
```

This allows the Proofs API (and desktop) to look up attestation and revocation
status by bundle hash.

Add new Proofs API endpoints:

```
GET /v1/marketplace/attestation/{bundle_hash}
  -> Returns the attestation envelope for this bundle

GET /v1/marketplace/revocation/{bundle_hash}
  -> Returns the revocation envelope (if any) for this bundle
```

### Step 7: Desktop Frontend -- Provenance UI Updates

Update the marketplace views to use the unified verification path:

1. In `MarketplaceView.tsx` (or equivalent), when displaying a policy entry:
   The desktop should use `@backbay/witness-react`'s `VerificationBadge`
   component for provenance badges, extending it with Spine-specific status
   strings ("Spine Verified", "Spine Offline Verified"). The
   `VerificationDetails` component can display the full verification chain
   including witness count and checkpoint info.
   - If `spine_envelope_hash` is present, show a "Spine Verified" badge with
     checkpoint info.
   - If offline inclusion proof is bundled, show "Spine Offline Verified" badge.
   - If only notary is available, show the existing "Notary Verified" badge.
   - Show witness count ("2/3 witnesses" style).

2. In the provenance settings panel
   (`marketplaceProvenanceSettings.ts`), add a `proofsApiUrl` field:

```typescript
export interface MarketplaceProvenanceSettings {
  notaryUrl: string | null;
  proofsApiUrl: string | null;       // NEW: Spine Proofs API URL
  trustedAttesters: string[];
  requireVerified: boolean;
  preferSpine: boolean;              // NEW: prefer Spine over notary
  trustedWitnessKeys: string[];      // NEW: for witness verification
}
```

### Step 8: Revocation Checking

When the desktop loads a marketplace feed, for each entry with Spine provenance,
check for revocations:

1. Query `GET {proofs_api_url}/v1/marketplace/revocation/{bundle_hash}`
2. If a revocation envelope exists:
   - Verify its envelope signature
   - Display a warning in the UI
   - If `requireVerified` is true, exclude the entry from the list
3. Check attestation time-bounds (`valid_from`, `valid_until`) if present.

---

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `crates/spine/src/marketplace_facts.rs` | **Create** | `PolicyAttestation`, `ReviewAttestation`, `PolicyRevocation` types |
| `crates/spine/src/lib.rs` | **Modify** | Add `pub mod marketplace_facts;` and re-exports |
| `crates/clawdstrike/src/marketplace_feed.rs` | **Modify** | Extend `MarketplaceProvenance` with `type`, `log_id`, `checkpoint_seq`, `inclusion_proof` fields; add `InclusionProofBundle`, `WitnessSignatureRef`, `effective_type()` method |
| `crates/clawdstrike/src/bin/marketplace_feed_gen.rs` | **Modify** | Add `--submit-attestation` and `--attestation-output` flags, attestation envelope submission logic |
| `apps/desktop/src-tauri/src/commands/marketplace.rs` | **Modify** | Add `marketplace_verify_provenance` unified command, witness verification in `marketplace_verify_spine_proof`, revocation checking |
| `crates/spine/src/bin/proofs_api.rs` | **Modify** | Add `/v1/marketplace/attestation/{bundle_hash}` and `/v1/marketplace/revocation/{bundle_hash}` endpoints |
| `apps/desktop/src/services/marketplaceProvenanceSettings.ts` | **Modify** | Add `proofsApiUrl`, `preferSpine`, `trustedWitnessKeys` fields |
| `crates/spine/tests/marketplace_facts_test.rs` | **Create** | Serde roundtrip and envelope integration tests |
| `backbay-sdk/packages/witness/src/fetchers/spine.ts` | **Create** | Spine Proofs API verification backend for `fetchAndVerifyChain()` |
| `backbay-sdk/packages/witness-react/` | **Reference** | Reuse `VerificationBadge` and `VerificationDetails` for marketplace UI |

---

## Testing Strategy

### Unit Tests

- `PolicyAttestation`, `ReviewAttestation`, `PolicyRevocation` serde roundtrip
- `deny_unknown_fields` rejection for all three types
- `MarketplaceProvenance.effective_type()` returns correct type for each field
  combination
- `InclusionProofBundle` serialization roundtrip

### Integration Tests

- Build a `PolicyAttestation` fact, wrap in `SignedEnvelope`, verify envelope,
  extract fact, deserialize back -- confirm all fields match.
- Build an attestation, store it in a mock NATS KV, query via Proofs API
  endpoint, verify the inclusion proof locally.
- Test offline verification: bundle an inclusion proof with a feed entry,
  verify it without network access.

### End-to-End Manual Testing

1. Run `marketplace_feed_gen --submit-attestation` against a local NATS
2. Confirm attestation envelopes appear in NATS subjects
3. Confirm `GET /v1/marketplace/attestation/{bundle_hash}` returns the envelope
4. Confirm `GET /v1/proofs/inclusion?envelope_hash=0x...` returns a valid proof
5. Confirm desktop's `marketplace_verify_provenance` returns `verified: true`
   with method `"spine"`
6. Confirm offline verification works with bundled inclusion proof
7. Submit a revocation envelope and confirm desktop shows a warning

---

## Rollback Plan

1. The `MarketplaceProvenance` additions are backward-compatible: all new fields
   are `Option` with `skip_serializing_if`. Existing feeds without these fields
   continue to work.
2. The `effective_type()` method falls back to `"notary"` for existing entries
   that have `attestation_uid` + `notary_url`.
3. The `marketplace_verify_provenance` command falls back to the existing notary
   path when Spine provenance is not present.
4. New Proofs API endpoints are additive and do not modify existing routes.
5. The `--submit-attestation` flag is opt-in; existing `marketplace_feed_gen`
   usage is unchanged.

Rollback procedure: revert the commit, redeploy. No data migration needed.
Existing feed JSON files remain valid.

---

## Dependencies

| Dependency | Status | Notes |
|-----------|--------|-------|
| `spine` crate | Exists | Envelope signing, checkpoint verification |
| `hush_core::MerkleProof` | Exists | RFC 6962 proof verification |
| Proofs API | Exists | `crates/spine/src/bin/proofs_api.rs` |
| Marketplace feed | Exists | `crates/clawdstrike/src/marketplace_feed.rs` |
| Desktop marketplace commands | Exists | `apps/desktop/src-tauri/src/commands/marketplace.rs` with `marketplace_verify_spine_proof` already doing local Merkle verification |
| NATS JetStream | Deployed | Required for attestation envelope submission |
| Spec 06 (Identity Binding) | Recommended | Attestation envelopes are stronger when issuer identity is bound to SPIFFE SVID, but this spec works without it |
| `@backbay/witness` | Existing (backbay-sdk) | Browser-side Ed25519 + Merkle verification; extend with Spine backend |
| `@backbay/witness-react` | Existing (backbay-sdk) | React verification UI components |

---

## Acceptance Criteria

- [ ] `PolicyAttestation` struct compiles, serializes, and roundtrips through
      `serde_json` with `deny_unknown_fields`
- [ ] `ReviewAttestation` and `PolicyRevocation` similarly roundtrip
- [ ] `MarketplaceProvenance` extended with `type`, `log_id`, `checkpoint_seq`,
      `inclusion_proof` fields -- all backward-compatible
- [ ] `effective_type()` returns `"spine"` when `spine_envelope_hash` is set,
      `"notary"` when legacy fields are set, `None` otherwise
- [ ] `marketplace_feed_gen --submit-attestation` publishes attestation
      envelopes to NATS
- [ ] Proofs API `GET /v1/marketplace/attestation/{bundle_hash}` returns the
      correct attestation envelope
- [ ] Proofs API `GET /v1/marketplace/revocation/{bundle_hash}` returns 404
      when no revocation exists, and the revocation envelope when one does
- [ ] Desktop `marketplace_verify_provenance` returns `verified: true` with
      method `"spine"` when Proofs API is reachable and proof is valid
- [ ] Desktop `marketplace_verify_provenance` returns `verified: true` with
      method `"spine_offline"` when inclusion proof is bundled and valid
- [ ] Desktop shows "Spine Verified" badge with checkpoint info for Spine
      entries
- [ ] Desktop falls back to notary verification for entries without
      `spine_envelope_hash`
- [ ] Revocation checking: desktop displays warning for revoked bundles
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo test --workspace` passes

---

## References

- Marketplace Trust Evolution, Section 1: current trust model analysis
- Marketplace Trust Evolution, Section 3: AegisNet as Notary Replacement
  (proposed attestation schema, verification flow, provenance schema)
- Marketplace Trust Evolution, Section 7: trust delegation chains
  (full chain and portable proof bundle)
- Marketplace Trust Evolution, Section 8: community curation model
  (review attestation schema)
- Marketplace Trust Evolution, Section 9: policy versioning and revocation
  (revocation mechanisms, time-bound attestations)
- Architecture Vision, Section 4.4: decentralized policy marketplace
- Architecture Vision, Section 4.6: marketplace-to-Spine unification mapping
- `crates/clawdstrike/src/marketplace_feed.rs`: `MarketplaceProvenance`, `SignedMarketplaceFeed`
- `apps/desktop/src-tauri/src/commands/marketplace.rs`:
  `marketplace_verify_attestation` (notary path, lines 253-313),
  `marketplace_verify_spine_proof` (Spine path with local Merkle verification, lines 599-690)
- `apps/desktop/src/services/marketplaceProvenanceSettings.ts`: provenance settings
- `crates/spine/src/bin/proofs_api.rs`: existing Proofs API endpoints
- `crates/spine/src/checkpoint.rs`: `verify_witness_signature()`
