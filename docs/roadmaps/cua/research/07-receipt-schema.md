# 07 Receipt Schema & Signing Pipeline

## Scope

CUA event model, hash-chain semantics, signature envelope strategy, verifier behavior, and artifact binding.

## What is already solid

- Hash-chaining action events with pre/post evidence is the correct anti-tamper base.
- Including structured UI context (DOM/AX/UIA) alongside pixel evidence improves audit quality.
- Multi-signer design (gateway + witness) is a good long-term direction.

## Corrections and caveats (2026-02-18)

- Proposed `clawdstrike.receipt.v1` must not bypass existing `SignedReceipt` verification paths in this repo.
- Define canonicalization and deterministic ordering explicitly; this is non-negotiable for cross-language verification.
- Redaction metadata must include enough provenance to prove what was removed and under which rule.

## Clawdstrike-specific integration suggestions

- Keep `SignedReceipt` as root envelope; embed CUA chain and artifact manifest under namespaced metadata.
- Add `receipt_profile` field to distinguish baseline Clawdstrike receipts from CUA-extended receipts.
- Reuse existing engine metadata merge patterns to avoid duplicating signing pipelines.

## Gaps for agent team to fill

- Formal JSON schema with compatibility/versioning policy and migration rules.
- Verifier algorithm spec with mandatory checks and failure codes.
- Re-sign/re-witness workflow when external transparency logs are unavailable.

## Pass #2 reviewer notes (2026-02-18)

- REVIEW-P2-CORRECTION: Preserve current `SignedReceipt` compatibility in all phases; treat alternate envelopes as transport wrappers, not replacement trust roots.
- REVIEW-P2-GAP-FILL: Define normative verifier behavior with explicit error codes and required checks before introducing new witness/transparency dependencies.
- REVIEW-P2-CORRECTION: Performance and size deltas (COSE vs JSON/JWS) should be validated with repo-specific payload fixtures before locking architecture decisions.

## Pass #2 execution criteria

- Any CUA-extended receipt verifies through existing baseline `SignedReceipt` validators.
- Chain verification fails deterministically on reordering, missing events, or altered artifact hashes.
- Redaction provenance fields are sufficient for independent replay and audit explanation.
- Envelope wrappers (if added) round-trip to identical canonical payload semantics.

## Pass #4 reviewer notes (2026-02-18)

- REVIEW-P4-CORRECTION: Schema evolution requires normative compatibility rules and machine-checkable migration tests, not best-effort interpretation.
- REVIEW-P4-GAP-FILL: Define canonical verifier pseudocode and failure taxonomy before introducing additional envelope/transparency layers.
- REVIEW-P4-CORRECTION: Keep receipt trust root singular (`SignedReceipt` baseline) unless a deliberate versioned migration redefines verifier root logic.

## Pass #4 implementation TODO block

- [x] Publish a versioned JSON Schema package for CUA metadata extensions with compatibility tests. *(`./schemas/cua-metadata/schema-package.json`, Pass #7)*
- [x] Implement a reference verifier flow spec with mandatory check order and error codes. *(`./verifier-flow-spec.md`, Pass #7)*
- [x] Add fixture corpus for schema migration (`v1 baseline`, `v1 + cua`, malformed variants). *(`../../../../fixtures/receipts/cua-migration/cases.json`, Pass #7/#8)*
- [x] Add equivalence tests proving envelope wrappers preserve canonical payload semantics. *(`./envelope_semantic_equivalence_suite.yaml`, `../../../../fixtures/receipts/envelope-equivalence/v1/cases.json`, Pass #11)*

## Suggested experiments

- Property tests for event ordering, hash-chain continuity, and canonical serialization stability.
- Cross-language round-trip verification (Rust -> TS -> Python) on CUA-extended receipts.
- Tamper matrix tests: reordered events, modified frame hash, removed redaction record, stale signature.

## Repo anchors

- `crates/libs/clawdstrike/src/engine.rs`
- `docs/src/concepts/design-philosophy.md`

## Primary references

- https://www.rfc-editor.org/rfc/rfc9052
- https://docs.sigstore.dev/
- https://datatracker.ietf.org/doc/html/rfc8785

---

# Deep Research: Receipt Schema Design & Signing Pipeline

> Comprehensive analysis of receipt schemas, hash chains, signing formats, evidence hashing, redaction, multi-signature, artifact storage, append-only ledgers, and verification flows for the CUA gateway.

---

## 1. Existing Clawdstrike Receipt System

### 1.1 Current Schema (receipt v1.0.0)

The existing receipt system in `hush-core` (`crates/libs/hush-core/src/receipt.rs`) defines a single-action attestation envelope:

```rust
pub struct Receipt {
    pub version: String,           // "1.0.0"
    pub receipt_id: Option<String>,
    pub timestamp: String,          // ISO-8601
    pub content_hash: Hash,         // SHA-256 of the content being attested
    pub verdict: Verdict,           // pass/fail + gate_id + scores + threshold
    pub provenance: Option<Provenance>,
    pub metadata: Option<JsonValue>,
}

pub struct SignedReceipt {
    pub receipt: Receipt,
    pub signatures: Signatures,  // signer + optional cosigner
}
```

Key design decisions:

| Decision | Implementation | Notes |
|----------|---------------|-------|
| Signing algorithm | Ed25519 via `ed25519-dalek` | 32-byte public keys, 64-byte signatures |
| Canonicalization | RFC 8785 (JCS) | Implemented in `crates/libs/hush-core/src/canonical.rs` |
| Hash algorithms | SHA-256 + Keccak-256 | SHA-256 for general use, Keccak-256 for Ethereum compatibility |
| Signature model | Primary signer + optional cosigner | `PublicKeySet` supports verification of both |
| Version gating | Fail-closed on unsupported versions | `validate_receipt_version()` rejects anything != "1.0.0" |
| TPM support | `TpmSealedSeedSigner` | Unseals Ed25519 seed from TPM2 on each sign call |
| Merkle trees | RFC 6962-compatible | `leaf_hash = SHA256(0x00 || data)`, `node_hash = SHA256(0x01 || left || right)` |
| Cross-language | Rust + TypeScript + FFI (C) | Identical schema in `packages/sdk/hush-ts/src/receipt.ts` and `crates/libs/hush-ffi/src/receipt.rs` |

### 1.2 Extension Points for CUA

The current receipt is designed for single-action tool-boundary checks. For CUA, we need:

1. **Event streams** -- multiple actions per session, hash-chained together
2. **Rich evidence** -- frame hashes, DOM/A11y snapshots, diff regions
3. **Redaction metadata** -- blur rects, content-based PII markers
4. **Artifact references** -- links to stored frames/video, encrypted storage
5. **Gateway identity** -- build attestation, platform info, runtime type
6. **Session context** -- session/run IDs, policy mode

Per the correction above: CUA extensions should be embedded under namespaced `metadata` within the existing `SignedReceipt` envelope, using a `receipt_profile` field to distinguish CUA-extended receipts from baseline receipts.

### 1.3 Signer Abstraction

The `Signer` trait (`crates/libs/hush-core/src/signing.rs`) already provides the right abstraction:

```rust
pub trait Signer {
    fn public_key(&self) -> PublicKey;
    fn sign(&self, message: &[u8]) -> Result<Signature>;
}
```

Current implementations: `Keypair` (in-memory Ed25519), `TpmSealedSeedSigner` (TPM2-backed).

For CUA, additional implementations: `CoseSign1Signer`, `EnclaveProxySigner`, `ThresholdSigner`.

---

## 2. Hash Chain Patterns

### 2.1 Linear Hash Chains (prev_event_hash)

Each event includes the hash of the previous event:

```
event[0].event_hash = H(canonicalize(event[0]))
event[0].prev_event_hash = H("genesis" || session_id)
event[n].prev_event_hash = event[n-1].event_hash
```

Properties: tamper-evident, append-only, verifiable ordering, O(n) verification.

The canonical JSON of each event should include all evidence hashes but NOT raw evidence blobs, keeping the chain compact while binding evidence integrity.

### 2.2 Merkle Tree Aggregation

The existing `MerkleTree` in `hush-core` (`crates/libs/hush-core/src/merkle.rs`) implements RFC 6962-compatible Certificate Transparency-style trees with `leaf_hash = SHA256(0x00 || data)` and `node_hash = SHA256(0x01 || left || right)`.

Two uses for CUA:
1. **Session checkpoint trees** -- periodically build Merkle tree from event hashes, sign root, provide O(log n) inclusion proofs
2. **Evidence bundle trees** -- Merkle root over all evidence artifacts for a single event

### 2.3 RFC 9162 -- Certificate Transparency v2

RFC 9162 defines Signed Tree Heads, inclusion proofs, and consistency proofs. The Clawdstrike Merkle implementation already follows RFC 6962 conventions, making it CT-compatible at the tree-construction layer. Algorithm and signature-suite choices should be validated against the target log/verifier implementation profile.

### 2.4 Recommended Approach

Hybrid: linear hash chain for streaming verification + periodic Merkle checkpoints for O(log n) proofs + final session Merkle root for session-level attestation.

---

## 3. Signing Formats

### 3.1 COSE Sign1 (RFC 9052)

CBOR-based signing envelope. Structure: `[protected_headers, unprotected_headers, payload, signature]`, CBOR tag 18.

Advantages: binary compactness (often smaller than JSON in practice), standardized algorithm negotiation, SCITT compatibility, emerging COSE Hash Envelope draft for content-addressed payloads.

Libraries: `coset` (Rust), `go-cose` (Go), `cose-js` (TypeScript), `pycose` (Python).

### 3.2 JWS (RFC 7515)

JSON-based signing. Structure: `{protected, payload, signature}` (all base64url).

Advantages: native JSON ecosystem, wide library support, human-readable, compact serialization available.

### 3.3 Comparison and Recommendation

| Dimension | COSE Sign1 | JWS |
|-----------|-----------|-----|
| Wire size | Smaller (CBOR) | Larger (base64 JSON) |
| Ecosystem | Growing (IoT, SCITT, supply chain) | Mature (web, OAuth, JWT) |
| Browser verification | Requires CBOR library | Native JSON parsing |
| Clawdstrike alignment | New format | Closer to existing JSON receipts |

**Recommendation**: Keep current Clawdstrike JSON receipt verification as the canonical baseline. Add COSE and/or JWS wrappers incrementally where interoperability demands it, with strict round-trip equivalence tests.

### 3.4 Existing Signing vs COSE/JWS

The current custom envelope (hex-encoded Ed25519 signatures in JSON) lacks algorithm negotiation, key ID headers, and standard verification tooling. For CUA, prioritize compatibility-first evolution: retain existing format support while layering standards-based envelopes behind explicit versioned profiles.

---

## 4. Evidence Hashing

### 4.1 SHA-256 for Frame Integrity

Every frame capture hashed with SHA-256. Already used throughout Clawdstrike, compatible with transparency log conventions.

### 4.2 Perceptual Hashing for Similarity

pHash (DCT-based, robust against compression/resizing) and dHash (gradient-based, faster) provide "similar but not identical" detection. Output: 64-bit hash, Hamming distance for similarity.

Use in CUA: cryptographic hash for tamper detection, perceptual hash for TOCTOU validation and audit deduplication.

Libraries: `img_hash` (Rust), `imagehash` (Python), `sharp` (Node.js).

### 4.3 DOM/A11y Tree Canonical Hashing

Use RFC 8785 (JCS) canonicalization (already implemented in `crates/libs/hush-core/src/canonical.rs`) on normalized DOM/A11y snapshots, then SHA-256 the canonical form. Produces stable, deterministic, cross-language-verifiable hashes.

### 4.4 Evidence Bundle Hashing

Merkle root over all evidence artifacts for a single event. Allows individual artifact verification via inclusion proofs and selective redaction while proving remaining artifacts are intact.

---

## 5. Redaction Design

### 5.1 Redaction-Aware Hashing

Core principle: **hash before redact, store redaction metadata alongside the hash**. Original frame -> SHA-256 hash in receipt -> apply redactions -> store redacted frame in artifacts -> store redaction metadata (rect, reason, detection_method, pre_redaction_hash) in receipt.

### 5.2 Blur Rect Regions

```json
"redactions": [{
  "kind": "blur_rect",
  "reason": "password_field",
  "rect": { "x": 120, "y": 220, "w": 540, "h": 60 },
  "detection_method": "dom_selector",
  "pre_redaction_hash": "sha256:..."
}]
```

The `pre_redaction_hash` enables verifiers with the original to confirm redaction correctness.

### 5.3 Content-Based PII Detection

DOM selector matching (password inputs, credit card fields), OCR + regex (SSN/CC patterns in screenshots), A11y tree role matching (textbox in sensitive contexts). Detection method recorded for audit trail.

### 5.4 Privacy-Preserving Evidence

Frame-level encryption (encrypt entire frame with evidence encryption key), selective disclosure (Merkle tree over frame regions with redacted leaves replaced by hashes), time-locked encryption for delayed-access audit.

---

## 6. Multi-Signature

### 6.1 Gateway + Witness Model

Gateway signs every event (key in TPM/Enclave). Witness independently validates and countersigns. Provides non-repudiation even if gateway is compromised.

### 6.2 Threshold Signatures

For high-assurance: FROST protocol (Schnorr threshold, compatible with Ed25519). MVP: multi-sig aggregation (multiple independent Ed25519 signatures, already partially supported by cosigner mechanism).

### 6.3 Signature Aggregation for Bandwidth

Checkpoint signatures (sign Merkle root every N events) recommended for MVP. Per-event signatures as configurable high-assurance mode.

---

## 7. Artifact Storage

### 7.1 Separation of Blob Storage from Receipt Ledger

Receipts (metadata, append-only, compact, tamper-evident) stored separately from artifacts (evidence blobs, potentially encrypted, referenced by hash). Enables independent retention policies, storage tiers, selective retrieval, and independent encryption.

### 7.2 Encryption Patterns

**age encryption**: simple file encryption, X25519 keypairs, good for local/self-hosted. **KMS Envelope Encryption**: generate DEK locally, encrypt artifact with DEK (AES-256-GCM), encrypt DEK with KEK via KMS. Only 32-byte DEK goes to KMS (fast, cheap). Key rotation rotates KEK without re-encrypting artifacts.

### 7.3 Content-Addressable Storage (CAS)

Store artifacts by hash (`cas://sha256:abc123/pre_000001.png`). Automatic deduplication, free integrity verification, works with any backend.

---

## 8. Append-Only Ledger

### 8.1 Implementation Options

| Option | Pros | Cons |
|--------|------|------|
| SQLite WAL | Single-file, ACID, fast reads | Single-writer |
| Append-only JSONL | Simplest, fast append | No indexing |
| Rekor (Sigstore) | Witnessing, inclusion proofs, public auditability | External dependency |
| PostgreSQL + triggers | Familiar, queryable | Not inherently tamper-evident |

### 8.2 Sigstore Rekor Integration

Rekor v2 (GA 2025) provides append-only tamper-evident log with tile-backed transparency, witnessing, inclusion/consistency proofs, REST API. Gateway submits signed receipt to Rekor, receives log index + inclusion proof + signed tree head, stores metadata in receipt.

### 8.3 Compaction and Retention

Checkpoint compaction (archive events before previous checkpoint), session finalization (final Merkle root + summary), configurable retention (receipts indefinitely, artifacts 30/90/365 days).

---

## 9. Receipt Verification Flow

### 9.1 Offline Verification

Parse receipt -> validate schema version (fail-closed) -> compute canonical JSON -> verify primary signature -> verify cosigner -> verify hash chain links -> verify Merkle proofs. Already implemented for single receipts; extend for CUA chain and checkpoint verification.

### 9.2 Online Verification

Additionally: fetch STH from Rekor -> verify inclusion proof -> verify consistency -> check gateway key in discovery service.

### 9.3 Key Discovery

JWKS endpoint (`.well-known/jwks.json`) for MVP. DNS TXT records, transparency log key registration, and COSE key sets for later phases.

---

## 10. Schema Versioning

### 10.1 Compatibility Strategy

Major version: breaking changes, verifier MUST reject unknown. Minor version: new optional fields, verifier SHOULD accept. Patch: clarifications only, always accepted. Use `$schema` URL for identification.

### 10.2 Migration Path

Receipt schema v1.0.0 (current single-action) -> CUA-extended receipts use `receipt_profile: "cua.v1"` field within existing `SignedReceipt` metadata. A CUA receipt with a single event and no evidence is equivalent to a v1.0.0 receipt.

---

## 11. Comparison with Existing Attestation Formats

### 11.1 in-toto / SLSA

in-toto's subject/predicate model is analogous to receipt/evidence. SLSA provenance uses in-toto as delivery medium. Both are designed for software supply chain (build provenance), not real-time UI interaction.

### 11.2 SCITT

IETF working group defining transparent supply chain claims. Uses COSE Sign1, transparent registry (append-only ledger), and notarization. Architecture highly aligned with CUA receipt requirements. Draft expires April 2026.

### 11.3 Comparison Table

| Dimension | Clawdstrike CUA | in-toto/SLSA | SCITT |
|-----------|-----------------|--------------|-------|
| Domain | UI interaction attestation | Software supply chain | Generic supply chain |
| Signing | Ed25519 (COSE/JWS) | DSSE | COSE Sign1 |
| Evidence model | Frames, DOM, A11y, diffs | Build artifacts, SBOMs | Generic claims |
| Real-time | Yes | Batch | Batch |
| Redaction | First-class | N/A | Not specified |

---

## 12. Refined Receipt Schema

Per integration suggestions: CUA extensions embedded within existing `SignedReceipt` via namespaced metadata, with `receipt_profile` field to distinguish.

### 12.1 CUA Metadata Extension

```json
{
  "receipt": {
    "version": "1.0.0",
    "receipt_id": "sess_01HXYZ_final",
    "timestamp": "2026-02-17T21:45:33Z",
    "content_hash": "sha256:...",
    "verdict": { "passed": true, "gate_id": "cua-guardrail" },
    "provenance": {
      "clawdstrike_version": "0.2.0",
      "provider": "cua-gateway",
      "policy_hash": "sha256:...",
      "ruleset": "cua-default"
    },
    "metadata": {
      "receipt_profile": "cua.v1",
      "cua": {
        "gateway": {
          "gateway_id": "gw-prod-01",
          "build": { "git_commit": "abc123", "binary_digest": "sha256:...", "config_digest": "sha256:..." },
          "platform": { "host_os": "linux", "arch": "x86_64", "runtime_type": "microvm", "runtime_engine": "firecracker" },
          "attestation": { "type": "nitro_enclave", "evidence_ref": "sha256:...", "verified_at": "2026-02-17T21:33:12Z" },
          "signing": { "algorithm": "Ed25519", "key_id": "kid:gw-prod-01", "key_protection": "tpm2" }
        },
        "session": {
          "session_id": "sess_01HXYZ",
          "run_id": "run_01HXYZ",
          "agent_id": "agent_01ABC",
          "policy_profile": "prod-guardrail",
          "mode": "guardrail",
          "started_at": "2026-02-17T21:30:00Z",
          "ended_at": "2026-02-17T21:45:33Z",
          "event_count": 42,
          "violation_count": 1,
          "approval_count": 2
        },
        "chain": {
          "genesis_hash": "sha256:...",
          "final_event_hash": "sha256:...",
          "final_merkle_root": "sha256:...",
          "total_events": 42,
          "checkpoints": [
            { "after_sequence": 100, "merkle_root": "sha256:...", "tree_size": 100, "ts": "2026-02-17T21:35:00Z" }
          ]
        },
        "events_ref": "cas://sha256:.../events.jsonl",
        "artifacts": {
          "storage": "s3",
          "bucket": "clawdstrike-evidence-prod",
          "bundle_digest": "sha256:...",
          "encryption": { "scheme": "kms-envelope", "algorithm": "AES-256-GCM", "key_ref": "arn:aws:kms:..." }
        },
        "transparency_log": {
          "provider": "rekor",
          "log_id": "sha256:...",
          "log_index": 12345678,
          "inclusion_proof": { "root_hash": "sha256:...", "tree_size": 99999999 }
        },
        "summary": {
          "decisions": { "allow": 39, "block": 1, "needs_approval": 2 },
          "evidence_stats": { "total_frames": 84, "total_redactions": 5 }
        }
      }
    }
  },
  "signatures": {
    "signer": "hex-ed25519-gateway-sig",
    "cosigner": "hex-ed25519-witness-sig"
  }
}
```

### 12.2 Per-Event Record (in events JSONL)

```json
{
  "event_id": "evt_00000001",
  "sequence": 1,
  "ts": "2026-02-17T21:30:05.123Z",
  "type": "computer.use",
  "action": {
    "kind": "click",
    "pointer": { "x": 812, "y": 614, "button": "left", "clicks": 1 },
    "intent": "open_settings",
    "target_hint": { "window_title": "Browser", "app_id": "chromium", "url": "https://example.com/account" }
  },
  "policy": {
    "decision": "allow",
    "rule_ids": ["ui.allow.browser.example.com"],
    "guard_results": [
      { "guard": "egress_allowlist", "passed": true },
      { "guard": "computer_use", "passed": true }
    ],
    "evaluation_ms": 2
  },
  "evidence": {
    "pre": { "frame_hash": "sha256:...", "frame_phash": "phash:0x...", "artifact_ref": "cas://sha256:abc123/pre_000001.png" },
    "post": { "frame_hash": "sha256:...", "frame_phash": "phash:0x...", "artifact_ref": "cas://sha256:def456/post_000001.png" },
    "diff": { "diff_hash": "sha256:...", "pixel_change_pct": 12.5, "changed_regions": [{ "x": 600, "y": 540, "w": 420, "h": 180 }] },
    "ui_context": {
      "browser": { "dom_snapshot_hash": "sha256:...", "url": "https://example.com/account", "selector": "button[data-testid='settings']" },
      "accessibility": { "ax_tree_hash": "sha256:...", "target_node": { "role": "button", "name": "Settings" } }
    },
    "evidence_root": "sha256:...",
    "redactions": [{
      "kind": "blur_rect", "reason": "password_field",
      "rect": { "x": 120, "y": 220, "w": 540, "h": 60 },
      "detection_method": "dom_selector", "pre_redaction_hash": "sha256:..."
    }]
  },
  "chain": { "prev_event_hash": "sha256:0000...0000", "event_hash": "sha256:..." }
}
```

### 12.3 Signing Pipeline Flow

```
1. Agent sends computer.use request
2. Gateway evaluates policy
3. If allowed, execute action in UI runtime
4. Capture evidence (pre/post frames, DOM, A11y)
5. Apply redactions (policy-driven + content-detected)
6. Compute evidence hashes (SHA-256, pHash, JCS for structured data)
7. Build event record with hash chain link
8. If checkpoint interval reached, build Merkle tree + sign root
9. Store evidence artifacts (encrypted CAS)
10. On session end: build final Merkle tree, create SignedReceipt with CUA metadata
11. Submit to Rekor, store in append-only ledger
```

---

## 13. Implementation Priorities

### Phase A: MVP

- CUA event schema as Rust structs with serde
- Linear hash chain (prev_event_hash)
- CUA metadata within existing `SignedReceipt` envelope
- SHA-256 frame hashing, basic redaction metadata
- Single-signer Ed25519, SQLite WAL ledger, local CAS

### Phase B: Hardening

- Merkle checkpoints, perceptual hashing, DOM/A11y canonical hashing
- KMS envelope encryption, COSE Sign1, witness cosigning, Rekor integration

### Phase C: Enterprise

- Threshold signatures (FROST), TEE-backed signing, SCITT compatibility
- Time-locked encryption, key transparency, formal verification of chain properties

---

## Primary references

- [RFC 9052 -- COSE Structures and Process](https://www.rfc-editor.org/rfc/rfc9052)
- [RFC 9162 -- Certificate Transparency v2](https://datatracker.ietf.org/doc/rfc9162/)
- [RFC 8785 -- JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
- [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/)
- [Rekor v2 GA](https://blog.sigstore.dev/rekor-v2-ga/)
- [SCITT Architecture](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/)
- [SLSA Attestation Model](https://slsa.dev/attestation-model)
- [in-toto Attestation Framework](https://github.com/in-toto/attestation)
- Clawdstrike source: `crates/libs/hush-core/src/receipt.rs`, `signing.rs`, `merkle.rs`, `canonical.rs`, `tpm.rs`
- Clawdstrike source: `packages/sdk/hush-ts/src/receipt.ts`
