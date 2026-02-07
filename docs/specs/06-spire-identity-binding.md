# Spec 06: SPIFFE SVID / Spine Issuer Identity Binding

> **Status:** Draft | **Date:** 2026-02-07
> **Effort:** ~8 engineer-days
> **Phase:** B (Cross-Layer Proofs) | **Priority:** High
> **Dependencies:** Spine crate (exists), SPIRE deployment (exists on EKS), Tetragon (Phase A)

---

## Summary / Objective

Bind SPIFFE workload identities (X.509 SVIDs issued by SPIRE) to Aegis Spine
issuer identities (`aegis:ed25519:<hex>`). This enables two new fact schemas --
`node_attestation.v1` and `runtime_proof.v1` -- that cryptographically link
what a workload _is_ (SPIFFE identity) with what it _did_ (Tetragon kernel
events) and what it _was allowed to do_ (ClawdStrike guard decisions), all
recorded in the Spine append-only log.

The end result: a verifiable proof chain that any auditor can check, answering
"this binary with this hash ran as this workload identity in this Kubernetes pod
and its guard decisions are recorded in this Merkle tree."

---

## Current State

### SPIRE Deployment

SPIRE 0.13.0 is already deployed on EKS (namespace `spire-system`, ArgoCD app
`spire`). The trust domain is `aegis.local`. SPIRE issues X.509 SVIDs to
workloads via the SPIFFE CSI Driver, with node attestation (AWS IID) and
Kubernetes workload attestation (service account + namespace binding).

SPIFFE IDs follow the format:
```
spiffe://aegis.local/ns/<namespace>/sa/<service-account>
```

### Spine Crate

The `spine` crate (`crates/spine/src/`) provides:

- **`envelope.rs`**: `build_signed_envelope()` creates envelopes with
  `issuer: "aegis:ed25519:<hex>"`, monotonic `seq`, `prev_envelope_hash`
  chaining, and Ed25519 signatures over RFC 8785 canonical JSON.
- **`trust.rs`**: `TrustBundle` with allowlists for log IDs, witness node IDs,
  receipt signer node IDs, kernel-loader signer node IDs, enforcement tier
  requirements, and witness quorum.
- **`checkpoint.rs`**: Checkpoint statements with domain-separated witness
  co-signatures (`AegisNetCheckpointHashV1`).

Key observation: The `TrustBundle` already has
`allowed_kernel_loader_signer_node_ids` and `require_kernel_loader_signatures`,
anticipating kernel-level identity integration but with no implementation yet.

### Identity Gap

Today, Spine issuers are bare Ed25519 public keys with no binding to a workload
identity system. A node's `aegis:ed25519:<hex>` key tells you _who signed_ but
not _what workload produced the signature_. There is no link from a Spine issuer
to a Kubernetes pod, service account, namespace, or container image.

---

## Target State

After this spec is implemented:

1. Every Spine-participating service (checkpointer, witness, proofs-api, hushd,
   tetragon-nats-bridge) publishes a `node_attestation.v1` fact that binds its
   Spine Ed25519 identity to its SPIFFE SVID, Kubernetes metadata, and optional
   transport endpoints (Reticulum destination hash for future Plane A-R).

2. The tetragon-nats-bridge publishes `runtime_proof.v1` facts combining
   Tetragon kernel observations (binary path, IMA hash, process ancestry,
   capabilities, namespaces) with SPIFFE identity and AegisNet envelope
   references.

3. The `TrustBundle` validates `node_attestation.v1` facts and can enforce
   that only attested issuers (those with a valid node attestation in the log)
   are trusted for receipt signing and kernel-loader signing.

4. The Proofs API (`proofs_api.rs`) exposes a new endpoint for querying node
   attestations by issuer ID.

---

## Implementation Plan

### Step 1: Define `node_attestation.v1` Fact Schema (Spine crate)

Create a new module `crates/spine/src/attestation.rs` defining the typed
fact structure:

```rust
// crates/spine/src/attestation.rs

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const NODE_ATTESTATION_SCHEMA: &str = "clawdstrike.spine.fact.node_attestation.v1";
pub const RUNTIME_PROOF_SCHEMA: &str = "clawdstrike.spine.fact.runtime_proof.v1";

/// Node attestation fact binding a Spine issuer to system identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAttestation {
    pub schema: String,
    pub fact_id: String,
    /// Spine node ID: "aegis:ed25519:<hex>"
    pub node_id: String,
    /// System-level attestation data.
    pub system_attestation: SystemAttestation,
    /// Optional transport bindings (Reticulum, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transports: Option<TransportBindings>,
    /// ISO-8601 timestamp.
    pub issued_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemAttestation {
    /// SPIFFE ID: "spiffe://aegis.local/ns/<ns>/sa/<sa>"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    /// SHA-256 of the X.509 SVID certificate (DER-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub svid_cert_hash: Option<String>,
    /// Trust domain from the SVID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<String>,
    /// Kubernetes metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<KubernetesMetadata>,
    /// Binary path of the attesting process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary: Option<String>,
    /// IMA hash of the binary (if Tetragon provides it).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_hash_ima: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KubernetesMetadata {
    pub namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_image_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportBindings {
    /// Reticulum transport binding (for Plane A-R).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reticulum: Option<ReticulumBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReticulumBinding {
    pub profile: String,
    pub destination_hash: String,
    #[serde(default)]
    pub announce_period_secs: u64,
    #[serde(default)]
    pub supports: Vec<String>,
}
```

Source: Architecture Vision Section 2.1 (SPIRE at L0), Tetragon Integration
Section 6.2 (runtime proof envelope), Reticulum SDR Transport Section 6.2
(identity binding Model A).

### Step 2: Define `runtime_proof.v1` Fact Schema

In the same `attestation.rs` module, add the runtime proof structure that
combines Tetragon kernel data with SPIFFE identity:

```rust
/// Runtime proof combining kernel-level evidence with workload identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProof {
    pub schema: String,
    pub fact_id: String,
    pub proof_type: String, // "execution", "file_access", "network"
    pub timestamp: String,

    /// Kernel-level execution evidence from Tetragon.
    pub execution: ExecutionEvidence,
    /// Workload identity from SPIRE.
    pub identity: WorkloadIdentity,
    /// Kubernetes context.
    pub kubernetes: KubernetesMetadata,
    /// Network enforcement context (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_enforcement: Option<NetworkEnforcement>,
    /// Cross-reference chain linking all layers.
    pub attestation_chain: AttestationChain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEvidence {
    pub binary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_hash_ima: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
    pub pid: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u64>,
    pub exec_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_exec_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadIdentity {
    pub spiffe_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub svid_serial: Option<String>,
    pub trust_domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkEnforcement {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tetragon_policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cilium_network_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_connections: Vec<ObservedConnection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedConnection {
    pub daddr: String,
    pub dport: u16,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationChain {
    /// Tetragon exec_id linking to the kernel event.
    pub tetragon_exec_id: String,
    /// SHA-256 of the SPIRE SVID certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spire_svid_hash: Option<String>,
    /// Hash of the ClawdStrike guard receipt (if a guard evaluated this action).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clawdstrike_receipt_hash: Option<String>,
    /// Envelope hash of this proof in the AegisNet/Spine log.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aegisnet_envelope_hash: Option<String>,
}
```

Source: Tetragon Integration Section 6.2 (full JSON example), Architecture
Vision Section 3.1 Flow 4 (cross-layer identity attestation).

### Step 3: Builder Helpers for Envelope Construction

Add convenience functions to build signed envelopes wrapping these facts:

```rust
// In crates/spine/src/attestation.rs

impl NodeAttestation {
    pub fn to_fact_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

impl RuntimeProof {
    pub fn to_fact_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}
```

Wire into `crates/spine/src/lib.rs`:

```rust
pub mod attestation;
pub use attestation::{
    NodeAttestation, RuntimeProof, SystemAttestation, KubernetesMetadata,
    WorkloadIdentity, ExecutionEvidence, AttestationChain,
    NODE_ATTESTATION_SCHEMA, RUNTIME_PROOF_SCHEMA,
};
```

### Step 4: TrustBundle Enhancement

Extend `TrustBundle` in `crates/spine/src/trust.rs` with a new field for
attested issuer enforcement:

```rust
// Add to TrustBundle struct:

/// When true, receipt signers must have a valid node_attestation.v1 fact
/// in the log with a SPIFFE ID. Verification requires querying the log.
#[serde(default)]
pub require_attested_issuers: bool,
```

Add a validation rule in `validate()`:

```rust
if self.require_attested_issuers && self.allowed_receipt_signer_node_ids.is_empty() {
    return Err(Error::InvalidTrustBundle(
        "require_attested_issuers requires allowed_receipt_signer_node_ids".into(),
    ));
}
```

Add a method for enforcement tier validation that includes the new kernel
attestation tiers:

```rust
/// Enforcement tiers, ordered by strength.
pub const ENFORCEMENT_TIERS: &[&str] = &[
    "best_effort",
    "daemon_enforced",
    "linux_kernel_enforced",
    "linux_kernel_attested",
];
```

Source: Tetragon Integration Section 6.3 (enforcement tier model), Architecture
Vision Section 4.1 (enforcement tier table).

### Step 5: Proofs API -- Node Attestation Query Endpoint

Add a new endpoint to `crates/spine/src/bin/proofs_api.rs`:

```
GET /v1/node-attestations/by-issuer/{issuer_hex}
```

This queries the `CLAWDSTRIKE_FACT_INDEX` KV bucket for keys matching
`node_attestation.<issuer_hex>` and returns the latest node attestation
envelope for that issuer.

Implementation:

```rust
async fn v1_node_attestation_by_issuer(
    State(state): State<Arc<AppState>>,
    Path(issuer_hex): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let normalized = normalize_hash_param("issuer_hex", &issuer_hex)?;
    let key = format!("node_attestation.{normalized}");
    let Some(envelope_hash) = kv_get_utf8(&state.fact_index_kv, &key).await? else {
        return Err(ApiError::not_found("no node attestation for issuer"));
    };
    v1_envelope_by_hash(State(state), Path(envelope_hash)).await
}
```

Add the route:

```rust
.route(
    "/v1/node-attestations/by-issuer/{issuer_hex}",
    get(v1_node_attestation_by_issuer),
)
```

### Step 6: Checkpointer Fact Indexing

The checkpointer (`crates/spine/src/bin/checkpointer.rs` or equivalent) must
index `node_attestation.v1` and `runtime_proof.v1` facts. When a new envelope
arrives with one of these schemas, write to the fact index KV:

For `node_attestation.v1`:
```
Key:   node_attestation.<issuer_pubkey_hex>
Value: <envelope_hash>
```

For `runtime_proof.v1`:
```
Key:   runtime_proof.<exec_id_sha256>
Value: <envelope_hash>
```

Where `<exec_id_sha256>` is `sha256(fact.execution.exec_id)` normalized to
lowercase hex. This allows querying runtime proofs by Tetragon exec_id.

### Step 7: SVID Reading Utility

Create a small utility module for reading SPIRE SVIDs from the filesystem
(the SPIFFE CSI Driver mounts them into pods):

File: `crates/spine/src/spiffe.rs`

```rust
use std::path::Path;

use crate::error::{Error, Result};

/// Default SVID mount path from SPIFFE CSI Driver.
pub const DEFAULT_SVID_PATH: &str = "/var/run/spire/agent/svid.pem";
pub const DEFAULT_BUNDLE_PATH: &str = "/var/run/spire/agent/bundle.pem";

/// Read SPIFFE ID from an X.509 SVID PEM file.
///
/// Extracts the URI SAN (Subject Alternative Name) matching `spiffe://`.
pub fn read_spiffe_id(svid_path: impl AsRef<Path>) -> Result<String> {
    let pem_bytes = std::fs::read(&svid_path).map_err(|e| {
        Error::Io(format!("failed to read SVID at {}: {}", svid_path.as_ref().display(), e))
    })?;
    // Parse PEM, extract first certificate, read URI SANs
    // Return the first SAN starting with "spiffe://"
    // Implementation uses x509-parser or rustls-pki-types
    todo!("parse X.509 SVID and extract SPIFFE URI SAN")
}

/// Compute SHA-256 hash of the DER-encoded SVID certificate.
pub fn svid_cert_hash(svid_path: impl AsRef<Path>) -> Result<String> {
    let pem_bytes = std::fs::read(&svid_path).map_err(|e| {
        Error::Io(format!("failed to read SVID at {}: {}", svid_path.as_ref().display(), e))
    })?;
    // Parse PEM, extract DER bytes, SHA-256 hash
    todo!("hash DER-encoded certificate")
}
```

This module depends on an X.509 parsing crate. Recommended: `x509-parser`
(MIT-licensed, already commonly used in the Rust ecosystem). Add to
`crates/spine/Cargo.toml`:

```toml
[dependencies]
x509-parser = "0.16"
pem = "3"
```

### Step 8: Integration Tests

Create `crates/spine/tests/attestation_test.rs`:

1. **`test_node_attestation_roundtrip`**: Build a `NodeAttestation`, wrap it in
   a `SignedEnvelope`, verify the envelope, extract the fact, deserialize back
   to `NodeAttestation`, and assert all fields match.

2. **`test_runtime_proof_roundtrip`**: Same pattern for `RuntimeProof`.

3. **`test_node_attestation_rejects_unknown_fields`**: Ensure
   `deny_unknown_fields` rejects extra JSON keys (fail-closed).

4. **`test_trust_bundle_require_attested_issuers`**: Validate that the new
   `require_attested_issuers` field interacts correctly with
   `allowed_receipt_signer_node_ids`.

5. **`test_enforcement_tier_ordering`**: Verify that
   `receipt_enforcement_tier_allowed` correctly handles the four tiers.

---

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `crates/spine/src/attestation.rs` | **Create** | `NodeAttestation`, `RuntimeProof`, and related types |
| `crates/spine/src/spiffe.rs` | **Create** | SVID reading utility (SPIFFE ID extraction, cert hashing) |
| `crates/spine/src/lib.rs` | **Modify** | Add `pub mod attestation; pub mod spiffe;` and re-exports |
| `crates/spine/src/trust.rs` | **Modify** | Add `require_attested_issuers` field, enforcement tier constants |
| `crates/spine/src/bin/proofs_api.rs` | **Modify** | Add `/v1/node-attestations/by-issuer/{issuer_hex}` endpoint |
| `crates/spine/Cargo.toml` | **Modify** | Add `x509-parser` and `pem` dependencies |
| `crates/spine/tests/attestation_test.rs` | **Create** | Integration tests for both fact schemas |

---

## Testing Strategy

### Unit Tests

- Serde roundtrip for `NodeAttestation` and `RuntimeProof` (serialize -> canonical JSON -> deserialize)
- `deny_unknown_fields` rejection for both types
- `TrustBundle` validation with `require_attested_issuers`
- Enforcement tier allowlist filtering

### Integration Tests

- Full envelope lifecycle: build `NodeAttestation` fact -> wrap in `SignedEnvelope` -> verify -> extract fact
- Same for `RuntimeProof`
- Proofs API endpoint returns node attestation by issuer (requires NATS test harness)
- SVID reading utility (mock PEM files with known SPIFFE URI SANs)

### Manual Validation

- Deploy to dev EKS cluster
- Verify SPIRE CSI mounts SVIDs into Spine service pods
- Confirm `node_attestation.v1` envelopes appear in NATS
- Confirm Proofs API returns attestations by issuer
- Verify TrustBundle enforcement: reject receipts from un-attested issuers when `require_attested_issuers: true`

---

## Rollback Plan

1. The new `attestation.rs` and `spiffe.rs` modules are additive -- removing
   them requires only deleting the files and the `pub mod` lines in `lib.rs`.
2. The `require_attested_issuers` field defaults to `false`, so existing
   TrustBundle JSON files remain valid without modification.
3. The new Proofs API endpoint is a new route that does not affect existing
   routes.
4. The fact index keys (`node_attestation.*`, `runtime_proof.*`) are new KV
   entries that do not conflict with existing keys.

Rollback procedure: revert the commit, redeploy. No data migration required.

---

## Dependencies

| Dependency | Status | Notes |
|-----------|--------|-------|
| `spine` crate | Exists | `crates/spine/src/` -- envelope, trust, checkpoint |
| SPIRE 0.13.0 | Deployed | `spire-system` namespace, trustDomain `aegis.local` |
| NATS JetStream | Deployed | `aegisnet` namespace, 3-replica cluster |
| Tetragon | Phase A | Required for `runtime_proof.v1` (kernel evidence). `node_attestation.v1` can be implemented without Tetragon. |
| `x509-parser` crate | New dependency | MIT-licensed, for SVID parsing |
| Spec 01 (TracingPolicy CRDs) | Phase A | Provides Tetragon events that feed into runtime proofs |

---

## Acceptance Criteria

- [ ] `NodeAttestation` struct compiles, serializes to canonical JSON, and
      roundtrips through `serde_json`
- [ ] `RuntimeProof` struct compiles, serializes to canonical JSON, and
      roundtrips through `serde_json`
- [ ] Both structs reject unknown fields (`deny_unknown_fields`)
- [ ] `build_signed_envelope()` with a `NodeAttestation` fact produces a valid
      envelope that passes `verify_envelope()`
- [ ] `build_signed_envelope()` with a `RuntimeProof` fact produces a valid
      envelope that passes `verify_envelope()`
- [ ] `TrustBundle` with `require_attested_issuers: true` validates correctly
      (requires `allowed_receipt_signer_node_ids` to be non-empty)
- [ ] `TrustBundle` with `require_attested_issuers: false` (default) is
      backward-compatible with existing JSON files
- [ ] ENFORCEMENT_TIERS constant includes all four tiers: `best_effort`,
      `daemon_enforced`, `linux_kernel_enforced`, `linux_kernel_attested`
- [ ] Proofs API `GET /v1/node-attestations/by-issuer/{issuer_hex}` returns a
      valid node attestation envelope (integration test)
- [ ] SVID reading utility extracts a `spiffe://` URI SAN from a test PEM file
- [ ] `cargo clippy --workspace -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] All new code has `#[serde(deny_unknown_fields)]` on struct definitions

---

## References

- Architecture Vision, Section 2.1 (SPIRE at L0): layer architecture diagram
- Architecture Vision, Section 3.1 Flow 4: cross-layer identity attestation flow
- Architecture Vision, Section 4.1: enforcement tiers table
- Tetragon Integration, Section 6.2: runtime proof envelope JSON example
- Tetragon Integration, Section 6.3: enforcement tier model
- Reticulum SDR Transport, Section 6.2: identity binding Model A (separate keys)
- Reticulum SDR Transport, Section 6.1: the two identity systems
- `crates/spine/src/envelope.rs`: issuer format, signing mechanics
- `crates/spine/src/trust.rs`: TrustBundle with existing kernel-loader fields
- `crates/spine/src/checkpoint.rs`: checkpoint and witness signature protocol
- `crates/spine/src/bin/proofs_api.rs`: existing API endpoints and KV patterns
