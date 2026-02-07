# Spec #13: EAS On-Chain Anchoring (Base L2)

> Ethereum Attestation Service integration for blockchain-backed timestamps
> on ClawdStrike policy attestations, curator actions, and key rotations.
>
> **Status:** Draft | **Date:** 2026-02-07
> **Effort Estimate:** 5-7 engineer-days
> **Branch:** `feat/sdr-execution`

---

## 1. Summary / Objective

Integrate the **Ethereum Attestation Service (EAS)** on **Base L2** as an
optional anchoring layer for ClawdStrike marketplace attestations. EAS provides
blockchain-backed timestamps and revocation capability for high-value
attestations -- policy approvals, key rotations, feed signing events, and
emergency revocations -- at negligible cost (~$0.10-$0.50/month for batched
operations).

This builds on top of the existing AegisNet Merkle proof infrastructure. EAS
anchoring is **additive and optional**: AegisNet remains the primary
verification mechanism. EAS provides an independent, censorship-resistant
timestamp anchor for organizations that require blockchain-level assurance.

**Key deliverables:**

1. EAS schema registration on Base L2 for ClawdStrike attestation types
2. Batched on-chain timestamp service (1 tx per batch of N attestations)
3. Off-chain attestation creation with on-chain timestamp anchoring
4. Client-side EAS verification in the desktop app and CLI
5. Revocation flow via EAS `revoke()` for emergency key compromise

---

## 2. Current State

### 2.1 Marketplace Provenance

The marketplace already has a provenance structure that maps cleanly to EAS
(from `marketplace-trust-evolution.md` Section 4):

```json
{
  "provenance": {
    "attestation_uid": "0x<uid>",
    "notary_url": "https://notary.example.com",
    "type": "...",
    "chain_id": 8453,
    "schema_uid": "0x<schema-uid>"
  }
}
```

The `MarketplaceProvenance` struct supports `attestation_uid` and `notary_url`
fields. For EAS, the `type` becomes `"eas"`, `chain_id` identifies Base L2
(8453), and `schema_uid` references the registered EAS schema.

### 2.2 AegisNet Attestation Pipeline

AegisNet already provides:

- **Merkle tree checkpointing** with RFC 6962 inclusion proofs
- **Witness co-signatures** for independent trust verification
- **Proofs API** (`GET /v1/proofs/inclusion?envelope_hash=0x...`)
- **NATS JetStream** as the event backbone

EAS anchoring **extends** this by timestamping AegisNet checkpoint hashes
on-chain. The checkpoint hash is the root of a Merkle tree containing
potentially hundreds of envelopes. One on-chain transaction anchors the
entire batch.

### 2.3 Spine Envelope Format

From `crates/spine/src/envelope.rs`, the `SignedEnvelope` contains:

- `schema`: `"aegis.spine.envelope.v1"`
- `issuer`: `"aegis:ed25519:<hex_pubkey>"`
- `seq`: monotonic sequence number
- `envelope_hash`: SHA-256 of canonical JSON (0x-prefixed)
- `signature`: Ed25519 signature
- `fact`: nested object with `schema` identifying the fact type

The EAS attestation will reference `envelope_hash` values from these envelopes,
creating a bridge between AegisNet's off-chain Merkle proofs and on-chain
blockchain timestamps.

### 2.4 What Does Not Exist Yet

- No EAS schema registration
- No on-chain attestation creation tooling
- No batching service for on-chain timestamps
- No client-side EAS verification
- No EAS revocation flow
- No Base L2 wallet/signer infrastructure

---

## 3. Target State

### 3.1 Architecture

```
                                                On-Chain (Base L2)
                                          ┌─────────────────────────┐
                                          │  EAS Contracts          │
                                          │  ┌───────────────────┐  │
                                          │  │ SchemaRegistry    │  │
                                          │  │ (registered)      │  │
                                          │  └───────────────────┘  │
                                          │  ┌───────────────────┐  │
                                          │  │ EAS.sol           │  │
                                          │  │ attest()          │  │
                                          │  │ multiAttest()     │  │
                                          │  │ revoke()          │  │
                                          │  └───────────────────┘  │
                                          └───────────┬─────────────┘
                                                      │ RPC
┌──────────────────────────────┐         ┌───────────▼─────────────┐
│  AegisNet                    │         │  EAS Anchor Service     │
│  ┌────────────────────┐      │         │  (Rust binary or hushd  │
│  │ Checkpointer       │      │         │   extension)            │
│  │ Merkle tree root   │──────┼────────►│                         │
│  │ checkpoint_hash    │      │         │  - Batch checkpoint     │
│  └────────────────────┘      │         │    hashes               │
│  ┌────────────────────┐      │         │  - Create EAS attest    │
│  │ Proofs API         │      │         │  - Submit to Base L2    │
│  │ /v1/proofs/        │      │         │  - Store tx hash        │
│  │  inclusion         │      │         │  - Handle revocations   │
│  └────────────────────┘      │         └─────────────────────────┘
└──────────────────────────────┘
         │                                         │
         │                                         │
         ▼                                         ▼
┌──────────────────────────────────────────────────────────────────┐
│  ClawdStrike Desktop / CLI                                       │
│                                                                  │
│  Verification chain:                                             │
│  1. Verify envelope Ed25519 signature (hush-core)                │
│  2. Verify AegisNet Merkle inclusion proof (proofs API)          │
│  3. Verify EAS on-chain timestamp (Base L2 RPC) [optional]       │
│  4. Check EAS revocation status [optional]                       │
└──────────────────────────────────────────────────────────────────┘
```

### 3.2 EAS Schema Definitions

Three schemas registered on Base L2:

**Schema 1: Policy Attestation**

```
Schema: "bytes32 bundleHash, string feedId, string entryId,
         bytes32 curatorKey, uint64 feedSeq, string policyVersion"
Resolver: 0x0 (no on-chain resolver)
Revocable: true
```

**Schema 2: Checkpoint Anchor**

```
Schema: "bytes32 checkpointHash, uint64 checkpointSeq, uint64 treeSize,
         bytes32 logOperatorKey, bytes32 witnessKey"
Resolver: 0x0
Revocable: false
```

**Schema 3: Key Rotation**

```
Schema: "bytes32 oldKey, bytes32 newKey, string feedId,
         uint64 rotationSeq, string reason"
Resolver: 0x0
Revocable: true
```

---

## 4. Implementation Plan

### Step 1: Base L2 Wallet Infrastructure

Set up the signer wallet that will submit EAS transactions:

**Wallet setup:**

- Generate a new Ethereum keypair for the EAS anchor service
- Fund with ETH on Base L2 (~0.01 ETH is sufficient for months of operations)
- Store private key in environment variable or K8s secret (production: AWS KMS
  or similar HSM)

**Config:**

```toml
# eas-anchor.toml

[chain]
rpc_url = "https://mainnet.base.org"   # Base L2 mainnet
chain_id = 8453
eas_contract = "0xA1207F3BBa224E2c9c3c6D5aF63D816e6e1f8e4b"  # EAS on Base
schema_registry = "0xA7b39296258348C78294F95B872b282326A97BDF"  # SchemaRegistry on Base

[signer]
# One of:
private_key_env = "EAS_SIGNER_PRIVATE_KEY"   # env var name
# or
kms_key_id = "aws-kms://arn:aws:kms:..."      # AWS KMS

[batching]
max_batch_size = 50              # attestations per tx
batch_interval_secs = 300        # flush every 5 minutes
min_batch_size = 1               # flush immediately if >= 1 pending

[schemas]
policy_attestation_uid = ""      # populated after registration (Step 2)
checkpoint_anchor_uid = ""       # populated after registration (Step 2)
key_rotation_uid = ""            # populated after registration (Step 2)
```

### Step 2: Schema Registration

Register the three EAS schemas on Base L2. This is a one-time operation:

```typescript
// scripts/register-eas-schemas.ts (run once)

import { SchemaRegistry } from "@ethereum-attestation-service/eas-sdk";
import { ethers } from "ethers";

const SCHEMA_REGISTRY_ADDRESS = "0xA7b39296258348C78294F95B872b282326A97BDF";

async function registerSchemas() {
    const provider = new ethers.JsonRpcProvider("https://mainnet.base.org");
    const signer = new ethers.Wallet(process.env.EAS_SIGNER_PRIVATE_KEY, provider);
    const registry = new SchemaRegistry(SCHEMA_REGISTRY_ADDRESS);
    registry.connect(signer);

    // Schema 1: Policy Attestation
    const policyTx = await registry.register({
        schema: "bytes32 bundleHash, string feedId, string entryId, bytes32 curatorKey, uint64 feedSeq, string policyVersion",
        resolverAddress: "0x0000000000000000000000000000000000000000",
        revocable: true,
    });
    const policySchemaUid = await policyTx.wait();
    console.log("Policy Attestation Schema UID:", policySchemaUid);

    // Schema 2: Checkpoint Anchor
    const checkpointTx = await registry.register({
        schema: "bytes32 checkpointHash, uint64 checkpointSeq, uint64 treeSize, bytes32 logOperatorKey, bytes32 witnessKey",
        resolverAddress: "0x0000000000000000000000000000000000000000",
        revocable: false,
    });
    const checkpointSchemaUid = await checkpointTx.wait();
    console.log("Checkpoint Anchor Schema UID:", checkpointSchemaUid);

    // Schema 3: Key Rotation
    const keyRotTx = await registry.register({
        schema: "bytes32 oldKey, bytes32 newKey, string feedId, uint64 rotationSeq, string reason",
        resolverAddress: "0x0000000000000000000000000000000000000000",
        revocable: true,
    });
    const keyRotSchemaUid = await keyRotTx.wait();
    console.log("Key Rotation Schema UID:", keyRotSchemaUid);
}
```

**Cost:** ~$0.10-$0.30 per schema registration on Base L2 (one-time).

### Step 3: EAS Anchor Service (Rust)

Implement a batching service that subscribes to AegisNet checkpoints and
creates on-chain EAS attestations:

**New crate: `crates/eas-anchor/`**

```
crates/eas-anchor/
├── Cargo.toml
├── src/
│   ├── main.rs          # Service entry point
│   ├── config.rs        # TOML config parsing
│   ├── batcher.rs       # Batching logic
│   ├── eas_client.rs    # EAS contract interaction
│   └── nats_sub.rs      # NATS subscription for checkpoints
```

**`Cargo.toml` dependencies:**

```toml
[package]
name = "eas-anchor"
version = "0.1.0"
edition = "2021"

[dependencies]
alloy = { version = "0.9", features = ["provider-http", "signer-local", "contract"] }
async-nats = "0.38"
hush-core = { path = "../hush-core" }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
toml = "0.8"
tracing = "0.1"
tracing-subscriber = "0.3"
```

**Core batcher logic:**

```rust
// crates/eas-anchor/src/batcher.rs

use std::time::{Duration, Instant};

pub struct AttestationBatcher {
    pending: Vec<PendingAttestation>,
    max_batch_size: usize,
    batch_interval: Duration,
    last_flush: Instant,
}

pub struct PendingAttestation {
    pub checkpoint_hash: [u8; 32],
    pub checkpoint_seq: u64,
    pub tree_size: u64,
    pub log_operator_key: [u8; 32],
    pub witness_key: [u8; 32],
    pub received_at: Instant,
}

impl AttestationBatcher {
    pub fn new(max_batch_size: usize, batch_interval: Duration) -> Self {
        Self {
            pending: Vec::new(),
            max_batch_size,
            batch_interval,
            last_flush: Instant::now(),
        }
    }

    pub fn add(&mut self, attestation: PendingAttestation) {
        self.pending.push(attestation);
    }

    pub fn should_flush(&self) -> bool {
        self.pending.len() >= self.max_batch_size
            || (!self.pending.is_empty()
                && self.last_flush.elapsed() >= self.batch_interval)
    }

    pub fn drain(&mut self) -> Vec<PendingAttestation> {
        self.last_flush = Instant::now();
        std::mem::take(&mut self.pending)
    }
}
```

**EAS contract interaction using alloy:**

```rust
// crates/eas-anchor/src/eas_client.rs

use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;

pub struct EasClient {
    provider: alloy::providers::RootProvider<alloy::transports::http::Http>,
    signer: PrivateKeySigner,
    eas_address: alloy::primitives::Address,
    schema_uid: alloy::primitives::FixedBytes<32>,
}

impl EasClient {
    pub async fn new(config: &EasConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let signer: PrivateKeySigner = config.private_key.parse()?;
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_http(config.rpc_url.parse()?);

        Ok(Self {
            provider,
            signer,
            eas_address: config.eas_contract.parse()?,
            schema_uid: config.checkpoint_anchor_schema_uid.parse()?,
        })
    }

    pub async fn submit_batch(
        &self,
        attestations: &[PendingAttestation],
    ) -> Result<String, Box<dyn std::error::Error>> {
        // Use EAS.multiAttest() for batch submission
        // Each attestation encodes:
        //   (checkpointHash, checkpointSeq, treeSize,
        //    logOperatorKey, witnessKey)
        //
        // Returns the transaction hash as confirmation

        // ... alloy contract call implementation ...
        todo!("Implement multiAttest contract call")
    }
}
```

**NATS subscription for checkpoint events:**

```rust
// crates/eas-anchor/src/nats_sub.rs

pub async fn subscribe_checkpoints(
    nats_url: &str,
    batcher: &mut AttestationBatcher,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = async_nats::connect(nats_url).await?;
    let mut subscriber = client
        .subscribe("clawdstrike.spine.envelope.log_checkpoint.v1")
        .await?;

    while let Some(msg) = subscriber.next().await {
        let envelope: serde_json::Value = serde_json::from_slice(&msg.payload)?;

        // Extract checkpoint data from the envelope fact
        let fact = &envelope["fact"];
        let checkpoint_hash = parse_hex_bytes32(
            fact["checkpoint_hash"].as_str().unwrap_or_default()
        )?;
        let checkpoint_seq = fact["checkpoint_seq"].as_u64().unwrap_or(0);
        let tree_size = fact["tree_size"].as_u64().unwrap_or(0);

        batcher.add(PendingAttestation {
            checkpoint_hash,
            checkpoint_seq,
            tree_size,
            log_operator_key: parse_hex_bytes32(
                fact["log_operator_key"].as_str().unwrap_or_default()
            )?,
            witness_key: parse_hex_bytes32(
                fact["witness_key"].as_str().unwrap_or_default()
            )?,
            received_at: Instant::now(),
        });

        if batcher.should_flush() {
            let batch = batcher.drain();
            // submit_batch in background task
        }
    }

    Ok(())
}
```

### Step 4: Off-Chain Attestation for Individual Policies

For individual policy attestations (Schema 1), use EAS off-chain attestations
with on-chain timestamp:

```typescript
// packages/eas-utils/src/attest-policy.ts

import { EAS, SchemaEncoder } from "@ethereum-attestation-service/eas-sdk";

const EAS_CONTRACT = "0xA1207F3BBa224E2c9c3c6D5aF63D816e6e1f8e4b";

export async function createPolicyAttestation(
    signer: ethers.Signer,
    schemaUid: string,
    params: {
        bundleHash: string;      // 0x-prefixed SHA-256
        feedId: string;
        entryId: string;
        curatorKey: string;      // 0x-prefixed Ed25519 pubkey
        feedSeq: number;
        policyVersion: string;
    }
): Promise<{ offchainAttestation: string; timestampTxHash?: string }> {
    const eas = new EAS(EAS_CONTRACT);
    eas.connect(signer);

    const schemaEncoder = new SchemaEncoder(
        "bytes32 bundleHash, string feedId, string entryId, " +
        "bytes32 curatorKey, uint64 feedSeq, string policyVersion"
    );

    const encodedData = schemaEncoder.encodeData([
        { name: "bundleHash", value: params.bundleHash, type: "bytes32" },
        { name: "feedId", value: params.feedId, type: "string" },
        { name: "entryId", value: params.entryId, type: "string" },
        { name: "curatorKey", value: params.curatorKey, type: "bytes32" },
        { name: "feedSeq", value: params.feedSeq, type: "uint64" },
        { name: "policyVersion", value: params.policyVersion, type: "string" },
    ]);

    // Create off-chain attestation (free, no gas)
    const offchain = await eas.getOffchain();
    const offchainAttestation = await offchain.signOffchainAttestation({
        recipient: "0x0000000000000000000000000000000000000000",
        expirationTime: 0n,    // no expiration (revocable instead)
        time: BigInt(Math.floor(Date.now() / 1000)),
        revocable: true,
        schema: schemaUid,
        refUID: "0x0000000000000000000000000000000000000000000000000000000000000000",
        data: encodedData,
    }, signer);

    // Optionally timestamp on-chain (minimal gas: ~$0.01 on Base)
    const timestampTxHash = await eas.timestamp(
        offchainAttestation.uid
    );

    return {
        offchainAttestation: JSON.stringify(offchainAttestation),
        timestampTxHash: timestampTxHash?.hash,
    };
}
```

### Step 5: Client-Side Verification

Add EAS verification to the ClawdStrike desktop client and CLI:

**Verification flow:**

```
1. VERIFY: Envelope Ed25519 signature (existing, hush-core)
2. VERIFY: AegisNet Merkle inclusion proof (existing, proofs API)
3. [Optional] VERIFY: EAS on-chain timestamp
   a. Query Base L2 RPC for the checkpoint anchor attestation
   b. Verify checkpoint_hash matches AegisNet checkpoint
   c. Verify block timestamp is within acceptable range
   d. Check revocation status (for revocable schemas)
4. Display verification result with trust level indicator:
   - "Ed25519 verified" (basic)
   - "AegisNet attested" (medium)
   - "Blockchain anchored" (highest)
```

**New TypeScript utility for desktop:**

```typescript
// packages/eas-utils/src/verify.ts

import { EAS } from "@ethereum-attestation-service/eas-sdk";
import { ethers } from "ethers";

export interface EasVerificationResult {
    verified: boolean;
    attestationUid: string;
    attester: string;
    timestamp: number;          // Unix timestamp from block
    revoked: boolean;
    revokedAt?: number;
    chainId: number;
    blockNumber: number;
    error?: string;
}

export async function verifyEasAttestation(
    provenance: {
        attestation_uid: string;
        chain_id: number;
        schema_uid: string;
    },
    rpcUrl: string = "https://mainnet.base.org"
): Promise<EasVerificationResult> {
    const provider = new ethers.JsonRpcProvider(rpcUrl);
    const eas = new EAS("0xA1207F3BBa224E2c9c3c6D5aF63D816e6e1f8e4b");
    eas.connect(provider);

    try {
        const attestation = await eas.getAttestation(
            provenance.attestation_uid
        );

        return {
            verified: true,
            attestationUid: provenance.attestation_uid,
            attester: attestation.attester,
            timestamp: Number(attestation.time),
            revoked: attestation.revocationTime > 0n,
            revokedAt: attestation.revocationTime > 0n
                ? Number(attestation.revocationTime) : undefined,
            chainId: provenance.chain_id,
            blockNumber: 0,  // filled from tx receipt
        };
    } catch (error) {
        return {
            verified: false,
            attestationUid: provenance.attestation_uid,
            attester: "",
            timestamp: 0,
            revoked: false,
            chainId: provenance.chain_id,
            blockNumber: 0,
            error: String(error),
        };
    }
}
```

### Step 6: Revocation Flow

For emergency key compromise or policy revocation:

```typescript
// packages/eas-utils/src/revoke.ts

export async function revokeAttestation(
    signer: ethers.Signer,
    schemaUid: string,
    attestationUid: string,
    reason?: string
): Promise<string> {
    const eas = new EAS("0xA1207F3BBa224E2c9c3c6D5aF63D816e6e1f8e4b");
    eas.connect(signer);

    const tx = await eas.revoke({
        schema: schemaUid,
        data: {
            uid: attestationUid,
            value: 0n,
        },
    });

    return tx.hash;
}
```

**Revocation propagation:**

1. Curator calls `revokeAttestation()` on-chain (Base L2)
2. EAS contract marks the attestation as revoked with timestamp
3. AegisNet revocation envelope is published to NATS
4. Revocation propagates via all Spine planes (including Reticulum, priority 1)
5. Desktop clients checking EAS status see `revoked: true`
6. Clients that cannot reach Base L2 still see the AegisNet revocation envelope

### Step 7: MarketplaceProvenance Schema Update

Update the provenance type to support EAS:

```json
{
  "provenance": {
    "attestation_uid": "0x<eas-attestation-uid>",
    "notary_url": "https://base.easscan.org",
    "type": "eas",
    "chain_id": 8453,
    "schema_uid": "0x<schema-uid>",
    "eas_data": {
      "off_chain_attestation": "...",
      "timestamp_tx_hash": "0x...",
      "block_number": 12345678
    }
  }
}
```

---

## 5. Cost Analysis

### On-Chain Operations (Base L2)

| Operation | Frequency | Gas (approx) | Cost per op | Monthly cost (100 policies) |
|---|---|---|---|---|
| Schema registration | One-time (3 schemas) | ~200K gas each | ~$0.10 | $0.30 (one-time) |
| `multiAttest()` batch (50 checkpoints) | ~6/day (5 min interval, 288 checkpoints/day) | ~500K gas | ~$0.25 | ~$4.50 |
| Individual policy attestation timestamp | Per policy update | ~100K gas | ~$0.05 | ~$5.00 |
| Revocation | Rare (emergency) | ~100K gas | ~$0.05 | ~$0.50 |
| **Total monthly estimate** | | | | **~$10** |

### Off-Chain Operations (Free)

| Operation | Cost |
|---|---|
| Off-chain attestation creation | Free (signed by curator) |
| Off-chain attestation storage (IPFS/feed) | Existing infrastructure |
| Client verification (read-only RPC) | Free (public RPC endpoints) |

**Summary:** ~$10/month for full on-chain anchoring of a marketplace with
100 policies and 288 daily checkpoint anchors. Negligible.

---

## 6. File Changes

### New Files

| Path | Description | Est. LOC |
|---|---|---|
| `crates/eas-anchor/Cargo.toml` | Rust crate for EAS anchor service | 25 |
| `crates/eas-anchor/src/main.rs` | Service entry point | 80 |
| `crates/eas-anchor/src/config.rs` | TOML config parsing | 60 |
| `crates/eas-anchor/src/batcher.rs` | Attestation batching logic | 120 |
| `crates/eas-anchor/src/eas_client.rs` | EAS contract interaction (alloy) | 200 |
| `crates/eas-anchor/src/nats_sub.rs` | NATS subscription for checkpoints | 100 |
| `packages/eas-utils/package.json` | TS package for EAS utilities | 20 |
| `packages/eas-utils/src/attest-policy.ts` | Off-chain policy attestation | 80 |
| `packages/eas-utils/src/verify.ts` | Client-side EAS verification | 100 |
| `packages/eas-utils/src/revoke.ts` | Revocation flow | 40 |
| `packages/eas-utils/src/schemas.ts` | Schema UIDs and ABI constants | 50 |
| `packages/eas-utils/src/index.ts` | Package exports | 10 |
| `packages/eas-utils/tests/verify.test.ts` | Verification tests | 100 |
| `scripts/register-eas-schemas.ts` | One-time schema registration script | 80 |
| `scripts/eas-anchor.toml` | Reference config for anchor service | 30 |
| **Total estimated** | | **~1,095** |

### Modified Files

| Path | Change | Description |
|---|---|---|
| `Cargo.toml` (workspace root) | Add `eas-anchor` to members | Workspace inclusion |
| `packages/hush-ts/src/index.ts` | Add EAS verification types | Type exports for TS SDK |

---

## 7. Testing Strategy

### Unit Tests

- **`batcher.rs` tests:** Verify batch size limits, time-based flushing,
  drain behavior, empty batch handling
- **`config.rs` tests:** TOML parsing, validation of required fields,
  default values
- **`eas_client.rs` tests:** Mock provider, encode attestation data,
  verify ABI encoding matches EAS SDK expectations
- **`verify.test.ts` tests:** Mock EAS contract responses, verify
  attestation parsing, revocation detection, error handling

### Integration Tests

- **Schema registration:** Run against Base Sepolia testnet. Register
  schemas, verify UIDs are returned.
- **Attestation roundtrip:** Create off-chain attestation, timestamp
  on-chain, verify from a separate client.
- **Batch anchoring:** Create 10 mock checkpoint envelopes, batch into
  1 `multiAttest()` call, verify all attestations on-chain.
- **Revocation:** Create attestation, revoke it, verify revocation
  status from client.

### Cross-Verification Tests

- **AegisNet + EAS consistency:** Verify that the `checkpoint_hash` in
  an EAS attestation matches the corresponding AegisNet checkpoint.
- **Offline fallback:** Verify that clients without Base L2 access still
  successfully verify via AegisNet inclusion proofs alone.

### Testnet Strategy

All integration tests run against **Base Sepolia** (testnet, chain ID 84532):

- Free testnet ETH from Base faucet
- EAS contracts deployed on Base Sepolia at same addresses
- CI runs integration tests on every PR (with cached testnet state)

---

## 8. Rollback Plan

EAS anchoring is entirely **additive and optional**:

1. **Remove `crates/eas-anchor/`** -- the anchor service is an independent
   binary. Stopping it has zero impact on AegisNet or hushd.
2. **Remove `packages/eas-utils/`** -- client-side EAS verification is a
   separate npm package. The desktop app falls back to AegisNet-only
   verification.
3. **On-chain schemas persist** -- registered EAS schemas on Base L2 remain
   but are inert without the anchor service creating new attestations.
4. **No NATS subject changes** -- the anchor service is a consumer of
   existing checkpoint subjects, not a producer.
5. **MarketplaceProvenance with `type: "eas"`** -- clients that encounter
   EAS provenance without the verification package simply skip EAS
   verification and rely on AegisNet/Ed25519 verification.

---

## 9. Dependencies

| Dependency | Status | Notes |
|---|---|---|
| `crates/spine/src/envelope.rs` | **Exists** | Envelope hash format |
| AegisNet Checkpointer | **Deployed** | Produces checkpoint envelopes |
| AegisNet Proofs API | **Deployed** | Inclusion proof verification |
| NATS JetStream | **Deployed** | Event backbone |
| Base L2 RPC access | **External** | Public endpoints available |
| `@ethereum-attestation-service/eas-sdk` | **External, stable** | npm package |
| `alloy` Rust crate | **External, stable** | Ethereum interaction |
| Spec #7 (AegisNet notary replacement) | **Pending** | EAS extends AegisNet, does not require it |
| Spec #12 (Reticulum adapter) | **Pending** | Revocations propagate via Reticulum |

---

## 10. Acceptance Criteria

- [ ] Three EAS schemas are registered on Base Sepolia (testnet) with
      correct field definitions
- [ ] EAS anchor service subscribes to AegisNet checkpoint NATS subject
      and batches checkpoint hashes
- [ ] Batched `multiAttest()` call creates on-chain attestations on Base
      Sepolia within 5 minutes of checkpoint emission
- [ ] Individual policy attestation can be created off-chain and
      timestamped on-chain for ~$0.05
- [ ] Client-side verification (`verifyEasAttestation()`) correctly
      reads attestation data from Base L2 and reports verified/revoked status
- [ ] Revocation via `revokeAttestation()` marks the attestation as revoked
      on-chain, and client verification reports `revoked: true`
- [ ] Total monthly cost for 100-policy marketplace with 288 daily
      checkpoint anchors is under $15
- [ ] Clients without Base L2 access gracefully fall back to AegisNet-only
      verification (no error, just lower trust level)
- [ ] Cross-verification: `checkpoint_hash` in EAS attestation matches
      the AegisNet checkpoint for the same `checkpoint_seq`
- [ ] All tests pass against Base Sepolia testnet in CI

---

## 11. Open Questions

1. **Base vs Optimism vs Arbitrum:** The research doc recommends Base L2.
   Should we support multiple L2s for redundancy? **Recommendation:** Start
   with Base only. Add Optimism support if organizations request it. The
   EAS SDK supports multiple chains with identical interfaces.

2. **Public vs dedicated RPC:** Should the desktop client use public Base
   RPC endpoints (free, rate-limited) or a dedicated endpoint (Alchemy/Infura)?
   **Recommendation:** Public endpoints for the open source release. The
   ClawdStrike Cloud SaaS (Spec #14) will use dedicated endpoints for
   reliability.

3. **Gas price spikes:** What happens if Base L2 gas prices spike?
   **Recommendation:** The batcher should have a configurable `max_gas_price`
   that pauses on-chain submissions when gas exceeds the threshold. The
   batch queue persists and flushes when gas drops. AegisNet verification
   continues working regardless.

4. **EAS schema versioning:** If we need to change schema fields, EAS
   requires registering a new schema (schemas are immutable).
   **Recommendation:** Version the schema in the `policyVersion` field.
   Old schemas remain valid for old attestations. New schemas are
   registered as needed.

---

## References

- [Marketplace Trust Evolution](../research/marketplace-trust-evolution.md) -- Section 4 (EAS), Section 7 (trust delegation chains)
- [Architecture Vision](../research/architecture-vision.md) -- Section 6.6 (Phase 5: Cross-Layer Proofs)
- [EAS Documentation](https://docs.attest.org/) -- Schema registry, on-chain/off-chain attestations
- [EAS on Base](https://docs.attest.org/docs/quick--start/contracts) -- Contract addresses
- [Base L2 Documentation](https://docs.base.org/) -- RPC endpoints, gas pricing
- [alloy Rust crate](https://alloy.rs/) -- Ethereum interaction library
- `crates/spine/src/envelope.rs` -- Envelope hash format (current implementation)
- `crates/spine/src/trust.rs` -- Trust bundle constraints
