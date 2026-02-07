# Reticulum as SDR Transport: Off-Grid Threat Intelligence for ClawdStrike

> How the Reticulum mesh networking stack extends ClawdStrike's Swarm Detection &
> Response platform to disconnected, air-gapped, and bandwidth-constrained
> environments using the same signed envelopes that already power the marketplace
> and AegisNet attestation pipeline.
>
> **Status:** Research Draft | **Date:** 2026-02-07
> **Audience:** Security architecture, product engineering, field operations

---

## Table of Contents

1. [Why Reticulum Matters for SDR](#1-why-reticulum-matters-for-sdr)
2. [Multi-Plane Architecture](#2-multi-plane-architecture)
3. [Marketplace Unification: The Incomplete Spine](#3-marketplace-unification-the-incomplete-spine)
4. [Concrete Use Cases](#4-concrete-use-cases)
5. [Priority System and Bandwidth-Aware Scheduling](#5-priority-system-and-bandwidth-aware-scheduling)
6. [Identity Binding: ClawdStrike Keys Meet Reticulum Destinations](#6-identity-binding-clawdstrike-keys-meet-reticulum-destinations)
7. [Gateway Architecture: Radio to NATS Bridge](#7-gateway-architecture-radio-to-nats-bridge)
8. [LXMF Store-and-Forward Integration](#8-lxmf-store-and-forward-integration)
9. [Compact Encoding for Constrained Links](#9-compact-encoding-for-constrained-links)
10. [Implementation Plan](#10-implementation-plan)
11. [Open Questions](#11-open-questions)
12. [References](#12-references)

---

## 1. Why Reticulum Matters for SDR

ClawdStrike's Swarm Detection & Response platform currently operates across two
transport planes: **libp2p gossipsub** (Plane A-L) for decentralized marketplace
discovery and **NATS JetStream** (Plane B) as the high-throughput backbone
connecting hushd, AegisNet checkpointer/witness/proofs-api, and desktop clients.
Both planes assume internet connectivity. When the internet is unavailable,
ClawdStrike nodes are deaf and mute.

Reticulum fills this gap. Created by Mark Qvist and developed over 15+ years,
Reticulum is a cryptography-based networking stack that can operate over LoRa
radios, packet radio, serial lines, WiFi, TCP/UDP, free-space optical links, and
any other medium supporting at least 5 bits per second with a 500-byte MTU. It
provides end-to-end encryption (X25519 + Ed25519), autoconfiguring multi-hop
transport, and store-and-forward messaging via the LXMF protocol -- all without
requiring central infrastructure.

This matters for ClawdStrike because:

**Off-grid threat intelligence distribution.** Security policy revocations --
"block compromised signing key X immediately" -- must reach every node regardless
of internet availability. A LoRa radio carrying a signed revocation envelope at
5 bps is infinitely more useful than a fiber optic cable that has been cut.

**Air-gapped facility operations.** Military installations, classified
environments, critical infrastructure (power grids, water treatment, nuclear
facilities), and SCIF environments cannot connect to the public internet by
policy. These environments still need runtime security enforcement, policy
updates, and attestation. Reticulum provides a transport that respects the
air gap while enabling verifiable policy distribution via USB sneakernet, QR
code exchange, or short-range radio.

**Disaster response.** When natural disasters or hostile actions destroy internet
infrastructure, security operations must continue. First responders deploying AI
agents for search, triage, or logistics coordination still need ClawdStrike
guards enforcing safety policies. Reticulum's ability to form ad-hoc mesh
networks over whatever radios are available makes it the natural transport for
distributing security policy in degraded environments.

**Hostile network environments.** Nation-state adversaries with the ability to
intercept or block internet traffic cannot intercept Reticulum traffic on LoRa
frequencies they do not monitor. The transport diversity (LoRa, packet radio,
serial, WiFi, TCP/UDP) means that blocking all paths simultaneously is
operationally difficult.

**IoT and edge deployments.** Edge nodes running lightweight AI inference (sensor
anomaly detection, predictive maintenance agents) in remote locations -- oil
platforms, agricultural monitoring stations, remote mining operations -- may have
only satellite or LoRa connectivity. These nodes still need policy enforcement
and must still produce attestable receipts.

**The key insight:** ClawdStrike's marketplace already uses Ed25519 signed bundles
and libp2p gossip -- the exact same cryptographic primitives as the Aegis Spine
protocol. Reticulum adds an offline mesh transport plane alongside the existing
internet-based planes. The signed envelopes are the same on all planes; only the
transport differs.

---

## 2. Multi-Plane Architecture

The Aegis Spine specification (`cyntra-aegis-spine.md`) defines a multi-plane
network architecture where all planes carry identical Layer 4 objects (signed
envelopes containing facts). The Reticulum transport profile
(`cyntra-aegis-spine-reticulum.md`) introduces **Plane A-R** as the off-grid
complement to the existing planes.

### 2.1 Plane Taxonomy

| Plane | Transport | Role in ClawdStrike | Connectivity | Bandwidth |
|-------|-----------|---------------------|-------------|-----------|
| **A-L** (libp2p) | TCP/QUIC + gossipsub + mDNS | Marketplace P2P discovery, feed URI gossip | Internet required | High (Mbps+) |
| **A-R** (Reticulum) | LoRa, packet radio, serial, WiFi, TCP/UDP | Off-grid policy distribution, emergency revocations, field sync | **No internet required** | Very low (5 bps to Mbps) |
| **B** (NATS) | TCP/TLS, JetStream | hushd event bus, AegisNet attestation pipeline, Tetragon/Hubble events | LAN/WAN required | Very high (100K+ msg/sec) |
| **C** (WireGuard) | UDP overlay | Private enclaves, classified operations | Administered overlay | High |

### 2.2 Same Envelope, Different Pipe

The critical design property: **all planes carry the same `SignedEnvelope`
(`aegis.spine.envelope.v1`)**. A revocation fact signed by a curator's Ed25519
key is byte-identical whether it travels over:

- NATS JetStream at 100,000 messages/second in a data center,
- libp2p gossipsub over a residential internet connection,
- Reticulum over a LoRa radio at 1,200 bps across 6+ km of open terrain, or
- a USB flash drive carried by hand (sneakernet).

Receivers validate the same way: recompute `envelope_hash` from canonical JSON
(RFC 8785), verify the Ed25519 signature against `issuer`, check `(issuer, seq)`
monotonicity, and detect forks. The transport is invisible to the truth layer.

### 2.3 Translation Gateways

Gateways bridge planes without modifying signed envelopes:

```
                    ┌─────────────────────────────────────────┐
                    │            Translation Gateway           │
                    │                                         │
  Plane A-R ◄──────┤  verify → filter → rate-limit → forward ├──────► Plane B
  (Reticulum)       │                                         │        (NATS)
                    │  audit log: envelope_hash + decision    │
                    └─────────────────────────────────────────┘
                                        │
                                        ▼
                                    Plane A-L
                                    (libp2p)
```

Gateway rules (from `cyntra-aegis-spine-reticulum.md` Section 8):

1. Verify envelope hash + signature before forwarding
2. Never mutate signed envelopes (forward or drop only)
3. Apply disclosure policy (filter by `fact.schema`, issuer, or policy)
4. Rate-limit and deduplicate by `envelope_hash`
5. Persist a tamper-evident audit log (JSONL + hash-chained entries)

---

## 3. Marketplace Unification: The Incomplete Spine

ClawdStrike's marketplace is, in structural terms, an incomplete implementation
of the Aegis Spine protocol. The primitives are already there; they just need
to be recognized and unified.

### 3.1 Mapping Marketplace Constructs to Spine Objects

| ClawdStrike Marketplace | Aegis Spine Equivalent | Status |
|------------------------|------------------------|--------|
| `SignedPolicyBundle` (Ed25519 signed, SHA-256 content hash) | `SignedEnvelope` wrapping a `policy_delta` or `artifact_pointer` fact | **Same crypto, different schema** |
| `SignedMarketplaceFeed` (canonical JSON, monotonic `seq`, Ed25519 signed) | Spine issuer chain (monotonic `seq`, `prev_envelope_hash`, Ed25519 signed) | **Structurally equivalent** |
| `MarketplaceProvenance` (`attestation_uid` + `notary_url`) | AegisNet inclusion proof (`envelope_hash` + checkpoint + witness) | **Notary is a centralized approximation of AegisNet** |
| libp2p gossipsub discovery (`marketplace_discovery.rs`) | Spine head announcements + gossip overlay | **Same transport, different semantics** |
| Feed `seq` for freshness | Spine `(issuer, seq)` for append-only ordering | **Identical concept** |
| `verify_trusted(&[PublicKey])` | Spine capability token + trust bundle | **Same verification model** |

### 3.2 What Unification Looks Like

**Policy bundles become Spine facts.** Instead of a standalone
`SignedPolicyBundle`, the policy becomes the `fact` body inside a
`SignedEnvelope`. The curator's Ed25519 key is the envelope `issuer`. The
bundle's SHA-256 hash becomes (or is referenced by) the `envelope_hash`.

```json
{
  "schema": "aegis.spine.envelope.v1",
  "issuer": "aegis:ed25519:<curator-pubkey>",
  "seq": 42,
  "prev_envelope_hash": "0x...",
  "fact": {
    "schema": "clawdstrike.marketplace.policy_attestation.v1",
    "fact_id": "pa_...",
    "bundle_hash": "0x<sha256-of-policy-bundle>",
    "feed_id": "clawdstrike-official",
    "feed_seq": 15,
    "entry_id": "hipaa-compliance-v2",
    "policy_hash": "0x..."
  },
  "envelope_hash": "0x...",
  "signature": "0x..."
}
```

**Feed updates become head announcements.** When a curator publishes a new feed
version (incrementing `seq`), this is equivalent to a Spine `head_announcement`:

```
(issuer=curator_pubkey, seq=42, head_hash=0x..., signature=0x...)
```

Peers that observe a higher `seq` than their local state initiate a `sync_request`
to catch up on missed envelopes.

**Notary verification becomes Spine inclusion proofs.** The current
`verifyMarketplaceAttestation(notaryUrl, uid)` call to a centralized HTTP
endpoint is replaced by:

1. Query AegisNet: `GET /v1/proofs/inclusion?envelope_hash=0x<attestation_hash>`
2. Receive RFC 6962 Merkle inclusion proof
3. Verify locally (no trust in the server beyond the signed checkpoint)
4. Verify witness co-signature for independent confirmation

**Discovery gossip carries Spine semantics.** The existing libp2p gossipsub
(`marketplace_discovery.rs`) already gossips feed URIs. Adding Spine head
announcements to the gossip payload enables anti-entropy: peers know when
they are behind and can request catch-up.

### 3.3 Why This Matters for Reticulum

Once the marketplace speaks Spine, adding Reticulum is "just another transport"
for the same objects. A policy revocation published to NATS by a curator:

1. Propagates to all connected hushd instances via NATS
2. Gets checkpointed by AegisNet (Merkle tree + witness signature)
3. Gets gossiped via libp2p to desktop marketplace peers
4. Gets relayed to a radio gateway and transmitted over LoRa to disconnected nodes

Step 4 is new. Steps 1-3 already work. The revocation envelope is identical in
all four steps.

---

## 4. Concrete Use Cases

### 4.1 Emergency Revocation Over LoRa

**Scenario:** A curator's signing key is compromised. All policy bundles signed
by that key must be immediately distrusted.

**Without Reticulum:** Nodes without internet connectivity continue trusting the
compromised key indefinitely. Air-gapped facilities never learn about the
compromise until a human physically delivers the revocation.

**With Reticulum:**

```
Curator publishes revocation fact
  │
  ▼ NATS (Plane B) ─────────────────────► All connected hushd instances
  │
  ▼ Radio Gateway (Plane A-R bridge)
  │
  ▼ LoRa radio broadcast (5-1200 bps)
  │
  ├──► Field node A (6 km away, no internet)
  ├──► Field node B (relays to node C via multi-hop)
  └──► Field node C (air-gapped facility with LoRa receiver)
```

A revocation fact is small (~200 bytes JSON, ~120 bytes CBOR). Even at 5 bps --
the minimum Reticulum link speed -- a revocation propagates in under 30 seconds.
At 1,200 bps (typical LoRa), it propagates in under 1 second.

Revocations have the highest priority in the Spine scheduling system and bypass
normal rate limits (with their own dedicated rate bucket to prevent abuse).

### 4.2 Threat Intel Distribution via Packet Radio

**Scenario:** A new attack pattern targeting AI agents is discovered. An incident
fact with MITRE ATT&CK tags and IOCs needs to reach all nodes, including those
on disconnected networks.

**Flow:**

1. Incident fact published to NATS (`aegis.spine.envelope.clawdstrike.incident.v1`)
2. AegisNet checkpoints it (Merkle proof available within 5-15 seconds)
3. Radio gateway receives the envelope from NATS
4. Gateway transmits over packet radio (300-9600 baud) or LoRa
5. Receiving nodes validate signature, store the fact, update their local threat intelligence
6. Desktop ClawdStrike visualizations (ThreatRadarView, AttackGraphView) update

The incident fact contains hashes and pointers, not bulk evidence. The actual
forensics bundle stays in regional vault storage -- only the signed claim and
pointers traverse the constrained link.

### 4.3 USB Sneakernet for Air-Gapped Facilities

**Scenario:** A classified facility runs AI agents for document processing under
ClawdStrike policy enforcement. The facility has no network connectivity of any
kind. Policy updates are delivered by security-cleared couriers.

**Flow:**

```bash
# Courier's connected workstation: export latest state
cyntra spine reticulum peers export --output /media/usb/peerbook.json
cyntra spine export --from-seq 0 --output /media/usb/spine_envelopes.jsonl

# Air-gapped facility: import
cyntra spine reticulum peers import --input /media/usb/peerbook.json
cyntra spine import --input /media/usb/spine_envelopes.jsonl
# Validates all signatures, checks seq monotonicity, detects forks
```

The USB drive contains:
- Signed envelopes (policy deltas, revocations, checkpoints)
- Inclusion proofs for each envelope (offline verification)
- Checkpoint with witness signatures (independent trust anchor)
- Peerbook for future Reticulum connectivity (if radio is later installed)

The facility can verify the entire chain offline using only the trusted root keys
(log operator + witness + curator public keys).

### 4.4 QR Code Peer Exchange for Rapid Field Deployment

**Scenario:** Two security operators meet in the field and need to establish
Reticulum connectivity for policy synchronization.

**Flow:**

```bash
# Operator A: export peer info as QR payload
cyntra spine reticulum peers export --format qr
# Displays QR code containing:
#   - Reticulum destination hash
#   - Aegis node_id binding (signed attestation)
#   - Supported capabilities: [envelopes, heads, sync, proofs]

# Operator B: scan and import
cyntra spine reticulum peers import --qr "<scanned-payload>"
# Verifies the signed binding between Aegis identity and Reticulum destination
```

Once peers are exchanged, the two nodes begin synchronizing their Spine state
over whatever Reticulum interfaces are available (LoRa, WiFi, serial).

### 4.5 Raspberry Pi Gateway: Radio to NATS Bridge

**Scenario:** A Pi-based device with a LoRa radio (RNode) and an Ethernet
connection bridges between a disconnected radio mesh and the NATS backbone.

```
┌───────────────────────────────────────────────────────────┐
│  Raspberry Pi 4 Gateway                                   │
│                                                           │
│  ┌────────────┐    ┌─────────────────────┐    ┌────────┐ │
│  │ Reticulum  │◄──►│ Reticulum Adapter   │◄──►│ NATS   │ │
│  │ (RNode     │    │ (Python sidecar)    │    │ client │ │
│  │  LoRa USB) │    │ verify → forward    │    │        │ │
│  └────────────┘    │ rate-limit          │    └────────┘ │
│                    │ audit log           │        │       │
│                    └─────────────────────┘        │       │
└──────────────────────────────────────────────────┼───────┘
                                                   │ Ethernet
                                              ┌────▼────┐
                                              │  NATS   │
                                              │ cluster │
                                              └─────────┘
```

The gateway runs:
- Reticulum stack (Python) with RNode LoRa interface
- Reticulum adapter/sidecar that bridges envelopes between Reticulum and the local Spine store
- NATS client that forwards verified envelopes to/from the NATS backbone
- Disclosure policy enforcement (what fact types are allowed to traverse the bridge)
- Audit log (tamper-evident JSONL with hash-chained entries)

Hardware cost: ~$70 (Pi 4 + RNode). Power consumption: ~5W.
Range: 6+ km line-of-sight with stock antenna; much more with directional antennas.

---

## 5. Priority System and Bandwidth-Aware Scheduling

Reticulum links can be as slow as 5 bits per second. At that speed, a 500-byte
envelope takes 800 seconds (~13 minutes) to transmit. Prioritization is not
optional; it is a correctness requirement.

### 5.1 Priority Tiers

The Reticulum transport profile defines seven priority tiers, ordered from
highest to lowest:

| Priority | Fact Schema | Typical Size | Why This Order |
|----------|------------|-------------|----------------|
| **1** (highest) | `aegis.spine.fact.revocation.v1` | ~200 bytes | Safety-critical: compromised keys/nodes must be blocked immediately |
| **2** | `aegis.spine.fact.log_checkpoint.v1` | ~300-500 bytes | Trust anchor: enables verification of all other facts |
| **3** | `aegis.spine.fact.incident.v1` | ~300-500 bytes | Threat awareness: active breaches require rapid dissemination |
| **4** | `aegis.spine.fact.policy_delta.v1` | ~200-400 bytes | Enforcement updates: new rules for guards and constraints |
| **5** | `aegis.spine.fact.run.v1` | ~300-500 bytes | Audit trail: proof of agent execution |
| **6** | `aegis.spine.fact.node_attestation.v1` | ~400-600 bytes | Identity: peer discovery and capability advertisement |
| **7** (lowest) | `aegis.spine.fact.heartbeat.v1` | ~200 bytes | Liveness: droppable if bandwidth is constrained |

### 5.2 Bandwidth Budget Scheduling

Each Reticulum link has a measured or configured bandwidth budget. The adapter
maintains a priority queue and schedules transmissions:

```
available_bandwidth = measured_link_bps
revocation_budget   = unlimited (but rate-bucketed to prevent abuse)
checkpoint_budget   = 30% of remaining
incident_budget     = 25% of remaining
remaining           = split among lower priorities by weight
```

At 1,200 bps (typical LoRa):
- A revocation (200 bytes CBOR) transmits in ~1.3 seconds
- A checkpoint (400 bytes CBOR) transmits in ~2.7 seconds
- 10 policy deltas (300 bytes each) transmit in ~20 seconds

At 5 bps (minimum Reticulum link):
- A revocation (200 bytes CBOR) transmits in ~320 seconds (~5 minutes)
- Only revocations and checkpoints should traverse such links
- Heartbeats are unconditionally dropped

### 5.3 Anti-Spam: Revocation Rate Bucketing

Because revocations bypass normal rate limits, they need their own constraint
to prevent abuse:

- Dedicated revocation rate bucket: max N revocations per hour per peer
- Maximum revocation envelope size: 500 bytes
- Unknown-issuer revocations: stored in a bounded quarantine buffer
- Revocations from known-trusted issuers: processed immediately

---

## 6. Identity Binding: ClawdStrike Keys Meet Reticulum Destinations

### 6.1 The Two Identity Systems

**ClawdStrike/Aegis identity:**
- Ed25519 keypair (32-byte seed, 64-byte signature)
- NodeId format: `aegis:ed25519:<hex_pubkey>`
- Used for: signing envelopes, signing receipts, signing policy bundles
- Stored in: hushd key store, `~/.clawdstrike/` config

**Reticulum identity:**
- X25519 (encryption) + Ed25519 (signing) keypair (512-bit combined keyset)
- Destination hash: truncated 128-bit hash of the identity
- Used for: transport routing, link establishment, LXMF addressing
- Stored in: Reticulum data directory (`.reticulum/`)

### 6.2 Binding Model (Recommended: Model A -- Separate Keys)

The Reticulum transport profile recommends Model A (separate keys) for the
initial implementation. The binding is established by publishing the Reticulum
destination info inside a signed Aegis Spine fact:

```json
{
  "schema": "aegis.spine.fact.node_attestation.v1",
  "fact_id": "na_...",
  "node_id": "aegis:ed25519:<hex_pubkey>",
  "system_attestation": { "...": "..." },
  "transports": {
    "reticulum": {
      "profile": "aegis.spine.reticulum.v1",
      "destination_hash": "0x<128-bit-hash>",
      "announce_period_secs": 300,
      "supports": ["envelopes", "heads", "sync", "proofs"]
    }
  },
  "issued_at": "2026-02-07T00:00:00Z"
}
```

**Why separate keys:**
- Operationally simpler: no need to understand Reticulum's internal key
  derivation to bind identity
- No cryptographic coupling: a vulnerability in one key system does not
  compromise the other
- Reticulum can upgrade its crypto independently
- The binding is verifiable: the node_attestation fact is signed by the Aegis
  key, attesting that "this Reticulum destination belongs to me"

**Binding verification:**
1. Receive a Reticulum message claiming to be from Aegis node X
2. Look up node X's latest `node_attestation` fact in the Spine store
3. Check that the `transports.reticulum.destination_hash` matches the sender
4. If a `revocation` exists for node X, distrust the binding

### 6.3 Model B (Optional: Derived Keys)

For advanced deployments, derive the Reticulum key material from the Aegis
Ed25519 seed. This eliminates the need for a separate binding attestation but
requires careful analysis of Reticulum's key model (X25519 for encryption,
Ed25519 for signing -- the Aegis Ed25519 key can potentially be converted to
X25519 via standard Curve25519 point conversion).

Model B is deferred to a future version.

---

## 7. Gateway Architecture: Radio to NATS Bridge

### 7.1 Gateway Components

```
┌────────────────────────────────────────────────────────────────┐
│                     Radio Gateway                              │
│                                                                │
│  ┌──────────────────┐   ┌─────────────────────────────┐       │
│  │ Reticulum Stack  │   │ Reticulum Adapter           │       │
│  │ (Python, RNS)    │   │ (Python sidecar to hushd)   │       │
│  │                  │   │                             │       │
│  │ Interfaces:      │   │ - Receive envelopes         │       │
│  │  - RNode (LoRa)  │◄─►│ - Validate (hash, sig, cap) │       │
│  │  - Serial        │   │ - Prioritize (revoc first)  │       │
│  │  - TCP/UDP       │   │ - Dedupe (envelope_hash)    │       │
│  │  - WiFi          │   │ - Rate-limit (per-peer)     │       │
│  └──────────────────┘   │ - Forward to Spine store    │       │
│                         └──────────────┬──────────────┘       │
│                                        │                       │
│  ┌─────────────────────────────────────▼──────────────────┐   │
│  │ Spine Store (SQLite)                                    │   │
│  │ - Envelopes by envelope_hash                           │   │
│  │ - Index by (issuer, seq)                               │   │
│  │ - Per-issuer head tracking                             │   │
│  │ - Fork detection                                       │   │
│  └─────────────────────────────────────┬──────────────────┘   │
│                                        │                       │
│  ┌─────────────────────────────────────▼──────────────────┐   │
│  │ NATS Bridge (optional)                                  │   │
│  │ - Subscribe: aegis.spine.envelope.>                    │   │
│  │ - Publish verified envelopes from Reticulum            │   │
│  │ - Forward NATS envelopes to Reticulum (with filter)    │   │
│  │ - Disclosure policy: what crosses the bridge           │   │
│  └────────────────────────────────────────────────────────┘   │
│                                                                │
│  ┌────────────────────────────────────────────────────────┐   │
│  │ Audit Log (JSONL, hash-chained)                        │   │
│  │ - Every forwarded envelope_hash                        │   │
│  │ - Every drop reason                                    │   │
│  │ - Every rate-limit event                               │   │
│  │ - prev_hash chain for tamper evidence                  │   │
│  └────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────┘
```

### 7.2 Disclosure Policy

Not all facts should cross the radio-NATS bridge in both directions. The gateway
enforces a configurable disclosure policy:

**Reticulum to NATS (inbound from field):**
- Allow: revocations, incidents, checkpoints, node attestations
- Filter: heartbeats (droppable), run facts (aggregate only)
- Block: raw telemetry, evidence bundles (these are pointers, not bulk data)

**NATS to Reticulum (outbound to field):**
- Allow: revocations (always), policy deltas, checkpoints
- Rate-limit: incidents, run facts (bandwidth-budgeted)
- Block: Tetragon raw events, Hubble flows (too high volume for radio)

### 7.3 Rate Limiting

The gateway implements per-peer token buckets:
- `bytes_per_second`: bounded by the measured Reticulum link capacity
- `envelopes_per_minute`: prevents flooding
- `unknown_issuer_quota`: bounded storage for envelopes from unrecognized issuers
- `revocation_always_allowed`: revocations bypass normal limits but have their own rate bucket

---

## 8. LXMF Store-and-Forward Integration

### 8.1 What LXMF Provides

LXMF (Lightweight Extensible Message Format) is Reticulum's native messaging
protocol. It adds store-and-forward semantics on top of Reticulum's transport:

- **Propagation Nodes:** When an LXMF Propagation Node exists on the network, it
  stores messages for offline recipients and delivers them when the recipient
  reconnects. Multiple Propagation Nodes automatically peer and synchronize,
  creating a distributed message store.

- **Delivery Acknowledgement:** LXMF provides unforgeable delivery
  acknowledgements -- the recipient's confirmation that a message was received
  and decrypted.

- **Minimal Overhead:** Complete LXMF message overhead is only 111 bytes.

- **No Registration Required:** LXMF addresses are derived directly from private
  keys. No accounts, no servers, no registration.

### 8.2 Mapping Spine Operations to LXMF

| Spine Operation | LXMF Mechanism | Notes |
|----------------|---------------|-------|
| Envelope delivery | LXMF message (direct or via propagation) | Envelope is the message payload |
| Head announcement | LXMF message to known peers + Reticulum announce piggyback | Compact `(issuer, seq, head_hash, signature)` |
| Sync request | LXMF message to specific peer | Request missing `(issuer, from_seq..to_seq)` |
| Sync response | LXMF message(s) with envelope batch | Chunked to fit link budget |
| Delivery confirmation | LXMF delivery receipt | Proof that the envelope reached its destination |

### 8.3 LXMF vs Direct Reticulum Sends

**Use LXMF when:**
- The recipient may be offline (store-and-forward via Propagation Nodes)
- Delivery acknowledgement is needed (revocations, critical policy updates)
- Messages are not time-sensitive (minutes-to-hours delivery acceptable)

**Use direct Reticulum sends when:**
- Both peers are online and connected
- Latency matters (real-time sync operations)
- The message is ephemeral (heartbeats, transient head announcements)

### 8.4 Propagation Node as Spine Cache

An LXMF Propagation Node running on the Reticulum mesh can serve as a
distributed Spine cache:

1. Propagation Nodes automatically peer and synchronize stored messages
2. Offline nodes reconnect and retrieve missed envelopes from any available
   Propagation Node
3. The Propagation Node does not need to understand Spine semantics -- it just
   stores and forwards LXMF messages
4. Spine-level deduplication (by `envelope_hash`) handles any duplicates from
   multiple Propagation Nodes delivering the same message

---

## 9. Compact Encoding for Constrained Links

### 9.1 The Problem: 500-Byte MTU

Reticulum's minimum supported MTU is approximately 500 bytes. A typical
`SignedEnvelope` in canonical JSON is 500-1000 bytes. On the slowest links,
encoding efficiency directly determines whether a fact can be transmitted in
minutes or hours.

### 9.2 Encoding Options

The Reticulum transport profile specifies three supported compact encodings:

**Option A: CBOR encoding**
- Convert the canonical JSON object to CBOR
- Typical compression: 30-50% smaller than JSON
- CBOR is a standard (RFC 8949) with implementations in every language
- A 500-byte JSON revocation becomes ~250-350 bytes in CBOR

**Option B: zstd-compressed canonical JSON**
- Prefix `Z1` + zstd-compressed UTF-8 JSON bytes
- Better compression ratio for larger payloads (~60-70% reduction)
- Higher CPU cost; receivers must bound decompression buffers (DoS protection)

**Option C: Purpose-built compact binary envelope**
- Fixed-layout binary header + variable body
- Maximum compression for known schemas
- A revocation could fit in ~100 bytes (32-byte pubkey hash + 32-byte target hash
  + 8-byte seq + 64-byte signature + minimal header)
- Must be deterministically expandable to canonical JSON for hash/signature verification

**Reference implementation: zlib framing**
- Prefix `Z1` + zlib-compressed UTF-8 JSON bytes
- Simpler than zstd; sufficient for small payloads
- Receivers bound decompression to prevent zip bombs

### 9.3 Fragmentation

For envelopes that exceed the link MTU even after compression:

- Prefix `F1` + fixed header (fragment index, total fragments, message ID)
- Fragments reassembled at the receiving adapter
- Reassembly buffer bounded in size and time (prevent fragment flood DoS)
- Alternative: rely on Reticulum's own transport-layer fragmentation where
  available (link-based sessions handle this automatically)

### 9.4 Normative Constraint

Regardless of transport encoding, a node must be able to validate an envelope
from a decoded JSON value. The transport encoding must not require access to the
original sender bytes for verification. This keeps the truth layer independent
of the transport.

---

## 10. Implementation Plan

### Phase 0: Prototype Adapter (Developer Mode)

**Goal:** Two nodes exchange signed envelopes over Reticulum. Basic validation
and deduplication work.

**Deliverables:**
- Reticulum adapter as a Python sidecar process (Reticulum is Python-native)
- Carries `SignedEnvelope` and `head_announcement` objects
- Stores envelopes locally in SQLite (same schema as Spine store)
- Peer management via `cyntra spine reticulum peers import/export`
- CLI: `cyntra spine reticulum start --mode reticulum --data-dir .cyntra/spine`

**Acceptance criteria:**
- Two nodes exchange envelopes; envelope validation passes; dedupe works
- Envelopes signed on one node verify on the other
- `(issuer, seq)` monotonicity enforced

**Estimated scope:** ~1,500 lines Python (adapter + CLI commands)

### Phase 1: Sync + Prioritization

**Goal:** Nodes can go offline, rejoin, and catch up to peers. Revocations
are always delivered first.

**Deliverables:**
- `sync_request` / `sync_response` over Reticulum
- Priority scheduling (revocations first, heartbeats last)
- Bandwidth budgeting per link
- LXMF integration for store-and-forward delivery

**Acceptance criteria:**
- Node goes offline for 1 hour, reconnects, catches up to peers within
  bandwidth budget
- Revocations bypass normal queue and are delivered first
- Heartbeats are dropped on links below 100 bps

### Phase 2: Gateway to Plane B / Plane A-L

**Goal:** Envelopes cross between Reticulum and NATS/libp2p.

**Deliverables:**
- Reticulum-to-NATS gateway (regional cluster ingestion/egress)
- Disclosure policy configuration (YAML)
- Rate limiting and audit logging
- Optional: Reticulum-to-libp2p gateway for public internet bridging

**Acceptance criteria:**
- Envelope created in a NATS cluster propagates to an off-grid node over
  Reticulum and validates
- Envelope created on an off-grid node propagates to NATS and is checkpointed
  by AegisNet
- Gateway audit log records all forwarded/dropped envelope hashes

### Phase 3: Hardened Ops + Radio Deployments

**Goal:** Production-ready operation on constrained carriers.

**Deliverables:**
- Operational tooling: config, metrics (Prometheus exporter), health checks
- Key storage recommendations (TPM where available)
- Compact binary encoding for high-priority facts
- Validated on LoRa (RNode), serial, and under partition scenarios
- Raspberry Pi gateway reference image

**Acceptance criteria:**
- 24-hour soak test on LoRa with intermittent connectivity
- Revocation delivery under 60 seconds on LoRa at 1,200 bps
- Gateway survives NATS restart and Reticulum interface flap without data loss

---

## 11. Open Questions

### 11.1 Compact Binary Envelope Format

Should the Reticulum plane define a purpose-built compact binary envelope to
guarantee delivery of high-priority facts within a single ~500-byte packet?

**Arguments for:** Revocations and checkpoints would fit in a single LoRa frame,
eliminating fragmentation overhead and reducing delivery time on extremely slow
links.

**Arguments against:** Adds a second serialization format that must be
maintained and tested. CBOR already provides good compression for small payloads.
The complexity cost may not be justified unless links below 100 bps are common.

**Recommendation:** Start with CBOR (Phase 0-1). Measure actual payload sizes
on real links. Only introduce a compact binary format in Phase 3 if CBOR proves
insufficient.

### 11.2 LXMF Store-and-Forward vs Direct Sends

When should the adapter use LXMF (store-and-forward with delivery
acknowledgement) versus direct Reticulum sends (lower latency, no persistence)?

**Working assumption:** Use LXMF for all priority 1-4 facts (revocations,
checkpoints, incidents, policy deltas) because delivery reliability matters
more than latency. Use direct sends for priority 5-7 facts (run facts,
attestations, heartbeats) because they are ephemeral and catch-up sync
handles missed deliveries.

### 11.3 Key Derivation: Model A vs Model B

Should Reticulum transport keys be separate from Aegis identity keys (Model A)
or derived from them (Model B)?

**Working assumption:** Model A (separate keys) for Phase 0-2. The binding
attestation inside a signed `node_attestation` fact provides verifiable
association without coupling the key systems. Model B can be evaluated in
Phase 3 once operational experience clarifies the key management burden.

### 11.4 Merkle Proofs Over Constrained Links

How should gateways serve Merkle inclusion proofs over Reticulum without turning
proof requests into a DoS vector?

**Considerations:**
- A Merkle inclusion proof for a 10,000-leaf tree is ~10 hashes (320 bytes) --
  fits in a single Reticulum packet
- For trees with millions of leaves, proofs grow to ~20 hashes (640 bytes) --
  requires fragmentation or compression
- Proof serving should be rate-limited and only available to authenticated peers
- Alternative: bundle proofs with envelopes at the gateway (pre-compute and
  attach proof when forwarding from NATS to Reticulum), so field nodes never
  need to request proofs

**Recommendation:** Bundle proofs at the gateway. When the NATS-to-Reticulum
gateway forwards an envelope, it also attaches the latest inclusion proof for
that envelope. Field nodes receive self-contained verifiable packets.

### 11.5 Reticulum Adapter Language

The Reticulum stack is Python-native (`rns` package on PyPI). ClawdStrike is
Rust-first. The adapter is best implemented in Python (direct RNS API access)
as a sidecar process communicating with hushd via Unix socket or gRPC.

**Alternative:** A Rust implementation would require either:
- Porting Reticulum's core networking to Rust (massive effort, unclear benefit)
- Using PyO3 to embed Python in Rust (complex build, fragile)
- Communicating with a Python Reticulum instance via IPC (essentially the
  sidecar approach with extra steps)

**Recommendation:** Python sidecar. The adapter is primarily I/O-bound (waiting
on radio transmissions), not CPU-bound. Python is the right choice for
interacting with a Python library.

---

## 12. References

### Internal Specifications

- [Aegis Spine Specification v1](../../../../platform/docs/specs/cyntra-aegis-spine.md) -- Layer 4 envelope/fact schemas, heads, sync, checkpoint proofs
- [Reticulum Transport Profile v0.1](../../../../platform/docs/specs/cyntra-aegis-spine-reticulum.md) -- How Spine objects are carried over Reticulum
- [Reticulum Field Manual](../../../../platform/docs/offgrid/reticulum_manual.md) -- Operator guide for offline Spine nodes
- [AegisNet Architecture](../../../aegis/apps/aegis/services/aegisnet/ARCHITECTURE.md) -- Verifiable log system on Kubernetes

### Internal Research Documents

- [Architecture Vision](./architecture-vision.md) -- Full five-layer security stack vision
- [Marketplace Trust Evolution](./marketplace-trust-evolution.md) -- Multi-curator, AegisNet notary, EAS, IPFS, P2P
- [Tetragon Integration](./tetragon-integration.md) -- Kernel runtime security and AegisNet pipeline
- [Cilium Network Security](./cilium-network-security.md) -- CNI, SPIRE mTLS, Hubble, CiliumNetworkPolicy

### ClawdStrike Source

- `apps/desktop/src-tauri/src/marketplace_discovery.rs` -- Existing libp2p gossipsub P2P discovery
- `crates/clawdstrike/src/marketplace_feed.rs` -- Feed signing and verification
- `crates/clawdstrike/src/policy_bundle.rs` -- Bundle signing (Ed25519 + SHA-256)
- `crates/hush-core/` -- Cryptographic primitives (Ed25519, SHA-256, canonical JSON)

### Reticulum External References

- [Reticulum GitHub](https://github.com/markqvist/Reticulum) -- Source code and documentation
- [Reticulum Manual v1.1.3](https://reticulum.network/manual/whatis.html) -- Architecture and capabilities
- [LXMF Protocol](https://github.com/markqvist/LXMF) -- Store-and-forward messaging for Reticulum
- [Reticulum Communications Hardware](https://reticulum.network/manual/hardware.html) -- RNode and supported devices
- [Understanding Reticulum](https://reticulum.network/manual/understanding.html) -- Cryptography, routing, identity
- [Reticulum Interface Configuration](https://reticulum.network/manual/interfaces.html) -- LoRa, serial, TCP/UDP setup
- [RMAP.WORLD](https://rmap.world/) -- Real-world Reticulum network deployment map

### Standards

- [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962) -- Certificate Transparency (Merkle tree proofs)
- [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) -- JSON Canonicalization Scheme (JCS)
- [RFC 8949](https://datatracker.ietf.org/doc/html/rfc8949) -- Concise Binary Object Representation (CBOR)
