# Spec #12: Reticulum Transport Adapter (Plane A-R)

> Python sidecar for off-grid envelope distribution over LoRa, packet radio,
> serial, WiFi, and TCP/UDP via the Reticulum mesh networking stack.
>
> **Status:** Draft | **Date:** 2026-02-07
> **Effort Estimate:** 8-10 engineer-days
> **Branch:** `feat/sdr-execution`

---

## 1. Summary / Objective

Implement a **Python sidecar process** (the "Reticulum adapter") that bridges
the Aegis Spine protocol to the Reticulum mesh networking stack. This enables
ClawdStrike's signed envelopes -- revocations, checkpoints, incidents, policy
deltas -- to propagate over off-grid carriers (LoRa, packet radio, serial,
WiFi, TCP/UDP) as **Plane A-R**, complementing the existing NATS (Plane B) and
libp2p (Plane A-L) transports.

The adapter carries the **same `SignedEnvelope` (clawdstrike.spine.envelope.v1)**
that already flows through NATS and libp2p. Only the transport differs.

**Key deliverables:**

1. Python sidecar process using the `rns` (Reticulum) PyPI package
2. LXMF integration for store-and-forward delivery of high-priority facts
3. 7-tier priority scheduling with bandwidth budgeting per link
4. Translation gateway bridging Plane A-R to Plane B (NATS JetStream)
5. Bandwidth budgeting and rate limiting for constrained links (down to ~5 bps)
6. Raspberry Pi reference gateway image (LoRa radio + Ethernet)

---

## 2. Current State

### 2.1 Spine Envelope Infrastructure

The `crates/spine/` crate already provides the core primitives the adapter
will carry:

- **`crates/spine/src/envelope.rs`** -- `SignedEnvelope` build/sign/verify
  using `hush_core` Ed25519 + RFC 8785 canonical JSON. Key functions:
  `build_signed_envelope()`, `verify_envelope()`, `sign_envelope()`. Envelopes
  contain `schema`, `issuer` (format `aegis:ed25519:<hex_pubkey>`), `seq`,
  `prev_envelope_hash`, `issued_at`, `capability_token`, `fact`,
  `envelope_hash`, and `signature`.
- **`crates/spine/src/nats_transport.rs`** -- NATS connection with JetStream
  helpers: `connect()`, `connect_with_auth()`, `ensure_kv()`, `ensure_stream()`.
  The adapter's NATS bridge will use these same patterns.
- **`crates/spine/src/trust.rs`** -- `TrustBundle` for mesh-grade verification
  with `allowed_log_ids`, `allowed_witness_node_ids`,
  `allowed_receipt_signer_node_ids`, `witness_quorum`, and enforcement tier
  constraints. The adapter must respect these same trust constraints.

### 2.2 Multi-Agent Identity

The `crates/hush-multi-agent/` crate provides:

- `AgentIdentity` with Ed25519 public key, role, trust level, capabilities
- `SignedDelegationToken` for capability grants with time bounds and
  redelegation chains
- `RevocationStore` (in-memory and SQLite) for token revocation

The Reticulum adapter will bind Aegis Ed25519 identities to Reticulum
destination hashes via signed `node_attestation` facts.

### 2.3 What Does Not Exist Yet

- No Reticulum integration code (Python or Rust)
- No Plane A-R transport adapter
- No LXMF message handling
- No priority scheduling or bandwidth budgeting for constrained links
- No translation gateway between Reticulum and NATS
- No compact encoding (CBOR) for ~500-byte MTU links
- No `docs/specs/` directory contents (this is the first spec)

---

## 3. Target State

A working **Python sidecar** (`spine-reticulum-adapter`) that:

1. Runs alongside `hushd` (or standalone) communicating via Unix socket or TCP
2. Sends and receives `SignedEnvelope` objects over Reticulum
3. Prioritizes revocations above all other fact types
4. Budgets bandwidth per link, dropping low-priority facts on slow links
5. Uses LXMF for store-and-forward delivery of priority 1-4 facts
6. Uses direct Reticulum sends for priority 5-7 facts
7. Stores received envelopes in a local SQLite database
8. Deduplicates by `envelope_hash`
9. Enforces `(issuer, seq)` monotonicity and detects forks
10. Optionally bridges to NATS (translation gateway mode)
11. Produces a tamper-evident audit log (JSONL + hash-chained entries)

### Architecture Diagram

```
                                      ┌─────────────────────────┐
                                      │   hushd (Rust daemon)   │
                                      │   or Spine store        │
                                      └────────┬────────────────┘
                                               │ Unix socket / TCP
                                               │ (JSON-over-line protocol)
┌──────────────────────────────────────────────▼───────────────────────┐
│                    spine-reticulum-adapter (Python)                   │
│                                                                      │
│  ┌──────────────┐  ┌──────────────────┐  ┌────────────────────────┐ │
│  │ RNS Stack    │  │ Priority Queue   │  │ Spine Store (SQLite)   │ │
│  │ Interfaces:  │  │ 7-tier scheduler │  │ Envelopes by hash      │ │
│  │  - RNode LoRa│  │ BW budgeting    │  │ Index by (issuer,seq)  │ │
│  │  - Serial    │  │ Rate limiter    │  │ Head tracking          │ │
│  │  - TCP/UDP   │  │ Revoc priority  │  │ Fork detection         │ │
│  │  - WiFi      │  └──────────────────┘  └────────────────────────┘ │
│  └──────────────┘                                                    │
│  ┌──────────────┐  ┌──────────────────┐  ┌────────────────────────┐ │
│  │ LXMF Client  │  │ CBOR Encoder    │  │ Audit Log (JSONL)      │ │
│  │ Store & fwd  │  │ ~30-50% smaller │  │ Hash-chained entries   │ │
│  │ Delivery ACK │  │ Fragmentation   │  │ Tamper-evident         │ │
│  └──────────────┘  └──────────────────┘  └────────────────────────┘ │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ NATS Bridge (optional gateway mode)                          │   │
│  │ Subscribe: clawdstrike.spine.envelope.>                           │   │
│  │ Publish verified envelopes from Reticulum                   │   │
│  │ Forward NATS envelopes to Reticulum (with disclosure filter)│   │
│  └──────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 4. Implementation Plan

### Phase 0: Prototype Adapter (Steps 1-6)

#### Step 1: Project Scaffold

Create `spine/reticulum/` as a Python package:

```
spine/reticulum/
├── pyproject.toml          # uv/pip project with rns, lxmf, cbor2, nats-py deps
├── src/
│   └── spine_reticulum/
│       ├── __init__.py
│       ├── adapter.py      # Main adapter class
│       ├── config.py       # YAML/TOML configuration
│       ├── envelope.py     # Envelope encode/decode/verify (Python port)
│       ├── store.py        # SQLite envelope store
│       ├── priority.py     # Priority queue + BW budget scheduler
│       ├── gateway.py      # NATS <-> Reticulum translation gateway
│       ├── identity.py     # Reticulum destination binding
│       ├── audit.py        # Hash-chained JSONL audit log
│       ├── encoding.py     # CBOR compact encoding + fragmentation
│       └── cli.py          # CLI entry points
├── tests/
│   ├── test_envelope.py
│   ├── test_store.py
│   ├── test_priority.py
│   ├── test_gateway.py
│   ├── test_encoding.py
│   └── test_audit.py
└── README.md
```

**`pyproject.toml` dependencies:**

```toml
[project]
name = "spine-reticulum-adapter"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = [
    "rns>=0.9.3",           # Reticulum Network Stack
    "lxmf>=0.6.0",          # LXMF store-and-forward messaging
    "cbor2>=5.6.0",          # CBOR encoding (RFC 8949)
    "nats-py>=2.9.0",        # NATS client (for gateway mode)
    "ed25519-blake2b>=1.4",  # Ed25519 verification
    "rfc8785>=0.1.2",        # RFC 8785 canonical JSON (JCS) by Trail of Bits
    "pyyaml>=6.0",           # Config parsing
    "click>=8.1",            # CLI framework
]

[project.optional-dependencies]
dev = ["pytest>=8.0", "pytest-asyncio>=0.24"]

[project.scripts]
spine-reticulum = "spine_reticulum.cli:main"
```

#### Step 2: Envelope Handling (Python Port)

Implement `envelope.py` to mirror the Rust `crates/spine/src/envelope.rs`:

```python
# spine_reticulum/envelope.py

import hashlib
import json
from typing import Optional

import rfc8785
from ed25519 import VerifyingKey

ENVELOPE_SCHEMA_V1 = "aegis.spine.envelope.v1"


def canonical_json_bytes(value: dict) -> bytes:
    """RFC 8785 canonical JSON encoding."""
    return rfc8785.dumps(value)


def compute_envelope_hash(unsigned_envelope: dict) -> str:
    """Compute 0x-prefixed SHA-256 hash of canonical JSON."""
    canonical = canonical_json_bytes(unsigned_envelope)
    digest = hashlib.sha256(canonical).hexdigest()
    return f"0x{digest}"


def verify_envelope(envelope: dict) -> bool:
    """
    Verify envelope hash integrity and Ed25519 signature.

    Strips envelope_hash and signature, recomputes canonical bytes,
    checks hash match, then verifies signature against issuer key.
    """
    issuer = envelope.get("issuer", "")
    sig_hex = envelope.get("signature", "")
    claimed_hash = envelope.get("envelope_hash", "")

    if not issuer.startswith("aegis:ed25519:"):
        raise ValueError(f"Invalid issuer format: {issuer}")

    pubkey_hex = issuer[len("aegis:ed25519:"):]
    if len(pubkey_hex) != 64:
        raise ValueError(f"Invalid pubkey length: {len(pubkey_hex)}")

    # Reconstruct unsigned envelope
    unsigned = {k: v for k, v in envelope.items()
                if k not in ("envelope_hash", "signature")}

    computed_hash = compute_envelope_hash(unsigned)
    if computed_hash != claimed_hash:
        raise ValueError(
            f"Hash mismatch: expected {claimed_hash}, computed {computed_hash}"
        )

    # Verify Ed25519 signature
    canonical = canonical_json_bytes(unsigned)
    vk = VerifyingKey(bytes.fromhex(pubkey_hex))
    sig_bytes = bytes.fromhex(sig_hex.removeprefix("0x"))
    try:
        vk.verify(sig_bytes, canonical)
        return True
    except Exception:
        return False
```

**Cross-language determinism requirement:** The Python `rfc8785` library
(from Trail of Bits) implements RFC 8785 (JSON Canonicalization Scheme) and
must produce byte-identical output to the Rust `hush_core::canonicalize_json()`
for the same input. Note: do NOT use the `canonicaljson` package, which
implements RFC 7159 (a different standard). This will be validated by
cross-language tests in Step 6.

#### Step 3: SQLite Envelope Store

Implement `store.py` with the same logical schema as the Spine store:

```python
# spine_reticulum/store.py

import sqlite3
from dataclasses import dataclass
from typing import Optional


@dataclass
class StoredEnvelope:
    envelope_hash: str
    issuer: str
    seq: int
    prev_envelope_hash: Optional[str]
    issued_at: str
    fact_schema: str
    raw_json: str
    received_at: str


class SpineStore:
    """SQLite-backed envelope store with dedup and monotonicity checks."""

    def __init__(self, db_path: str):
        self._conn = sqlite3.connect(db_path)
        self._create_tables()

    def _create_tables(self):
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS envelopes (
                envelope_hash TEXT PRIMARY KEY,
                issuer TEXT NOT NULL,
                seq INTEGER NOT NULL,
                prev_envelope_hash TEXT,
                issued_at TEXT NOT NULL,
                fact_schema TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                received_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_issuer_seq
                ON envelopes(issuer, seq);
            CREATE TABLE IF NOT EXISTS heads (
                issuer TEXT PRIMARY KEY,
                seq INTEGER NOT NULL,
                envelope_hash TEXT NOT NULL
            );
        """)
        self._conn.commit()

    def has_envelope(self, envelope_hash: str) -> bool:
        """Dedup check by envelope_hash."""
        cur = self._conn.execute(
            "SELECT 1 FROM envelopes WHERE envelope_hash = ?",
            (envelope_hash,)
        )
        return cur.fetchone() is not None

    def insert_envelope(self, envelope: dict) -> bool:
        """
        Insert envelope if not duplicate and seq is monotonically increasing.
        Returns True if inserted, False if duplicate or fork detected.
        """
        env_hash = envelope["envelope_hash"]
        issuer = envelope["issuer"]
        seq = envelope["seq"]

        if self.has_envelope(env_hash):
            return False  # dedup

        # Check monotonicity
        head = self.get_head(issuer)
        if head is not None and seq <= head["seq"]:
            # Fork detection: same issuer, seq <= known head
            if seq == head["seq"] and env_hash != head["envelope_hash"]:
                # Fork: two different envelopes with same (issuer, seq)
                raise ForkDetected(issuer, seq, head["envelope_hash"], env_hash)
            return False  # already have this or earlier seq

        fact_schema = envelope.get("fact", {}).get("schema", "unknown")
        import json
        self._conn.execute(
            """INSERT INTO envelopes
               (envelope_hash, issuer, seq, prev_envelope_hash,
                issued_at, fact_schema, raw_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (env_hash, issuer, seq, envelope.get("prev_envelope_hash"),
             envelope["issued_at"], fact_schema, json.dumps(envelope))
        )
        self._conn.execute(
            """INSERT OR REPLACE INTO heads (issuer, seq, envelope_hash)
               VALUES (?, ?, ?)""",
            (issuer, seq, env_hash)
        )
        self._conn.commit()
        return True

    def get_head(self, issuer: str) -> Optional[dict]:
        cur = self._conn.execute(
            "SELECT seq, envelope_hash FROM heads WHERE issuer = ?",
            (issuer,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {"seq": row[0], "envelope_hash": row[1]}

    def get_envelopes_range(self, issuer: str, from_seq: int,
                            to_seq: int) -> list[dict]:
        """Retrieve envelopes for sync response."""
        import json
        cur = self._conn.execute(
            """SELECT raw_json FROM envelopes
               WHERE issuer = ? AND seq >= ? AND seq <= ?
               ORDER BY seq ASC""",
            (issuer, from_seq, to_seq)
        )
        return [json.loads(row[0]) for row in cur.fetchall()]


class ForkDetected(Exception):
    def __init__(self, issuer, seq, existing_hash, new_hash):
        self.issuer = issuer
        self.seq = seq
        self.existing_hash = existing_hash
        self.new_hash = new_hash
        super().__init__(
            f"Fork detected for {issuer} at seq {seq}: "
            f"{existing_hash} vs {new_hash}"
        )
```

#### Step 4: Priority Queue and Bandwidth Budget Scheduler

Implement 7-tier priority scheduling per the research doc (Section 5):

```python
# spine_reticulum/priority.py

import heapq
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class Priority(IntEnum):
    """7-tier priority from highest (1) to lowest (7)."""
    REVOCATION = 1
    CHECKPOINT = 2
    INCIDENT = 3
    POLICY_DELTA = 4
    RUN = 5
    NODE_ATTESTATION = 6
    HEARTBEAT = 7


# Map fact schema -> priority
SCHEMA_PRIORITY = {
    "clawdstrike.spine.fact.revocation.v1": Priority.REVOCATION,
    "clawdstrike.spine.fact.log_checkpoint.v1": Priority.CHECKPOINT,
    "clawdstrike.spine.fact.incident.v1": Priority.INCIDENT,
    "clawdstrike.spine.fact.policy_delta.v1": Priority.POLICY_DELTA,
    "clawdstrike.spine.fact.run.v1": Priority.RUN,
    "clawdstrike.spine.fact.node_attestation.v1": Priority.NODE_ATTESTATION,
    "clawdstrike.spine.fact.heartbeat.v1": Priority.HEARTBEAT,
}


def priority_for_envelope(envelope: dict) -> Priority:
    """Determine priority from the fact.schema field."""
    fact_schema = envelope.get("fact", {}).get("schema", "")
    return SCHEMA_PRIORITY.get(fact_schema, Priority.HEARTBEAT)


@dataclass(order=True)
class PrioritizedEnvelope:
    priority: int
    timestamp: float = field(compare=True)
    envelope: dict = field(compare=False)
    size_bytes: int = field(compare=False, default=0)


class BandwidthBudgetScheduler:
    """
    Schedules envelope transmission respecting link bandwidth.

    Budget allocation (from research doc Section 5.2):
      - Revocations: unlimited (but rate-bucketed)
      - Checkpoints: 30% of remaining
      - Incidents: 25% of remaining
      - Remaining: split among lower priorities by weight
    """

    def __init__(self, link_bps: float,
                 revocation_rate_limit: int = 10):
        self._queue: list[PrioritizedEnvelope] = []
        self._link_bps = link_bps
        self._revocation_rate_limit = revocation_rate_limit  # per hour
        self._revocation_count_this_hour = 0
        self._hour_start = time.time()

        # Drop thresholds: below this BPS, drop these priorities
        self._drop_thresholds = {
            Priority.HEARTBEAT: 100,       # Drop heartbeats below 100 bps
            Priority.NODE_ATTESTATION: 50, # Drop attestations below 50 bps
            Priority.RUN: 20,              # Drop run facts below 20 bps
        }

    def enqueue(self, envelope: dict, size_bytes: int):
        """Add envelope to priority queue, applying drop rules."""
        priority = priority_for_envelope(envelope)

        # Check if this priority should be dropped on this link
        threshold = self._drop_thresholds.get(priority)
        if threshold is not None and self._link_bps < threshold:
            return  # silently drop

        entry = PrioritizedEnvelope(
            priority=priority.value,
            timestamp=time.time(),
            envelope=envelope,
            size_bytes=size_bytes,
        )
        heapq.heappush(self._queue, entry)

    def dequeue(self) -> Optional[dict]:
        """Get next envelope to transmit, respecting rate limits."""
        if not self._queue:
            return None

        # Reset hourly revocation counter
        now = time.time()
        if now - self._hour_start >= 3600:
            self._revocation_count_this_hour = 0
            self._hour_start = now

        entry = heapq.heappop(self._queue)

        # Rate-limit revocations (anti-spam)
        if entry.priority == Priority.REVOCATION:
            if self._revocation_count_this_hour >= self._revocation_rate_limit:
                return self.dequeue()  # skip, try next
            self._revocation_count_this_hour += 1

        return entry.envelope

    @property
    def pending_count(self) -> int:
        return len(self._queue)
```

#### Step 5: CBOR Compact Encoding

Implement CBOR encoding for constrained links (Section 9 of research doc):

```python
# spine_reticulum/encoding.py

import json
from typing import Optional

import cbor2


CBOR_MAGIC = b"CB"          # 2-byte prefix for CBOR-encoded envelopes
FRAGMENT_MAGIC = b"F1"      # 2-byte prefix for fragments
MAX_REASSEMBLY_BUFFER = 64  # max concurrent fragment reassemblies
MAX_FRAGMENT_AGE_SECS = 300 # discard incomplete reassemblies after 5 min


def encode_envelope_cbor(envelope: dict) -> bytes:
    """Encode envelope as CBOR with magic prefix."""
    cbor_bytes = cbor2.dumps(envelope)
    return CBOR_MAGIC + cbor_bytes


def decode_envelope(data: bytes) -> dict:
    """Decode envelope from either CBOR or JSON."""
    if data[:2] == CBOR_MAGIC:
        return cbor2.loads(data[2:])
    elif data[:2] == FRAGMENT_MAGIC:
        raise ValueError("Fragment received; use FragmentReassembler")
    else:
        return json.loads(data)


def fragment_envelope(data: bytes, mtu: int = 500,
                      message_id: bytes = b"") -> list[bytes]:
    """
    Fragment encoded data into MTU-sized chunks.

    Fragment header: F1 + msg_id(4) + index(2) + total(2) = 10 bytes overhead
    """
    payload_size = mtu - 10  # 10 bytes header overhead
    if payload_size <= 0:
        raise ValueError(f"MTU {mtu} too small for fragmentation")

    if len(data) <= mtu:
        return [data]  # no fragmentation needed

    import os
    if not message_id:
        message_id = os.urandom(4)

    fragments = []
    total = (len(data) + payload_size - 1) // payload_size
    if total > 65535:
        raise ValueError("Data too large to fragment")

    for i in range(total):
        chunk = data[i * payload_size:(i + 1) * payload_size]
        header = (FRAGMENT_MAGIC + message_id
                  + i.to_bytes(2, "big") + total.to_bytes(2, "big"))
        fragments.append(header + chunk)

    return fragments
```

#### Step 6: Cross-Language Envelope Verification Tests

Create tests that verify Python envelope handling produces identical results
to the Rust implementation:

```python
# tests/test_envelope.py

import json
import subprocess

def test_canonical_json_determinism():
    """
    Verify that Python canonical JSON produces byte-identical output
    to Rust hush_core::canonicalize_json() for the same input.
    """
    test_cases = [
        {"z": 1, "a": 2},                    # key ordering
        {"nested": {"b": 1, "a": 2}},        # nested key ordering
        {"unicode": "caf\u00e9"},             # unicode normalization
        {"numbers": [1, 2.0, -3, 0]},         # number encoding
        {"null_field": None, "bool": True},    # null and bool
    ]
    for case in test_cases:
        py_canonical = rfc8785.dumps(case)
        # Compare against a pre-generated fixture from Rust
        # (generated by: cargo test -p spine -- --test-threads=1
        #  dump_canonical_fixtures)
        fixture_path = f"tests/fixtures/canonical_{hash(str(case))}.json"
        # In CI, these fixtures are generated by a Rust test and committed
        assert py_canonical is not None  # placeholder


def test_envelope_verify_cross_language():
    """
    Verify that a Rust-signed envelope can be verified in Python.
    """
    # Pre-generated by: cargo test -p spine -- generate_test_envelope
    fixture = json.loads(open("tests/fixtures/rust_signed_envelope.json").read())
    assert verify_envelope(fixture) is True
```

### Phase 1: Sync + Prioritization (Steps 7-9)

#### Step 7: Head Announcements and Sync Protocol

Implement the Spine sync protocol over Reticulum:

- **Head announcement:** Compact message `(issuer, seq, head_hash, signature)`
  piggybacked on Reticulum announces and sent to known peers
- **Sync request:** `{type: "sync_request", issuer: "...", from_seq: N, to_seq: M}`
  sent to a specific peer when the local head is behind
- **Sync response:** Batch of envelopes for the requested range, chunked to
  fit within the link budget

Message types over Reticulum:

| Message Type | Reticulum Mechanism | LXMF? |
|---|---|---|
| `head_announcement` | Announce piggyback + LXMF | Direct for online peers, LXMF for offline |
| `sync_request` | LXMF message to specific peer | Yes (delivery matters) |
| `sync_response` | LXMF message(s) with batched envelopes | Yes (chunked) |
| `envelope` (single) | LXMF for priority 1-4, direct for 5-7 | Conditional |

#### Step 8: LXMF Store-and-Forward Integration

```python
# spine_reticulum/adapter.py (LXMF integration sketch)

import RNS
import LXMF


class ReticulumAdapter:
    """Main adapter class bridging Spine to Reticulum."""

    def __init__(self, config):
        self._config = config
        self._reticulum = RNS.Reticulum(config.reticulum_config_dir)
        self._identity = RNS.Identity(config.identity_path)

        # LXMF for store-and-forward
        self._lxmf_router = LXMF.LXMRouter(
            identity=self._identity,
            storagepath=config.lxmf_storage_dir,
        )
        self._lxmf_destination = self._lxmf_router.register_delivery_identity(
            self._identity,
            display_name=config.node_name,
        )
        self._lxmf_router.register_delivery_callback(self._on_lxmf_delivery)

        # Local state
        self._store = SpineStore(config.db_path)
        self._scheduler = BandwidthBudgetScheduler(
            link_bps=config.default_link_bps,
            revocation_rate_limit=config.revocation_rate_limit_per_hour,
        )
        self._audit_log = AuditLog(config.audit_log_path)
        self._peers = {}  # destination_hash -> peer info

    def _on_lxmf_delivery(self, message):
        """Handle incoming LXMF message containing a Spine envelope."""
        try:
            envelope = decode_envelope(message.content)
            if not verify_envelope(envelope):
                self._audit_log.log_drop(
                    envelope.get("envelope_hash", "unknown"),
                    reason="signature_verification_failed"
                )
                return

            inserted = self._store.insert_envelope(envelope)
            if inserted:
                self._audit_log.log_forward(
                    envelope["envelope_hash"],
                    direction="inbound",
                    source=str(message.source_hash),
                )
                # Re-broadcast to other peers if applicable
                self._rebroadcast(envelope, exclude=message.source_hash)

        except ForkDetected as e:
            self._audit_log.log_fork(e.issuer, e.seq,
                                     e.existing_hash, e.new_hash)
        except Exception as e:
            self._audit_log.log_error(str(e))

    def send_envelope(self, envelope: dict, peer_destination=None):
        """Send envelope to a specific peer or broadcast to all."""
        priority = priority_for_envelope(envelope)
        encoded = encode_envelope_cbor(envelope)

        if priority <= Priority.POLICY_DELTA:
            # Priority 1-4: use LXMF (reliable, store-and-forward)
            self._send_via_lxmf(encoded, peer_destination)
        else:
            # Priority 5-7: use direct Reticulum send (ephemeral)
            self._send_direct(encoded, peer_destination)

    def _send_via_lxmf(self, data: bytes, destination=None):
        """Send via LXMF with delivery acknowledgement."""
        if destination:
            msg = LXMF.LXMessage(
                destination=destination,
                source=self._lxmf_destination,
                content=data,
                desired_method=LXMF.LXMessage.DIRECT,
            )
            msg.try_propagation_on_fail = True
            self._lxmf_router.handle_outbound(msg)
        else:
            for peer_dest in self._peers.values():
                msg = LXMF.LXMessage(
                    destination=peer_dest,
                    source=self._lxmf_destination,
                    content=data,
                    desired_method=LXMF.LXMessage.DIRECT,
                )
                msg.try_propagation_on_fail = True
                self._lxmf_router.handle_outbound(msg)
```

#### Step 9: Bandwidth Budget Enforcement

Per link, the adapter measures or configures available bandwidth and applies
the budget from research doc Section 5.2:

```yaml
# Config: ~/.spine-reticulum/config.yaml

reticulum:
  config_dir: "~/.reticulum"
  identity_path: "~/.spine-reticulum/identity"

adapter:
  node_name: "field-node-alpha"
  db_path: "~/.spine-reticulum/spine.db"
  audit_log_path: "~/.spine-reticulum/audit.jsonl"
  lxmf_storage_dir: "~/.spine-reticulum/lxmf/"

  # Default link bandwidth (overridden per-interface if measurable)
  default_link_bps: 1200

  # Anti-spam: max revocations per hour per peer
  revocation_rate_limit_per_hour: 10

  # Drop thresholds (bps): below this bandwidth, drop these fact types
  drop_thresholds:
    heartbeat: 100
    node_attestation: 50
    run: 20

# Peers (can also be imported via CLI)
peers:
  - name: "gateway-1"
    destination_hash: "0xabcdef..."
    aegis_node_id: "aegis:ed25519:..."
```

### Phase 2: Translation Gateway (Steps 10-12)

#### Step 10: NATS Bridge

The gateway bridges Plane A-R (Reticulum) to Plane B (NATS JetStream):

```python
# spine_reticulum/gateway.py

import asyncio
import nats


class NATSBridge:
    """
    Bidirectional bridge between Reticulum and NATS.

    Reticulum -> NATS: verified envelopes from radio mesh published to NATS
    NATS -> Reticulum: envelopes from NATS forwarded to radio mesh
    """

    def __init__(self, adapter: ReticulumAdapter, nats_url: str,
                 disclosure_policy: dict):
        self._adapter = adapter
        self._nats_url = nats_url
        self._disclosure = disclosure_policy
        self._nc = None
        self._js = None
        self._seen_hashes = set()  # dedup ring buffer

    async def connect(self):
        self._nc = await nats.connect(self._nats_url)
        self._js = self._nc.jetstream()

        # Subscribe to all Spine envelopes from NATS
        await self._js.subscribe(
            "clawdstrike.spine.envelope.>",
            cb=self._on_nats_envelope,
        )

    async def _on_nats_envelope(self, msg):
        """Forward NATS envelope to Reticulum (outbound to field)."""
        import json
        envelope = json.loads(msg.data.decode())
        env_hash = envelope.get("envelope_hash", "")

        if env_hash in self._seen_hashes:
            return  # dedup

        fact_schema = envelope.get("fact", {}).get("schema", "")

        # Apply disclosure policy (NATS -> Reticulum direction)
        if not self._disclosure_allows_outbound(fact_schema):
            self._adapter._audit_log.log_drop(
                env_hash, reason=f"disclosure_blocked:{fact_schema}"
            )
            return

        self._seen_hashes.add(env_hash)
        self._adapter.send_envelope(envelope)

    def forward_to_nats(self, envelope: dict):
        """Forward verified Reticulum envelope to NATS (inbound from field)."""
        fact_schema = envelope.get("fact", {}).get("schema", "")

        if not self._disclosure_allows_inbound(fact_schema):
            self._adapter._audit_log.log_drop(
                envelope["envelope_hash"],
                reason=f"disclosure_blocked_inbound:{fact_schema}"
            )
            return

        # Publish to appropriate NATS subject
        subject = f"clawdstrike.spine.envelope.reticulum.{fact_schema}"
        asyncio.create_task(
            self._nc.publish(subject, json.dumps(envelope).encode())
        )

    def _disclosure_allows_outbound(self, fact_schema: str) -> bool:
        """Check if fact type is allowed to cross NATS -> Reticulum."""
        outbound = self._disclosure.get("nats_to_reticulum", {})
        blocked = outbound.get("blocked", [])
        allowed = outbound.get("allowed", [])
        if fact_schema in blocked:
            return False
        if allowed and fact_schema not in allowed:
            return False
        return True

    def _disclosure_allows_inbound(self, fact_schema: str) -> bool:
        """Check if fact type is allowed to cross Reticulum -> NATS."""
        inbound = self._disclosure.get("reticulum_to_nats", {})
        blocked = inbound.get("blocked", [])
        allowed = inbound.get("allowed", [])
        if fact_schema in blocked:
            return False
        if allowed and fact_schema not in allowed:
            return False
        return True
```

#### Step 11: Disclosure Policy Configuration

```yaml
# Gateway disclosure policy
# ~/.spine-reticulum/disclosure.yaml

nats_to_reticulum:
  # What fact types are forwarded from NATS to radio mesh
  allowed:
    - clawdstrike.spine.fact.revocation.v1       # Always
    - clawdstrike.spine.fact.log_checkpoint.v1   # Trust anchors
    - clawdstrike.spine.fact.policy_delta.v1     # Policy updates
    - clawdstrike.spine.fact.incident.v1         # Threat intel
  blocked:
    - clawdstrike.spine.envelope.tetragon.*      # Too high volume for radio
    - aegisnet.hubble.*                    # Way too high volume

reticulum_to_nats:
  # What fact types are forwarded from radio mesh to NATS
  allowed:
    - clawdstrike.spine.fact.revocation.v1
    - clawdstrike.spine.fact.incident.v1
    - clawdstrike.spine.fact.log_checkpoint.v1
    - clawdstrike.spine.fact.node_attestation.v1
  blocked:
    - clawdstrike.spine.fact.heartbeat.v1        # Droppable

rate_limits:
  bytes_per_second: 150        # ~1200 bps link budget
  envelopes_per_minute: 30
  unknown_issuer_quota: 100    # bounded storage for unknown issuers
```

#### Step 12: Identity Binding

Bind Aegis Ed25519 identity to Reticulum destination hash via a signed
`node_attestation` fact (Model A -- separate keys, per research doc Section 6):

```python
# spine_reticulum/identity.py

import json
from datetime import datetime, timezone


def create_identity_binding(aegis_keypair, reticulum_identity,
                            capabilities=None):
    """
    Create a node_attestation fact binding an Aegis identity
    to a Reticulum destination hash.
    """
    if capabilities is None:
        capabilities = ["envelopes", "heads", "sync", "proofs"]

    dest_hash = reticulum_identity.hash.hex()

    fact = {
        "schema": "clawdstrike.spine.fact.node_attestation.v1",
        "fact_id": f"na_{uuid4()}",
        "node_id": f"aegis:ed25519:{aegis_keypair.public_key_hex()}",
        "transports": {
            "reticulum": {
                "profile": "aegis.spine.reticulum.v1",
                "destination_hash": f"0x{dest_hash}",
                "announce_period_secs": 300,
                "supports": capabilities,
            }
        },
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }

    # Sign with Aegis key (not Reticulum key)
    # This is the binding attestation
    return fact
```

**Binding verification flow:**

1. Receive Reticulum message claiming to be from Aegis node X
2. Look up node X's latest `node_attestation` in local Spine store
3. Check `transports.reticulum.destination_hash` matches sender
4. If a `revocation` exists for node X, distrust the binding

### Phase 3: Raspberry Pi Gateway (Step 13)

#### Step 13: Pi Gateway Reference Image

Create a reference deployment for a Raspberry Pi 4 with an RNode LoRa USB
radio:

```
pi-gateway/
├── Dockerfile              # Based on python:3.12-slim-bookworm + rns + adapter
├── docker-compose.yml      # adapter + NATS client containers
├── config/
│   ├── reticulum.conf      # RNode interface config
│   ├── adapter.yaml        # Spine adapter config
│   └── disclosure.yaml     # Gateway disclosure policy
├── scripts/
│   ├── setup-rnode.sh      # Flash RNode firmware
│   └── health-check.sh     # Gateway health check
└── README.md               # Pi gateway setup guide
```

**Reticulum interface config for RNode:**

```ini
# config/reticulum.conf

[reticulum]
  enable_transport = True
  share_instance = True

[interfaces]
  [[RNode LoRa Interface]]
    type = RNodeInterface
    interface_enabled = True
    port = /dev/ttyUSB0
    frequency = 915000000    # 915 MHz (US ISM band)
    bandwidth = 125000
    txpower = 17
    spreadingfactor = 8
    codingrate = 5
    # ~1200 bps effective throughput

  [[TCP Server Interface]]
    type = TCPServerInterface
    interface_enabled = True
    listen_ip = 0.0.0.0
    listen_port = 4242
    # For LAN-connected nodes to join the mesh
```

**Hardware BOM:**

| Component | Cost | Notes |
|---|---|---|
| Raspberry Pi 4 (4GB) | ~$55 | ARM64, 4x Cortex-A72 |
| RNode LoRa USB | ~$15 | 915 MHz ISM, ~6 km range LOS |
| microSD 32GB | ~$8 | Class 10 |
| USB-C power supply | ~$10 | 5V 3A |
| Case + heatsink | ~$10 | Passive cooling |
| **Total** | **~$98** | |

**Power budget:** ~5W idle, ~7W peak (including LoRa TX)

---

## 5. File Changes

### New Files

| Path | Description | Est. LOC |
|---|---|---|
| `spine/reticulum/pyproject.toml` | Python project config | 40 |
| `spine/reticulum/src/spine_reticulum/__init__.py` | Package init | 10 |
| `spine/reticulum/src/spine_reticulum/adapter.py` | Main adapter class | 300 |
| `spine/reticulum/src/spine_reticulum/config.py` | YAML config parsing | 80 |
| `spine/reticulum/src/spine_reticulum/envelope.py` | Envelope encode/decode/verify | 150 |
| `spine/reticulum/src/spine_reticulum/store.py` | SQLite envelope store | 180 |
| `spine/reticulum/src/spine_reticulum/priority.py` | Priority queue + BW scheduler | 150 |
| `spine/reticulum/src/spine_reticulum/gateway.py` | NATS bridge | 200 |
| `spine/reticulum/src/spine_reticulum/identity.py` | Identity binding | 80 |
| `spine/reticulum/src/spine_reticulum/audit.py` | Hash-chained audit log | 100 |
| `spine/reticulum/src/spine_reticulum/encoding.py` | CBOR + fragmentation | 120 |
| `spine/reticulum/src/spine_reticulum/cli.py` | CLI entry points | 150 |
| `spine/reticulum/tests/test_envelope.py` | Envelope tests | 100 |
| `spine/reticulum/tests/test_store.py` | Store tests | 120 |
| `spine/reticulum/tests/test_priority.py` | Priority/scheduler tests | 100 |
| `spine/reticulum/tests/test_gateway.py` | Gateway tests | 100 |
| `spine/reticulum/tests/test_encoding.py` | CBOR/fragment tests | 80 |
| `spine/reticulum/tests/test_audit.py` | Audit log tests | 60 |
| `spine/reticulum/tests/fixtures/` | Cross-language test fixtures | -- |
| `spine/reticulum/pi-gateway/Dockerfile` | Pi gateway container | 30 |
| `spine/reticulum/pi-gateway/docker-compose.yml` | Pi gateway compose | 25 |
| `spine/reticulum/pi-gateway/config/reticulum.conf` | RNode config | 25 |
| `spine/reticulum/pi-gateway/config/adapter.yaml` | Adapter config | 30 |
| `spine/reticulum/pi-gateway/config/disclosure.yaml` | Disclosure policy | 25 |
| `spine/reticulum/README.md` | Adapter documentation | 100 |
| **Total estimated** | | **~2,255** |

### Modified Files

| Path | Change | Description |
|---|---|---|
| `Cargo.toml` (workspace) | Add comment | Note the Python sidecar in `spine/reticulum/` |
| `crates/spine/src/envelope.rs` | Add test | `generate_test_envelope` fixture generator for cross-language tests |

---

## 6. Testing Strategy

### Unit Tests

- **`test_envelope.py`**: Verify canonical JSON determinism, hash computation,
  signature verification, tamper detection, cross-language fixture validation
- **`test_store.py`**: SQLite insert/dedup/monotonicity/fork detection,
  head tracking, range queries for sync
- **`test_priority.py`**: 7-tier ordering, bandwidth drop thresholds,
  revocation rate bucketing, scheduler dequeue ordering
- **`test_encoding.py`**: CBOR encode/decode roundtrip, fragmentation at
  various MTUs, reassembly correctness
- **`test_gateway.py`**: Disclosure policy allow/block, dedup ring buffer,
  NATS mock publish/subscribe
- **`test_audit.py`**: Hash chain integrity, log rotation, tamper detection

### Integration Tests

- **Two-node exchange:** Two adapter processes exchange envelopes over
  Reticulum TCP interface (loopback). Verify: dedup, monotonicity, signature
  validation.
- **Sync protocol:** Node A has seq 1-10. Node B has seq 1-5. B requests
  sync from A. Verify B catches up to seq 10.
- **Gateway bridge:** Envelope published to NATS propagates through gateway
  to Reticulum node. Verify: disclosure filter, signature preserved, audit
  log entry.
- **Priority ordering:** Enqueue revocation + heartbeat + policy delta.
  Verify revocation dequeued first regardless of insertion order.

### Cross-Language Tests

- Generate canonical JSON fixtures from Rust (`cargo test -p spine`),
  commit to `tests/fixtures/`.
- Python tests verify byte-identical output for the same inputs.
- Rust-signed envelopes verified by Python; Python-signed envelopes
  verified by Rust.

### Performance / Stress Tests

- **Bandwidth simulation:** Mock a 5 bps link. Verify only revocations
  and checkpoints are transmitted. Heartbeats are dropped.
- **Fragment reassembly:** Send 1000-byte envelope over 500-byte MTU.
  Verify correct reassembly.
- **Store scalability:** Insert 100K envelopes. Verify query performance
  for sync ranges stays under 100ms.

---

## 7. Rollback Plan

The Reticulum adapter is a **new Python sidecar** with zero coupling to
existing Rust crates at runtime. Rollback is trivial:

1. Stop the `spine-reticulum` process
2. Remove the `spine/reticulum/` directory
3. No Cargo.toml changes are needed (no Rust dependency added)
4. No changes to existing NATS subjects, streams, or hushd behavior

The adapter is additive-only. Existing Plane B (NATS) and Plane A-L (libp2p)
transports are unaffected.

---

## 8. Dependencies

| Dependency | Status | Notes |
|---|---|---|
| `crates/spine/src/envelope.rs` | **Exists** | Envelope format the adapter carries |
| `crates/spine/src/nats_transport.rs` | **Exists** | NATS patterns the gateway mirrors |
| `crates/spine/src/trust.rs` | **Exists** | Trust bundle constraints |
| Spec #8 (Marketplace -> Spine unification) | **Pending** | Adapter benefits from unified Spine but does not require it |
| Spec #9 (Helm chart) | **In progress** | Pi gateway is standalone, not Helm-deployed |
| `rns` PyPI package | **External, stable** | Reticulum v0.9.3+, actively maintained |
| `lxmf` PyPI package | **External, stable** | LXMF v0.6.0+, actively maintained |
| `cbor2` PyPI package | **External, stable** | RFC 8949 CBOR implementation |
| `nats-py` PyPI package | **External, stable** | Python NATS client |

---

## 9. Acceptance Criteria

- [ ] Two adapter instances exchange a signed envelope over Reticulum TCP
      interface and both verify the signature successfully
- [ ] Envelopes signed by the Rust `crates/spine/src/envelope.rs` verify
      correctly in the Python adapter (cross-language determinism)
- [ ] `(issuer, seq)` monotonicity is enforced; duplicate envelopes are
      deduped by `envelope_hash`
- [ ] Fork detection raises an error when two different envelopes share the
      same `(issuer, seq)`
- [ ] Priority scheduler dequeues revocations before all other fact types
- [ ] On a simulated 5 bps link, heartbeats and node attestations are dropped;
      only revocations and checkpoints are transmitted
- [ ] LXMF store-and-forward delivers a revocation to an offline node that
      reconnects within 5 minutes
- [ ] NATS gateway forwards a verified envelope from Reticulum to NATS,
      respecting disclosure policy
- [ ] NATS gateway forwards a NATS envelope to Reticulum, applying bandwidth
      budget and disclosure filter
- [ ] Audit log entries are hash-chained; tampering with an entry is detectable
- [ ] CBOR-encoded envelope is 30-50% smaller than JSON equivalent
- [ ] Fragmented envelope (>500 bytes) reassembles correctly
- [ ] Gateway disclosure policy blocks Tetragon and Hubble events from
      crossing to Reticulum
- [ ] `pytest` passes with >90% coverage on the `spine_reticulum` package
- [ ] Pi gateway Dockerfile builds and runs on ARM64

---

## 10. Open Questions

1. **Ed25519 library choice for Python:** The `ed25519-blake2b` package
   uses the same Ed25519 algorithm as `ed25519-dalek` (Rust), but we must
   confirm byte-level signature compatibility. Alternative: use `PyNaCl`
   (libsodium bindings) which is a more common Ed25519 implementation.
   **Recommendation:** Use `PyNaCl` for wider compatibility and audit
   history.

2. **Reticulum announce frequency:** The default announce period of 300
   seconds (5 minutes) may be too long for rapid peer discovery in
   disaster response scenarios. Should this be configurable per-interface?
   **Recommendation:** Yes, configurable. Default 300s, min 60s.

3. **LXMF propagation node:** Should the adapter optionally run an LXMF
   Propagation Node to serve as a distributed Spine cache on the mesh?
   **Recommendation:** Defer to Phase 1. The propagation node is a
   significant operational commitment and should be proven in a lab
   environment first.

4. **Compact binary envelope (Option C):** The research doc recommends
   starting with CBOR and only introducing a compact binary format if CBOR
   proves insufficient on links below 100 bps. When should this decision
   be revisited? **Recommendation:** After Phase 1 field testing with
   actual LoRa hardware.

---

## References

- [Reticulum SDR Transport Research](../research/reticulum-sdr-transport.md) -- Primary reference
- [Architecture Vision](../research/architecture-vision.md) -- Multi-plane transport architecture (Section 2.4)
- [Open Source Strategy](../research/open-source-strategy.md) -- Target monorepo structure (`spine/reticulum/`)
- `crates/spine/src/envelope.rs` -- Envelope format (current implementation)
- `crates/spine/src/nats_transport.rs` -- NATS transport patterns
- `crates/spine/src/trust.rs` -- Trust bundle constraints
- [Reticulum Manual](https://reticulum.network/manual/) -- RNS API documentation
- [LXMF Protocol](https://github.com/markqvist/LXMF) -- Store-and-forward messaging
- [RFC 8949 (CBOR)](https://datatracker.ietf.org/doc/html/rfc8949) -- Compact encoding
- [RFC 8785 (JCS)](https://datatracker.ietf.org/doc/html/rfc8785) -- Canonical JSON
