# Spine Reticulum Adapter

Python sidecar that bridges ClawdStrike Spine signed envelopes to the
[Reticulum](https://reticulum.network/) mesh networking stack (Plane A-R).

This enables off-grid distribution of revocations, checkpoints, incidents, and
policy deltas over LoRa, packet radio, serial, WiFi, and TCP/UDP carriers.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Run tests
pytest

# Start the adapter (requires Reticulum and config)
spine-reticulum --config config.yaml run
```

## Architecture

```
hushd / Spine store
    |
    | Unix socket / TCP
    v
spine-reticulum-adapter (this package)
    |
    |-- RNS stack (LoRa, serial, TCP, WiFi)
    |-- LXMF store-and-forward (priority 1-4 facts)
    |-- Priority queue (7-tier, bandwidth-budgeted)
    |-- SQLite envelope store (dedup, monotonicity, fork detection)
    |-- CBOR encoder (30-50% smaller than JSON)
    |-- Hash-chained JSONL audit log
    |-- Optional NATS bridge (gateway mode)
```

## Priority Tiers

| Priority | Fact Type          | LXMF? | Drop Threshold |
|----------|--------------------|-------|----------------|
| 1        | Revocation         | Yes   | Never          |
| 2        | Checkpoint         | Yes   | Never          |
| 3        | Incident           | Yes   | Never          |
| 4        | Policy Delta       | Yes   | Never          |
| 5        | Run                | No    | < 20 bps       |
| 6        | Node Attestation   | No    | < 50 bps       |
| 7        | Heartbeat          | No    | < 100 bps      |

## Configuration

See `pi-gateway/config/adapter.yaml` for a complete example.

## Pi Gateway

The `pi-gateway/` directory contains a reference deployment for a Raspberry Pi 4
with an RNode LoRa USB radio:

```bash
cd pi-gateway
docker compose up -d
```

Hardware BOM: ~$98 (Pi 4 + RNode LoRa USB + microSD + power + case).

## CLI Commands

```bash
spine-reticulum run              # Start the adapter
spine-reticulum verify FILE      # Verify a signed envelope
spine-reticulum verify-audit LOG # Verify audit log hash chain
spine-reticulum status           # Show store stats
spine-reticulum send-envelope F  # Send an envelope via Reticulum
```

## License

Apache-2.0
