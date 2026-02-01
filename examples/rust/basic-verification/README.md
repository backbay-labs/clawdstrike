# Basic Verification Example

Demonstrates how to verify a hushclaw receipt.

## What It Does

1. Loads a receipt JSON file
2. Verifies the Ed25519 signature
3. Validates the Merkle root
4. Reports the result

## Build

```bash
cargo build --release
```

## Run

```bash
cargo run -- receipt.json
```

## Example Output

```
Receipt Verification
====================

Run ID:     run_abc123
Started:    2026-01-31T14:00:00Z
Ended:      2026-01-31T14:30:00Z
Events:     127
Denials:    2

Signature:  VALID
Merkle:     VALID

Receipt is authentic and unmodified.
```

## Sample Receipt

Create a `receipt.json` file:

```json
{
  "run_id": "run_abc123",
  "started_at": "2026-01-31T14:00:00Z",
  "ended_at": "2026-01-31T14:30:00Z",
  "events": [],
  "event_count": 127,
  "denied_count": 2,
  "merkle_root": "0x7f3a4b2c...",
  "signature": "ed25519:abc...",
  "public_key": "ed25519:xyz..."
}
```

## Exit Codes

- `0` - Receipt is valid
- `1` - Verification failed or error
