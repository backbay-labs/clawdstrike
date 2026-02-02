# Basic Verification Example

Demonstrates how to verify a signed hushclaw receipt.

## What It Does

1. Loads a signed receipt JSON file
2. Loads a public key (hex)
3. Verifies the Ed25519 signature over canonical JSON
4. Reports the result

## Build

```bash
cargo build --release
```

## Run

```bash
cargo run -- receipt.json key.pub
```

## Example Output

```
Receipt Verification
====================

Version:    1.0.0
Timestamp:  2026-01-31T14:00:00Z
Content:    0x7f3a4b2c...
Verdict:    PASS

Signature:  VALID

Signed receipt verified.
```

## Sample Receipt

Create a `receipt.json` file (signed receipt):

```json
{
  "receipt": {
    "version": "1.0.0",
    "timestamp": "2026-01-31T14:00:00Z",
    "content_hash": "0x7f3a4b2c00000000000000000000000000000000000000000000000000000000",
    "verdict": { "passed": true },
    "provenance": {
      "hushclaw_version": "0.1.0",
      "ruleset": "default",
      "violations": []
    }
  },
  "signatures": {
    "signer": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "cosigner": null
  }
}
```

And a `key.pub` file containing the Ed25519 public key (hex, 32 bytes).

## Exit Codes

- `0` - Receipt is valid
- `1` - Verification failed or error
