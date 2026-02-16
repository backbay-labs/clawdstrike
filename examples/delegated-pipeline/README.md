# Delegated Pipeline Example

Demonstrates the full multi-agent crypto chain using `hush-multi-agent` primitives:

1. **Delegation** - Architect grants scoped capabilities to coder and tester
2. **Re-delegation** - Coder re-delegates attenuated capabilities to tester
3. **Signed messages** - Coder sends verified task request with embedded delegation
4. **Replay protection** - Same message nonce rejected on second attempt
5. **Revocation** - Revoked delegation token is correctly rejected
6. **Escalation rejection** - Attempt to re-delegate beyond ceiling is denied

## Architecture

```
Architect (System)
  |-- delegate FileWrite{src/**} + CommandExec{cargo,npm} --> Coder (Medium)
  |     \-- re-delegate CommandExec{cargo} (attenuated) --> Tester (Medium)
  \-- delegate FileRead{src/**,tests/**} + CommandExec{cargo test} --> Tester
```

## Run

```bash
cargo run
```

## What It Demonstrates

- Ed25519 signatures on all tokens and messages (via `hush-core`)
- Canonical JSON (RFC 8785 / JCS) for deterministic serialization
- Capability ceiling enforcement prevents privilege escalation
- Chain validation ensures proper delegation lineage
- Nonce-based replay protection per (sender, recipient) pair
- In-memory revocation store for token invalidation
