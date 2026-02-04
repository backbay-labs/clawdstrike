# Clawdstrike

Clawdstrike is a Rust library + CLI for **policy-driven security checks** in agent runtimes.
It evaluates actions (filesystem, network egress, patches, and MCP tool calls) against a YAML policy and returns an allow / warn / block result.

This book is a **contract for what is implemented in this repository** (Clawdstrike `0.1.0`).
If you are looking for a full process wrapper / sandbox (`hush run`), that is not shipped in the current Rust codebase—see `docs/plans/` for roadmap work.

## Quick Start (CLI)

```bash
# Install from source (recommended for now)
cargo install --path crates/hush-cli

# List built-in rulesets
hush policy list

# Check a file access
hush check --action-type file --ruleset strict ~/.ssh/id_rsa

# Check network egress
hush check --action-type egress --ruleset default api.github.com:443
```

## Policies

Policies are YAML files that configure the built-in guards under `guards.*`.
They can inherit from a built-in ruleset or another file via `extends`.

```yaml
version: "1.1.0"
name: My Policy
extends: clawdstrike:default

guards:
  egress_allowlist:
    additional_allow:
      - "api.mycompany.com"
```

## Receipts

`hush-core` provides hashing + Ed25519 signing and a `SignedReceipt` schema.
Receipts are created via the Rust API (`HushEngine::create_signed_receipt`) and verified with the CLI:

```bash
hush keygen --output hush.key
hush verify receipt.json --pubkey hush.key.pub
```

## Next Steps

- [Installation](getting-started/installation.md)
- [Quick Start](getting-started/quick-start.md)
- [Policy Schema](reference/policy-schema.md)
- [CLI Reference](reference/api/cli.md)
