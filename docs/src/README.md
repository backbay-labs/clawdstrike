# Clawdstrike

Clawdstrike is a Rust library + CLI for **policy-driven security checks** in agent runtimes.
It evaluates actions (filesystem, network egress, patches, and MCP tool calls) against a YAML policy and returns an allow / warn / block result.

This book is a **contract for what is implemented in this repository** (Clawdstrike `0.1.0`).
Clawdstrike ships a best-effort process wrapper (`clawdstrike run`) for audit logging + proxy-based egress enforcement. It is not a complete OS sandbox; see `docs/plans/` for security notes and roadmap items.

## Quick Start (CLI)

```bash
# Install from source (recommended for now)
cargo install --path crates/hush-cli

# List built-in rulesets
clawdstrike policy list

# Check a file access
clawdstrike check --action-type file --ruleset strict ~/.ssh/id_rsa

# Check network egress
clawdstrike check --action-type egress --ruleset default api.github.com:443
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
clawdstrike keygen --output hush.key
clawdstrike verify receipt.json --pubkey hush.key.pub
```

To keep the Ed25519 seed off disk, you can seal it into TPM2 (best-effort, requires `tpm2-tools`):

```bash
clawdstrike keygen --tpm-seal --out hush.keyblob
```

## Next Steps

- [Installation](getting-started/installation.md)
- [Quick Start](getting-started/quick-start.md)
- [Policy Schema](reference/policy-schema.md)
- [CLI Reference](reference/api/cli.md)
