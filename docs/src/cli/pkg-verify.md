# clawdstrike pkg verify

Verify an installed package against local integrity and registry trust metadata.

## Usage

```bash
clawdstrike pkg verify <NAME> --version <VERSION> [--trust-level <LEVEL>] [--registry <URL>]
```

## Checks

- Local package metadata and content hash
- Registry attestation checksum match
- Publisher signature verification
- Registry counter-signature verification against configured registry public key (for `verified`/`certified`)
- Transparency checkpoint signature + inclusion proof verification against the same key (for `certified`)

`verified`/`certified` require registry key pinning via:
- `~/.clawdstrike/config.toml` `[registry].public_key`
- or `CLAWDSTRIKE_REGISTRY_PUBLIC_KEY`

## Exit Codes

- `0` when achieved trust meets/exceeds required level
- non-zero when checks fail or trust level is insufficient
