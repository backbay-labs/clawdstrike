# Publishing Packages

Publishing sends a signed package archive and manifest to the registry.

## Prerequisites

- `clawdstrike-pkg.toml` present and valid
- publisher keypair available locally
- registry auth token (`CLAWDSTRIKE_AUTH_TOKEN`) or OIDC CI identity (`--oidc`)

## Publish

```bash
clawdstrike pkg publish --registry https://registry.clawdstrike.com
```

## OIDC Publish (CI)

```bash
clawdstrike pkg publish --oidc --registry https://registry.clawdstrike.com
```

## What Gets Signed

- Publisher signs SHA-256 of archive bytes.
- Registry verifies publisher signature, then adds registry counter-signature.
- Registry records transparency metadata for proof retrieval.
