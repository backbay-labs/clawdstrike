# clawdstrike pkg publish

Package, sign, and publish the current package directory to a registry.

## Usage

```bash
clawdstrike pkg publish [PATH] [--registry <URL>] [--oidc]
```

## Behavior

1. Reads `clawdstrike-pkg.toml`
2. Builds `.cpkg` archive
3. Signs archive hash with local publisher key
4. Uploads JSON payload to `POST /api/v1/packages`

## Auth Modes

- API token mode (default): uses `CLAWDSTRIKE_AUTH_TOKEN`
- OIDC mode (`--oidc`): obtains CI token and sets OIDC headers

## Requirements

- Publisher keypair must be present (auto-generated if missing).
- Registry token must be configured for non-OIDC publishing.
