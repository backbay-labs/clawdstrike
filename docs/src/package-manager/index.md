# Package Manager

Clawdstrike's package manager (`clawdstrike pkg`) handles packaging, publishing, installation, and verification of policy-related artifacts such as policy packs and custom guards.

It is built for fail-closed operation: if required trust evidence is missing or invalid, installation fails.

## Core Concepts

### Package Types

A Clawdstrike package is one of six types:

- **guard**: WASM guard artifact with package metadata
- **policy-pack**: policy/ruleset bundle (plus optional data files)
- **adapter**: integration package for framework/runtime adapters
- **engine**: alternate engine/runtime component
- **template**: scaffolding for new packages/projects
- **bundle**: pre-assembled package set for repeatable deployment

Each package includes `clawdstrike-pkg.toml` describing identity, type, dependencies, and metadata.

### Names and Versions

- Scoped package names use `@scope/name`.
- Unscoped names use `name`.
- Versions follow semantic versioning.

## Publish and Install Flow

### Publishing

```bash
# Initialize package scaffold
clawdstrike pkg init --pkg-type policy-pack --name @acme/agent-baseline

# Build/sign/upload current directory
clawdstrike pkg publish .
```

`pkg publish` packages and signs archive content, then uploads publish metadata to the registry API.

### Installing

```bash
# Install latest version from registry
clawdstrike pkg install @acme/agent-baseline

# Install a specific version
clawdstrike pkg install @acme/agent-baseline --version 1.2.0

# Install from local archive
clawdstrike pkg install ./dist/acme-agent-baseline-1.2.0.cpkg
```

### Referencing Installed Policy Packages

Installed policy packages can be used via `extends`:

```yaml
version: "1.2.0"
extends: pkg:@acme/agent-baseline

guards:
  egress_allowlist:
    additional_allow:
      - "api.myapp.com"
```

## Verification and Trust

Registry installs support trust levels:

- `unverified`: no registry trust requirement
- `signed`: publisher signature + checksum binding
- `verified`: signed + registry signature verified against configured registry public key
- `certified`: verified + cryptographically validated checkpoint signature and Merkle inclusion proof

For `verified` and `certified`, configure a registry trust anchor key:

- `~/.clawdstrike/config.toml` `[registry].public_key`
- or `CLAWDSTRIKE_REGISTRY_PUBLIC_KEY`

Example verification:

```bash
clawdstrike pkg verify @acme/agent-baseline --version 1.2.0 --trust-level certified
```

Audit history (publish/yank events) is package-scoped:

```bash
clawdstrike pkg audit @acme/agent-baseline
```

## Registry and Mirroring

The registry provides package APIs for publish/download/search/audit operations and stores package blobs plus metadata.

Common deployment modes:

- local/dev registry
- self-hosted internal registry
- mirrored upstream via `clawdstrike pkg mirror`

## Command Surface

`clawdstrike pkg` provides:

- `init`
- `publish`
- `install`
- `verify`
- `search`
- `audit`
- `yank`
- `stats`
- `mirror`
- org/trusted-publisher management commands

## Next Steps

- [Package Types](package-types.md)
- [Publishing Packages](publishing.md)
- [Installing & Managing](installing.md)
- [Registry Architecture](registry-architecture.md)
- [Trust & Verification](trust-verification.md)
- [RFC-0001: Package Manager](../rfcs/0001-package-manager.md)
