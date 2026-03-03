# clawdstrike pkg install

Install a package from a local `.cpkg` file or a registry.

## Usage

```bash
clawdstrike pkg install <SOURCE> [--version <VERSION>] [--registry <URL>] [--trust-level <LEVEL>] [--allow-unverified]
```

## SOURCE

- Local path: `/path/to/pkg.cpkg`
- Registry name: `@scope/name` or `name`

## Behavior

- Local source installs directly into the package store.
- Registry source downloads and installs a version.
- If `--version` is omitted for registry installs, the CLI resolves latest from package stats.

## Trust Enforcement

- Default trust level: `signed`.
- At `signed` and above, publisher signature and checksum binding are verified.
- At `verified` and above, registry counter-signature is verified against configured registry public key (`[registry].public_key` or `CLAWDSTRIKE_REGISTRY_PUBLIC_KEY`).
- At `certified`, the CLI verifies checkpoint signature + Merkle inclusion proof against the same anchored registry key.
