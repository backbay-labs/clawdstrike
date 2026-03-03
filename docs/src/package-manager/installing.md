# Installing & Managing Packages

Clawdstrike installs packages into a local package store and can source packages from either local archives or registries.

## Local Install

```bash
clawdstrike pkg install ./my-guard-1.0.0.cpkg
```

## Registry Install

```bash
clawdstrike pkg install @acme/demo-guard --version 1.0.0 --trust-level verified
```

## Listing Installed Packages

```bash
clawdstrike pkg list
```

## Verification After Install

Use `pkg verify` to validate trust against registry attestations:

```bash
clawdstrike pkg verify @acme/demo-guard --version 1.0.0 --trust-level verified
```
