# GitHub Actions

Use the `hush` CLI in CI to validate policy files and keep rulesets/examples from drifting.

## Validate a policy file

If your repo contains policy YAML files (for example under `.hush/`), you can validate them in CI:

```yaml
name: Policy validation

on:
  pull_request:
    paths:
      - ".hush/**/*.yaml"
      - ".hush/**/*.yml"

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable

      - name: Install hush
        run: cargo install --path crates/hush-cli

      - name: Validate policy
        run: hush policy validate --resolve .hush/policy.yaml
```

## Recommended CI baseline

Start from the built-in `cicd` ruleset:

```yaml
version: "1.1.0"
name: CI Policy
extends: clawdstrike:cicd
```
