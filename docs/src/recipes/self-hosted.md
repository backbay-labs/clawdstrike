# Self-Hosted Runners (hushd)

`hushd` is an optional HTTP daemon for centralized policy evaluation and a persistent audit ledger (SQLite).

Packaging/deployment (Docker/Kubernetes/Helm) is not provided in this repository yet; treat this as a “run from source” recipe.

## Install

```bash
cargo install --path crates/hushd
```

## Run

Use a ruleset:

```bash
hushd start --bind 127.0.0.1 --port 9876 --ruleset default
```

Or use a config file (YAML or TOML):

```bash
hushd start --config ./hushd.yaml
```

## Minimal config example

```yaml
listen: "127.0.0.1:9876"
ruleset: "default"
log_level: "info"
```

## Health check

```bash
curl -s http://127.0.0.1:9876/health | jq .
```
