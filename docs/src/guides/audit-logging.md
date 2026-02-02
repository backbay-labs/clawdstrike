# Audit Logging

Hushclaw emits logs via `tracing`.

## CLI logging

The `hush` CLI sets log level via `-v`:

- no `-v`: warnings only
- `-v`: info
- `-vv`: debug
- `-vvv`: trace

Example:

```bash
hush -vv check --action-type file --ruleset default ./README.md
```

## Policy-controlled verbosity

Some components emit additional debug logs when enabled:

```yaml
settings:
  verbose_logging: true
```

## Persistent audit trails (daemon)

For a persistent audit ledger, use `hushd` (optional/WIP). It stores audit events in an SQLite database.

```bash
cargo install --path crates/hushd
hushd start
```
