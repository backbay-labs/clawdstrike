# CLI Reference

The `hush` CLI is provided by the `hush-cli` crate.

## Installation

```bash
cargo install --path crates/hush-cli
```

## `hush check`

Evaluate a single action against a ruleset or policy file.

```bash
hush check [--json] --action-type <file|egress|mcp> [--ruleset NAME | --policy FILE] <TARGET>
```

- `file`: `<TARGET>` is a path string.
- `egress`: `<TARGET>` is `host[:port]` (port defaults to `443`).
- `mcp`: `<TARGET>` is a tool name. (The CLI currently evaluates with empty tool args `{}`.)

Examples:

```bash
hush check --action-type file --ruleset strict ~/.ssh/id_rsa
hush check --action-type egress --ruleset default api.github.com:443
hush check --action-type mcp --ruleset strict shell_exec
```

Machine-readable JSON:

```bash
hush check --json --action-type egress --ruleset default api.github.com:443 | jq .
```

## `hush policy`

- `hush policy list` — list built-in rulesets.
- `hush policy show [RULESET_OR_FILE]` — print a ruleset policy or a policy file.
  - `--merged` resolves `extends` (useful for files).
- `hush policy validate <FILE>` — validate YAML + patterns.
  - `--resolve` resolves `extends` and prints the merged policy.
- `hush policy diff <LEFT> <RIGHT> [--resolve] [--json]` — structural diff for rulesets or policy files.
- `hush policy lint <FILE> [--resolve] [--json]` — policy linting (risky defaults, common mistakes).
- `hush policy test <SUITE.yaml>` — run a policy test suite.
- `hush policy eval <POLICY_REF> <EVENT.json|-> [--resolve] [--json]` — evaluate a canonical `PolicyEvent`.
- `hush policy simulate <POLICY_REF> [EVENTS.jsonl|-] [--json|--jsonl|--summary]` — run a stream of events.
- `hush policy bundle build <POLICY_REF> --key <private_key> [--resolve] [--embed-pubkey]` — build a signed policy bundle (JSON) for distribution.
- `hush policy bundle verify <BUNDLE.json> [--pubkey <pubkey>]` — verify a signed policy bundle.

Examples:

```bash
hush policy list
hush policy show ai-agent
hush policy show ./policy.yaml
hush policy show --merged ./policy.yaml
hush policy validate ./policy.yaml
hush policy validate --resolve ./policy.yaml
hush policy diff default strict --json
hush policy bundle build ai-agent --resolve --key ./bundle-signing.key --embed-pubkey --output ./policy.bundle.json
hush policy bundle verify ./policy.bundle.json
```

## Receipts and crypto

- `hush keygen --output <path> [--tpm-seal]` — generate an Ed25519 keypair.
  - Default: writes a hex-encoded seed to `<path>` and a hex-encoded public key to `<path>.pub`.
  - With `--tpm-seal`: writes a TPM-sealed blob JSON to `<path>` and a hex-encoded public key to `<path>.pub` (requires `tpm2-tools`).
- `hush verify [--json] <receipt.json> --pubkey <pubkey>` — verify a `SignedReceipt` (signature + verdict).
- `hush hash <file|- >` — compute `sha256` or `keccak256`.
- `hush sign --key <private_key> <file>` — sign a file (raw Ed25519 signature).
- `hush merkle root|proof|verify` — Merkle tree utilities for files.

## `hush daemon` (optional)

The CLI can start/inspect a `hushd` daemon, but `hushd` must be installed separately.

```bash
cargo install --path crates/hushd
hush daemon start
hush daemon status
hush daemon stop
hush daemon reload
```

## Shell completions

```bash
hush completions zsh
```

```bash
# Start daemon
hush daemon start --config /etc/hush/config.yaml

# Status
hush daemon status

# Stop
hush daemon stop

# Reload policy
hush daemon reload
```

If auth is enabled, set `HUSHD_ADMIN_KEY` or pass `--token`:

```bash
hush daemon stop --token "$HUSHD_ADMIN_KEY"
hush daemon reload --token "$HUSHD_ADMIN_KEY"
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | OK (allowed / receipt verified + PASS) |
| 1 | Warning (allowed, but warnings present) |
| 2 | Fail (blocked / receipt invalid / receipt verdict FAIL) |
| 3 | Config error (invalid policy/ruleset/pubkey/receipt JSON) |
| 4 | Runtime error (I/O or internal) |
| 5 | Invalid arguments |

## Shell Completions

Generate shell completions for your preferred shell:

```bash
# Bash - system-wide
sudo hush completions bash > /etc/bash_completion.d/hush

# Bash - user-local
hush completions bash > ~/.local/share/bash-completion/completions/hush

# Zsh - add to fpath
hush completions zsh > ~/.zfunc/_hush
# Then add to ~/.zshrc: fpath=(~/.zfunc $fpath)

# Fish
hush completions fish > ~/.config/fish/completions/hush.fish

# PowerShell
hush completions powershell > $PROFILE.CurrentUserAllHosts

# Elvish
hush completions elvish > ~/.elvish/lib/hush.elv
```

Supported shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`
