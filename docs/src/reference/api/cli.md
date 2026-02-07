# CLI Reference

The `clawdstrike` CLI is provided by the `hush-cli` crate.

## Installation

```bash
cargo install --path crates/hush-cli
```

## `clawdstrike check`

Evaluate a single action against a ruleset or policy file.

```bash
clawdstrike check [--json] --action-type <file|egress|mcp> [--ruleset NAME | --policy FILE] <TARGET>
```

- `file`: `<TARGET>` is a path string.
- `egress`: `<TARGET>` is `host[:port]` (port defaults to `443`).
- `mcp`: `<TARGET>` is a tool name. (The CLI currently evaluates with empty tool args `{}`.)

Examples:

```bash
clawdstrike check --action-type file --ruleset strict ~/.ssh/id_rsa
clawdstrike check --action-type egress --ruleset default api.github.com:443
clawdstrike check --action-type mcp --ruleset strict shell_exec
```

Machine-readable JSON:

```bash
clawdstrike check --json --action-type egress --ruleset default api.github.com:443 | jq .
```

## `clawdstrike policy`

- `clawdstrike policy list` — list built-in rulesets.
- `clawdstrike policy show [RULESET_OR_FILE]` — print a ruleset policy or a policy file.
  - `--merged` resolves `extends` (useful for files).
- `clawdstrike policy validate <FILE>` — validate YAML + patterns.
  - `--resolve` resolves `extends` and prints the merged policy.
  - `--check-env` also requires referenced `${VAR}` environment variables to be set.
- `clawdstrike policy diff <LEFT> <RIGHT> [--resolve] [--json]` — structural diff for rulesets or policy files.
- `clawdstrike policy lint <FILE> [--resolve] [--strict] [--json|--sarif]` — policy linting (risky defaults, common mistakes).
- `clawdstrike policy test <SUITE.yaml> [--coverage|--by-guard] [--min-coverage <PERCENT>] [--format text|json|html|junit] [--output <PATH>] [--snapshots] [--update-snapshots] [--mutation]` — run a policy test suite.
- `clawdstrike policy test generate <POLICY_REF> [--events <EVENTS.jsonl>] [--output <SUITE.yaml>] [--json]` — generate a baseline test suite from policy defaults and optional observed events.
- `clawdstrike policy eval <POLICY_REF> <EVENT.json|-> [--resolve] [--json]` — evaluate a canonical `PolicyEvent`.
- `clawdstrike policy simulate <POLICY_REF> [EVENTS.jsonl|-] [--json|--jsonl|--summary] [--track-posture]` — run a stream of events.
- `clawdstrike policy rego compile <POLICY.rego> [--entrypoint <QUERY>] [--json]` — compile/check a Rego module.
- `clawdstrike policy rego eval <POLICY.rego> <INPUT.json|-> [--entrypoint <QUERY>] [--trace] [--json]` — evaluate Rego against input JSON.
- `clawdstrike policy observe [--policy <ref>] [--out <events.jsonl>] -- <cmd ...>` — observe local command activity into canonical `PolicyEvent` JSONL.
- `clawdstrike policy observe --hushd-url <url> --session <id> [--out <events.jsonl>]` — export + map hushd audit events for a session.
- `clawdstrike policy synth <EVENTS.jsonl> [--extends <ref>] [--out <candidate.yaml>] [--diff-out <candidate.diff.json>] [--risk-out <candidate.risks.md>] [--with-posture]` — synthesize a least-privilege candidate policy.
- `clawdstrike policy migrate <INPUT> --to 1.2.0 [--output <path>|--in-place]` — migrate policy schema versions.
- `clawdstrike policy bundle build <POLICY_REF> --key <private_key> [--resolve] [--embed-pubkey]` — build a signed policy bundle (JSON) for distribution.
- `clawdstrike policy bundle verify <BUNDLE.json> [--pubkey <pubkey>]` — verify a signed policy bundle.

Examples:

```bash
clawdstrike policy list
clawdstrike policy show ai-agent
clawdstrike policy show ./policy.yaml
clawdstrike policy show --merged ./policy.yaml
clawdstrike policy validate ./policy.yaml
clawdstrike policy validate --resolve ./policy.yaml
clawdstrike policy diff default strict --json
clawdstrike policy rego compile ./policy.rego --entrypoint data.example.allow
clawdstrike policy rego eval ./policy.rego ./input.json --entrypoint data.example.allow --trace
clawdstrike policy test ./tests/policy.test.yaml --coverage --min-coverage 80 --format junit --output ./reports/policy-tests.xml
clawdstrike policy test generate clawdstrike:default --events ./events.jsonl --output ./tests/generated.policy.test.yaml
clawdstrike policy observe --out run.events.jsonl -- your-agent-command
clawdstrike policy synth run.events.jsonl --extends clawdstrike:default --out candidate.yaml --risk-out candidate.risks.md
clawdstrike policy simulate candidate.yaml run.events.jsonl --json --track-posture
clawdstrike policy bundle build ai-agent --resolve --key ./bundle-signing.key --embed-pubkey --output ./policy.bundle.json
clawdstrike policy bundle verify ./policy.bundle.json
```

## `clawdstrike guard`

- `clawdstrike guard inspect <PLUGIN_REF> [--json]` — inspect manifest metadata and compatibility.
- `clawdstrike guard validate <PLUGIN_REF> [--strict] [--json]` — validate manifest and plugin load plan.

Examples:

```bash
clawdstrike guard inspect ./plugins/my-guard
clawdstrike guard validate ./plugins/my-guard --strict --json
```

## Receipts and crypto

- `clawdstrike keygen --output <path> [--tpm-seal]` — generate an Ed25519 keypair.
  - Default: writes a hex-encoded seed to `<path>` and a hex-encoded public key to `<path>.pub`.
  - With `--tpm-seal`: writes a TPM-sealed blob JSON to `<path>` and a hex-encoded public key to `<path>.pub` (requires `tpm2-tools`).
- `clawdstrike verify [--json] <receipt.json> --pubkey <pubkey>` — verify a `SignedReceipt` (signature + verdict).
- `clawdstrike hash <file|- >` — compute `sha256` or `keccak256`.
- `clawdstrike sign --key <private_key> <file>` — sign a file (raw Ed25519 signature).
- `clawdstrike merkle root|proof|verify` — Merkle tree utilities for files.

## `clawdstrike daemon` (optional)

The CLI can start/inspect a `clawdstriked` daemon, but `clawdstriked` must be installed separately.

```bash
cargo install --path crates/hushd
clawdstrike daemon start
clawdstrike daemon status
clawdstrike daemon stop
clawdstrike daemon reload
```

## Shell completions

```bash
clawdstrike completions zsh
```

```bash
# Start daemon
clawdstrike daemon start --config /etc/clawdstriked/config.yaml

# Status
clawdstrike daemon status

# Stop
clawdstrike daemon stop

# Reload policy
clawdstrike daemon reload
```

If auth is enabled, set `CLAWDSTRIKE_ADMIN_KEY` or pass `--token`:

```bash
clawdstrike daemon stop --token "$CLAWDSTRIKE_ADMIN_KEY"
clawdstrike daemon reload --token "$CLAWDSTRIKE_ADMIN_KEY"
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
sudo clawdstrike completions bash > /etc/bash_completion.d/clawdstrike

# Bash - user-local
clawdstrike completions bash > ~/.local/share/bash-completion/completions/clawdstrike

# Zsh - add to fpath
clawdstrike completions zsh > ~/.zfunc/_clawdstrike
# Then add to ~/.zshrc: fpath=(~/.zfunc $fpath)

# Fish
clawdstrike completions fish > ~/.config/fish/completions/clawdstrike.fish

# PowerShell
clawdstrike completions powershell > $PROFILE.CurrentUserAllHosts

# Elvish
clawdstrike completions elvish > ~/.elvish/lib/clawdstrike.elv
```

Supported shells: `bash`, `zsh`, `fish`, `powershell`, `elvish`
