# CLI Reference

Command-line interface for hushclaw.

## Installation

```bash
cargo install hush-cli
```

## Commands

### hush run

Run a command with policy enforcement.

```bash
hush run --policy policy.yaml -- your-command args
```

Options:

| Flag | Description |
|------|-------------|
| `--policy <path>` | Policy file or built-in name |
| `--mode <mode>` | `deterministic`, `advisory`, or `audit` |
| `--log-level <level>` | `error`, `warn`, `info`, `debug`, `trace` |
| `--receipt <path>` | Save receipt to file |
| `--no-receipt` | Don't generate receipt |

Examples:

```bash
# Basic usage
hush run --policy policy.yaml -- python script.py

# Advisory mode (warn only)
hush run --policy policy.yaml --mode advisory -- ./build.sh

# Save receipt
hush run --policy policy.yaml --receipt ./run.receipt.json -- npm test

# Use built-in policy
hush run --policy hushclaw:strict -- cargo build
```

### hush policy

Policy management commands.

#### policy lint

Validate a policy file.

```bash
hush policy lint policy.yaml
```

Output:

```
Validating policy.yaml...

✓ Syntax valid
✓ Schema valid
✓ No conflicts detected

Suggestions:
  - Consider adding 'pypi.org' for Python projects
```

#### policy show

Display policy details.

```bash
hush policy show --policy policy.yaml
hush policy show --effective --policy policy.yaml
```

#### policy test

Test an event against a policy.

```bash
hush policy test event.json --policy policy.yaml
```

Or from stdin:

```bash
echo '{"event_type":"file_read","data":{"path":"~/.ssh/id_rsa"}}' | \
  hush policy test - --policy policy.yaml
```

Output:

```
Event: file_read ~/.ssh/id_rsa
Result: DENIED
Guard: ForbiddenPathGuard
Reason: Path matches forbidden pattern: ~/.ssh/*
Severity: CRITICAL
```

#### policy diff

Compare two policies.

```bash
hush policy diff policy-a.yaml policy-b.yaml
```

### hush verify

Verify a signed receipt.

```bash
hush verify receipt.json
```

Output:

```
Receipt Verification
────────────────────

Run ID:     run_abc123
Events:     127
Denials:    2

Signature:  VALID
Merkle:     VALID

Receipt is authentic and unmodified.
```

Options:

| Flag | Description |
|------|-------------|
| `--public-key <path>` | Use specific public key |
| `--json` | Output as JSON |
| `--quiet` | Only exit code |

### hush sign

Sign a payload.

```bash
hush sign payload.json --key ~/.hush/keys/private.key
```

### hush hash

Compute content hash.

```bash
hush hash file.txt
# 7f3a4b2c...

hush hash --algorithm sha256 file.txt
hush hash --algorithm keccak256 file.txt
```

### hush keygen

Generate a keypair.

```bash
hush keygen --output ~/.hush/keys/
```

Creates:
- `~/.hush/keys/private.key`
- `~/.hush/keys/public.key`

### hush merkle

Merkle tree operations.

```bash
# Build tree
hush merkle build events.jsonl --output tree.json

# Get root
hush merkle root events.jsonl
# 0x7f3a4b2c...

# Verify proof
hush merkle verify proof.json
```

### hush explain

Explain a blocked event.

```bash
hush explain event-id
```

Output:

```
Event Details
─────────────────────────────

Event ID:    evt_abc123
Timestamp:   2026-01-31T14:23:45Z
Type:        file_read
Target:      ~/.ssh/id_rsa

Decision:    BLOCKED

Evaluation Chain:
─────────────────────────────

1. ForbiddenPathGuard
   Pattern: ~/.ssh/*
   Result: DENY
   Reason: Path matches forbidden pattern

Remediation:
─────────────────────────────

To allow this path:

  filesystem:
    forbidden_paths:
      # Remove: - "~/.ssh/*"
```

### hush audit

Query audit logs.

```bash
# Recent denials
hush audit query --denied --since 1h

# By event type
hush audit query --event-type network_egress --since 24h

# By guard
hush audit query --guard EgressAllowlistGuard --since 7d

# Export
hush audit query --since 24h --format json > audit.json
```

Generate report:

```bash
hush audit report --period week --output report.pdf
```

### hush daemon

Daemon control.

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

## Environment Variables

| Variable | Description |
|----------|-------------|
| `HUSHCLAW_POLICY` | Default policy path |
| `HUSH_LOG_LEVEL` | Log level |
| `HUSH_LOG_FORMAT` | `json` or `human` |
| `HUSH_RECEIPTS_DIR` | Receipt storage path |
| `HUSH_KEY_PATH` | Signing key path |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Policy violation (blocked) |
| 2 | Configuration error |
| 3 | Runtime error |
| 4 | Invalid arguments |

## Configuration File

```yaml
# ~/.hush/config.yaml
policy: ~/.hush/policy.yaml
mode: deterministic

logging:
  level: info
  format: json
  path: ~/.hush/logs/audit.log

receipts:
  enabled: true
  path: ~/.hush/receipts
  sign: true
  key_path: ~/.hush/keys/private.key

daemon:
  address: 127.0.0.1:9090
  pidfile: /var/run/hushd.pid
```

## Shell Completion

```bash
# Bash
hush completion bash > /etc/bash_completion.d/hush

# Zsh
hush completion zsh > ~/.zsh/completions/_hush

# Fish
hush completion fish > ~/.config/fish/completions/hush.fish
```
