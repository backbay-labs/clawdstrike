# Quick Start

Get hushclaw protecting your agent in 5 minutes.

## Step 1: Install

```bash
cargo install hush-cli
```

## Step 2: Create a Policy

Create a file named `policy.yaml`:

```yaml
# policy.yaml
version: "hushclaw-v1.0"

# Use a built-in base policy
extends: hushclaw:ai-agent-minimal

# Customize as needed
filesystem:
  allowed_write_roots:
    - "/workspace"
    - "/tmp"
```

## Step 3: Enable Protection

### Option A: Wrap Your Command

```bash
hush run --policy policy.yaml -- python my_agent.py
```

### Option B: OpenClaw Config

```json
{
  "plugins": {
    "entries": {
      "@hushclaw/openclaw": {
        "enabled": true,
        "config": {
          "policy": "./policy.yaml"
        }
      }
    }
  }
}
```

## Step 4: Verify It Works

Try an operation that should be blocked:

```bash
# This should fail
hush run --policy policy.yaml -- cat ~/.ssh/id_rsa
```

Expected output:

```
⛔ BLOCKED by ForbiddenPathGuard
   Path: ~/.ssh/id_rsa
   Reason: Path matches forbidden pattern: ~/.ssh/*
   Severity: CRITICAL
```

## What's Protected?

With the default `ai-agent-minimal` policy:

| Protected | Examples |
|-----------|----------|
| Credentials | `~/.ssh/*`, `~/.aws/*`, `~/.gnupg/*` |
| Secrets | `.env` files, `*.pem`, `*.key` |
| Network | Only allowlisted domains |
| System files | `/etc/shadow`, `/etc/passwd` |

## Try These Examples

```bash
# Allowed: Read workspace files
hush run --policy policy.yaml -- cat ./README.md
# ✅ ALLOWED

# Blocked: Read SSH keys
hush run --policy policy.yaml -- cat ~/.ssh/id_rsa
# ⛔ BLOCKED

# Allowed: Fetch from GitHub
hush run --policy policy.yaml -- curl https://api.github.com/zen
# ✅ ALLOWED

# Blocked: Fetch from unknown domain
hush run --policy policy.yaml -- curl https://evil.com/data
# ⛔ BLOCKED
```

## Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `deterministic` | Block violations | Production (default) |
| `advisory` | Warn but allow | Testing policies |
| `audit` | Log only | Gradual rollout |

```bash
# Advisory mode (warn only)
hush run --policy policy.yaml --mode advisory -- your-command
```

## Next Steps

- [Understanding Guards](../concepts/guards.md) - Learn about the 5 built-in guards
- [Writing Custom Policies](./first-policy.md) - Create policies for your needs
- [OpenClaw Integration](../guides/openclaw-integration.md) - Deep integration guide
