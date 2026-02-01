# Getting Started with Hushclaw for OpenClaw

Hushclaw provides security enforcement for AI agents running in OpenClaw.

## Installation

```bash
npm install @hushclaw/openclaw
openclaw plugins enable @hushclaw/openclaw
```

## Quick Start

### 1. Create a Policy File

Create `.hush/policy.yaml` in your project:

```yaml
version: "hushclaw-v1.0"

egress:
  mode: allowlist
  allowed_domains:
    - "api.github.com"
    - "pypi.org"
    - "registry.npmjs.org"

filesystem:
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - "~/.gnupg"
    - ".env"

on_violation: cancel
```

### 2. Configure OpenClaw

Add to your `openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "@hushclaw/openclaw": {
        "enabled": true,
        "config": {
          "policy": "./.hush/policy.yaml"
        }
      }
    }
  }
}
```

### 3. Start OpenClaw

```bash
openclaw start
```

Your agent is now protected!

## Verify It Works

Ask your agent: "Try to read ~/.ssh/id_rsa"

Expected response: Operation blocked by ForbiddenPathGuard.

## Using the CLI

### Validate Your Policy

```bash
hushclaw policy lint .hush/policy.yaml
```

### Test an Event

Create `test-event.json`:
```json
{
  "type": "file_read",
  "resource": "~/.ssh/id_rsa"
}
```

```bash
hushclaw policy test test-event.json --policy .hush/policy.yaml
```

### Query Audit Log

```bash
hushclaw audit query --denied
```

### Explain a Block

```bash
hushclaw why <event-id>
```

## Agent Tools

### policy_check

Agents can use the `policy_check` tool to check permissions before attempting operations:

```
policy_check({ action: "file_write", resource: "/etc/passwd" })
-> { allowed: false, reason: "Path is forbidden" }
```

The tool provides:
- `allowed`: Whether the action is permitted
- `denied`: Whether the action is blocked
- `reason`: Human-readable explanation
- `guard`: Which guard made the decision
- `suggestion`: Helpful alternative approaches

## Policy Reference

### Egress Control

```yaml
egress:
  mode: allowlist  # allowlist | denylist | open
  allowed_domains:
    - "api.github.com"
    - "*.amazonaws.com"  # Wildcards supported
  denied_domains:
    - "*.onion"
    - "localhost"
```

### Filesystem Protection

```yaml
filesystem:
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - ".env"
  allowed_write_roots:
    - "/tmp"
    - "/workspace"
```

### Violation Handling

```yaml
on_violation: cancel  # cancel | warn | log
```

- `cancel`: Block the operation (recommended)
- `warn`: Log a warning but allow
- `log`: Silently log

## Built-in Rulesets

Use predefined rulesets by extending them:

```yaml
extends: hushclaw:ai-agent-minimal
```

Available rulesets:
- `hushclaw:ai-agent-minimal` - Basic protection
- `hushclaw:ai-agent` - Standard development
- `hushclaw:strict` - Production environments

## Next Steps

- See the [Policy Reference](./policy-reference.md) for all options
- Check the [Examples](../examples/) directory
- Read about [Advanced Configuration](./advanced.md)
