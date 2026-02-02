# Getting Started with Clawdstrike for OpenClaw

Clawdstrike provides **tool-layer guardrails** for AI agents running in OpenClaw.

## What this plugin can (and cannot) enforce

Clawdstrike enforces policy at the **OpenClaw tool boundary**:

- **Preflight**: agents can use `policy_check` before attempting risky operations.
- **Post-action**: the `tool_result_persist` hook can block/redact tool outputs and record violations.

This is **not** an OS sandbox. If an agent/runtime can access the filesystem/network without going through OpenClaw tools, Clawdstrike cannot stop it.

## Installation

```bash
npm install @clawdstrike/openclaw
openclaw plugins enable @clawdstrike/openclaw
```

## Quick Start

### 1. Create a Policy File

Create `.hush/policy.yaml` in your project:

```yaml
version: "clawdstrike-v1.0"

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
      "@clawdstrike/openclaw": {
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

Clawdstrike is now configured for your OpenClaw runtime.

## Verify It Works

Ask your agent: "Try to read ~/.ssh/id_rsa" (via whatever file-reading tool OpenClaw provides).

Expected behavior: the tool result should be blocked/redacted and you should see a message indicating the `forbidden_path` guard denied it.

## Using the CLI

### Validate Your Policy

```bash
clawdstrike policy lint .hush/policy.yaml
```

### Test an Event

Create `test-event.json`:
```json
{
  "eventId": "example-1",
  "eventType": "file_read",
  "timestamp": "2026-02-02T00:00:00Z",
  "data": { "type": "file", "path": "~/.ssh/id_rsa", "operation": "read" }
}
```

```bash
clawdstrike policy test test-event.json --policy .hush/policy.yaml
```

### Query Audit Log

```bash
clawdstrike audit query --denied
```

### Explain a Block

```bash
clawdstrike why <event-id>
```

## Agent Tools

### policy_check

Agents can use the `policy_check` tool to check permissions before attempting operations:

```
policy_check({ action: "file_write", resource: "/etc/passwd" })
-> { allowed: false, denied: true, warn: false, guard: "forbidden_path", message: "Denied by forbidden_path: …" }
```

The tool provides:
- `allowed`: Whether the action is permitted
- `denied`: Whether the action is blocked
- `reason` / `message`: Human-readable explanation
- `guard`: Which guard made the decision
- `suggestion`: Helpful alternative approaches

## Policy Reference

### Egress Control

```yaml
egress:
  mode: allowlist  # allowlist | denylist | open | deny_all
  allowed_domains:
    - "api.github.com"
    - "*.amazonaws.com"  # Wildcards supported
  denied_domains:
    - "*.onion"
    - "localhost"
```

Note: egress policy is enforced at the tool boundary. If a network request is already executed by a tool, the post-action hook cannot undo the side effect; it can only block/redact persistence of the result.

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
extends: clawdstrike:ai-agent-minimal
```

Available rulesets:
- `clawdstrike:ai-agent-minimal` - Basic protection
- `clawdstrike:ai-agent` - Standard development
- `clawdstrike:strict` - Production environments

## Next Steps

- See the [Policy Reference](./policy-reference.md) for all options
- Check the [Examples](../examples/) directory
- Read about [Advanced Configuration](./advanced.md)
