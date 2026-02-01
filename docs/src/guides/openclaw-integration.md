# OpenClaw Integration

Complete guide to using hushclaw with OpenClaw.

## Installation

```bash
npm install @hushclaw/openclaw
openclaw plugins enable @hushclaw/openclaw
```

## Configuration

### Minimal Setup

```json
{
  "plugins": {
    "entries": {
      "@hushclaw/openclaw": {
        "enabled": true
      }
    }
  }
}
```

This enables hushclaw with the default `ai-agent-minimal` policy.

### Custom Policy

```json
{
  "plugins": {
    "entries": {
      "@hushclaw/openclaw": {
        "enabled": true,
        "config": {
          "policy": "./.hush/policy.yaml",
          "mode": "deterministic",
          "logLevel": "info"
        }
      }
    }
  }
}
```

### Per-Agent Override

```json
{
  "agents": {
    "list": [
      {
        "id": "trusted-agent",
        "security": {
          "policy": "hushclaw:permissive"
        }
      },
      {
        "id": "untrusted-agent",
        "security": {
          "policy": "hushclaw:strict"
        }
      }
    ]
  }
}
```

## How It Works

### Hook Integration

Hushclaw uses two OpenClaw hooks:

1. **`tool_result_persist`** - Evaluates every tool call against policy
2. **`agent:bootstrap`** - Injects security context into agent prompts

### Enforcement Flow

```
Agent calls tool
    ↓
tool_result_persist hook fires
    ↓
Hushclaw evaluates policy
    ↓
├─ Allow: Tool result added to transcript
├─ Warn: Warning logged, result added
└─ Deny: Error returned, operation blocked
```

## Agent-Aware Features

### Security Prompt Injection

Agents automatically receive security context explaining:

- What paths are forbidden
- Which domains are allowed
- How to use the `policy_check` tool

This is injected via the `agent:bootstrap` hook.

### policy_check Tool

Agents can query the policy before attempting risky operations:

```typescript
// Agent can call this tool
const result = await policy_check({
  action: "file_write",
  resource: "/etc/passwd"
});
// Returns: { allowed: false, reason: "Path is forbidden" }
```

This helps agents avoid triggering violations.

## Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `deterministic` | Block violations | Production |
| `advisory` | Warn but allow | Testing policies |
| `audit` | Log only | Gradual rollout |

### Set via config

```json
{
  "plugins": {
    "entries": {
      "@hushclaw/openclaw": {
        "config": {
          "mode": "advisory"
        }
      }
    }
  }
}
```

### Set via environment

```bash
HUSHCLAW_MODE=advisory openclaw start
```

## CLI Commands

```bash
# Validate a policy
openclaw hushclaw policy lint ./policy.yaml

# Show current effective policy
openclaw hushclaw policy show

# Test an event against policy
openclaw hushclaw policy test ./event.json

# Explain why something was blocked
openclaw hushclaw why <event-id>

# Query audit log
openclaw hushclaw audit query --denied --since 1h
```

## Project Setup

### Initialize with security

```bash
openclaw init --with-security
```

Creates:
- `.hush/policy.yaml` - Your security policy
- `.hush/config.yaml` - Hushclaw configuration
- Updates `.gitignore` for receipts

### Manual setup

1. Create `.hush/policy.yaml`:

```yaml
version: "hushclaw-v1.0"
extends: hushclaw:ai-agent

egress:
  allowed_domains:
    - "api.mycompany.com"

filesystem:
  forbidden_paths:
    - "./secrets"
```

2. Add to `openclaw.json`:

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

## Troubleshooting

### "Policy not found"

Check your policy path in openclaw.json:

```json
"policy": "./.hush/policy.yaml"  // Relative to openclaw.json
```

### "Unexpected block"

Use advisory mode to debug:

```bash
HUSHCLAW_MODE=advisory openclaw start
```

Check the logs for warnings that explain what would be blocked.

### "Agent doesn't see security context"

Ensure the `agent:bootstrap` hook is enabled:

```bash
openclaw hooks list | grep hushclaw
```

Should show:
```
@hushclaw/openclaw:agent-bootstrap  enabled
@hushclaw/openclaw:tool-guard       enabled
```

### View recent violations

```bash
openclaw hushclaw audit query --denied --since 1h
```

## Example: Secure Agent

See the [Hello Secure Agent](../recipes/claude-code.md) recipe for a complete working example.

## Next Steps

- [Custom Guards](./custom-guards.md) - Extend with your own guards
- [Policy Inheritance](./policy-inheritance.md) - Build on base policies
- [Audit Logging](./audit-logging.md) - Configure logging
