# Getting Started with Clawdstrike for OpenClaw

Clawdstrike provides **tool-layer guardrails** for AI agents running in OpenClaw.

## What this plugin can (and cannot) enforce

Clawdstrike enforces policy at the **OpenClaw tool boundary**:

- **Pre-context inbound**: `inbound_message` / `user_input` hooks can allow, warn, block, or sanitize text before it reaches the model context.
- **Preflight**: agents can use `policy_check` before attempting risky operations.
- **Post-action**: the synchronous `tool_result_persist` hook can rewrite/redact persisted tool outputs and record violations.

This is **not** an OS sandbox. If an agent/runtime can access the filesystem/network without going through OpenClaw tools, Clawdstrike cannot stop it.

See [Enforcement Tiers & Integration Contract](https://github.com/backbay-labs/clawdstrike/blob/main/docs/src/concepts/enforcement-tiers.md) for what is enforceable at the tool boundary (and what requires a sandbox/broker).

## Installation

### From local development (recommended during alpha)

```bash
# Link the local plugin entry path
openclaw plugins install --link /path/to/clawdstrike/packages/adapters/clawdstrike-openclaw/clawdstrike-security.js

# Enable the plugin
openclaw plugins enable clawdstrike-security
```

### From npm (when published)

```bash
openclaw plugins install @clawdstrike/openclaw
```

## Quick Start

### 1. Create a Policy File

Create `.hush/policy.yaml` in your project:

```yaml
version: "clawdstrike-v1.0"   # legacy alias; canonical current version is "1.2.0"

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

Add to your `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "clawdstrike-security": {
        "enabled": true,
        "config": {
          "policy": "./.hush/policy.yaml",
          "mode": "deterministic"
        }
      }
    }
  }
}
```

### 3. Restart Gateway (if running)

```bash
openclaw gateway restart
```

Clawdstrike is now configured for your OpenClaw runtime.

## Verify It Works

### Using the CLI

```bash
# Check plugin status
openclaw clawdstrike status

# Test a policy check
openclaw clawdstrike check file_read ~/.ssh/id_rsa
# → Denied by forbidden_path: Access to forbidden path...

openclaw clawdstrike check file_read /tmp/test.txt
# → Action allowed
```

### Using an Agent

Ask your agent to use the policy_check tool:

```bash
openclaw agent --local --session-id test \
  --message "Use policy_check to check if reading ~/.ssh/id_rsa is allowed"
```

Expected: The agent uses `policy_check` and reports that access is denied by the `forbidden_path` guard.

## Agent Tools

### policy_check

Agents can use the `policy_check` tool to check permissions before attempting operations:

```
policy_check({ action: "file_read", resource: "~/.ssh/id_rsa" })
→ {
    "allowed": false,
    "denied": true,
    "guard": "forbidden_path",
    "message": "Denied by forbidden_path: Access to forbidden path...",
    "suggestion": "SSH keys are protected. Consider using a different credential storage method."
  }
```

**Parameters:**
- `action`: One of `file_read`, `file_write`, `network`, `command`, `tool_call`
- `resource`: The resource to check (file path, domain/URL, command string, or tool name)

**Response fields:**
- `allowed`: Whether the action is permitted
- `denied`: Whether the action is blocked
- `guard`: Which guard made the decision
- `reason` / `message`: Human-readable explanation
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

Note: egress policy is enforced at the tool boundary. If a network request is already executed by a tool, the post-action hook cannot undo the side effect; it can only rewrite/redact persistence of the result. Because `tool_result_persist` is synchronous in OpenClaw, deterministic blocking/redaction happens inline and async custom guards run as best-effort follow-up observers.

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

Use predefined rulesets:

```yaml
extends: clawdstrike:ai-agent-minimal
```

Available rulesets:
- `clawdstrike:ai-agent-minimal` - Basic protection
- `clawdstrike:ai-agent` - Standard development

## Plugin Configuration Options

```json
{
  "clawdstrike-security": {
    "enabled": true,
    "config": {
      "policy": "./policy.yaml",
      "mode": "deterministic",
      "logLevel": "info",
      "guards": {
        "forbidden_path": true,
        "egress": true,
        "secret_leak": true,
        "patch_integrity": true
      },
      "inbound": {
        "enabled": true,
        "failMode": "open",
        "customType": "untrusted_text",
        "auditContentMode": "hash",
        "redactedSnippetLength": 160
      }
    }
  }
}
```

- `policy`: Path to policy YAML or built-in ruleset name
- `mode`: `deterministic` (block), `advisory` (warn), or `audit` (log only)
- `logLevel`: `debug`, `info`, `warn`, or `error`
- `guards`: Enable/disable specific guards
- `inbound.enabled`: Enable inbound hook enforcement (`inbound_message` / `user_input`)
- `inbound.failMode`: `open` (warn+continue on errors) or `closed` (block on evaluator errors)
- `inbound.customType`: Custom event subtype for policy (`custom` event with `customType`)
- `inbound.auditContentMode`: `hash` (default), `raw`, or `redacted_snippet`
- `inbound.redactedSnippetLength`: Max snippet length when `auditContentMode` is `redacted_snippet`

## Next Steps

- Check the [Examples](../examples/) directory
- Run `openclaw clawdstrike --help` to explore CLI commands
- See the main [Clawdstrike documentation](https://github.com/backbay-labs/clawdstrike/blob/main/docs/src/reference/guards/README.md) for guard details
