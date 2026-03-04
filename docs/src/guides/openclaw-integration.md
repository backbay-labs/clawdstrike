# OpenClaw Integration

This repository contains an OpenClaw plugin under `packages/adapters/clawdstrike-openclaw`.

For desktop + local agent runtime operations, see [Agent OpenClaw Operations](agent-openclaw-operations.md).

## Prerequisites

- OpenClaw CLI/runtime installed and working (`openclaw --help`).
- A local project with `openclaw.json` plugin configuration access.
- `clawdstrike` CLI available for policy validation checks.

## Enforcement boundaries (read this)

The OpenClaw plugin enforces policy at the **tool boundary**. For the full integration contract (and what requires an OS sandbox/broker), see [Enforcement Tiers & Integration Contract](../concepts/enforcement-tiers.md).

- **Preflight** via the `policy_check` tool (agents should call it before risky operations).
- **Post-action** via the `tool_result_persist` hook (can block/redact what is persisted + record violations).

This is **not** an OS sandbox and does not intercept syscalls. If an agent/runtime bypasses the OpenClaw tool layer, Clawdstrike cannot stop it.

## Installation

### From local development (alpha)

```bash
# Link the local package
openclaw plugins install --link /path/to/clawdstrike/packages/adapters/clawdstrike-openclaw

# Enable the plugin
openclaw plugins enable clawdstrike-security

# Verify it's loaded
openclaw plugins list | grep clawdstrike
```

### From npm (when published)

```bash
openclaw plugins install @clawdstrike/openclaw
```

## Quick verification

```bash
# Check plugin status
openclaw clawdstrike status

# Test policy checks
openclaw clawdstrike check file_read ~/.ssh/id_rsa
# → Denied by forbidden_path

openclaw clawdstrike check file_read /tmp/test.txt
# → Action allowed

# Test with an agent
openclaw agent --local --session-id test \
  --message "Use policy_check to check if reading ~/.ssh/id_rsa is allowed"
```

## Important: policy schema is different from Rust

The OpenClaw plugin uses its **own policy schema** (currently `version: "clawdstrike-v1.0"`). It is **not** the same as the Rust `clawdstrike::Policy` schema (`version: "1.2.0"`).

If you paste a Rust policy into OpenClaw, it should fail closed (and it does): unknown fields are rejected.

**Exception:** OpenClaw policies may include `guards.custom[]` entries (threat-intel guards) using the canonical config shape (`package`, `config`, `async`). This is intentionally plugin-shaped and is validated fail-closed.

See [Schema Governance](../concepts/schema-governance.md) for the repo-wide versioning/compat rules.

## Configuration

Add to `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "clawdstrike-security": {
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

## Recommended flow

1. Use a built-in ruleset as a starting point: `clawdstrike:ai-agent`.

2. Test policy checks via CLI:
   ```bash
   openclaw clawdstrike check file_read ~/.ssh/id_rsa
   openclaw clawdstrike check network api.github.com
   ```

3. Use `policy_check` tool for **preflight** decisions (before the agent attempts an action).

4. Use the OpenClaw hook(s) for **post-action** defense-in-depth (e.g., block/strip tool outputs that contain secrets).

## Agent tool: policy_check

The plugin registers a `policy_check` tool that agents can use:

```text
policy_check({ action: "file_read", resource: "~/.ssh/id_rsa" })
→ {
    "allowed": false,
    "denied": true,
    "guard": "forbidden_path",
    "message": "Denied by forbidden_path: Access to forbidden path...",
    "suggestion": "SSH keys are protected..."
	  }
```

**Actions:** `file_read`, `file_write`, `network`, `command`, `tool_call`

## CLI commands

```bash
# Plugin status
openclaw clawdstrike status

# Check an action
openclaw clawdstrike check <action> <resource>
```

## Where to look

- OpenClaw plugin docs: `packages/adapters/clawdstrike-openclaw/docs/`
- OpenClaw plugin code: `packages/adapters/clawdstrike-openclaw/src/`
- Plugin-scoped minimal example: `packages/adapters/clawdstrike-openclaw/examples/hello-secure-agent/`
- Top-level example app: `examples/openclaw-plugin/`
