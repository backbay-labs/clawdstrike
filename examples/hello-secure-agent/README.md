# Hello Secure Agent

A minimal OpenClaw agent with hushclaw security integration. This example demonstrates the complete setup for a secure AI agent.

## What It Does

1. Runs an OpenClaw agent with a simple "hello" skill
2. All tool calls are verified by hushclaw guards
3. Provides a `policy_check` tool for preflight checks
4. Demonstrates fail-closed policy enforcement in action

## Project Structure

```
hello-secure-agent/
├── README.md           # This file
├── openclaw.json       # OpenClaw configuration
├── policy.yaml         # Hushclaw security policy
├── agent.js            # Simple agent script
└── skills/
    └── hello/
        └── SKILL.md    # Hello world skill
```

## Prerequisites

- Node.js 18+
- OpenClaw CLI (`npm install -g @openclaw/cli`)
- `@hushclaw/openclaw` CLI (`npx hushclaw ...`)

## Quick Start

```bash
# 1. Verify policy syntax
npm run policy:lint

# 2. Dry-run policy checks (no OpenClaw required)
npm start

# 3. Run the agent with OpenClaw + hushclaw enabled (requires OpenClaw CLI)
# openclaw run --config ./openclaw.json

# 4. Confirm enforcement (example)
# Try to read ~/.ssh/id_rsa via a tool and expect the plugin to block it.
```

## Configuration

### openclaw.json

The OpenClaw configuration enables the hushclaw plugin:

```json
{
  "plugins": [
    {
      "name": "@hushclaw/openclaw",
      "config": {
        "policy": "./policy.yaml",
        "mode": "deterministic"
      }
    }
  ]
}
```

### policy.yaml

The security policy defines:
- Forbidden filesystem paths
- Network egress allowlist/denylist rules
- Command deny patterns (regex)
- Optional tool allow/deny lists

## Understanding the Output

When you run the agent, you'll see security decisions in the logs:

```
[hushclaw] Allowed: file_read("/project/src/index.ts")
[hushclaw] Denied by forbidden_path: file_read("~/.ssh/id_rsa")
[hushclaw] Denied by egress: network("http://localhost:8080")
```

This example focuses on guard enforcement in OpenClaw. Receipt generation/attestation is handled by the Rust crates and is documented separately.

## Policy Customization

Edit `policy.yaml` to adjust security rules:

```yaml
# Allow additional network destinations
egress:
  mode: allowlist
  allowed_domains:
    - "api.anthropic.com"
    - "api.openai.com"
    - "my-api.com"

# Protect additional filesystem paths
filesystem:
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - ".env"
    - "**/secrets/**"

# Block dangerous commands (regex)
execution:
  denied_patterns:
    - "rm -rf /"
    - "curl.*\\|.*bash"
```

## Verification

This example does not generate cryptographic receipts. See `crates/hush-core` and the `hush` CLI docs for receipt signing/verification.

## Next Steps

- [Guard Reference](../../docs/reference/guards/) - Learn about all guards
- [Policy Schema](../../docs/reference/policy-schema.md) - Full policy options
- [OpenClaw Integration](../../docs/guides/openclaw-integration.md) - Detailed setup
