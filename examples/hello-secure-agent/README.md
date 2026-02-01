# Hello Secure Agent

A minimal OpenClaw agent with hushclaw security integration. This example demonstrates the complete setup for a secure AI agent.

## What It Does

1. Runs an OpenClaw agent with a simple "hello" skill
2. All tool calls are verified by hushclaw guards
3. Generates a cryptographically signed receipt
4. Demonstrates policy enforcement in action

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
- Hushclaw CLI (`cargo install hush-cli`)

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Verify policy syntax
hush policy validate policy.yaml

# 3. Run the agent with security
openclaw run --with-hushclaw

# 4. View the receipt
hush receipt show .hush/receipts/latest.json
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
- Allowed file paths
- Network egress rules
- Secret patterns to block
- Tool restrictions

## Understanding the Output

When you run the agent, you'll see security decisions in the logs:

```
[hush] ALLOW: read_file("/app/data.txt")
[hush] DENY:  write_file("/etc/passwd") - forbidden path
[hush] ALLOW: http_request("api.example.com")
```

After the run completes, a receipt is generated:

```
Receipt: .hush/receipts/run_abc123.json
  Events:    15
  Denied:    2
  Signature: VALID
  Merkle:    VALID
```

## Policy Customization

Edit `policy.yaml` to adjust security rules:

```yaml
# Allow additional paths
guards:
  forbidden_path:
    allow:
      - "./my-data/**"

# Add network destinations
  egress:
    allowlist:
      - host: "my-api.com"
        ports: [443]
```

## Verification

Verify the receipt independently:

```bash
# Using CLI
hush receipt verify .hush/receipts/run_abc123.json

# Using Rust SDK
cargo run --example verify -- .hush/receipts/run_abc123.json

# Using TypeScript (browser)
# See ../typescript/browser-verify/
```

## Next Steps

- [Guard Reference](../../docs/reference/guards/) - Learn about all guards
- [Policy Schema](../../docs/reference/policy-schema.md) - Full policy options
- [OpenClaw Integration](../../docs/guides/openclaw-integration.md) - Detailed setup
