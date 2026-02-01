# Hushclaw

**Multi-model security enforcement for AI agents**

Hushclaw is an open-source security suite that protects AI agents from:

- **Credential theft** - Blocks access to SSH keys, cloud credentials, API keys
- **Data exfiltration** - Controls network egress with domain allowlists
- **Code injection** - Detects dangerous patterns like `curl|bash`
- **Secret leakage** - Prevents API keys from appearing in outputs

## Quick Start

```bash
# Install the CLI
cargo install hush-cli

# Create a policy
cat > policy.yaml << 'EOF'
version: "hushclaw-v1.0"
extends: hushclaw:ai-agent
EOF

# Run with protection
hush run --policy policy.yaml -- your-agent
```

## For OpenClaw Users

```bash
npm install @hushclaw/openclaw
openclaw plugins enable @hushclaw/openclaw
```

[Get Started →](./getting-started/installation.md)

## Key Features

| Feature | Description |
|---------|-------------|
| **5 Built-in Guards** | ForbiddenPath, Egress, SecretLeak, PatchIntegrity, McpTool |
| **YAML Policies** | Simple, readable policy definitions |
| **Hot Reload** | Update policies without restarting |
| **3 Modes** | Deterministic (block), Advisory (warn), Audit (log) |
| **Crypto Primitives** | Ed25519 signing, Merkle trees for audit trails |
| **Multi-Language** | Rust core, TypeScript SDK, Python SDK (coming) |

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                    Your Agent                          │
│  (Claude Code, OpenClaw, Custom)                       │
└─────────────────────────┬──────────────────────────────┘
                          │
┌─────────────────────────▼──────────────────────────────┐
│                    Hushclaw                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐ │
│  │ Guards   │  │ Policy   │  │ Audit    │  │ Crypto │ │
│  │ (5 types)│  │ Engine   │  │ Logging  │  │ (sign) │ │
│  └──────────┘  └──────────┘  └──────────┘  └────────┘ │
└────────────────────────────────────────────────────────┘
```

## What's Protected by Default?

With the `ai-agent-minimal` policy:

| Category | Protected Items |
|----------|-----------------|
| Credentials | `~/.ssh/*`, `~/.aws/*`, `~/.gnupg/*` |
| Secrets | `.env` files, `*.pem`, `*.key` |
| Network | Only allowlisted domains |
| System | `/etc/shadow`, `/etc/passwd` |

## Community

- [GitHub](https://github.com/hushclaw/hushclaw)
- [Discord](https://discord.gg/hushclaw)
- [Contributing](https://github.com/hushclaw/hushclaw/blob/main/CONTRIBUTING.md)

## License

MIT
