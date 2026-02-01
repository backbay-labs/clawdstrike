# Guards Reference

Complete reference for all built-in guards.

## Overview

| Guard | Purpose | Default |
|-------|---------|---------|
| [ForbiddenPathGuard](./forbidden-path.md) | Block sensitive paths | Enabled |
| [EgressAllowlistGuard](./egress.md) | Control network access | Enabled |
| [SecretLeakGuard](./secret-leak.md) | Detect secrets in output | Enabled |
| [PatchIntegrityGuard](./patch-integrity.md) | Block dangerous code | Enabled |
| [McpToolGuard](./mcp-tool.md) | Control tool access | Enabled |

## Enable/Disable Guards

```yaml
guards:
  forbidden_path: true
  egress_allowlist: true
  secret_leak: true
  patch_integrity: true
  mcp_tool: true
```

## Event Types

Each guard handles specific events:

| Guard | FileRead | FileWrite | NetworkEgress | ToolCall | PatchApply |
|-------|----------|-----------|---------------|----------|------------|
| ForbiddenPath | ✓ | ✓ | | | |
| Egress | | | ✓ | | |
| SecretLeak | | | | | ✓ |
| PatchIntegrity | | | | | ✓ |
| McpTool | | | | ✓ | |

## Guard Evaluation Order

Guards are evaluated in this order:

1. **ForbiddenPathGuard** - Filesystem checks first
2. **EgressAllowlistGuard** - Network checks
3. **McpToolGuard** - Tool access checks
4. **SecretLeakGuard** - Content inspection
5. **PatchIntegrityGuard** - Code pattern checks

Evaluation short-circuits on first Deny.

## Common Configuration Patterns

### Maximum Security

```yaml
guards:
  forbidden_path: true
  egress_allowlist: true
  secret_leak: true
  patch_integrity: true
  mcp_tool: true

egress:
  mode: allowlist
  allowed_domains: []  # Nothing allowed

filesystem:
  forbidden_paths:
    - "~/*"  # Block all home directory access
```

### Development Mode

```yaml
guards:
  forbidden_path: true
  egress_allowlist: false  # Open network
  secret_leak: true
  patch_integrity: false   # Allow eval() etc.
  mcp_tool: false          # All tools allowed
```

### CI/CD Pipeline

```yaml
guards:
  forbidden_path: true
  egress_allowlist: true
  secret_leak: true
  patch_integrity: true
  mcp_tool: true

egress:
  allowed_domains:
    - "*.internal.company.com"
```

## Custom Guards

See [Custom Guards Guide](../../guides/custom-guards.md) for implementing your own guards.
