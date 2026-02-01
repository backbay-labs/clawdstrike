# Your First Policy

Learn to write custom security policies for your agents.

## Policy Basics

A hushclaw policy is a YAML file that defines security rules:

```yaml
version: "hushclaw-v1.0"

egress:
  mode: allowlist
  allowed_domains:
    - "api.github.com"

filesystem:
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"

on_violation: cancel
```

## Extending Built-in Policies

Start from a base policy and customize:

```yaml
version: "hushclaw-v1.0"
extends: hushclaw:ai-agent-minimal

# Add your domains
egress:
  allowed_domains:
    - "api.stripe.com"
    - "sentry.io"

# Add project-specific protections
filesystem:
  forbidden_paths:
    - "./secrets"
    - "./.env.production"
```

## Policy Sections

### Egress (Network)

Control outbound network connections:

```yaml
egress:
  mode: allowlist  # allowlist, denylist, or open

  allowed_domains:
    - "api.anthropic.com"
    - "api.openai.com"
    - "*.github.com"

  denied_domains:
    - "*.onion"
    - "localhost"
    - "127.*"
```

### Filesystem

Control file access:

```yaml
filesystem:
  # Directories where writes are allowed
  allowed_write_roots:
    - "/workspace"
    - "/tmp"

  # Paths that must never be accessed
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - ".env"
    - "*.pem"
```

### Execution

Control command execution:

```yaml
execution:
  # Patterns to block
  denied_patterns:
    - "rm -rf /"
    - "curl.*|.*bash"
    - "sudo su"
```

### Tools

Control MCP/agent tools:

```yaml
tools:
  allowed: []  # Empty = all allowed
  denied:
    - "shell_exec_raw"
```

### Limits

Resource limits:

```yaml
limits:
  max_execution_seconds: 300
  max_memory_mb: 4096
  max_output_bytes: 10485760
```

## Violation Actions

What happens when a rule is violated:

```yaml
on_violation: cancel  # Options: cancel, warn, isolate, escalate
```

| Action | Behavior |
|--------|----------|
| `cancel` | Block the operation immediately |
| `warn` | Log warning but allow |
| `isolate` | Cut network, continue read-only |
| `escalate` | Require human approval |

## Validate Your Policy

```bash
hush policy lint policy.yaml
```

Output:

```
✓ Syntax valid
✓ Schema valid
✓ No conflicts detected

Suggestions:
  - Consider adding 'pypi.org' for Python package access
```

## Test Against Events

```bash
# Create a test event
cat > event.json << 'EOF'
{
  "event_type": "file_read",
  "data": {
    "path": "~/.ssh/id_rsa"
  }
}
EOF

# Test it
hush policy test event.json --policy policy.yaml
```

Output:

```
Event: file_read ~/.ssh/id_rsa
Result: DENIED
Guard: ForbiddenPathGuard
Reason: Path matches forbidden pattern: ~/.ssh/*
```

## Complete Example

```yaml
# my-project-policy.yaml
version: "hushclaw-v1.0"
extends: hushclaw:ai-agent

# Project uses Stripe and Sentry
egress:
  allowed_domains:
    - "api.stripe.com"
    - "sentry.io"

# Project-specific secrets
filesystem:
  forbidden_paths:
    - "./secrets"
    - "./.env.production"
    - "./credentials.json"
  allowed_write_roots:
    - "./src"
    - "./tests"
    - "/tmp"

# Tighter execution limits
limits:
  max_execution_seconds: 120

on_violation: cancel
```

## Next Steps

- [Architecture](../concepts/architecture.md) - Understand how hushclaw works
- [Guards Reference](../reference/guards/README.md) - All guard details
- [Policy Schema](../reference/policy-schema.md) - Full schema reference
