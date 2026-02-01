# Claude Code Integration

Protect Claude Code with hushclaw security policies.

## Overview

Claude Code is an AI coding assistant. This recipe shows how to add security enforcement to prevent:

- Credential access
- Data exfiltration
- Dangerous commands

## Quick Setup

### 1. Install hush-cli

```bash
cargo install hush-cli
```

### 2. Create Policy

Create `.hush/policy.yaml` in your project:

```yaml
version: "hushclaw-v1.0"
extends: hushclaw:ai-agent

# Your APIs
egress:
  allowed_domains:
    - "api.stripe.com"

# Project secrets
filesystem:
  forbidden_paths:
    - "./secrets"
    - "./.env.production"
```

### 3. Run with Protection

```bash
hush run --policy .hush/policy.yaml -- claude
```

Or add an alias:

```bash
alias claude-secure="hush run --policy .hush/policy.yaml -- claude"
```

## Recommended Policy

```yaml
# .hush/policy.yaml
version: "hushclaw-v1.0"
extends: hushclaw:ai-agent

egress:
  mode: allowlist
  allowed_domains:
    # Claude API
    - "api.anthropic.com"

    # Your project's APIs
    - "api.yourcompany.com"

    # Package registries (if needed)
    - "pypi.org"
    - "registry.npmjs.org"

filesystem:
  forbidden_paths:
    # Standard credentials
    - "~/.ssh"
    - "~/.aws"
    - "~/.gnupg"

    # Project secrets
    - "./secrets"
    - "./.env.production"
    - "./credentials.json"

  allowed_write_roots:
    - "${WORKSPACE}"
    - "/tmp"

execution:
  denied_patterns:
    - "rm -rf /"
    - "curl.*|.*bash"

limits:
  max_execution_seconds: 600

on_violation: cancel
```

## Advisory Mode for Testing

Start in advisory mode to see what would be blocked:

```bash
hush run --policy .hush/policy.yaml --mode advisory -- claude
```

Check logs for warnings, then switch to `deterministic` mode.

## Integration with Claude's CLAUDE.md

Add to your `CLAUDE.md`:

```markdown
## Security

This project uses hushclaw security policies.

Protected paths:
- ~/.ssh, ~/.aws, ~/.gnupg (credentials)
- ./secrets, ./.env.production (project secrets)

Allowed domains:
- api.anthropic.com
- api.yourcompany.com
- pypi.org, registry.npmjs.org

If an operation is blocked, check `.hush/policy.yaml`.
```

## Shell Wrapper

Create a wrapper script:

```bash
#!/bin/bash
# ~/.local/bin/claude-secure

POLICY="${HOME}/.hush/claude-policy.yaml"

if [ ! -f "$POLICY" ]; then
    echo "Policy not found: $POLICY"
    exit 1
fi

exec hush run --policy "$POLICY" -- claude "$@"
```

Make it executable:

```bash
chmod +x ~/.local/bin/claude-secure
```

## Per-Project Policies

Different projects can have different policies:

```bash
# Project A - strict
cd project-a
hush run --policy .hush/strict-policy.yaml -- claude

# Project B - permissive
cd project-b
hush run --policy .hush/dev-policy.yaml -- claude
```

## Viewing Blocked Actions

When something is blocked:

```
⛔ BLOCKED by ForbiddenPathGuard
   Path: ~/.ssh/id_rsa
   Reason: Path matches forbidden pattern: ~/.ssh/*
   Severity: CRITICAL
```

To understand why:

```bash
hush explain <event-id>
```

## Audit Trail

Enable receipts for audit:

```bash
hush run --policy .hush/policy.yaml --receipt ./receipts/$(date +%Y%m%d).json -- claude
```

Verify later:

```bash
hush verify ./receipts/20260131.json
```

## Troubleshooting

### Claude can't access package registry

Add the registry to your policy:

```yaml
egress:
  allowed_domains:
    - "pypi.org"
    - "files.pythonhosted.org"
```

### Claude can't write to certain directories

Check `allowed_write_roots`:

```yaml
filesystem:
  allowed_write_roots:
    - "${WORKSPACE}"
    - "/tmp"
    - "./output"  # Add your directory
```

### Too many false positives

Use advisory mode to test, then tune:

```bash
hush run --mode advisory -- claude
# Check logs, adjust policy
```

## Best Practices

1. **Start with ai-agent base** - It's designed for this
2. **Test in advisory mode first** - Before enforcing
3. **Keep policy in version control** - Track changes
4. **Use project-specific policies** - Different needs for different projects
5. **Enable receipts** - For audit trails
