# AI Agent Ruleset

Optimized security for AI coding agents.

## Use Case

The AI Agent ruleset is designed for:

- Claude Code, Cursor, and similar tools
- Autonomous coding agents
- Human-in-the-loop AI development
- OpenClaw integration

## Configuration

```yaml
# hushclaw:ai-agent
version: "hushclaw-v1.0"
name: ai-agent
extends: hushclaw:default
description: Security policy tuned for AI coding agents

egress:
  mode: allowlist
  allowed_domains:
    # AI APIs
    - "api.anthropic.com"
    - "api.openai.com"
    - "generativelanguage.googleapis.com"

    # Code hosting
    - "github.com"
    - "api.github.com"
    - "*.githubusercontent.com"

    # Package registries
    - "pypi.org"
    - "files.pythonhosted.org"
    - "registry.npmjs.org"
    - "crates.io"

    # Documentation
    - "docs.python.org"
    - "docs.rs"

  # Log all requests for audit
  audit_all_requests: true

filesystem:
  allowed_write_roots:
    - "${WORKSPACE}"
    - "${TMPDIR}"

  forbidden_paths:
    # Standard credentials
    - "~/.ssh"
    - "~/.aws"
    - "~/.gnupg"
    - "~/.config/gcloud"

    # IDE/editor configs (don't let AI modify)
    - "~/.config"
    - "~/.local/share"
    - "${WORKSPACE}/.vscode"
    - "${WORKSPACE}/.idea"

execution:
  denied_patterns:
    # Standard dangerous patterns
    - "rm -rf /"
    - "curl.*|.*bash"

  # Require confirmation for sensitive ops
  require_confirmation:
    - "git commit"
    - "git push"
    - "npm install"
    - "pip install"
    - "cargo add"

  # Prevent prompt injection via long args
  max_command_length: 10000

tools:
  # Per-tool policies
  policies:
    write_file:
      max_size_bytes: 1048576  # 1MB per file
      require_diff: true

    run_command:
      timeout_seconds: 60
      max_output_lines: 1000

    read_file:
      max_size_bytes: 5242880  # 5MB per file

limits:
  max_execution_seconds: 600  # 10 min for complex tasks
  max_tool_calls_per_minute: 100

on_violation: escalate

escalation:
  notify:
    - "slack://channel/ai-agent-alerts"
  require_human_approval_for:
    - "repeated_violations"
    - "credential_access_attempt"
    - "network_exfiltration_pattern"
```

## AI-Specific Features

### Confirmation Prompts

Agents must confirm before:
- Git commits and pushes
- Package installations
- Dependency additions

### Tool Policies

Per-tool limits prevent runaway operations:

```yaml
tools:
  policies:
    write_file:
      max_size_bytes: 1048576
      require_diff: true
```

### Rate Limiting

Prevent excessive API calls:

```yaml
limits:
  max_tool_calls_per_minute: 100
```

### Escalation

Suspicious patterns trigger human review:

```yaml
on_violation: escalate
escalation:
  require_human_approval_for:
    - "credential_access_attempt"
```

## Differences from Default

| Feature | Default | AI Agent |
|---------|---------|----------|
| Audit requests | No | Yes |
| IDE config protection | No | Yes |
| Confirmation prompts | No | Yes |
| Tool limits | No | Yes |
| Rate limiting | No | Yes |
| On violation | Cancel | Escalate |

## OpenClaw Integration

This ruleset is the default for OpenClaw:

```json
{
  "plugins": {
    "entries": {
      "@hushclaw/openclaw": {
        "enabled": true,
        "config": {
          "policy": "hushclaw:ai-agent"
        }
      }
    }
  }
}
```

## Extending

```yaml
version: "hushclaw-v1.0"
extends: hushclaw:ai-agent

# Add company APIs
egress:
  allowed_domains:
    - "api.company.com"

# Tighter tool limits
tools:
  policies:
    write_file:
      max_size_bytes: 524288  # 512KB
```

## Minimal Variant

For less restricted agents:

```yaml
version: "hushclaw-v1.0"
extends: hushclaw:ai-agent

# Remove confirmation requirements
execution:
  require_confirmation: []

# Allow longer execution
limits:
  max_execution_seconds: 1800
```

## When to Use

- Any AI coding assistant
- Autonomous code generation
- AI-assisted PR creation
- Agent-driven development workflows
