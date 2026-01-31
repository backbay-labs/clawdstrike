---
name: hushclaw-tool-guard
description: "Enforce security policy on tool executions"
metadata: {"openclaw":{"emoji":"🔒","events":["tool_result_persist"]}}
---

# HushClaw Tool Guard Hook

This hook intercepts tool results before they're persisted to the agent transcript.
It enforces security policies, redacts sensitive data, and blocks dangerous operations.

## Features

- **Policy Enforcement**: Evaluates each tool call against the loaded security policy
- **Secret Redaction**: Automatically redacts detected secrets from tool outputs
- **Violation Logging**: Records policy violations for audit purposes
- **Mode Support**: Respects deterministic/advisory/audit enforcement modes

## Configuration

Configure via the hushclaw plugin settings:

```json
{
  "plugins": {
    "entries": {
      "@hushclaw/openclaw": {
        "config": {
          "policy": "./policy.yaml",
          "mode": "deterministic"
        }
      }
    }
  }
}
```

## Behavior

1. **On tool_result_persist event**:
   - Creates a PolicyEvent from the tool result
   - Evaluates against all enabled guards
   - If denied: Sets error on tool result, adds message to event
   - If allowed: Redacts any secrets from output
   - Logs decision for audit trail

2. **Enforcement Modes**:
   - `deterministic`: Block on policy violation
   - `advisory`: Warn but allow on policy violation
   - `audit`: Log only, never block
