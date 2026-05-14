---
name: clawdstrike-tool-guard
description: "Enforce security policy on tool executions"
metadata: {"openclaw":{"emoji":"🔒","events":["tool_result_persist"]}}
---

# Clawdstrike Tool Guard Hook

This hook intercepts tool results before they're persisted to the agent transcript.
It enforces security policies, redacts sensitive data, and rewrites denied outputs into
guard-generated error messages.

## Enforcement boundary (important)

This hook runs on `tool_result_persist` (post-action). OpenClaw executes that hook
**synchronously**, so Clawdstrike performs deterministic blocking/redaction inline and then
optionally triggers async follow-up guards in the background. It can block/redact what is
persisted and record an audit trail, but it cannot undo side effects that already happened
(e.g., a network request a tool already made).

For preflight decisions, use the `policy_check` tool (and/or ensure your runtime consults clawdstrike before executing tools).

## Features

- **Policy Enforcement**: Evaluates each tool call against the loaded security policy
- **Secret Redaction**: Automatically redacts detected secrets from tool outputs
- **Violation Logging**: Records policy violations for audit purposes
- **Mode Support**: Respects deterministic/advisory/audit enforcement modes

## Configuration

Configure via the clawdstrike plugin settings:

```json
{
  "plugins": {
    "entries": {
      "@clawdstrike/openclaw": {
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
   - Runs deterministic guards synchronously against the real runtime payload
   - If denied: Replaces the persisted tool result with a guard-generated error result
   - If allowed: Redacts secrets and PII from the persisted output
   - If async custom guards are configured: runs a best-effort follow-up evaluation after persistence

2. **Enforcement Modes**:
   - `deterministic`: Block on policy violation
   - `advisory`: Warn but allow on policy violation
   - `audit`: Log only, never block
