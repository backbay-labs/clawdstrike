# Guide: Write a Posture Policy

This guide shows a minimal posture policy with `work` and `quarantine` states.

## 1. Start from a baseline

```yaml
version: "1.2.0"
name: Team Posture Policy
extends: clawdstrike:default
```

## 2. Add posture states

```yaml
posture:
  initial: work
  states:
    work:
      capabilities: [file_access, file_write, egress, mcp_tool]
      budgets:
        file_writes: 100
        egress_calls: 50
        mcp_tool_calls: 200

    quarantine:
      capabilities: []
      budgets: {}
```

## 3. Add transitions

```yaml
posture:
  transitions:
    - { from: "*", to: quarantine, on: critical_violation }
    - { from: "*", to: quarantine, on: budget_exhausted }
```

## 4. Validate

```bash
hush policy validate ./policy.yaml
hush policy lint ./policy.yaml --strict
```

## 5. Simulate with posture tracking

```bash
hush policy simulate ./policy.yaml ./events.jsonl --json --track-posture
```

Use `posture.state`, `posture.budgets`, and `posture.transition` in output entries to verify expected behavior.

## Example policies

- `examples/policies/minimal-posture.yaml`
- `examples/policies/enterprise-posture.yaml`
