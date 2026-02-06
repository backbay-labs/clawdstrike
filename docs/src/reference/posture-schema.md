# Posture Schema Reference

Posture is available in policy schema `1.2.0+` under `policy.posture`.

## `posture`

```yaml
posture:
  initial: <state_name>
  states:
    <state_name>:
      description: <optional string>
      capabilities: [<capability>, ...]
      budgets:
        <budget_key>: <non-negative integer>
  transitions:
    - from: <state_name|"*">
      to: <state_name>
      on: <trigger>
      after: <duration>   # required only for timeout
      requires: []        # reserved
```

## Capability values

- `file_access`
- `file_write`
- `egress`
- `shell`
- `mcp_tool`
- `patch`
- `custom`

## Budget keys

- `file_writes`
- `egress_calls`
- `shell_commands`
- `mcp_tool_calls`
- `patches`
- `custom_calls`

## Transition triggers

- `user_approval`
- `user_denial`
- `critical_violation`
- `any_violation`
- `timeout`
- `budget_exhausted`
- `pattern_match` (reserved)

## Duration format

Timeout transitions require `after` in one of:

- `<n>s`
- `<n>m`
- `<n>h`

Examples: `30s`, `5m`, `1h`.

## Validation rules

- `posture.initial` must exist in `posture.states`
- unknown capabilities are rejected
- unknown budget keys are rejected
- negative budget values are rejected
- transition `from` must be a known state or `"*"`
- transition `to` must be a known state (`"*"` is invalid)
- timeout transitions require a valid `after` duration

## Runtime persistence

When posture is enabled, runtime state is stored per session in `SessionContext.state["posture"]` with:

- `current_state`
- `entered_at`
- `budgets`
- `transition_history`
