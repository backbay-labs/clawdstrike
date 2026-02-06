# Postures

Postures add session-aware policy enforcement on top of static guard rules.

A posture model defines:

- `states`: named security modes such as `observe`, `work`, `elevated`, `quarantine`
- `capabilities`: which action kinds are allowed in each state (`file_access`, `file_write`, `egress`, `shell`, `mcp_tool`, `patch`, `custom`)
- `budgets`: optional per-capability usage limits for a state
- `transitions`: how a session moves between states (`user_approval`, `any_violation`, `critical_violation`, `timeout`, `budget_exhausted`)

## Runtime Model

At runtime, posture state is stored per session in `SessionContext.state["posture"]`:

- `current_state`
- `entered_at`
- `budgets` (`used`/`limit` counters)
- `transition_history`

The engine evaluates posture in three phases:

1. **Precheck**: capability + budget gate
2. **Guard pipeline**: built-in/custom/async guards
3. **Postcheck**: budget consumption and transition trigger handling

## Fail-Closed Behavior

When posture is configured, runtimes should enforce through a single mediation path and persist posture updates atomically. If posture state cannot be persisted, enforcement should fail closed.
