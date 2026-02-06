# Decisions (Guard Results)

Clawdstrike returns a `GuardResult` for an evaluated action.

## GuardResult

In Rust, a `GuardResult` contains:

- `allowed` (`bool`)
- `severity` (`info` | `warning` | `error` | `critical`)
- `message` (string)
- `details` (optional JSON)

The important contract:

- `allowed: false` means the action should be blocked by the caller.
- `allowed: true` with `severity: warning` means “allowed, but suspicious” (surface it to humans/logs).

## Aggregation in `HushEngine`

Multiple guards can apply to the same action. `HushEngine` aggregates the per-guard results into an overall verdict:

- any blocked result ⇒ overall is blocked
- otherwise, any warning ⇒ overall is warning (allowed)
- otherwise ⇒ overall is allowed

If `settings.fail_fast: true`, evaluation stops on the first block.

## Posture-Aware Decisions (`1.2.0+`)

When a policy includes `posture`, the engine adds posture checks around guard evaluation:

1. Precheck: capability + budget gate for the current posture state.
2. Guard pipeline: built-in/custom/async guards.
3. Postcheck: budget consumption + transition triggers.

This means denials can come from posture precheck (`posture` or `posture_budget`) before any guard runs.
