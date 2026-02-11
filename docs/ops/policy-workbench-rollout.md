# Policy Workbench Rollout

This guide covers rollout and rollback for the desktop Policy Workbench embedded in Forensics River.

## Scope

- Surface: `apps/desktop` Forensics River policy editor/test panel.
- Backend dependency: `hushd` policy APIs (`/api/v1/policy`, `/api/v1/policy/validate`, `/api/v1/eval`).
- Safety goal: fail closed on parse/eval errors and keep rollback immediate.

## Feature Controls

Environment flags (desktop app):

- `VITE_POLICY_WORKBENCH=0` disables the panel.
- `VITE_ENABLE_POLICY_WORKBENCH=0` is accepted as a compatibility alias.

Local storage override (takes precedence per user session):

- Key: `sdr:feature:policy-workbench`
- Values:
  - `"1"` force enable
  - `"0"` force disable
  - missing key falls back to environment/default behavior

## Rollout Sequence

1. Enable for internal operators only (canary build/profile).
2. Monitor policy validate/eval error rates and save failure rates.
3. Expand to default-enabled profile after no unexpected error-state spikes.
4. Keep env toggle available for one release cycle as a rollback valve.

## Rollback

1. Set `VITE_POLICY_WORKBENCH=0` in the shipped desktop environment.
2. If a local override forced `"1"`, clear it:
   - `localStorage.removeItem("sdr:feature:policy-workbench")`
3. Restart desktop app to guarantee flag re-evaluation.

## Verification Checklist

- Desktop loads and Forensics River renders without Workbench when disabled.
- Workbench load/validate/eval/save calls succeed when enabled.
- Unsaved draft protection prompts before leaving Forensics River.
- `hushd` eval regressions pass:

```bash
cargo test -p hushd --test integration eval_policy_event_regression
```

## Security Notes

- UI never shells out directly; all checks flow through typed Tauri/API bridge calls.
- Eval input is schema-normalized to canonical `PolicyEvent` shapes.
- Invalid policy/eval inputs must remain explicit error states (no silent allow).
