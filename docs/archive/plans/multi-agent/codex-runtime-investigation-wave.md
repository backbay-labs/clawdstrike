# Codex Runtime Investigation Wave

## Objective
Determine whether the detached `codex exec` background-exit issue is caused by sandbox / approval mode, runtime environment, or something else.

## Questions To Answer
- Does `codex exec` still background-exit after `thread.started` with:
  - default swarm args
  - `-s danger-full-access -a never`
  - `--dangerously-bypass-approvals-and-sandbox`
- Does the behavior differ between:
  - direct foreground execution
  - detached `nohup` execution
  - worktree vs main checkout
- Is the failure correlated with:
  - Bun-managed environment variables
  - missing TTY
  - sandbox / approval config
  - working directory or profile selection

## Deliverables
- Concrete reproduction matrix
- Small launcher/runtime patch if the root cause is inside our scripts
- Clear recommendation for the swarm launcher:
  - keep current defaults
  - add opt-in flag support only
  - or adopt a new safer default

## Findings (2026-03-06)

### Reproduction Matrix

| Case | Result | Notes |
| --- | --- | --- |
| Foreground `codex exec` in `p7-codex-runtime` with launcher env unsets | Pass | Completed normally with `thread.started` and `turn.completed` |
| Foreground `codex exec` in `p7-codex-runtime` with an allocated TTY | Pass | Completed normally; no behavior change versus no-TTY foreground execution |
| Detached `nohup` execution in `p7-codex-runtime` with launcher env unsets | Pass | Completed normally; no early background exit after `thread.started` |
| Detached `nohup` execution in `p7-codex-runtime` with inherited `CODEX_THREAD_ID` and `CODEX_MANAGED_BY_BUN=1` | Pass | Bun-managed env inheritance did not reproduce the failure in this environment |
| Detached `nohup` execution in main checkout `clawdstrike-sdks` with launcher env unsets | Pass | No worktree-specific failure observed |
| Detached `nohup` execution with `--dangerously-bypass-approvals-and-sandbox` | Pass | Completed normally |
| Detached execution with `CLAWDSTRIKE_SWARM_CODEX_ARGS='-s danger-full-access -a never'` before patch | Fail before start | `codex exec` rejected `-a` with `unexpected argument '-a' found`; no `thread.started` event |

### Root Cause

The documented extra-args hook was wired after the `exec` subcommand:

```bash
codex exec "${codex_args[@]}" ...
```

That works for `--sandbox`, but not for `-a/--ask-for-approval` on `codex-cli 0.111.0`, because approval mode is parsed as a global `codex` flag rather than an `exec` subcommand flag. The detached-launch investigation therefore surfaced a launcher argument-order bug, not a reproducible detached-runtime exit in the current environment.

### Recommendation

- Keep current swarm defaults.
- Keep explicit sandbox/approval overrides opt-in through `CLAWDSTRIKE_SWARM_CODEX_ARGS`.
- Place extra/profile args before `exec` so both global and `exec`-scoped flags work.
- Do not adopt `-s danger-full-access -a never` as a default based on this investigation.

## Existing Hook
Swarm scripts now accept additional `codex` args via:

```bash
export CLAWDSTRIKE_SWARM_CODEX_ARGS='-s danger-full-access -a never'
```

Launcher scripts must pass those args before `exec`, for example:

```bash
codex $CLAWDSTRIKE_SWARM_CODEX_ARGS exec ...
```

Use that hook for the investigation. Do not silently widen permissions as a global default.
