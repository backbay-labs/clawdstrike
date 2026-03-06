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

## Existing Hook
Swarm scripts now accept additional `codex` args via:

```bash
export CLAWDSTRIKE_SWARM_CODEX_ARGS='-s danger-full-access -a never'
```

Use that hook for the investigation. Do not silently widen permissions as a global default.
