# Codex CLI Orchestration Playbook

> **Status:** Draft | **Date:** 2026-03-06
>
> This playbook shows how to use Codex CLI as the execution mechanism for the
> fleet-security workstreams.

## Purpose

The goal is not “run many agents and hope.” The goal is to run bounded worker
lanes in isolated worktrees with repeatable review and merge discipline.

## Recommended Layout

Starting from the main repository root:

```text
/Users/connor/Medica/backbay/standalone/clawdstrike
```

Use sibling directories for orchestration state and worker worktrees:

```text
/Users/connor/Medica/backbay/standalone/clawdstrike
/Users/connor/Medica/backbay/standalone/clawdstrike-worktrees/
/Users/connor/Medica/backbay/standalone/clawdstrike-orchestration/
```

Keeping worker worktrees outside the main repo tree reduces accidental staging
or cleanup mistakes.

## Worktree Setup

```bash
mkdir -p ../clawdstrike-worktrees
mkdir -p ../clawdstrike-orchestration

git worktree add ../clawdstrike-worktrees/orch -b feature/fleet-orchestrator
git worktree add ../clawdstrike-worktrees/a1-directory -b feature/fleet-directory
git worktree add ../clawdstrike-worktrees/a2-detection -b feature/fleet-detection
git worktree add ../clawdstrike-worktrees/a3-response -b feature/fleet-response
git worktree add ../clawdstrike-worktrees/a4-hunt -b feature/fleet-hunt
git worktree add ../clawdstrike-worktrees/a5-console -b feature/fleet-console
git worktree add ../clawdstrike-worktrees/a6-cases -b feature/fleet-cases
git worktree add ../clawdstrike-worktrees/a7-graph -b feature/fleet-graph
git worktree add ../clawdstrike-worktrees/a8-telemetry -b feature/fleet-telemetry
```

The orchestrator lane should be created first and used to keep the workstream
docs, branch plan, and merge queue current.

## Dispatch Pattern

Each worker lane should be launched from its own worktree with a brief from
[Agent Brief Pack](agent-briefs.md).

Recommended pattern:

```bash
mkdir -p ../clawdstrike-orchestration/a1-directory

codex exec \
  -C ../clawdstrike-worktrees/a1-directory \
  --full-auto \
  -o ../clawdstrike-orchestration/a1-directory/final.md \
  -
```

When the command waits for stdin, paste the corresponding brief from
[Agent Brief Pack](agent-briefs.md) and then send EOF.

If the worktree is intentionally disposable and externally isolated, the
orchestrator may choose the lower-friction mode:

```bash
mkdir -p ../clawdstrike-orchestration/a1-directory

codex exec \
  -C ../clawdstrike-worktrees/a1-directory \
  --dangerously-bypass-approvals-and-sandbox \
  -o ../clawdstrike-orchestration/a1-directory/final.md \
  -
```

That mode should not be used casually in the canonical repository root.

## Suggested Dispatch Order

1. `A1`
2. `A2`
3. `A3`
4. review and merge the Wave 1 lanes
5. `A4`
6. review and merge `A4`
7. `A6` and `A7`
8. `A5`
9. `A8`

This order matches the dependency graph and keeps the backend ahead of the UI.

## Resume Pattern

If a worker lane needs another turn:

```bash
mkdir -p ../clawdstrike-orchestration/a1-directory

(
  cd ../clawdstrike-worktrees/a1-directory &&
  codex exec resume \
    --last \
    --full-auto \
    -o ../../clawdstrike-orchestration/a1-directory/resume.md \
    "Continue from the current branch state. Keep file ownership boundaries. Finish the outstanding verification items."
)
```

Use resume for incremental follow-up, not for redirecting the lane into a new
scope.

## Review Pattern

Before a worker branch is merged:

```bash
mkdir -p ../clawdstrike-orchestration/a1-directory

(
  cd ../clawdstrike-worktrees/a1-directory &&
  codex exec review \
    --base main \
    --full-auto \
    -o ../../clawdstrike-orchestration/a1-directory/review.md
)
```

If the lane depends on another feature branch that is not yet merged, review
against that branch instead of `main`.

## Orchestrator Loop

For each active lane, the orchestrator should do the same loop:

1. confirm the lane is still within its file-ownership boundary
2. inspect the worker handoff summary
3. run review
4. rebase or cherry-pick as needed
5. wire shared registration files in the orchestrator worktree
6. run the relevant verification gates
7. merge or restack the branch

## Logging and Traceability

Each lane should have a directory under `../clawdstrike-orchestration/` that
contains:

- `final.md`: worker handoff
- `review.md`: review findings
- any additional merge notes

Suggested layout:

```text
../clawdstrike-orchestration/
  a1-directory/
    final.md
    review.md
  a2-detection/
    final.md
    review.md
```

This keeps the orchestration evidence outside the repo but still local and easy
to inspect.

## Merge Hygiene

Recommended merge hygiene:

- rebase each worker branch on the latest merged upstream before final review
- let the orchestrator own final migration numbers
- avoid merging more than one shared-file integration at a time
- keep shared-file edits in separate orchestrator commits where possible

## Cleanup

After a lane is fully merged:

```bash
git worktree remove ../clawdstrike-worktrees/a1-directory
git branch -d feature/fleet-directory
```

Do not remove a worktree until:

- the branch is merged or archived
- the orchestration notes are captured
- any needed follow-up tasks are moved into the next lane or backlog

## Related Documents

- [Multi-Agent Execution Overview](execution-orchestration.md)
- [Workstream Map](workstream-map.md)
- [Dependency and Merge Graph](dependency-graph.md)
- [Verification Matrix](verification-matrix.md)
- [Agent Brief Pack](agent-briefs.md)
