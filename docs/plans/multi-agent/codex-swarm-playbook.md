# Codex Swarm Playbook

This repo now supports two complementary Codex layers:

- a project-wide swarm/orchestration layer in `.codex/` and `.agents/skills/`
- a TUI-specific agent pack for `apps/terminal`

Use the swarm layer when the job is parallel planning, worktree coordination, lane execution, or merge sequencing across multiple sub-agents.
Use the TUI pack when the work is specifically about the operator cockpit, PTY dogfooding, UI polish, or release hardening inside `apps/terminal`.

## File Layout

- `.codex/config.toml`: root role registry and shared profiles
- `.codex/agents/*.toml`: per-role settings and developer instructions
- `.codex/swarm/lanes.tsv`: lane metadata for the active initiative
- `.codex/swarm/waves.tsv`: wave order for the active initiative
- `scripts/codex-swarm/*`: worktree setup, launch, status, resume, review, and notification helpers
- `.agents/skills/clawdstrike-*/SKILL.md`: reusable orchestration skills
- `apps/terminal/docs/codex-agent-pack.md`: TUI-specific usage guide

## Roles

Generic swarm roles:

- `repo_explorer`: map the repo before planning
- `architecture_planner`: turn ideas into architecture and docs
- `workstream_orchestrator`: define lanes, dependencies, and verification
- `docs_researcher`: validate repo docs and reading order
- `lane_worker`: implement one bounded lane inside one worktree
- `merge_reviewer`: review a lane before integration

TUI-specific roles remain available for terminal-specific work:

- `tui_explorer`
- `tui_dogfooder`
- `tui_worker`
- `tui_reviewer`
- `openai_docs_researcher`

## Profiles

Generic swarm profiles:

- `swarm-docs`
- `swarm-orchestrator`
- `swarm-worker`
- `swarm-review`

TUI-specific profiles remain available:

- `tui-dogfood`
- `tui-polish`
- `tui-review`
- `tui-docs`

## Workflow

### 1. Frame the work

Use one of:

- `$clawdstrike-idea-to-architecture`
- `$clawdstrike-spec-and-roadmap`
- `$clawdstrike-workstream-orchestrator`

This should leave:

- initiative docs
- explicit lane ownership
- verification commands
- `.codex/swarm/lanes.tsv`
- `.codex/swarm/waves.tsv`

### 2. Seed worktrees

Prefer the repo-local script suite:

```bash
scripts/codex-swarm/setup-worktrees.sh orch p1a p1b
scripts/codex-swarm/bootstrap-lane.sh p1a p1b
```

The scripts use `.codex/swarm/lanes.tsv` and `.codex/swarm/waves.tsv` as the
source of truth. Raw `git worktree` commands remain a fallback for debugging the
orchestration flow itself.

By default they create sibling directories named after the repo, for example:

- `../clawdstrike-sdks-worktrees/`
- `../clawdstrike-sdks-orchestration/`

Override them with `CLAWDSTRIKE_SWARM_WORKTREES_DIR` and
`CLAWDSTRIKE_SWARM_ORCH_DIR` when needed.

Example:

```bash
git worktree add ../clawdstrike-sdks-orch -b feature/tui-dispatch-orchestrator
git worktree add ../clawdstrike-sdks-p1a -b feature/tui-dispatch-phase1-foundation
git worktree add ../clawdstrike-sdks-p1b -b feature/tui-dispatch-phase1-run-detail
```

### 3. Launch lanes

Launch a whole wave:

```bash
scripts/codex-swarm/launch-wave.sh wave1 \
  --note "Execute the first dispatch foundation wave and leave clean handoffs."
```

Launch a single lane:

```bash
scripts/codex-swarm/launch-lane.sh p1a \
  --note "Focus on Phase 1 dispatch foundation only."
```

Fallback raw commands:

Orchestrator lane:

```bash
codex exec -C ../clawdstrike-sdks-orch -p swarm-orchestrator \
  "Use $clawdstrike-swarm-supervisor. Launch wave0 from .codex/swarm/waves.tsv, keep ORCH focused on shared wiring and merge sequencing, and leave a status summary with next-wave readiness."
```

Worker lane:

```bash
codex exec -C ../clawdstrike-sdks-p1a -p swarm-worker \
  "Use $clawdstrike-lane-executor. Execute lane P1A from .codex/swarm/lanes.tsv against the dispatch docs, stay within owned files, and leave a verification-backed handoff."
```

Review lane:

```bash
codex exec -C ../clawdstrike-sdks-p1a -p swarm-review \
  "Use $clawdstrike-merge-verifier. Review lane P1A for regressions, ownership violations, and missing verification. Findings first."
```

### 4. Advance waves deliberately

- do not launch later waves until prerequisite lanes are reviewed
- keep shared files orchestrator-owned
- update `.codex/swarm/*.tsv` if the plan changes
- merge narrow lanes instead of waiting for a massive restack
- use `scripts/codex-swarm/status.sh` to monitor lane state before launching more work

## Current Seeded Initiative

`.codex/swarm/lanes.tsv` and `.codex/swarm/waves.tsv` are currently seeded for the Huntronomer
workspace-shell initiative described in:

- `docs/plans/clawdstrike/huntronomer/workspace-shell/README.md`
- `docs/plans/clawdstrike/huntronomer/workspace-shell/roadmap.md`
- `docs/plans/clawdstrike/huntronomer/workspace-shell/swarm-plan.md`
- `docs/specs/17-huntronomer-workspace-services.md`
- `docs/specs/18-huntronomer-shell-command-model.md`

Older dispatch and fleet-security lane maps remain valid examples, but they are not the active
launcher target anymore.

## Guardrails

- Do not sync another dirty worktree wholesale into this repo.
- Keep the generic swarm layer additive; do not remove the TUI-specific pack.
- Prefer exact worktree, branch, lane, and verification metadata over hand-wavy instructions.
