# Codex Swarm Pack

> **Status:** Draft | **Date:** 2026-03-06
>
> This document describes the repo-local Codex skill pack and command suite for
> the exact Clawdstrike workflow we have been using:
>
> 1. idea and framing
> 2. repo-backed architecture and docs index
> 3. hard specs and roadmap
> 4. workstreams, dependencies, and verification
> 5. Codex lane launch, monitoring, review, and wave advancement

## Layout

The pack is split across three repo-local locations:

- `.agents/skills/`: repo-scoped Codex skills
- `.codex/`: project Codex config, agent roles, lane metadata
- `scripts/codex-swarm/`: launch and supervision commands

This follows the Codex project-scope model:

- repo skills live in `.agents/skills`
- project config lives in `.codex/config.toml`
- agent roles are configured through `[agents]` and role `config_file` entries

## Installed Skills

| Skill | Purpose |
|---|---|
| `clawdstrike-idea-to-architecture` | turn a raw idea into repo-backed architecture docs |
| `clawdstrike-spec-and-roadmap` | turn architecture into harder specs, migrations, and implementation slices |
| `clawdstrike-workstream-orchestrator` | define lanes, dependencies, verification, and merge order |
| `clawdstrike-lane-executor` | run one bounded implementation lane inside one worktree |
| `clawdstrike-swarm-supervisor` | set up worktrees, launch lanes, monitor progress, advance waves |
| `clawdstrike-merge-verifier` | review, verify, and gate lane merges |

## Project Codex Config

The project config is in `.codex/config.toml`.

It sets:

- larger `project_doc_max_bytes` so layered `AGENTS.md` and docs fit cleanly
- a repo-local `notify` hook that logs Codex events into the orchestration area
- multi-agent limits under `[agents]`
- reusable profiles:
  - `swarm-docs`
  - `swarm-orchestrator`
  - `swarm-worker`
  - `swarm-review`
- reusable role configs:
  - `repo-explorer`
  - `architecture-planner`
  - `workstream-orchestrator`
  - `docs-researcher`
  - `lane-worker`
  - `merge-reviewer`

## Lane Metadata

Lane metadata lives in:

- `.codex/swarm/lanes.tsv`
- `.codex/swarm/waves.tsv`

These files are the stable registry for:

- branch names
- worktree names
- profile selection
- brief IDs
- wave membership
- optional lane bootstrap commands

The command suite reads these files instead of hard-coding lane state in
multiple places.

## Command Suite

Use the repo-local commands:

```bash
scripts/codex-swarm/setup-worktrees.sh
scripts/codex-swarm/bootstrap-lane.sh
scripts/codex-swarm/launch-lane.sh
scripts/codex-swarm/launch-wave.sh
scripts/codex-swarm/status.sh
scripts/codex-swarm/resume-lane.sh
scripts/codex-swarm/review-lane.sh
```

### What Each Command Does

- `setup-worktrees.sh`: creates lane worktrees, orchestration directories, and runs configured lane bootstrap commands
- `bootstrap-lane.sh`: reruns a lane bootstrap command for an existing worktree
- `launch-lane.sh`: starts one background `codex exec` job for a lane
- `launch-wave.sh`: launches every lane in a wave after ensuring worktrees exist
- `status.sh`: shows lane state, branch, change count, and review/final outputs
- `resume-lane.sh`: resumes the most recent Codex session for a lane worktree
- `review-lane.sh`: runs `codex exec review` for a completed lane

## Expected Runtime Layout

By default, runtime artifacts are written outside the repo tree:

```text
../clawdstrike-worktrees/
../clawdstrike-orchestration/
```

This keeps the tracked repository clean while still making the swarm state easy
to inspect.

## End-to-End Flow

### Phase 1: Idea to Architecture

Run Codex in the repo and explicitly invoke:

```text
Use $clawdstrike-idea-to-architecture ...
```

Goal:

- build or extend the docs spine
- ground the idea in real crates, apps, routes, and docs

### Phase 2: Specs and Roadmap

Run:

```text
Use $clawdstrike-spec-and-roadmap ...
```

Goal:

- write harder API, storage, migration, and implementation docs

### Phase 3: Workstream Design

Run:

```text
Use $clawdstrike-workstream-orchestrator ...
```

Goal:

- finalize lanes, dependency graph, verification matrix, and merge order

### Phase 4: Swarm Execution

Set up worktrees:

```bash
scripts/codex-swarm/setup-worktrees.sh orch a1 a2 a3
```

If a lane needs local dependency install or similar prep, define it in the
`bootstrap` column of `.codex/swarm/lanes.tsv`. `setup-worktrees.sh` will run it
automatically, and you can rerun it directly with:

```bash
scripts/codex-swarm/bootstrap-lane.sh a5
```

Launch the orchestrator and first wave:

```bash
scripts/codex-swarm/launch-lane.sh orch
scripts/codex-swarm/launch-wave.sh wave1
```

Monitor:

```bash
scripts/codex-swarm/status.sh
```

Review a finished lane:

```bash
scripts/codex-swarm/review-lane.sh a1 main
```

Resume a lane if needed:

```bash
scripts/codex-swarm/resume-lane.sh a1 --message "Finish the remaining verification and handoff items."
```

Advance only after the dependency graph and merge gates say it is safe.

## Supporting Docs

This pack is designed to work with the fleet-security execution docs:

- [Multi-Agent Execution Overview](execution-orchestration.md)
- [Workstream Map](workstream-map.md)
- [Dependency and Merge Graph](dependency-graph.md)
- [Verification Matrix](verification-matrix.md)
- [Codex CLI Orchestration Playbook](codex-cli-playbook.md)
- [Agent Brief Pack](agent-briefs.md)
