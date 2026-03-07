---
name: clawdstrike-idea-to-architecture
description: Use when a raw ClawdStrike product, platform, or security idea needs to be grounded in the current repository, framed as architecture, and turned into a docs index, current-state inventory, or first-pass design set.
---

# ClawdStrike Idea to Architecture

Use this skill when the user starts from an idea, category framing, or product thesis and needs repo-grounded architecture work instead of abstract brainstorming.

## Outcomes

Drive toward these outputs:

- repo-backed current-state assessment
- architecture framing tied to real code paths
- documentation spine in the appropriate docs area
- code and artifact map
- clear gap statement: what exists, what is missing, what should be documented next

## Workflow

1. Capture the idea in one sentence.
2. Inspect the repo before making claims.
3. Identify the code surfaces that already support the idea.
4. Choose the right docs home before writing: `apps/terminal/docs/` for terminal-specific work, `docs/plans/` or `docs/specs/` for planning/spec work, and `docs/src/` only for user-facing book docs.
5. Write current-state and target-architecture docs before implementation plans.

## Repo Discipline

- Prefer `rg` and `rg --files` for discovery.
- Do not invent capabilities without finding the relevant crate, route, app, or document.
- Reference concrete code paths in the docs.
- If you add docs under `docs/src/`, update `docs/src/SUMMARY.md` and validate with `mdbook build docs`.
- If you add docs under `docs/plans/`, `docs/specs/`, or `apps/terminal/docs/`, keep a clear reading order inside the local index or parent document.

## Reading Order

Start with the nearest existing docs for the idea:

- terminal execution work: `apps/terminal/README.md`, `apps/terminal/docs/codex-agent-pack.md`, and the local initiative docs
- multi-agent or swarm work: `docs/plans/multi-agent/overview.md`, `docs/plans/multi-agent/isolation-boundaries.md`, `docs/plans/multi-agent/coordination-protocols.md`
- broader roadmap/spec work: `docs/plans/README.md`, the relevant `docs/plans/**`, `docs/roadmaps/**`, and `docs/specs/**`

## Stop Condition

Do not jump into coding from this skill unless the user explicitly asks. The job here is to convert the idea into repo-grounded architecture and a stable docs entry point.
