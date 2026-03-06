---
name: clawdstrike-spec-and-roadmap
description: Use when architecture docs exist and need to be hardened into API, storage, migration, protocol, roadmap, or ticket-level specifications for ClawdStrike work.
---

# ClawdStrike Spec and Roadmap

Use this skill after the architecture is real enough that the next step is not more framing, but sharper specs and executable plans.

## Outcomes

Drive toward these outputs:

- harder API and storage specs
- migration plans
- implementation milestones
- ticket-style work breakdown
- delivery roadmap tied back to code and docs

## Workflow

1. Read the architecture and current-state docs first.
2. Identify which concepts still need a harder contract.
3. Prefer one focused spec per concern rather than bloated umbrella documents.
4. Turn each important spec into implementation slices and migration order.
5. Keep every plan tied to existing crates, routes, apps, or docs.

## Repo Discipline

- Keep the docs in the docs area that already owns the subject instead of scattering plans across unrelated folders.
- Update `docs/src/SUMMARY.md` only when adding user-facing book docs under `docs/src/`.
- Use stable file names that match the concept: `*-api-contract.md`, `*-storage-model.md`, `*-implementation.md`, `*-roadmap.md`.

## Documents To Reuse

Read the most relevant existing docs instead of repeating them:

- `docs/plans/README.md`
- `docs/specs/*.md`
- `docs/roadmaps/*.md`
- `docs/plans/multi-agent/*.md` when coordination matters
- `apps/terminal/docs/dispatch-*.md` for the current TUI dispatch initiative

## Stop Condition

Stop when the plan is specific enough that an implementation worker can pick up one slice without another planning roundtrip.
