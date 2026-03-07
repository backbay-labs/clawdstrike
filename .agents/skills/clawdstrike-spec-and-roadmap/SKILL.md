---
name: clawdstrike-spec-and-roadmap
description: Use when architecture docs exist and need to be hardened into API, storage, migration, protocol, roadmap, or ticket-level specifications for Clawdstrike fleet-security work.
---

# Clawdstrike Spec and Roadmap

Use this skill after the architecture is real enough that the next step is not
more framing, but sharper specs and executable plans.

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
3. Prefer writing one focused spec per concern rather than bloated umbrella
   documents.
4. Turn each important spec into implementation slices and migration order.
5. Keep every plan tied to existing crates, routes, or apps.

## Repo Discipline

- Keep the docs under the existing section instead of scattering plans across
  unrelated folders.
- Update `docs/src/SUMMARY.md` and the local section index when adding new
  documents.
- Use stable file names that match the concept: `*-api-contract.md`,
  `*-storage-model.md`, `*-migrations.md`, `*-implementation.md`.
- Validate with `mdbook build docs`.

## Documents To Reuse

Read the most relevant existing docs instead of repeating them:

- `docs/src/fleet-security/index.md`
- `docs/src/fleet-security/roadmap.md`
- `docs/src/fleet-security/directory-implementation.md`
- `docs/src/fleet-security/directory-migrations.md`
- `docs/src/fleet-security/detection-api-contract.md`
- `docs/src/fleet-security/detection-storage-model.md`

## Stop Condition

Stop when the plan is specific enough that an implementation worker can pick up
one slice without needing another planning roundtrip.
