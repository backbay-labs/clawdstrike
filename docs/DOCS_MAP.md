# Documentation Map

Last updated: 2026-02-09

This page defines where documentation lives and which source is canonical when documents overlap.

## Canonical Sources

| Path | Role | Canonical? |
| --- | --- | --- |
| `docs/src/**` | Public mdBook docs for users/contributors. | Yes for user-facing behavior and usage. |
| `docs/plans/**` | Implementation plans and migration/roadmap docs. | Yes for planned execution details. |
| `docs/plans/decisions/**` | Architecture decision records. | Yes for architectural decisions. |
| `docs/specs/**` | Formal feature/specification docs. | Yes for accepted normative spec details. |
| `docs/research/**` | Exploratory/non-normative analysis. | No (context only). |
| `docs/roadmaps/**` | Time-based planning docs. | No (planning context only). |
| `docs/audits/**` | Point-in-time repository and quality audits. | No (operational guidance/context). |

## Conflict Resolution Order

If documents disagree, interpret sources in this order:

1. Implemented code and tests in repo
2. ADRs in `docs/plans/decisions/**`
3. Accepted specs in `docs/specs/**`
4. Public behavior docs in `docs/src/**`
5. Plans in `docs/plans/**`
6. Research and roadmaps in `docs/research/**` and `docs/roadmaps/**`

## What Goes Where

1. New user-facing feature docs: `docs/src/`
2. Architecture decision records: `docs/plans/decisions/`
3. Execution plans and migration guides: `docs/plans/`
4. Formal specs and schema-level details: `docs/specs/`
5. Open-ended exploratory writing: `docs/research/`
6. Point-in-time audit reports: `docs/audits/`

## Maintenance Rules

1. Update this map whenever a new docs domain is added.
2. Link new major docs from either `docs/src/SUMMARY.md` (mdBook) or `docs/plans/README.md`.
3. When moving paths, update docs references in the same PR.
