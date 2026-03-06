---
name: clawdstrike-idea-to-architecture
description: Use when a raw Clawdstrike product, platform, or security idea needs to be grounded in the current repository, framed as architecture, and turned into a docs index, current-state inventory, or first-pass design set.
---

# Clawdstrike Idea to Architecture

Use this skill when the user starts from an idea, category framing, or product
thesis and needs repo-grounded architecture work instead of brainstorming in the
abstract.

## Outcomes

Drive toward these outputs:

- repo-backed current-state assessment
- architecture framing tied to real code paths
- documentation spine under `docs/src/fleet-security/` or another appropriate
  docs area
- code and artifact map
- clear gap statement: what exists, what is missing, what should be documented
  next

## Workflow

1. Capture the idea in one sentence.
2. Inspect the repo before making claims.
3. Identify the code surfaces that already support the idea.
4. Create or extend a docs index that becomes the canonical reading order.
5. Write the current-state and target-architecture documents before writing an
   implementation plan.

## Repo Discipline

- Prefer `rg` and `rg --files` for discovery.
- Do not invent capabilities without finding the relevant crate, route, app, or
  document.
- Reference concrete code paths in the docs.
- If you create or move docs, update `docs/src/SUMMARY.md`.
- Validate with `mdbook build docs`.

## Reading Order

Start with the existing fleet-security spine if it exists:

- `docs/src/fleet-security/index.md`
- `docs/src/fleet-security/current-state.md`
- `docs/src/fleet-security/architecture.md`
- `docs/src/fleet-security/code-map.md`

If the section does not exist yet, create the minimal spine first and keep the
documents narrow and additive.

## Stop Condition

Do not jump into coding from this skill unless the user explicitly asks. The job
here is to convert the idea into repo-grounded architecture and a stable docs
entry point.
