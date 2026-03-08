---
name: clawdstrike-desktop-dogfood-loop
description: Use when the Huntronomer desktop app needs live dogfooding, reproduction, or smoke validation across the shell, launch overlay, Hunt Deck, Playwright browser flow, Tauri bridge, or OpenClaw and receipt states.
---

# ClawdStrike Desktop Dogfood Loop

Use this skill when the job is to prove what the Huntronomer desktop surface actually does, not
what the React tree or Tauri code seems like it should do.

## Outcomes

Drive toward:

- exact reproduction steps for Huntronomer shell behavior
- artifact-backed smoke validation from a live browser session
- clear separation between browser-shell issues, Tauri bridge issues, and runtime-data issues
- the smallest follow-up fix or verification plan

## Workflow

1. Launch the real surface first.
2. Prefer `scripts/huntronomer-playwright-smoke.sh` for fast shell and launch-overlay checks.
3. When the issue involves native commands, pair the smoke flow with `cd apps/desktop && bun run tauri:dev`.
4. Classify the problem before editing: shell IA, routing, visual polish, OpenClaw runtime,
   daemon connectivity, Tauri bridge, proof and replay UI, or release packaging.
5. Capture artifacts under `output/playwright/` and keep the failure mode concrete.
6. After a fix, rerun the smallest live pass that proves the issue is gone.

## Current Fast Path

Run:

```bash
scripts/huntronomer-playwright-smoke.sh
```

This smoke path:

- opens a fresh browser session against the Huntronomer shell
- captures the launch overlay
- dismisses into the current Hunt Deck
- saves screenshots, snapshots, console output, network output, and `summary.json`

Read `apps/desktop/docs/huntronomer-dogfooding.md` for environment knobs and current limitations.

## Required Verification

Use the relevant subset of:

- `scripts/huntronomer-playwright-smoke.sh`
- `cd apps/desktop && bun run typecheck`
- `cd apps/desktop && bun run test -- --run`
- `cd apps/desktop && bun run build`
- `cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml`

## Guardrails

- Do not treat browser smoke as proof that the native macOS Tauri shell is correct.
- Do not fail the smoke run on expected offline OpenClaw or daemon console errors unless the
  environment is meant to be fully connected.
- Use a fresh browser session for smoke checks so local storage does not hide first-run behavior.
- Keep screenshots and snapshot artifacts for regressions that are hard to explain in prose.
