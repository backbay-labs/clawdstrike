# Huntronomer Dogfooding

This document defines the current fast dogfood loop for the restored Huntronomer desktop app.

## Quick Smoke

Run:

```bash
scripts/huntronomer-playwright-smoke.sh
```

The script:

- reuses `http://localhost:1420` if a dev server is already live
- otherwise starts `bun run dev --host localhost --port 1420` in `apps/desktop`
- opens a fresh browser session with `playwright-cli`
- captures the Huntronomer launch overlay
- dismisses into the current Hunt Deck shell
- saves artifacts under `output/playwright/huntronomer-smoke/<timestamp>/`

Artifacts:

- `launch-overlay.png`
- `command-deck.png`
- `command-deck-snapshot.md`
- `launch-overlay.txt`
- `command-deck.txt`
- `console-errors.txt`
- `network.txt`
- `summary.json`

## Environment Knobs

```bash
HUNTRONOMER_SMOKE_URL=http://localhost:1420
HUNTRONOMER_SMOKE_START_DEV=1
HUNTRONOMER_SMOKE_HEADED=0
HUNTRONOMER_SMOKE_KEEP_BROWSER=0
HUNTRONOMER_SMOKE_STRICT_CONSOLE=0
HUNTRONOMER_SMOKE_TIMEOUT_SECS=30
```

Examples:

```bash
HUNTRONOMER_SMOKE_HEADED=1 scripts/huntronomer-playwright-smoke.sh
HUNTRONOMER_SMOKE_STRICT_CONSOLE=1 scripts/huntronomer-playwright-smoke.sh
HUNTRONOMER_SMOKE_START_DEV=0 scripts/huntronomer-playwright-smoke.sh
```

## What The Smoke Proves

Today the smoke path verifies:

1. the Huntronomer page loads
2. the first-run launch overlay renders
3. the overlay can be dismissed with `Enter`
4. the current Hunt Deck shell renders with `LIVE` and `REPLAY`
5. the command deck artifacts can be captured for regression review

This is intentionally a shell-level smoke, not a complete product validation.

## Current Expected Console Errors

In a normal local browser-only run, the current app may emit errors like:

- `Agent local API token is unavailable`
- `ERR_CONNECTION_REFUSED` for `http://localhost:9876/health`

Those reflect missing local agent or daemon dependencies, not necessarily a broken shell load. The
smoke script records them but does not fail on them unless `HUNTRONOMER_SMOKE_STRICT_CONSOLE=1`.

## Tauri Boundary

This smoke flow drives the browser-hosted UI, not the native Tauri shell. Use it for:

- layout regressions
- route and shell regressions
- launch overlay regressions
- obvious runtime-state failures visible from the web surface

Do not treat it as proof of native Tauri correctness on macOS. For native-path checks, pair it
with:

```bash
cd apps/desktop && bun run tauri:dev
cd apps/desktop && bun run typecheck
cd apps/desktop && bun run test -- --run
cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml
```

## Current Product Assumption

This smoke targets the current restored Huntronomer shell, which still lands in the Hunt Deck
(`#/nexus`) after the launch overlay. When the roadmap moves the product to a true `Signal Wire`
home surface, update this smoke to follow the new default operator loop.
