# Huntronomer Dogfooding

This note defines the current fast dogfood loop for the Huntronomer desktop shell and the
spirit-ritual chamber.

## Quick Browser Smoke

Run:

```bash
scripts/huntronomer-playwright-smoke.sh
```

The script:

- reuses `http://localhost:1420` if a dev server is already live
- otherwise starts `bun run dev --host localhost --port 1420` in `apps/desktop`
- opens a fresh browser session with `playwright-cli`
- waits for the first settled shell paint before capturing the live deck
- captures `launch-overlay.*` and `command-deck.*` as separate browser artifacts
- creates a hunt from the dock
- opens the ritual chamber from the hunt header spirit affordance
- releases the default spirit, prefers a room field stain when the room is mounted, and otherwise captures the deck aftermath beat
- switches to observatory-specific assertions automatically when `HUNTRONOMER_SMOKE_URL` points at `#/nexus/scene`
- saves artifacts under `output/playwright/huntronomer-smoke/<timestamp>/`

Artifacts:

- `launch-overlay.png`
- `command-deck.png`
- `command-deck-snapshot.md`
- `launch-overlay.txt`
- `command-deck.txt`
- `spirit-chamber.png`
- `spirit-chamber.txt`
- `spirit-chamber-snapshot.md`
- `spirit-release.json`
- `spirit-release.png`
- `console-errors.txt`
- `network.txt`
- `summary.json`

The `launch-overlay.*` and `command-deck.*` names are historical compatibility labels from the
older shell smoke path, but they are now captured separately from the live page instead of being
file-copied placeholders.

## Spirit Verification Smoke

Run:

```bash
scripts/huntronomer-spirit-smoke.sh
```

This focused smoke now covers the ritual chamber and the existing spirit runtime surfaces:

1. ritual chamber launch via the public `SpiritBindSheet` seam
2. ritual-native chamber copy and release controls
3. keyboard reachability for the mode rail and manual selection controls
4. multimodal ritual draft tests under `spirit-ritual/state`, `draw`, `upload`, and `modes`
5. atmosphere and release overlay pointer safety checks
6. dock and smart-bucket identity rendering
7. Forensics spirit actor derivation
8. Nexus spirit companion derivation

Artifacts:

- `output/tests/huntronomer-spirit-smoke/<timestamp>/vitest.log`
- `output/tests/huntronomer-spirit-smoke/<timestamp>/summary.json`

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
HUNTRONOMER_SMOKE_URL=http://localhost:1420/#/nexus/scene scripts/huntronomer-playwright-smoke.sh
```

## What The Smoke Proves

Today the combined smoke path verifies:

1. the Huntronomer shell loads from a fresh browser session
2. the workbench chrome renders with `WIRE`, `SCOPES`, `TAPE`, and `CONTEXT`
3. the dock `New hunt` control adds a new active hunt without forcing the chamber open
4. the hunt header spirit affordance opens the chamber on demand
5. the chamber presents `Spirit Chamber`, `Creation modes`, `Current read`, and `Release Spirit`
6. the default quick release can be committed and the chamber closes
7. the default quick release prefers a visible room field stain before the smoke captures, and falls back to the deck aftermath on routes without the room mounted
8. the ritual atmosphere and release overlays stay non-blocking in component-level verification
9. `#/nexus/scene` renders the observatory atlas shell with `OBSERVATORY ATLAS`, `STATIONS`, `FIELD BIAS`, and `CONTEXT`

This is still a fast operator smoke, not a full product validation.

## Current Manual Dogfood Gaps

Use manual dogfood or targeted Vitest for:

- thesis, draw, upload, and hybrid release behavior in a live browser session
- focus trap, Escape dismissal, and focus return from the chamber
- native Tauri correctness
- fully connected local agent and daemon behavior

## Current Expected Console Errors

In a normal local browser-only run, the app may emit errors like:

- `Agent local API token is unavailable`
- `ERR_CONNECTION_REFUSED` for `http://localhost:9876/health`

Those reflect missing local agent or daemon dependencies, not necessarily a broken shell load. The
smoke script records them but does not fail on them unless `HUNTRONOMER_SMOKE_STRICT_CONSOLE=1`.

## Tauri Boundary

This smoke flow drives the browser-hosted UI, not the native Tauri shell. Use it for:

- layout regressions
- route and shell regressions
- ritual chamber launch/regression checks
- obvious runtime-state failures visible from the web surface

Do not treat it as proof of native Tauri correctness on macOS. Pair it with:

```bash
cd apps/desktop && bun run tauri:dev
cd apps/desktop && bun run typecheck
cd apps/desktop && bun run test -- --run
cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml
```
