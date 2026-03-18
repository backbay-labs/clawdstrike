# Hunt Spirits Verification

## Scope

This note tracks the `SR6` verification lane for the spirit-ritual program.

Owned verification surfaces:

- ritual-native smoke tests
- spirit and 3D runtime smoke coverage
- browser dogfood scripts
- verification and dogfooding notes

This lane does not own chamber state, reducer wiring, dock/sidebar integration, or scene runtime
logic outside those smoke surfaces.

## Verification Commands

Run from the repo root:

```bash
npm --prefix apps/desktop run typecheck
npm --prefix apps/desktop run build
npm --prefix apps/desktop test -- --run src/shell/workbench/spirit/spiritVerification.smoke.test.tsx
scripts/huntronomer-spirit-smoke.sh
scripts/huntronomer-playwright-smoke.sh
```

## What The Current Verification Proves

- `spiritVerification.smoke.test.tsx` proves the public `SpiritBindSheet` seam resolves to the
  ritual chamber, not the legacy settings sheet.
- ritual chamber smoke now checks visible chamber copy, the release CTA, the mode rail,
  keyboard-reachable manual spirit selection, and the pin switch accessibility contract.
- `scripts/huntronomer-spirit-smoke.sh` now runs the ritual suite under
  `src/shell/workbench/spirit-ritual/**` alongside dock/sidebar identity and Forensics/Nexus
  runtime derivation tests.
- atmosphere and release tests prove the current ritual overlays stay click-through via
  `pointer-events: none`.
- `scripts/huntronomer-playwright-smoke.sh` now goes beyond shell load:
  1. load the current workbench shell
  2. click the dock `New hunt` control
  3. open the chamber from the hunt header spirit affordance
  4. assert `Spirit Chamber`, `Creation modes`, `Ritual controls`, and `Release Spirit`
  5. release the default quick bind and confirm the chamber closes

## Artifact Surfaces

`scripts/huntronomer-playwright-smoke.sh` writes browser artifacts under
`output/playwright/huntronomer-smoke/<timestamp>/`.

Relevant ritual artifacts:

- `spirit-chamber.txt`
- `spirit-chamber.png`
- `spirit-chamber-snapshot.md`
- `spirit-release.json`
- `spirit-release.png`

The script still keeps the historical `launch-overlay.*` and `command-deck.*` artifacts for shell
compatibility, even though the current flow lands directly in the workbench.

## Current Boundaries

- Browser smoke only proves the fast path: create hunt -> open chamber from the hunt header -> quick release closes it.
- Multimodal thesis, draw, upload, and hybrid behavior are currently proven by Vitest, not by the
  Playwright smoke.
- Focus trap, Escape dismissal, and focus return are still manual dogfood checks until the chamber
  root adopts a stricter dialog contract.
- Browser smoke still does not prove native Tauri correctness. Keep pairing this lane with:

```bash
cd apps/desktop && bun run tauri:dev
cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml
```

## Expected Console Noise

In a browser-only local run, the app may still report expected offline errors such as:

- `Agent local API token is unavailable`
- `ERR_CONNECTION_REFUSED` against `localhost:9876`

The Playwright smoke records those errors but only fails on them when
`HUNTRONOMER_SMOKE_STRICT_CONSOLE=1`.
