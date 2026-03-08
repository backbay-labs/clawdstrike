# Hunt Spirits Verification

## Scope

This note captures the `HS7` verification lane evidence for the hunt-spirits initiative.

The lane owns:

- spirit-related desktop tests
- smoke scripts
- dogfood notes
- verification notes

The lane does not own shared shell registration or reducer wiring files held by `ORCH`.

## Verification Commands

Commands run from the repo root on 2026-03-08:

```bash
cd apps/desktop && npm test -- --run
cd apps/desktop && npm run typecheck
cd apps/desktop && npm run build
scripts/huntronomer-spirit-smoke.sh
```

## Results

- `npm test -- --run`: passed. Current spirit tests plus the new smoke coverage all ran green.
- `scripts/huntronomer-spirit-smoke.sh`: passed. This now covers create, bind payloads, pinned
  rebind payloads, dock/sidebar identity, and Forensics/Nexus runtime derivation.
- `npm run typecheck`: failed outside lane ownership.
- `npm run build`: failed outside lane ownership with the same missing import.

Current `typecheck` blocker:

- `apps/desktop/src/shell/workbench/bottomPanelRegistry.ts:33`
  Missing module `@/features/workspace/terminal/WorkspaceTerminalPanel`

Current `build` blocker:

- `apps/desktop/src/shell/workbench/bottomPanelRegistry.ts:33`
  Vite cannot load `src/features/workspace/terminal/WorkspaceTerminalPanel`

## Live Dogfood Boundary

The browser smoke at `scripts/huntronomer-playwright-smoke.sh` still proves the launch overlay and
current Hunt Deck shell load.

It does not yet prove live `Bind Spirit` interaction because the `SpiritBindSheet` implementation is
not currently wired into the shared workbench shell path inside this lane's ownership boundary.

Until that shared wiring lands, use:

```bash
scripts/huntronomer-playwright-smoke.sh
scripts/huntronomer-spirit-smoke.sh
```

Together they cover the current shell load plus the spirit operator/runtime contract.
