---
phase: 30-left-drawer-hotkeys-flight-hud-restyle
plan: "02"
subsystem: observatory-hud
tags: [hotkeys, panel-registry, hud, keyboard, observatory]
dependency_graph:
  requires: [30-01]
  provides: [HUD-14, HUD-15, HUD-16]
  affects: [ObservatoryTab, observatory-store]
tech_stack:
  added: []
  patterns: [getState-imperative-hotkeys, paneIsActive-gate]
key_files:
  created:
    - apps/workbench/src/features/observatory/components/hud/useObservatoryHotkeys.ts
    - apps/workbench/src/features/observatory/__tests__/observatory-hotkeys.test.ts
  modified:
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx
decisions:
  - "useObservatoryStore.getState() (imperative) used in hotkey handler — event callbacks are not per-frame, no subscription needed"
  - "paneIsActive gates all hotkeys — prevents E/R/M/G from firing when another pane has focus"
  - "handleSelectStation always calls openPanel('explainability') on new station select — openPanel is idempotent if panel already open"
metrics:
  duration: ~2 min
  completed: 2026-03-21T14:02:12Z
  tasks_completed: 2
  files_touched: 3
---

# Phase 30 Plan 02: Observatory Hotkeys + Station Click Summary

**One-liner:** Keyboard hotkeys E/R/M/G/Escape wired to panel registry via useObservatoryHotkeys hook, station click opens Explainability panel.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create useObservatoryHotkeys hook + 8 unit tests | 05b4d2f63 | useObservatoryHotkeys.ts, observatory-hotkeys.test.ts |
| 2 | Wire hook in ObservatoryTab + HUD-16 station click | 836bff62c | ObservatoryTab.tsx, observatory-hotkeys.test.ts (type fix) |

## What Was Built

**useObservatoryHotkeys(enabled: boolean)** — custom hook that binds window `keydown` events to panel registry actions. Uses `getState().actions` imperatively (event-driven, not per-frame). Gated by `enabled` parameter (caller passes `paneIsActive`).

Hotkey map:
- `e` → `togglePanel("explainability")`
- `r` → `togglePanel("replay")`
- `m` → `togglePanel("mission")`
- `g` → `togglePanel("ghost")`
- `Escape` → `closePanel()`

Suppression rules:
- Hotkeys suppressed when `enabled=false` (pane not focused)
- Hotkeys suppressed when `event.target` is `INPUT`, `TEXTAREA`, or `contentEditable`

**ObservatoryTab wiring:** `useObservatoryHotkeys(paneIsActive)` called immediately after `paneIsActive` is defined. `handleSelectStation` now calls `observatoryActions.openPanel("explainability")` on new station select (HUD-16).

## Verification

- TypeScript: 0 errors
- 8 unit tests pass (all hotkeys, escape, unrelated keys, disabled state, input filtering)

## Deviations from Plan

**1. [Rule 1 - Bug] Fixed vi.fn() TypeScript type mismatch in test**
- **Found during:** Task 2 (final TS check)
- **Issue:** `vi.fn()` resolves to `Mock<Procedure | Constructable>` which TypeScript does not accept as `(id: HudPanelId) => void` or `() => void` in the strict store types
- **Fix:** Added `as unknown as` type casts for `togglePanel` and `closePanel` in the `useObservatoryStore.setState()` call in the test
- **Files modified:** apps/workbench/src/features/observatory/__tests__/observatory-hotkeys.test.ts
- **Commit:** 836bff62c

## Self-Check: PASSED

- [x] useObservatoryHotkeys.ts exists
- [x] observatory-hotkeys.test.ts exists
- [x] ObservatoryTab.tsx modified with hook call and openPanel
- [x] Commit 05b4d2f63 exists
- [x] Commit 836bff62c exists
