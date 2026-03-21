---
phase: 29-status-strip-panel-registry
plan: "01"
subsystem: observatory-store
tags: [panel-registry, hud, types, zustand, tdd]
dependency_graph:
  requires: []
  provides: [panel-registry-slice, HudPanelId, ghost-preset-rename]
  affects: [observatory-store, observatory-types, observatory-scene-bridge, observatory-command-actions]
tech_stack:
  added: []
  patterns: [zustand-single-field-mutex, tdd-red-green]
key_files:
  created:
    - apps/workbench/src/features/observatory/__tests__/observatory-store.test.ts
  modified:
    - apps/workbench/src/features/observatory/types.ts
    - apps/workbench/src/features/observatory/stores/observatory-store.ts
    - apps/workbench/src/features/observatory/world/observatory-scene-bridge.ts
    - apps/workbench/src/features/observatory/commands/observatory-command-actions.ts
decisions:
  - "Mutual exclusion achieved via single activePanel field — no explicit close-then-open; overwriting is sufficient"
  - "ObservatoryAnalystPresetId 'nexus' renamed to 'ghost' to match HUD-12 THREAT/EVIDENCE/RECEIPTS/GHOST labels"
  - "ObservatoryStationKind 'nexus' left unchanged — different concept (pane route kind, not analyst preset)"
metrics:
  duration: "4 min"
  completed_date: "2026-03-21"
  tasks_completed: 2
  files_modified: 5
---

# Phase 29 Plan 01: Panel Registry Slice + Ghost Preset Rename Summary

Panel registry Zustand slice with openPanel/closePanel/togglePanel mutual exclusion and analyst preset rename from "nexus" to "ghost".

## What Was Built

### HudPanelId Type (types.ts)
Added `export type HudPanelId = "explainability" | "replay" | "mission" | "ghost"` — the four panel IDs for the v7.0 HUD framework. This is the source-of-truth union type that status strip (Plan 29-02), left drawer (Phase 30), and hotkeys all depend on.

### ObservatoryState Updates (types.ts)
- Added `activePanel: HudPanelId | null` field to the state interface
- Added `openPanel`, `closePanel`, `togglePanel` to the actions interface

### Analyst Preset Rename (types.ts + consumers)
`ObservatoryAnalystPresetId` "nexus" renamed to "ghost" to match the locked HUD-12 decision (THREAT / EVIDENCE / RECEIPTS / GHOST). Updated in:
- `observatory-scene-bridge.ts` PRESET_FOCUS_STATION record
- `observatory-command-actions.ts` PRESET_FOCUS_STATION record

### Panel Registry Slice (observatory-store.ts)
Three new actions with minimal, correct implementations:
```typescript
openPanel: (id: HudPanelId) => set({ activePanel: id }),
closePanel: () => set({ activePanel: null }),
togglePanel: (id: HudPanelId) =>
  set((state) => ({ activePanel: state.activePanel === id ? null : id })),
```

Mutual exclusion is enforced by design — there is only one `activePanel` field. No explicit "close current before opening new" logic is needed; overwriting the field is sufficient.

### Unit Tests (observatory-store.test.ts)
7 new tests in "panel registry" describe block:
1. Initial activePanel is null
2. openPanel sets activePanel
3. openPanel replaces current (mutual exclusion verified)
4. closePanel resets to null
5. togglePanel opens when null
6. togglePanel closes when same ID active
7. togglePanel switches when different ID active

## Verification Results

- TypeScript: `npx tsc --noEmit` — PASS (0 errors)
- observatory-store.test.ts: 11/11 tests pass (4 original + 7 new)
- observatory-scene-bridge.test.ts: 3/3 tests pass
- No remaining "nexus" as analyst preset ID

## Deviations from Plan

None - plan executed exactly as written.

## Self-Check: PASSED

- [x] `apps/workbench/src/features/observatory/types.ts` — contains HudPanelId, ghost preset, activePanel, panel actions
- [x] `apps/workbench/src/features/observatory/stores/observatory-store.ts` — contains activePanel, openPanel, closePanel, togglePanel
- [x] `apps/workbench/src/features/observatory/__tests__/observatory-store.test.ts` — contains "panel registry" describe, "mutual exclusion" comment
- [x] Commit ac2fa04ed (Task 1)
- [x] Commit 89e85776e (Task 2)
