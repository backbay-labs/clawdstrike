---
phase: 03-full-immersive-panes-observatory-forensics
plan: "03"
subsystem: observatory-character-controller
tags:
  - observatory
  - character-controller
  - rapier
  - ecctrl
  - physics
  - easter-egg
  - lazy-loading
dependency_graph:
  requires:
    - 03-02 (ObservatoryWorldCanvas + flow mode)
  provides:
    - OBS-06 (WASD character controller Easter-egg in observatory flow mode)
  affects:
    - apps/workbench/src/features/observatory/character/ (new subsystem)
    - apps/workbench/src/features/observatory/components/FlowModeController.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx
tech_stack:
  added:
    - "@react-three/rapier@^2.2.0 — Rapier physics engine (lazy-loaded)"
    - "ecctrl@^1.0.97 — character controller built on Rapier"
  patterns:
    - "React.lazy + Suspense for lazy module boundary (Rapier not in main bundle)"
    - "Null guard pattern (FlowModeController returns null when disabled — zero Physics overhead)"
    - "Keyboard scope gate (useObservatoryPlayerInput enabled only when paneIsActive)"
    - "Inline transient notification (avoids ToastProvider context requirement)"
key_files:
  created:
    - apps/workbench/src/features/observatory/character/types.ts
    - apps/workbench/src/features/observatory/character/animation/moveSet.ts
    - apps/workbench/src/features/observatory/character/controller/runtime.ts
    - apps/workbench/src/features/observatory/character/controller/useObservatoryPlayerRuntime.ts
    - apps/workbench/src/features/observatory/character/input/useObservatoryPlayerInput.ts
    - apps/workbench/src/features/observatory/character/physics/colliders.ts
    - apps/workbench/src/features/observatory/character/physics/spawn.ts
  modified:
    - apps/workbench/src/features/observatory/components/FlowModeController.tsx (full implementation)
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx (lazy import + paneIsActive)
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx (toast + paneIsActive)
    - apps/workbench/package.json (rapier + ecctrl added)
decisions:
  - "Inline transient notification instead of useToast — avoids ToastProvider context requirement in tests"
  - "FlowModeController API uses characterControllerEnabled+onEnable (matches Wave 0 test contract) rather than plan's enabled+paneIsActive"
  - "moveSet.ts ported alongside runtime.ts to satisfy getObservatoryPlayerMoveSpec dependency (flip physics)"
  - "Simplified grounded detection in PlayerController (always-grounded in Phase 3, contact detection deferred)"
  - "createStationPlateSpecs alias added to colliders.ts for FlowModeController imports"
metrics:
  duration: "~9 minutes"
  completed: "2026-03-19T00:33:16Z"
  tasks_completed: 3
  files_created: 7
  files_modified: 4
---

# Phase 03 Plan 03: Character Controller Easter-egg Summary

**One-liner:** Rapier + ecctrl lazy-loaded WASD character controller Easter-egg — double-click in flow mode activates, Physics only wraps scene when active, Rapier isolated to FlowModeController lazy boundary.

## What Was Built

### Task 1: Install Rapier + ecctrl + port character subsystem (commit 4898f220e)

Installed `@react-three/rapier@^2.2.0` and `ecctrl@^1.0.97` to `apps/workbench/package.json`. Ported the full character subsystem from huntronomer verbatim:

- `character/types.ts` — all player types, `DEFAULT_OBSERVATORY_PLAYER_CONFIG` (walkSpeed=4.4, sprintMultiplier=1.55, gravity=18), `DEFAULT_OBSERVATORY_PLAYER_SPAWN` (position=[0, 1.18, 6.6])
- `character/animation/moveSet.ts` — `getObservatoryPlayerMoveSpec`, flip physics specs (required by runtime.ts)
- `character/controller/runtime.ts` — `stepObservatoryPlayerState` pure function, full physics step logic
- `character/physics/colliders.ts` — `createObservatoryBoundaryColliders`, `createObservatoryPlayerCapsuleCollider`, `createStationPlateSpecs` alias
- `character/physics/spawn.ts` — `resolveObservatorySpawnPoint` pure calculation

No `@react-three/rapier` imports at this layer — lazy boundary maintained.

### Task 2: FlowModeController + input/runtime hooks (commit 7a21a43e5)

- `character/input/useObservatoryPlayerInput.ts` — WASD → `ObservatoryPlayerIntent`, enabled guard via `useEffect` dependency
- `character/controller/useObservatoryPlayerRuntime.ts` — state machine driving `stepObservatoryPlayerState`, body adapter integration
- `FlowModeController.tsx` — full Rapier implementation: `Physics > RigidBody > CapsuleCollider` + simple green capsule avatar. Returns null when `characterControllerEnabled=false`. Rapier imports only here (lazy boundary).

flow-mode-controller tests: 3/3 GREEN.

### Task 3: Wire lazy FlowModeController + double-click Easter-egg (commit e2d5db63f)

- `ObservatoryWorldCanvas.tsx` — `React.lazy(() => import("./FlowModeController"))` at module top, conditional render `{mode === "flow" && characterControllerEnabled && <Suspense><LazyFlowModeController /></Suspense>}`, `paneIsActive` prop threaded through
- `ObservatoryTab.tsx` — `handleDoubleClick` guard (`mode !== "flow"` early return), inline transient notification "WASD controls activated", `paneIsActive` derived from `usePaneStore(getActivePaneRoute === "/observatory")`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing critical functionality] Added moveSet.ts dependency**
- **Found during:** Task 1 — `runtime.ts` imports `getObservatoryPlayerMoveSpec` from `../animation/moveSet`
- **Issue:** Plan said "port runtime.ts verbatim" but didn't list `character/animation/moveSet.ts` in the files_modified list; moveSet is required by runtime.ts for flip physics
- **Fix:** Ported `moveSet.ts` from huntronomer verbatim alongside runtime.ts
- **Files modified:** `apps/workbench/src/features/observatory/character/animation/moveSet.ts` (created)
- **Commit:** 4898f220e

**2. [Rule 1 - Bug] FlowModeController API conflict — test contract vs plan spec**
- **Found during:** Task 2 — Wave 0 test scaffold uses `characterControllerEnabled`+`onEnable` props; plan describes `enabled`+`paneIsActive`
- **Issue:** Implementing plan's `enabled`+`paneIsActive` API would break the existing test contract
- **Fix:** Used `characterControllerEnabled`+`onEnable`+`paneIsActive` (test contract wins) — `ObservatoryWorldCanvas` passes `characterControllerEnabled={true}` when rendering it
- **Files modified:** `apps/workbench/src/features/observatory/components/FlowModeController.tsx`
- **Commit:** 7a21a43e5

**3. [Rule 1 - Bug] useToast requires ToastProvider context not available in tests**
- **Found during:** Task 3 — `observatory-tab.test.tsx` uses bare `render()` without ToastProvider wrapper; adding `useToast()` to ObservatoryTab caused 9 test failures
- **Fix:** Replaced `useToast()` with inline transient notification state (`easterEggMsg` + auto-clear timer) — no external context required, displays same "WASD controls activated" text, auto-clears after 3s
- **Files modified:** `apps/workbench/src/features/observatory/components/ObservatoryTab.tsx`
- **Commit:** e2d5db63f

## Self-Check

Files exist:
- `apps/workbench/src/features/observatory/character/types.ts` ✓
- `apps/workbench/src/features/observatory/character/animation/moveSet.ts` ✓
- `apps/workbench/src/features/observatory/character/controller/runtime.ts` ✓
- `apps/workbench/src/features/observatory/character/controller/useObservatoryPlayerRuntime.ts` ✓
- `apps/workbench/src/features/observatory/character/input/useObservatoryPlayerInput.ts` ✓
- `apps/workbench/src/features/observatory/character/physics/colliders.ts` ✓
- `apps/workbench/src/features/observatory/character/physics/spawn.ts` ✓
- `apps/workbench/src/features/observatory/components/FlowModeController.tsx` ✓

Commits exist:
- 4898f220e (Task 1) ✓
- 7a21a43e5 (Task 2) ✓
- e2d5db63f (Task 3) ✓

Test suite: 2284/2302 passing (18 pre-existing failures unchanged) ✓

Rapier isolation: `grep -r "react-three/rapier" src/ | grep -v FlowModeController` → empty ✓
