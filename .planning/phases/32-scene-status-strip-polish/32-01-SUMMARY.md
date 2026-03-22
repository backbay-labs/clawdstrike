---
phase: 32-scene-status-strip-polish
plan: 01
subsystem: observatory-hud
tags: [scene-background, hud-polish, status-strip, mode-toggle, scn-01, scn-02]
dependency_graph:
  requires: []
  provides: [ObservatoryStatusStrip.mode-prop, ObservatoryWorldCanvas.deep-blue-bg]
  affects: [ObservatoryTab, ObservatoryStatusStrip, ObservatoryWorldCanvas]
tech_stack:
  added: []
  patterns: [hardcoded-css-fallback-before-webgl, prop-drilling-mode-state]
key_files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx
    - apps/workbench/src/features/observatory/components/hud/ObservatoryStatusStrip.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-status-strip.test.tsx
decisions:
  - "SCN-01: CSS background #04080f hardcoded on both wrapper div and Canvas element — matches scene color, eliminates pre-WebGL black flash"
  - "SCN-02: ATLAS/FLOW toggle moved from orphaned top-right button to status strip segment — mode prop drilled from ObservatoryTab to ObservatoryStatusStrip"
metrics:
  duration: ~8 min
  completed: "2026-03-22"
  tasks_completed: 2
  files_modified: 4
requirements_satisfied: [SCN-01, SCN-02]
---

# Phase 32 Plan 01: Scene & Status Strip Polish Summary

**One-liner:** Deep-blue CSS fallback (#04080f) on canvas wrapper eliminates black flash; ATLAS/FLOW toggle relocated from floating top-right button into the status strip as a mode segment.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Fix blank-scene background + relocate ATLAS toggle | 405f8f95e | ObservatoryWorldCanvas.tsx, ObservatoryTab.tsx, ObservatoryStatusStrip.tsx |
| 2 | Update status strip tests for ATLAS segment | 798c55f4e | observatory-status-strip.test.tsx |

## Changes Made

### SCN-01: Blank Scene Fix (ObservatoryWorldCanvas.tsx)

The Canvas wrapper div and the `<Canvas>` element both previously used `world.environment.backgroundColor` as their CSS background. Before WebGL initializes, the canvas element renders black. The fix: both elements now hardcode `background: "#04080f"` (deep blue, matching the in-scene `<color attach="background" args={["#04080f"]} />`). Users see deep blue from frame 0 instead of a jarring black rectangle.

### SCN-02: ATLAS Toggle Relocation

**Before:** A floating `<button>` at absolute top-right in ObservatoryTab rendered the ATLAS/FLOW mode toggle detached from all other mode controls.

**After:**
- `ObservatoryStatusStrip` gained two new required props: `mode: "atlas" | "flow"` and `onModeToggle: () => void`
- A new button with `data-testid="status-strip-mode-toggle"` is the first item in the center-right section, before analyst presets, with a thin vertical separator
- Active in flow mode: green `#3dbf84` with glow; inactive (atlas): muted text
- `ObservatoryTab` passes mode state and toggle callback to the strip
- The orphaned top-right button replaced with `{/* SCN-02: ATLAS toggle relocated to ObservatoryStatusStrip */}`

### Test Updates

All 6 existing status strip tests updated to pass required `mode`/`onModeToggle` props via `defaultProps`. Four new tests added:
1. Renders ATLAS/FLOW mode toggle segment
2. Shows FLOW label when mode is "flow"
3. Calls onModeToggle on click
4. Mode toggle and analyst presets coexist

**Final test count: 10/10 passing.**

## Deviations from Plan

None — plan executed exactly as written.

## Verification

```
grep -n "04080f" apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
# 4694:    <div className={className} style={{ background: "#04080f" }}>
# 4708:        style={{ background: "#04080f" }}

grep -n "status-strip-mode-toggle" apps/workbench/src/features/observatory/components/hud/ObservatoryStatusStrip.tsx
# 219:          data-testid="status-strip-mode-toggle"

# OBS-05 button removed from ObservatoryTab — confirmed absent
# SCN-02 comment present at line 935

All 10 status strip tests pass.
```

## Self-Check: PASSED

- FOUND: 32-01-SUMMARY.md
- FOUND: ObservatoryWorldCanvas.tsx
- FOUND: ObservatoryStatusStrip.tsx
- FOUND commit: 405f8f95e (feat: blank-scene fix + ATLAS toggle relocation)
- FOUND commit: 798c55f4e (test: status strip test updates)
