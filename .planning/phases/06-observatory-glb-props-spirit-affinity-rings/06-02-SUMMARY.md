---
phase: 06-observatory-glb-props-spirit-affinity-rings
plan: "02"
subsystem: spirit/observatory-3d
tags: [spirit, affinity-rings, scene-math, three-js, tdd]
dependency_graph:
  requires: [06-01]
  provides: [SPRT-14]
  affects: [ObservatoryWorldCanvas, ObservatoryTab, spirit/scene-math]
tech_stack:
  added: []
  patterns: [pure-math-module, tdd-red-green, r3f-ring-geometry]
key_files:
  created:
    - apps/workbench/src/features/spirit/scene-math.ts
    - apps/workbench/src/features/observatory/__tests__/affinity-rings.test.ts
  modified:
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx
decisions:
  - "blendHex test midpoint expectation corrected: Math.round(127.5)=128=0x80 not 0x7f (JS rounding)"
  - "accentColor changed to null default in ObservatoryScene; CoreNode gets explicit '#d8c895' fallback"
  - "AffinityRingMesh uses depthWrite=false to prevent z-fighting with floor plane"
metrics:
  duration: 353s
  completed_date: "2026-03-19"
  tasks_completed: 2
  files_changed: 4
requirements_satisfied: [SPRT-14]
---

# Phase 06 Plan 02: blendHex + AffinityRingMesh + stationAffinities Wiring Summary

Port blendHex pure math utility into `spirit/scene-math.ts`, add floor halo ring meshes beneath each observatory station driven by spirit affinity values, and wire `stationAffinities` from spirit store through ObservatoryTab into ObservatoryWorldCanvas.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | scene-math.ts with blendHex + unit tests (TDD) | 71da4eaff | scene-math.ts, affinity-rings.test.ts |
| 2 | AffinityRingMesh + stationAffinities wiring | 30b16b185 | ObservatoryWorldCanvas.tsx, ObservatoryTab.tsx |

## What Was Built

**`spirit/scene-math.ts`** — Pure TypeScript module with no React/Three.js dependencies:
- `blendHex(base, target, t)` — linear RGB interpolation between 6-digit hex colors, copied verbatim from yaml-editor.tsx
- `STATION_AFFINITY_MAP` — per-SpiritKind per-HuntStationId affinity values in [0,1]: sentinel favors signal+receipts, oracle favors receipts+targets, witness favors case-notes+targets, specter favors run+watch

**`AffinityRingMesh` component** in ObservatoryWorldCanvas — floor halo beneath each station:
- Flat `ringGeometry` (rotation -PI/2) at y=-0.3 (just above floor, below station sphere)
- `innerRadius=1.58`, `outerRadius=1.98 + affinity*0.24` (scales with affinity)
- `opacity=0.08 + affinity*0.22` (min ~0.08 at low affinity, max ~0.30 at full)
- `depthWrite={false}` — prevents z-fighting with floor circle
- Returns `null` when no spirit bound (`accentColor=null`) or `affinity <= 0`

**`stationAffinities` wiring** in ObservatoryTab:
- New `stationAffinities?: Record<HuntStationId, number>` prop on `ObservatoryWorldCanvasProps`
- `ObservatoryTab` derives `STATION_AFFINITY_MAP[kind]` when spirit is bound, `undefined` when unbound
- Pass-through: ObservatoryTab → ObservatoryWorldCanvas → ObservatoryScene → AffinityRingMesh

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed test 3 midpoint expectation**
- **Found during:** Task 1 RED→GREEN phase
- **Issue:** Plan spec said `blendHex("#000000", "#ffffff", 0.5) === "#7f7f7f"` but `Math.round(255*0.5) = Math.round(127.5) = 128 = 0x80` in JavaScript (rounds to even), not 0x7f
- **Fix:** Updated test expectation to `"#808080"` to match actual verbatim-copied function behavior
- **Files modified:** `affinity-rings.test.ts`
- **Commit:** 71da4eaff

## Test Results

| Suite | Tests | Status |
|-------|-------|--------|
| affinity-rings.test.ts | 6 | PASS (new) |
| probe-runtime.test.ts | 9 | PASS (pre-existing) |
| hero-prop-mesh.test.ts | 7 | PASS (pre-existing) |
| observatory-minimap.test.tsx | 13 | PASS (pre-existing) |
| flow-mode-controller.test.tsx | 1 | PASS (pre-existing) |
| observatory-tab.test.tsx | 0 | FAIL (pre-existing — useGLTF mock missing, out of scope) |

**Total: 36 tests pass, 1 pre-existing suite failure unchanged.**

## TypeScript

Zero new TypeScript errors introduced. The 21 pre-existing errors in ObservatoryWorldCanvas.tsx and other files are unchanged and out of scope for this plan.

## Self-Check: PASSED

- FOUND: apps/workbench/src/features/spirit/scene-math.ts
- FOUND: apps/workbench/src/features/observatory/__tests__/affinity-rings.test.ts
- FOUND: .planning/phases/06-observatory-glb-props-spirit-affinity-rings/06-02-SUMMARY.md
- FOUND commit: 71da4eaff (Task 1)
- FOUND commit: 30b16b185 (Task 2)
