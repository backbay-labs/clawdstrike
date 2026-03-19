---
phase: 05-spirit-reactivity-editor-integration
plan: 03
subsystem: observatory
tags: [observatory, minimap, svg, activity-bar, command-palette, sidebar]
dependency_graph:
  requires:
    - apps/workbench/src/features/observatory/stores/observatory-store.ts
    - apps/workbench/src/features/observatory/world/stations.ts
    - apps/workbench/src/features/activity-bar/components/sidebar-panel.tsx
    - apps/workbench/src/lib/command-registry.ts
    - apps/workbench/src/components/desktop/command-palette.tsx
    - apps/workbench/src/components/desktop/sidebar-icons.tsx
  provides:
    - apps/workbench/src/features/observatory/panels/observatory-minimap-panel.tsx
    - SigilObservatory icon
    - "observatory" activity bar item
    - "Observatory" CommandCategory + CATEGORY_ORDER entry
  affects:
    - apps/workbench/src/features/activity-bar/types.ts
    - apps/workbench/src/features/activity-bar/components/sidebar-panel.tsx
tech_stack:
  added: []
  patterns:
    - "SVG minimap with polar coordinate math (polarToSvg exported for testing)"
    - "TDD: RED (test) → GREEN (impl) commit flow"
    - "Artifact count badge: conditional SVG text with fontWeight=bold"
key_files:
  created:
    - apps/workbench/src/features/observatory/panels/observatory-minimap-panel.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-minimap.test.tsx
  modified:
    - apps/workbench/src/lib/command-registry.ts
    - apps/workbench/src/components/desktop/command-palette.tsx
    - apps/workbench/src/components/desktop/sidebar-icons.tsx
    - apps/workbench/src/features/activity-bar/types.ts
    - apps/workbench/src/features/activity-bar/components/sidebar-panel.tsx
decisions:
  - "polarToSvg exported as named export to enable pure unit testing of coordinate math"
  - "RING_R=70 maps to 200x200 SVG viewBox; watch station at radius=1.26 extends to ~11.8x"
  - "Observatory category placed between Hunt and Test in CATEGORY_ORDER"
  - "Artifact badge uses fontWeight=bold text near the station dot (x+7, y-5 offset)"
  - "18 baseline TS errors pre-existed; zero new errors introduced"
metrics:
  duration: "~12 minutes"
  completed: "2026-03-19T12:39:20Z"
  tasks_completed: 2
  files_created: 2
  files_modified: 5
requirements_fulfilled:
  - OBS-10
---

# Phase 5 Plan 3: Observatory Minimap Panel Summary

SVG minimap sidebar panel wired into activity bar + "Observatory" CommandCategory for glanceable operator overview of observatory station state.

## What Was Built

**ObservatoryMinimapPanel** — A pure SVG component in a 200x200 viewBox that renders 6 HUNT_STATION_PLACEMENTS as station dots at their polar coordinate positions. Reads `observatory-store` for artifact counts and seam summary. Dot color shifts to `--spirit-accent` when a probe is active and the station has artifacts. Artifact count appears as a gold bold badge (x+7, y-5 from dot center) when count > 0. Footer shows total artifact count and "probe active" indicator.

**SigilObservatory** — New activity bar icon: ring (r=9) + center core dot (r=2) + 5 station dots at ring positions.

**Wiring** — Activity bar now has an "Observatory" item (9th item). Clicking it opens `ObservatoryMinimapPanel` via the `sidebar-panel.tsx` switch. `CommandCategory` union and `CATEGORY_ORDER` both include "Observatory" between Hunt and Test.

## Tasks

| # | Name | Commit | Type | Result |
|---|------|--------|------|--------|
| 1 | ObservatoryMinimapPanel SVG + coordinate tests | d8a353b71 | TDD | 13/13 tests pass |
| 2 | Wire Observatory into activity bar + sidebar + command registry | 3f77aab63 | auto | 0 new TS errors |

## Test Results

```
Test Files: 1 passed
Tests:      13 passed
  - polarToSvg — coordinate math: 4 tests
  - ObservatoryMinimapPanel rendering: 9 tests
```

## Coordinate Math

```
polarToSvg(angleDeg, radius):
  rad = angleDeg * PI / 180
  x = 100 + radius * 70 * cos(rad)
  y = 100 + radius * 70 * sin(rad)

Examples:
  angleDeg=0,   radius=1    → x=170, y=100  (right)
  angleDeg=-132, radius=1   → x≈53,  y≈48   (signal station)
  angleDeg=180,  radius=1.26 → x≈12, y=100  (watch station, perimeter)
```

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check

Files created:
- [x] apps/workbench/src/features/observatory/panels/observatory-minimap-panel.tsx — FOUND
- [x] apps/workbench/src/features/observatory/__tests__/observatory-minimap.test.tsx — FOUND

Commits:
- [x] d8a353b71 — FOUND (feat(05-03): ObservatoryMinimapPanel SVG component + coordinate tests)
- [x] 3f77aab63 — FOUND (feat(05-03): wire Observatory into activity bar, sidebar, and command registry)

TypeScript: 18 errors (all pre-existing baseline, 0 new)

## Self-Check: PASSED
