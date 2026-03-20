---
phase: 26-discovery-missions
plan: "02"
subsystem: observatory-flight
tags: [waypoint-trail, mission-hud, flight-mode, r3f, catmullrom]
dependency_graph:
  requires:
    - 26-01 (discovery state + station visibility gate)
    - 21-01 (flight state types — flightState.position)
    - 25-xx (character controller enabled pattern)
  provides:
    - MissionWaypointTrail component (glowing CatmullRom tube, ship -> objective)
    - shouldShowWaypointTrail pure gate function
    - FLIGHT_NARRATIVES station directive map
    - inFlightMode prop on ObservatoryMissionHud
  affects:
    - ObservatoryWorldCanvas (new MissionWaypointTrail mount)
    - ObservatoryTab (inFlightMode wired to mission HUD)
tech_stack:
  added: []
  patterns:
    - CatmullRomCurve3 / TubeGeometry rebuilt on ship movement threshold (>2 units)
    - MeshBasicMaterial + AdditiveBlending + toneMapped=false for bloom glow
    - Opacity fade: clamp((distance - 10) / 50, 0, 0.6) as ship enters 60-unit dock zone
    - Pure gate function (shouldShowWaypointTrail) for testability without R3F
    - key={objective.stationId} on narrative <p> for React remount transition
key_files:
  created:
    - apps/workbench/src/features/observatory/components/MissionWaypointTrail.tsx
    - apps/workbench/src/features/observatory/__tests__/mission-waypoint-trail.test.ts
  modified:
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryMissionHud.tsx
    - apps/workbench/src/features/observatory/components/ObservatoryTab.tsx
decisions:
  - MissionWaypointTrail mounted inside Canvas in ObservatoryWorldCanvas — uses playerInputEnabled prop (already encodes characterControllerEnabled && flow mode) rather than prop drilling characterControllerEnabled separately
  - Geometry rebuild threshold 2 units (distanceToSquared=4) — fast enough for responsiveness, cheap enough to avoid per-frame TubeGeometry recreation
  - FLIGHT_NARRATIVES exported from ObservatoryMissionHud for downstream test access
  - inFlightMode defaults to false so existing callers without prop remain unchanged
metrics:
  duration: ~12m
  completed: 2026-03-20
  tasks_completed: 2
  files_created: 2
  files_modified: 3
---

# Phase 26 Plan 02: Mission Waypoint Trail + Narrative Flight Directives Summary

Glowing green waypoint trail (CatmullRom tube) from ship to active mission objective, plus station-specific narrative directives in the mission HUD when flying.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | MissionWaypointTrail component + mount in ObservatoryWorldCanvas | c6e3342d3 | MissionWaypointTrail.tsx, ObservatoryWorldCanvas.tsx, mission-waypoint-trail.test.ts |
| 2 | Mission HUD narrative flight directives | 8b1f79f64 | ObservatoryMissionHud.tsx, ObservatoryTab.tsx |

## What Was Built

**MissionWaypointTrail** (`MissionWaypointTrail.tsx`) — R3F component rendering a glowing green CatmullRom tube trail from the ship's current position to the active mission objective station.

- Visibility gate: `shouldShowWaypointTrail(mission, characterControllerEnabled)` — pure function, exported for unit testing
- 3-point arc: ship pos → midpoint (Y+10 lift for gentle arc) → target station
- `TubeGeometry(curve, 64 segments, 0.2 radius, 6 radial)` rebuilt only when ship moves >2 units
- Material: `#44ff88` MeshBasicMaterial + `AdditiveBlending` + `toneMapped=false` for bloom glow
- Opacity fade: full 0.6 when >60 units away; fades to 0 as ship enters 10-60 unit dock zone
- Mounted after `ExtractedObservatoryWorldScene` in ObservatoryWorldCanvas Canvas

**ObservatoryMissionHud narrative directives** (`ObservatoryMissionHud.tsx`) — Station-specific flight narrative text displayed above the objective title when `inFlightMode=true`.

- `FLIGHT_NARRATIVES: Record<HuntStationId, string>` — covers all 6 stations with distinct narrative text
- `inFlightMode` prop (default false) — backward-compatible, wired from ObservatoryTab as `characterControllerEnabled && mode === "flow"`
- Green `#44ff88` text matching the waypoint trail color
- `key={objective.stationId}` on the narrative `<p>` for React remount-based fade transition when objective advances

## Verification

- All 6 waypoint trail gate tests pass
- All 5 existing observatory-mission-hud tests pass
- 51/51 observatory test files pass (261 tests)
- Pre-existing TypeScript errors in NexusCanvas, minimap test, ObservatoryProbeHud, FovController are not from this plan's changes

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED
