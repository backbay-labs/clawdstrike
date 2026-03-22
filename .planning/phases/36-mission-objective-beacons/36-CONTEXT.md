# Phase 36: Mission Objective Beacons - Context

**Gathered:** 2026-03-22
**Status:** Ready for planning

<domain>
## Phase Boundary

Render vertical emissive beacon columns at mission objective stations. Active objective pulses, completed objectives show static muted glow. No beacons when no mission is active.
</domain>

<decisions>
## Implementation Decisions

### Claude's Discretion
- Beacon geometry: tall cylinder or line with emissive material, visible through fog at 500+ units
- Breathing animation: useFrame-driven opacity oscillation (~2s cycle)
- Color: station accent color for active, desaturated version for completed
- Mount in ObservatoryWorldCanvas, conditional on `mission` state from observatory-store
- Reference: `StationBeacon.tsx` for visibility-at-distance pattern, `MissionWaypointTrail.tsx` for mission state reading
</decisions>

<code_context>
## Existing Code Insights

- `observatory-store.ts` — `mission: ObservatoryMissionLoopState | null` with objectives and completedObjectiveIds
- `missionLoop.ts` — `getCurrentObservatoryMissionObjective()` gets current objective
- `OBSERVATORY_STATION_POSITIONS` — station world coordinates for beacon placement
- `STATION_COLORS_HEX` in `hud-constants.ts` — per-station accent colors
</code_context>

<specifics>No specific requirements</specifics>
<deferred>None</deferred>
