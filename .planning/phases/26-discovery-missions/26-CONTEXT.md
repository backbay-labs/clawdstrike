# Phase 26: Discovery + Missions - Context

**Gathered:** 2026-03-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Progressive station discovery (hidden until approached) with dramatic reveal animation, mission waypoint trails visible during flight, and narrative-framed mission objectives directing analysts between stations. The final polish layer — depends on stations (Phase 20/23), flight (Phase 21), and existing mission system (Phase 8).

</domain>

<decisions>
## Implementation Decisions

### Progressive Station Reveal (DSC-01)
- On observatory open: only origin hub beacon + 2 nearest stations (signal, targets) are visible at full detail
- Remaining 4 stations (run, receipts, case-notes, watch) start as "uncharted" — dim markers only
- Uncharted marker: faint pulsing sprite (opacity 0.15, same beacon texture), no label, no LOD tiers, no detail
- Discovery radius: 200 units from station center (triggers slightly beyond approach zone 180)
- State: `discoveredStations: Set<HuntStationId>` in observatory store, initialized with ["signal", "targets"]
- Session-only persistence (resets on tab close — no localStorage)
- `StationLodWrapper` checks discoveredStations: if not discovered, renders only the uncharted marker sprite
- Star chart minimap also respects discovery state: uncharted stations show as dim dots with "?" label

### Station Discovery Animation (DSC-02)
- Triggered when ship enters 200 units of an uncharted station
- Sequence (1.5s total):
  1. Station geometry opacity ramps 0→1 over 1.5s (lerp in useFrame)
  2. Station beacon PointLight intensity ramps 0→3 over 1.0s
  3. Docking ring scales from 0→1 over 1.2s (with slight overshoot easeOutBack)
  4. Fresnel glow opacity ramps 0→0.6 over 1.0s
- Fires `observatory:station-discovered` CustomEvent with `{ stationId }` detail (for future audio hookup)
- TRN-03 arrival name card triggers automatically (already built in Phase 25 — triggers on first approach)
- After animation completes: station added to `discoveredStations` set, renders normally from then on

### Mission Waypoint Trail (DSC-03)
- CatmullRomCurve3 tube from ship position to mission target station
- Midpoint lifted Y+10 for gentle arc (not a straight line)
- TubeGeometry (64 segments, radius 0.2, 6 radial segments)
- Emissive green (#44ff88) material, toneMapped=false — distinct from blue space lanes
- Ship end updates every frame via useFrame (reads ship position from flight store)
- Only renders when: mission is active AND characterControllerEnabled (flight mode)
- Fades out (opacity 0) when within 60 units of target (docking system takes over visually)
- Component: `MissionWaypointTrail` in observatory/components/

### Mission-Guided Flight Narrative (DSC-04)
- Extend existing ObservatoryMissionHud with station-aware directive text
- Each mission objective gets a flight-mode narrative string:
  - signal: "Investigate Horizon Station — anomalous signal detected"
  - targets: "Scan Subjects Cluster — identify threat actors"
  - run: "Arm Operations Scan Rig — prepare countermeasures"
  - receipts: "Inspect Evidence Vault — verify receipt chain"
  - case-notes: "Seal Judgment Dais — finalize case findings"
  - watch: "Raise Watchfield Perimeter — secure outer boundary"
- Narrative text appears in MissionHud when in flight mode, replaces or supplements existing objective title
- When mission objective changes (station completed), narrative updates to next station with transition fade

### Claude's Discretion
- Exact easeOutBack parameters for docking ring scale
- Which 2 stations are initially discovered (signal + targets chosen for narrative flow, but could be configurable)
- Whether to add a subtle camera shake on discovery
- Mission waypoint trail exact midpoint Y offset
- Whether uncharted dots should slowly drift/oscillate

</decisions>

<canonical_refs>
## Canonical References

### Station rendering
- `apps/workbench/src/features/observatory/world/StationLodWrapper.tsx` — LOD wrapper (gate on discovery state)
- `apps/workbench/src/features/observatory/world/StationBeacon.tsx` — Beacon sprite (reuse for uncharted marker)
- `apps/workbench/src/features/observatory/world/StationFresnelGlow.tsx` — Fresnel glow (animate on discovery)
- `apps/workbench/src/features/observatory/world/StationDockingRing.tsx` — Docking ring (scale animation)

### Mission system
- `apps/workbench/src/features/observatory/world/missionLoop.ts` — Mission objectives, station targeting
- `apps/workbench/src/features/observatory/components/ObservatoryMissionHud.tsx` — Mission HUD text (extend with narrative)
- `apps/workbench/src/features/observatory/components/ObservatoryMissionOverlay.tsx` — Mission overlay

### Store
- `apps/workbench/src/features/observatory/stores/observatory-store.ts` — Add discoveredStations field
- `apps/workbench/src/features/observatory/types.ts` — ObservatoryState type (extend)

### Star chart
- `apps/workbench/src/features/observatory/panels/observatory-minimap-panel.tsx` — Star chart (respect discovery state)

### Flight state
- `apps/workbench/src/features/observatory/character/ship/flight-types.ts` — FlightState for position
- `apps/workbench/src/features/observatory/character/ship/useFlightLoop.ts` — Ship position ref

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `StationBeacon` — reuse as uncharted marker (just lower opacity)
- `ObservatoryCinematicOverlay` + `StationArrivalCard` — arrival name card already fires on first approach
- `ObservatoryMissionHud` — existing mission text display, extend with narrative strings
- `ObservatorySpaceLanes` tube geometry pattern — reuse for mission waypoint trail
- `observatory:station-discovered` custom event pattern matches existing `observatory:shake`, `observatory:footstrike`

### Established Patterns
- Zustand store slices for new state fields (discoveredStations Set)
- `useFrame` ref-based opacity/scale animation (NPC fade, beacon pulse)
- Custom events for cross-component communication
- `toneMapped={false}` for bloom-visible materials

### Integration Points
- `StationLodWrapper` is the gate for station visibility — check discoveredStations here
- `observatory-minimap-panel.tsx` star chart renders station dots — dim uncharted ones
- `ObservatoryMissionHud` renders mission text — add narrative strings
- `ObservatoryWorldCanvas` or `ObservatoryWorldScene` — mount MissionWaypointTrail

</code_context>

<specifics>
## Specific Ideas

- Discovery should feel like finding something in No Man's Sky — the station "powering on" should be a wow moment
- The waypoint trail should be a clear green beacon path through the void — you follow it like a highway
- Mission narrative should make the analyst feel like they're on a mission briefing — purposeful, directed
- The gradual reveal creates a sense of exploration even though there are only 6 stations

</specifics>

<deferred>
## Deferred Ideas

- Persistent discovery state across sessions (localStorage) — keep session-only for v6.0
- Discovery audio cues — v7.0 with audio system (AUD-01)
- Anomaly encounters in void space — v7.0 (ENV-02)
- Dynamic mission generation — future milestone

</deferred>

---

*Phase: 26-discovery-missions*
*Context gathered: 2026-03-20 via smart discuss (auto mode)*
