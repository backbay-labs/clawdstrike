# Phase 41: Constellation Routes + Spirit Trails - Context

**Gathered:** 2026-03-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Two new starfield/world visual systems: (1) permanent constellation curves traced from completed missions, persisted to localStorage and visible on the star chart minimap; (2) luminous spirit trails between stations driven by mood and XP level, with hidden resonance connections at level 5.

</domain>

<decisions>
## Implementation Decisions

### Constellation Visual Design
- drei `<Line>` (Line2) with `depthWrite={false}` — lightweight, renders above starfield, matches space lane aesthetic
- Soft white color with 30% spirit accent tint — constellations feel like stars but hint at which spirit was bound
- Altitude range y=40 to y=60 (above stations, below deep starfield) — visible but not competing
- Star chart minimap interaction via tooltip on hover showing constellation name + creation date

### Spirit Trail Behavior
- drei `<Trail>` component — already in use for spirit companion canvas, handles decay/length natively
- Trails follow the spirit companion's world position — traces spirit movement between stations
- 3 hidden connections at level 5 between non-adjacent station pairs: signal↔case-notes, targets↔watch, run↔receipts — cross-ring shortcuts rewarding deep investigation
- Hidden connections rendered as dashed luminous lines with spirit accent color + gentle particle sparkle — clearly distinct from solid transit lanes

### Integration & Persistence
- Auto-generated constellation names from mission briefing title (e.g. "Signal Cluster Alpha") — zero friction
- 12 constellations max in localStorage — oldest evicted when cap reached
- 150 points max trail capacity (per SPRT-05) with 60% opacity fadeout on oldest quarter

### Claude's Discretion
- Exact CatmullRom curve tension for constellation curves
- Trail width and attenuation parameters for drei Trail
- Dashed line dash/gap ratio for hidden connections
- Tooltip positioning and styling on star chart minimap
- Spirit companion position tracking mechanism (ref vs store)

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `spirit-companion-canvas.tsx` — already uses drei `<Trail>` component for spirit orb
- `ObservatorySpaceLanes.tsx` — CatmullRom curves with ShaderMaterial for transit routes
- `ObservatoryStarfield.tsx` — existing starfield layer where constellations should sit above
- `observatory-derivations.ts` — `deriveConstellationFromMission` and `deriveSpiritResonanceConnections` (Phase 39)
- `observatory-store.ts` — constellation CRUD actions (addConstellation, removeConstellation, clearConstellations) from Phase 39
- `observatory-replay-persistence.ts` — v2 schema with constellations field (Phase 39)
- `spirit-evolution-store.ts` — spirit level for gating hidden connections

### Established Patterns
- Scene layers are prop-driven from ObservatoryTab → ObservatoryWorldCanvas → ObservatoryWorldScene
- drei Line/Trail components for curve rendering
- localStorage v2 persistence for replay artifacts
- InvalidationController already has constellationCount and spiritTrailSegmentCount keys (Phase 39)

### Integration Points
- `ObservatoryWorldScene.tsx` — mount ConstellationRoutesLayer and SpiritResonanceTrails as new render layers
- `ObservatoryWorldCanvas.tsx` / `ObservatoryTab.tsx` — derive and thread constellation + spirit trail props
- `panels/observatory-minimap-panel.tsx` — add constellation markers + tooltip

</code_context>

<specifics>
## Specific Ideas

- Constellation curves should use CatmullRomCurve3 with station positions as control points, elevated to y=40-60 range
- Spirit trail color should lerp between dim (mood=idle) and vivid (mood=alert) using spirit accent hex
- Hidden connections should be visually ephemeral — appear with a brief glow animation when level 5 is reached
- Constellation names derived from: mission objectives[0].title + station name (e.g. "Horizon Ingress at Signal")

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>
