# Phase 43: Station Interior Zones - Context

**Gathered:** 2026-03-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Seamless camera-push interior system: each of the 6 stations has a unique interior room with procedural geometry, 3 active NPCs, and hero prop interaction. Analyst enters via double-click or dock-Enter, explores with constrained orbit camera, interacts with hero prop to complete missions, and exits via Escape or HUD button.

</domain>

<decisions>
## Implementation Decisions

### Interior Geometry & Layout
- Procedural box/cylinder primitives matching exterior aesthetic — no GLB models needed
- 20x20x8 unit rooms — spacious at close range, fits 3 NPCs comfortably
- Each station has 2-3 unique prop meshes + distinct wall accent color:
  - Signal: radar dish + antennas (blue #1a5fb4)
  - Targets: lattice grid + terminal (green #3dbf84)
  - Run: scan rings + console (amber #d4a84b)
  - Receipts: vault doors + shelving (gold #c8a22c)
  - Case-notes: dais + hologram (purple #7b68ee)
  - Watch: beacon core + screens (red #c45c5c)
- Per-station interior point light (accent color, intensity 1.5) + ambient bump overrides exterior lighting

### Camera Transition & Controls
- Entry trigger: double-click on station in ATLAS mode, or Enter key when docked in FLOW mode
- 1.2s smooth lerp from exterior position to interior center, FOV narrows 60→50 during push
- Constrained orbit around room center — can look around but can't leave boundary, distance 3-12 units
- Exit via Escape key AND visible "Exit Interior" button in HUD status strip

### NPC Activity & Hero Prop
- 3 NPCs per interior room with idle animation loop (bobbing/breathing) + station-specific pose
- Hero prop interaction uses same trigger as exterior (proximity + E key or click) — no new interaction pattern
- Camera near plane set to 0.02 on entry, restored to exterior value on exit (INTR-06 z-fighting prevention)

### Claude's Discretion
- Exact procedural geometry dimensions for each station's unique props
- NPC placement positions within the 20x20 room
- Orbit controls constraint parameters (polar angle limits, etc.)
- Lerp easing function and intermediate keyframe positions for the push animation
- Interior group positioning relative to station world position
- How to suppress exterior HUD elements during interior view

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `observatory-store.ts` — ObservatoryInteriorState slice with enterInterior/exitInterior actions (Phase 39)
- `types.ts` — ObservatoryInteriorState interface (Phase 39)
- `ObservatoryInvalidationController.tsx` — interiorTransitionPhase source key (Phase 39)
- `districtGeometry.tsx` — existing station mesh rendering patterns
- `npcCrew.tsx` — existing NPC character rendering with patrol/wave animations
- `propAssets.ts` — hero prop asset definitions per station
- `observatory-hud.css` — glassmorphism tokens for HUD button
- `ObservatoryStatusStrip.tsx` — status strip where Exit button would go

### Established Patterns
- Scene layers are prop-driven from ObservatoryTab → ObservatoryWorldCanvas → ObservatoryWorldScene
- Camera manipulation via OrbitControls ref + target.set
- Interior state machine already defined in observatory-store (enterInterior/exitInterior/activeInteriorStationId)
- NPC crew patterns from exterior stations (waypoint loops, animation states)

### Integration Points
- `ObservatoryWorldScene.tsx` — mount StationInteriorScene conditionally when interior is active
- `ObservatoryWorldCanvas.tsx` — thread interior state + camera transition props
- `ObservatoryTab.tsx` — handle double-click entry trigger, dispatch enterInterior
- `ObservatoryStatusStrip.tsx` — add Exit Interior button when interior active

</code_context>

<specifics>
## Specific Ideas

- Interior group should be positioned at the station's world position + offset y=0 (same level as station)
- Exterior scene layers should dim (opacity 0.2) when interior is active rather than unmounting — allows smooth transition back
- The 1.2s camera push should use a quadratic ease-out curve for natural deceleration
- NPC idle bobbing should use the same sin(time) pattern established in npcCrew.tsx
- Hero prop inside the interior should be the same mesh as the exterior hero prop, just repositioned to room center

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>
