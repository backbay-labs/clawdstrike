# Requirements: ClawdStrike Workbench IDE

**Defined:** 2026-03-22
**Core Value:** Security operators work across multiple views simultaneously with a spirit-driven immersive layer — flying between floating space stations in an observatory that makes threat investigation feel like exploration.

## v10.0 Requirements

Requirements for v10.0 Observatory Analyst Toolkit. Each maps to roadmap phases.

### Replay Annotations

- [ ] **ANNO-01**: Analyst can click a point in 3D space during replay to drop a pin marker at that world position
- [ ] **ANNO-02**: Analyst can attach a text note to each dropped pin via an inline input field
- [ ] **ANNO-03**: Dropped pins persist to localStorage alongside replay frames and survive tab close/reopen
- [ ] **ANNO-04**: Analyst can view all pins for the current replay as a scrollable list in the Replay drawer panel
- [ ] **ANNO-05**: Analyst can click a pin in the Replay drawer to jump the replay timeline to that pin's frame and focus the camera on its 3D position
- [ ] **ANNO-06**: Analyst can delete individual pins from the Replay drawer or by clicking the pin in 3D space

### Probe Intelligence

- [ ] **PRBI-01**: After a probe fires and completes, a floating delta card appears near the target station in 3D space
- [ ] **PRBI-02**: Delta card shows what changed (pressure shift direction, new artifact count, status transition)
- [ ] **PRBI-03**: Delta card shows a one-sentence explanation of why the change matters (from probe consequences)
- [ ] **PRBI-04**: Delta card shows a recommended next action that is clickable to open the relevant workbench route or advance the mission
- [ ] **PRBI-05**: Delta card auto-dismisses after 8 seconds or on analyst click/keypress
- [ ] **PRBI-06**: Delta card triggers invalidation so the demand-based frame loop renders it correctly

### Constellation Routes

- [ ] **CNST-01**: When a mission completes, the route the analyst followed is permanently traced as a constellation in the starfield
- [ ] **CNST-02**: Each constellation is rendered as a luminous curve connecting the stations visited during the mission, positioned above the world plane in the star layer
- [ ] **CNST-03**: Constellations persist to localStorage and are visible across sessions
- [ ] **CNST-04**: Analyst can click a constellation in the star chart minimap to see its name and the date it was created
- [ ] **CNST-05**: Over multiple completed missions, the starfield accumulates constellations showing the analyst's investigation history

### Threat Heatmap

- [ ] **HEAT-01**: A ground-plane gradient mesh renders below the station ring showing threat pressure intensity as a continuous color field
- [ ] **HEAT-02**: Heatmap uses SOC-standard color ramp (blue/teal = calm, amber/red = critical) driven by per-station pressure values
- [ ] **HEAT-03**: Heatmap pulses and shifts as telemetry updates arrive, with smooth interpolation between states
- [ ] **HEAT-04**: Heatmap respects the existing performance budget system (off/reduced/full) and is gated behind weatherBudget
- [ ] **HEAT-05**: Heatmap integrates with analyst presets — THREAT preset intensifies the heatmap, other presets dim it

### Spirit Trails

- [ ] **SPRT-01**: When a spirit is bound, it leaves luminous trails between stations as the analyst navigates the observatory
- [ ] **SPRT-02**: Trail color and intensity reflect the spirit's current mood (idle=dim, active=bright, alert=pulsing)
- [ ] **SPRT-03**: Trail intensity scales with spirit XP level (level 1 = faint wisps, level 5 = vivid luminous ribbons)
- [ ] **SPRT-04**: At spirit level 5, trails reveal hidden resonance connections between stations that are not visible in the normal transit layer
- [ ] **SPRT-05**: Trails use fixed-capacity geometry (max 150 points) with oldest points fading out to prevent memory growth

### Station Interiors

- [ ] **INTR-01**: Analyst can trigger a seamless camera-push transition from the exterior station view into a detailed interior view
- [ ] **INTR-02**: Each of the 6 stations has a unique interior layout with distinct room geometry matching its function (signal = radar room, receipts = vault, etc.)
- [ ] **INTR-03**: Interior view shows NPCs performing station-specific activities inside the room
- [ ] **INTR-04**: Analyst can interact with the station's hero prop from inside the interior (same mission objective completion as exterior)
- [ ] **INTR-05**: Analyst can exit the interior back to the exterior observatory view via a back action or Escape key
- [ ] **INTR-06**: Interior transition adjusts camera near plane to prevent z-fighting in close-quarters geometry

## v11.0 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Replay Advanced

- **RPLY-01**: Analyst can draw freehand investigation trails connecting stations/props during replay
- **RPLY-02**: Split-screen compare mode showing "then" (replay frame) vs "now" (live) observatory side-by-side
- **RPLY-03**: Diff overlay highlighting stations that changed status, emphasis, or artifact count between frames

### Acoustic

- **ACST-01**: Spatial audio mapped to station telemetry via Web Audio API + PositionalAudio

## Out of Scope

| Feature | Reason |
|---------|--------|
| Dual Canvas split-screen | WebGL context budget risk; deferred to v11.0 with RenderTexture/View approach |
| VR/XR observatory mode | Desktop-first; WebXR deferred indefinitely |
| Real-time collaborative annotations | Backend sync needed; local-only for v10.0 |
| Procedural planet generation | Stations are the destination, not planets |
| Combat/weapons | Observatory is investigation, not combat |
| Acoustic landscape | Interesting but lower priority than visual features |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| ANNO-01 | Phase 42 | Pending |
| ANNO-02 | Phase 42 | Pending |
| ANNO-03 | Phase 42 | Pending |
| ANNO-04 | Phase 42 | Pending |
| ANNO-05 | Phase 42 | Pending |
| ANNO-06 | Phase 42 | Pending |
| PRBI-01 | Phase 40 | Pending |
| PRBI-02 | Phase 40 | Pending |
| PRBI-03 | Phase 40 | Pending |
| PRBI-04 | Phase 40 | Pending |
| PRBI-05 | Phase 40 | Pending |
| PRBI-06 | Phase 40 | Pending |
| CNST-01 | Phase 41 | Pending |
| CNST-02 | Phase 41 | Pending |
| CNST-03 | Phase 41 | Pending |
| CNST-04 | Phase 41 | Pending |
| CNST-05 | Phase 41 | Pending |
| HEAT-01 | Phase 40 | Pending |
| HEAT-02 | Phase 40 | Pending |
| HEAT-03 | Phase 40 | Pending |
| HEAT-04 | Phase 40 | Pending |
| HEAT-05 | Phase 40 | Pending |
| SPRT-01 | Phase 41 | Pending |
| SPRT-02 | Phase 41 | Pending |
| SPRT-03 | Phase 41 | Pending |
| SPRT-04 | Phase 41 | Pending |
| SPRT-05 | Phase 41 | Pending |
| INTR-01 | Phase 43 | Pending |
| INTR-02 | Phase 43 | Pending |
| INTR-03 | Phase 43 | Pending |
| INTR-04 | Phase 43 | Pending |
| INTR-05 | Phase 43 | Pending |
| INTR-06 | Phase 43 | Pending |

**Coverage:**
- v10.0 requirements: 33 total
- Mapped to phases: 33
- Unmapped: 0

---
*Requirements defined: 2026-03-22*
*Last updated: 2026-03-22 after roadmap creation (v10.0 Phases 39-43)*
