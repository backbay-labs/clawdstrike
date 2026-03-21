# Requirements: ClawdStrike Workbench v7.0 Observatory Production HUD

**Defined:** 2026-03-21
**Core Value:** The observatory is a clean cockpit — the 3D scene dominates, panels appear on demand via hotkeys, and nothing overlaps

## Constraints

- **Clean slate:** All existing observatory panel/overlay components are removed first. New panels are built for the new system, not patched onto the old one.
- **Panel framework first:** The layout system (status strip, left drawer, panel registry) must land before any panel content is rebuilt.
- **Visual consistency:** All HUD surfaces use glassmorphism (backdrop-filter blur, semi-transparent bg, subtle borders). Spirit accent color as highlight.
- **Performance:** No React re-renders in 60fps loops. Status strip uses rAF + ref-mutation pattern established in v6.0 HUD.

## v7.0 Requirements

### Panel Framework

- [x] **HUD-10**: Observatory opens to clean 3D scene with only a thin glassmorphism status strip at the bottom — no panels, no overlays, no floating boxes visible by default
- [x] **HUD-11**: Status strip shows speed, heading cardinal, station count, and minimap indicator — updated at 60fps via ref-mutation (no setState)
- [x] **HUD-12**: Analyst preset segments (THREAT, EVIDENCE, RECEIPTS, GHOST) are toggle buttons inside the status strip — clicking one activates that lens, clicking the active one deactivates it
- [x] **HUD-13**: Single left-drawer panel slot (300-400px wide, glassmorphism) slides in from the left edge with a CSS transition — opening a new panel replaces the current one with no overlap
- [x] **HUD-14**: Panel hotkeys (E = Explainability, R = Replay, M = Mission, G = Ghost) toggle their panel open/closed — pressing the same key closes the active panel
- [x] **HUD-15**: Escape key closes any open left-drawer panel and returns to clean scene view
- [x] **HUD-16**: Clicking a station in the 3D scene opens the Explainability panel for that station in the left drawer
- [x] **HUD-17**: Panel registry (Zustand slice) tracks which panel is active, supports open/close/toggle actions, and prevents multiple panels from being open simultaneously

### Panel Cleanup

- [x] **CLN-01**: All existing observatory panel/overlay components are removed from the render tree — Hunt Loop, Explainability, Concurrent Pressure, Mission Overlay, Analyst Preset bar, Ghost Layer, Weather Layer, Cinematic Overlay, Probe HUD, Replay HUD (10 components)
- [x] **CLN-02**: Flight HUD (speed bar, compass, target brackets, off-screen arrows) is preserved but restyled to match glassmorphism treatment and repositioned to not conflict with the status strip
- [x] **CLN-03**: Removed panel components are deleted from the codebase (not just unmounted) — dead code eliminated

### Rebuilt Panels

- [x] **PNL-01**: Explainability panel rebuilt for left drawer — station name, ranked pressure causes, top anomalies, and a "probe" action button. Glassmorphism styling. Content sourced from existing observatory-store data.
- [x] **PNL-02**: Mission panel rebuilt for left drawer — active objective, waypoint guidance, narrative text, and objective completion state. Designed for the drawer width.
- [x] **PNL-03**: Replay panel rebuilt for left drawer — timeline scrubber, bookmark list, jump-to-spike button, compare-now-vs-then toggle. Compact vertical layout.
- [x] **PNL-04**: Ghost memory panel rebuilt for left drawer — prior findings list, receipt traces, case-note history. Scrollable list with timestamps.

### Visual Polish

- [x] **VIS-01**: Glassmorphism design tokens (background, border, shadow, text colors, accent) defined as CSS custom properties so all HUD surfaces share the same visual language
- [x] **VIS-02**: Status strip uses glassmorphism treatment with solid-enough contrast for text readability (opacity ~0.85 minimum)
- [x] **VIS-03**: Left drawer panel transitions are smooth (200-300ms ease-out slide), with content fade-in after the drawer reaches its open position
- [x] **VIS-04**: Active panel indicator in the status strip (subtle glow or underline on the panel's trigger segment) so the analyst knows which panel is open without looking at the drawer

## v8.0 Requirements (Deferred)

### Advanced Panels
- **PNL-10**: Weather visualization panel (telemetry-driven ambience controls)
- **PNL-11**: Cinematic replay with causal overlay and route jump
- **PNL-12**: Cooperative timeline markers from multiple analysts

### Ship Customization
- **SHIP-01**: Spirit companion changes ship appearance (color, trail, thruster style)
- **SHIP-02**: Ship model selection (3-4 variants)

### Audio
- **AUD-01**: Thruster engine audio with intensity-based pitch/volume
- **AUD-02**: Ambient space music with station proximity crossfade

## Out of Scope

| Feature | Reason |
|---------|--------|
| Multiple simultaneous drawers | Clean cockpit = one panel at a time. Two drawers = clutter. |
| Right-side drawer | Simplicity. One drawer slot is enough for v7.0. |
| Draggable/resizable panels | Game cockpit, not a window manager. Fixed positions. |
| Panel tabs within the drawer | Each panel is its own hotkey. No tab UI inside the drawer. |
| Cockpit view camera mode | Chase camera only. Cockpit deferred to v8.0+. |
| Real GLTF station models | Procedural primitives. GLBs are v8.0 polish. |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CLN-01 | Phase 28 | Complete |
| CLN-03 | Phase 28 | Complete |
| VIS-01 | Phase 28 | Complete |
| HUD-10 | Phase 29 | Complete |
| HUD-11 | Phase 29 | Complete |
| HUD-12 | Phase 29 | Complete |
| HUD-17 | Phase 29 | Complete |
| VIS-02 | Phase 29 | Complete |
| VIS-04 | Phase 29 | Complete |
| HUD-13 | Phase 30 | Complete |
| HUD-14 | Phase 30 | Complete |
| HUD-15 | Phase 30 | Complete |
| HUD-16 | Phase 30 | Complete |
| CLN-02 | Phase 30 | Complete |
| VIS-03 | Phase 30 | Complete |
| PNL-01 | Phase 31 | Complete |
| PNL-02 | Phase 31 | Complete |
| PNL-03 | Phase 31 | Complete |
| PNL-04 | Phase 31 | Complete |

**Coverage:**
- v7.0 requirements: 19 total
- Mapped to phases: 19
- Unmapped: 0

---
*Requirements defined: 2026-03-21*
*Last updated: 2026-03-21 after v7.0 roadmap creation (Phases 28-31)*
