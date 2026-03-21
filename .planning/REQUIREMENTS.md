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

- [ ] **HUD-10**: Observatory opens to clean 3D scene with only a thin glassmorphism status strip at the bottom — no panels, no overlays, no floating boxes visible by default
- [ ] **HUD-11**: Status strip shows speed, heading cardinal, station count, and minimap indicator — updated at 60fps via ref-mutation (no setState)
- [ ] **HUD-12**: Analyst preset segments (THREAT, EVIDENCE, RECEIPTS, GHOST) are toggle buttons inside the status strip — clicking one activates that lens, clicking the active one deactivates it
- [ ] **HUD-13**: Single left-drawer panel slot (300-400px wide, glassmorphism) slides in from the left edge with a CSS transition — opening a new panel replaces the current one with no overlap
- [ ] **HUD-14**: Panel hotkeys (E = Explainability, R = Replay, M = Mission, G = Ghost) toggle their panel open/closed — pressing the same key closes the active panel
- [ ] **HUD-15**: Escape key closes any open left-drawer panel and returns to clean scene view
- [ ] **HUD-16**: Clicking a station in the 3D scene opens the Explainability panel for that station in the left drawer
- [ ] **HUD-17**: Panel registry (Zustand slice) tracks which panel is active, supports open/close/toggle actions, and prevents multiple panels from being open simultaneously

### Panel Cleanup

- [ ] **CLN-01**: All existing observatory panel/overlay components are removed from the render tree — Hunt Loop, Explainability, Concurrent Pressure, Mission Overlay, Analyst Preset bar, Ghost Layer, Weather Layer, Cinematic Overlay, Probe HUD, Replay HUD (10 components)
- [ ] **CLN-02**: Flight HUD (speed bar, compass, target brackets, off-screen arrows) is preserved but restyled to match glassmorphism treatment and repositioned to not conflict with the status strip
- [ ] **CLN-03**: Removed panel components are deleted from the codebase (not just unmounted) — dead code eliminated

### Rebuilt Panels

- [ ] **PNL-01**: Explainability panel rebuilt for left drawer — station name, ranked pressure causes, top anomalies, and a "probe" action button. Glassmorphism styling. Content sourced from existing observatory-store data.
- [ ] **PNL-02**: Mission panel rebuilt for left drawer — active objective, waypoint guidance, narrative text, and objective completion state. Designed for the drawer width.
- [ ] **PNL-03**: Replay panel rebuilt for left drawer — timeline scrubber, bookmark list, jump-to-spike button, compare-now-vs-then toggle. Compact vertical layout.
- [ ] **PNL-04**: Ghost memory panel rebuilt for left drawer — prior findings list, receipt traces, case-note history. Scrollable list with timestamps.

### Visual Polish

- [ ] **VIS-01**: Glassmorphism design tokens (background, border, shadow, text colors, accent) defined as CSS custom properties so all HUD surfaces share the same visual language
- [ ] **VIS-02**: Status strip uses glassmorphism treatment with solid-enough contrast for text readability (opacity ~0.85 minimum)
- [ ] **VIS-03**: Left drawer panel transitions are smooth (200-300ms ease-out slide), with content fade-in after the drawer reaches its open position
- [ ] **VIS-04**: Active panel indicator in the status strip (subtle glow or underline on the panel's trigger segment) so the analyst knows which panel is open without looking at the drawer

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
| HUD-10 | Pending | Pending |
| HUD-11 | Pending | Pending |
| HUD-12 | Pending | Pending |
| HUD-13 | Pending | Pending |
| HUD-14 | Pending | Pending |
| HUD-15 | Pending | Pending |
| HUD-16 | Pending | Pending |
| HUD-17 | Pending | Pending |
| CLN-01 | Pending | Pending |
| CLN-02 | Pending | Pending |
| CLN-03 | Pending | Pending |
| PNL-01 | Pending | Pending |
| PNL-02 | Pending | Pending |
| PNL-03 | Pending | Pending |
| PNL-04 | Pending | Pending |
| VIS-01 | Pending | Pending |
| VIS-02 | Pending | Pending |
| VIS-03 | Pending | Pending |
| VIS-04 | Pending | Pending |

**Coverage:**
- v7.0 requirements: 19 total
- Mapped to phases: 0
- Unmapped: 19

---
*Requirements defined: 2026-03-21*
*Last updated: 2026-03-21 after milestone v7.0 definition*
