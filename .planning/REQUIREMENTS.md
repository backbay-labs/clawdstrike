# Requirements: ClawdStrike Workbench v8.0 Observatory Visual Polish

**Defined:** 2026-03-21
**Core Value:** The observatory looks and feels production-ready from the first frame — no blank screens, no invisible effects, no bare empty states

## Constraints

- **No new features:** This is a polish pass on v7.0's panel system. Fix what's broken/ugly, don't add capabilities.
- **Playwright verification:** Each fix must be visually confirmable via Playwright screenshots.
- **Backward compatible:** All existing hotkeys, panel registry, status strip behavior preserved.

## v8.0 Requirements

### Scene & Rendering

- [x] **SCN-01**: Observatory 3D scene renders visible content (stars, stations, or loading indicator) within the first frame — no blank black rectangle during fly-by or initial load
- [x] **SCN-02**: ATLAS mode toggle button moves from orphaned top-right corner into the status strip as a labeled segment alongside the analyst presets

### Glassmorphism

- [x] **GLS-01**: Left drawer panel has visible backdrop-filter blur effect — when the 3D scene is rendering behind the drawer, the blur is perceptible (not just a flat dark rectangle)
- [x] **GLS-02**: Left drawer has a visible top border or subtle edge glow distinguishing it from the scene behind it

### Panel Empty States

- [x] **EMP-01**: Explainability panel empty state shows structured placeholder content — section headers (Station, Pressure, Anomalies), muted icons, and a hint ("Click a station or press E while hovering") instead of bare "Select a station to inspect" text
- [x] **EMP-02**: Mission panel empty state shows structured placeholder — section outline (Briefing, Objectives, Narrative) with muted labels and a "Start a mission from the command palette" hint
- [x] **EMP-03**: Ghost Memory panel empty state shows structured placeholder — "0 traces" header with a muted explanation of what ghost memory is and when traces appear

### Status Strip

- [x] **STS-01**: Status strip has a visible top border (1px solid with enough contrast to separate it from the scene above)
- [x] **STS-02**: Status strip text (speed, heading, station count) is legible at a glance — minimum 11px monospace, opacity >= 0.8

### Drawer Chrome

- [x] **DRW-01**: Left drawer has a header bar showing the active panel name (EXPLAINABILITY / MISSION / REPLAY / GHOST MEMORY) in uppercase monospace
- [x] **DRW-02**: Drawer header bar has a close button (X icon or similar) that calls closePanel() — provides a mouse-based close affordance alongside Escape key

## v9.0 Requirements (Deferred)

### Audio
- **AUD-01**: Thruster engine audio with intensity-based pitch/volume
- **AUD-02**: Ambient space music with station proximity crossfade

### Ship Customization
- **SHIP-01**: Spirit companion changes ship appearance
- **SHIP-02**: Ship model selection (3-4 variants)

## Out of Scope

| Feature | Reason |
|---------|--------|
| New panel types | v8.0 is polish only — no new panels |
| Panel resize/drag | Fixed 360px drawer. Not a window manager. |
| Animated loading spinner | Scene should render content, not show a spinner |
| Panel transition redesign | 250ms ease-out from v7.0 is fine — just needs visual depth |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| SCN-01 | Phase 32 | Complete |
| SCN-02 | Phase 32 | Complete |
| STS-01 | Phase 32 | Complete |
| STS-02 | Phase 32 | Complete |
| GLS-01 | Phase 33 | Complete |
| GLS-02 | Phase 33 | Complete |
| DRW-01 | Phase 33 | Complete |
| DRW-02 | Phase 33 | Complete |
| EMP-01 | Phase 34 | Complete |
| EMP-02 | Phase 34 | Complete |
| EMP-03 | Phase 34 | Complete |

**Coverage:**
- v8.0 requirements: 11 total
- Mapped to phases: 11
- Unmapped: 0

---
*Requirements defined: 2026-03-21*
*Last updated: 2026-03-21 after roadmap creation (Phases 32-34 assigned)*
