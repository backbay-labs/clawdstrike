# Requirements: ClawdStrike Workbench v2.0 — Huntronomer Integration

**Defined:** 2026-03-18
**Core Value:** Security operators get an immersive IDE with spirit-driven 3D layers — observatory, nexus, and spirit companion woven into IDE surfaces across three tiers

## v2.0 Requirements

### Spirit System

- [x] **SPRT-01**: User can see spirit field stain CSS gradients on panel/sidebar backgrounds when a spirit is bound
- [x] **SPRT-02**: User can see spirit accent color applied to hunt-related UI elements
- [x] **SPRT-03**: User can see animated spirit orb in ActivityBar replacing static icon when spirit is bound
- [x] **SPRT-04**: User can see mini spirit companion R3F canvas (~150px) in right sidebar
- [x] **SPRT-05**: User can open spirit chamber as a pane tab via command palette (spirit.bind) to bind/unbind spirits
- [x] **SPRT-06**: User can open spirit creation chamber with full atmosphere and manifestation canvas as a pane tab

### Observatory

- [x] **OBS-01**: User can see artifact count badges on activity bar icons from observatory seam data
- [x] **OBS-02**: User can click observatory stations to open corresponding views as pane tabs (route bridge)
- [x] **OBS-03**: User can open observatory world as a full editor pane tab via command palette (observatory.open)
- [x] **OBS-04**: User can probe active station via command palette (observatory.probe) to scan for artifacts
- [x] **OBS-05**: User can switch observatory to flow mode for immersive exploration
- [x] **OBS-06**: User can activate WASD character controller Easter-egg in observatory flow mode

### Nexus

- [x] **NXS-01**: User can open cyber nexus as "Hunt Deck" pane tab via command palette (nexus.open)

### Forensics

- [x] **FRNX-01**: User can see forensics river mini-view in bottom pane "Tape" tab

## v3.0 Requirements (Spirit Reactivity & Observatory Evolution)

### Spirit Reactivity

- [x] **SPRT-10**: Spirit mood auto-transitions based on policy lint errors + probe activity (deriveSpiritMood + SpiritMoodReactor)
- [x] **SPRT-11**: Spirit kind visually shifts CodeMirror editor palette without cursor loss (Compartment reconfiguration)

### Observatory Minimap

- [x] **OBS-10**: User can see observatory minimap sidebar panel with SVG station dots, artifact counts, and probe state

## v2 Future Requirements

### Advanced Spirit

- **SPRT-07**: Receipt/evidence 3D preview in editor tabs (hero prop viewer)
- **SPRT-08**: Spirit mood transitions animate in real-time based on hunt activity
- **SPRT-09**: Observatory minimap in sidebar showing station overview (superseded by OBS-10)

### Advanced Observatory

- **OBS-07**: Observatory missions with multi-station probe sequences
- **OBS-08**: Probe cooldown timers visible in observatory HUD

## Out of Scope

| Feature | Reason |
|---------|--------|
| VRM avatar rendering | Too heavy for IDE context; spirit orb is the right abstraction |
| Full Rapier physics outside observatory flow mode | Only needed for character controller Easter-egg |
| postprocessing effects (bloom, SSAO) | GPU budget belongs to IDE responsiveness, not visual effects |
| glia SOCBackground theme provider | Desktop-app-only; workbench has its own design system |
| Multiple simultaneous 3D tabs | Tauri/WebKit 8-context WebGL limit; one active 3D tab at a time |
| VRM avatar in spirit companion | Orb + simple geometry is sufficient for sidebar scale |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| SPRT-01 | Phase 1 | Complete |
| SPRT-02 | Phase 1 | Complete |
| OBS-01 | Phase 1 | Complete |
| OBS-02 | Phase 1 | Complete |
| SPRT-03 | Phase 2 | Complete |
| SPRT-04 | Phase 2 | Complete |
| SPRT-05 | Phase 2 | Complete |
| OBS-03 | Phase 3 | Complete |
| OBS-04 | Phase 3 | Complete |
| OBS-05 | Phase 3 | Complete |
| OBS-06 | Phase 3 | Complete |
| FRNX-01 | Phase 3 | Complete |
| NXS-01 | Phase 4 | Complete |
| SPRT-06 | Phase 4 | Complete |
| SPRT-10 | Phase 5 | Complete |
| OBS-10 | Phase 5 | Complete |

**Coverage:**
- v2.0 requirements: 14 total, all complete
- v3.0 requirements: SPRT-10 complete, OBS-10 complete, SPRT-11 pending
- Unmapped: 0 ✓

---
*Requirements defined: 2026-03-18*
*Last updated: 2026-03-19 — v3.0 requirements added; SPRT-10 + OBS-10 marked complete*
