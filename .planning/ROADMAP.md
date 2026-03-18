# Roadmap: ClawdStrike Workbench v2.0 — Huntronomer Integration

## Overview

This milestone integrates the huntronomer 3D spirit companion, observatory world, cyber nexus, and forensics river from the standalone `apps/desktop` shell into the production IDE workbench at `apps/workbench`. All source features are implemented and running in the huntronomer source — the work is integration and adaptation across three strict tiers: Tier 1 (pure CSS + Zustand state, zero WebGL), Tier 2 (targeted R3F embeds with architecture contract locked), Tier 3 (full immersive pane tabs). The ordering is mandatory because every visual feature depends on `spirit-store.ts` and `observatory-store.ts`, which do not yet exist in the workbench.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (e.g., 1.1): Urgent insertions (marked with INSERTED)

- [x] **Phase 1: Spirit + Observatory State Foundation** — Two Zustand stores, CSS field stain, accent color, activity bar seam badges, route bridge, 5 commands (no R3F) (completed 2026-03-18)
- [ ] **Phase 2: R3F Infrastructure + Small Embeds** — Install R3F packages, resolve WebGL Canvas architecture, spirit orb (CSS/SVG), spirit companion mini-canvas, spirit chamber pane tab
- [ ] **Phase 3: Full Immersive Panes (Observatory + Forensics)** — Observatory world as full editor pane with probe/flow-mode/character-controller, forensics river Tape tab
- [ ] **Phase 4: Nexus + Spirit Creation** — NexusStateContext → Zustand migration, cyber nexus Hunt Deck pane tab, spirit creation chamber with full atmosphere

## Phase Details

### Phase 1: Spirit + Observatory State Foundation
**Goal**: The workbench knows about spirits and observatory state — CSS gradients bleed into panel surfaces, activity bar badges reflect live seam data, and station clicks navigate to pane tabs
**Depends on**: Nothing (first phase)
**Requirements**: SPRT-01, SPRT-02, OBS-01, OBS-02
**Success Criteria** (what must be TRUE):
  1. User sees a spirit-colored gradient wash on sidebar and panel backgrounds when a spirit is bound (field stain CSS vars injected at DesktopLayout level)
  2. User sees `--spirit-accent` color applied to hunt-related UI chrome elements (buttons, borders, icons in hunt views)
  3. User sees artifact count badges on activity bar icons sourced from observatory seam data (non-zero when a hunt is active)
  4. User can click an observatory station and the corresponding workbench view opens as a pane tab (route bridge wired via pane-store.openApp)
**Plans**: 3 plans

Plans:
- [ ] 01-01-PLAN.md — spirit-store.ts + observatory-store.ts (Zustand stores with createSelectors)
- [ ] 01-02-PLAN.md — SpiritFieldInjector component + CSS vars injection in DesktopLayout
- [ ] 01-03-PLAN.md — Activity bar seam badge integration + route bridge (station → openApp) + 5 commands

### Phase 2: R3F Infrastructure + Small Embeds
**Goal**: R3F packages are installed, the WebGL Canvas architecture is decided and validated in a spike, and the three Tier 2 surfaces are live: animated spirit orb in ActivityBar, mini spirit companion canvas in right sidebar, and spirit chamber pane tab
**Depends on**: Phase 1
**Requirements**: SPRT-03, SPRT-04, SPRT-05
**Success Criteria** (what must be TRUE):
  1. User sees an animated spirit orb CSS/SVG animation in the ActivityBar replacing the static icon when a spirit is bound (no R3F canvas — pure CSS/SVG)
  2. User sees a mini R3F spirit companion (~150px canvas, demand frameloop) in the right sidebar spirit-companion panel
  3. User can open spirit chamber as a pane tab via command palette (spirit.bind) and interact with the bind/unbind ritual
  4. The WebGL Canvas architecture decision (separate Canvas vs root Canvas + drei View) is documented and validated in a spike component before any further 3D tabs are built
**Plans**: TBD

Plans:
- [ ] 02-01: Install R3F packages + WebGL architecture spike (audit drei #2471 in v10, test context count ceiling, document decision)
- [ ] 02-02: Animated spirit orb in ActivityBar (CSS/SVG), right-sidebar spirit-companion panel switch, SpiritCompanionCanvas (mini R3F)
- [ ] 02-03: SpiritChamberTab route + pane-store integration + spirit.bind command wiring

### Phase 3: Full Immersive Panes (Observatory + Forensics)
**Goal**: The full observatory world renders as an editor pane tab with atlas mode by default, probe command active, flow mode opt-in, and WASD character controller Easter-egg; the forensics river mini-view lives in the bottom pane Tape tab
**Depends on**: Phase 2
**Requirements**: OBS-03, OBS-04, OBS-05, OBS-06, FRNX-01
**Success Criteria** (what must be TRUE):
  1. User can open the observatory world as a full editor pane tab (atlas mode) via command palette (observatory.open), with the scene rendering at full pane dimensions without collapsing to 150px
  2. User can invoke observatory.probe from the command palette to scan the active station for artifacts, with results appearing in the observatory HUD
  3. User can toggle observatory flow mode — the scene transitions from atlas overview to immersive first-person-ready navigation
  4. User can activate WASD character controller in flow mode as an opt-in Easter egg (lazily loaded with Rapier physics; not active by default)
  5. User sees the forensics river mini-view in a "Tape" tab in the bottom pane, rendering live telemetry (conditional on glia-three own-Canvas audit from Phase 2 spike)
**Plans**: TBD

Plans:
- [ ] 03-01: ObservatoryTab route + deriveObservatoryWorld port + atlas mode rendering + tab-switch visibility-toggle (no shader recompile)
- [ ] 03-02: Observatory probe command + flow mode toggle + observatory HUD
- [ ] 03-03: WASD character controller Easter-egg (lazy-load Rapier + ecctrl, opt-in only, flow mode only)
- [ ] 03-04: ForensicsTapeTab in bottom pane (conditional on glia-three audit; fork/adapter plan if glia-three owns its own Canvas)

### Phase 4: Nexus + Spirit Creation
**Goal**: The cyber nexus Hunt Deck pane tab is live (backed by nexus-store.ts after NexusStateContext migration), and the spirit creation chamber offers full atmosphere and manifestation canvas as a pane tab
**Depends on**: Phase 3
**Requirements**: NXS-01, SPRT-06
**Success Criteria** (what must be TRUE):
  1. User can open the cyber nexus as a "Hunt Deck" pane tab via command palette (nexus.open), with the nexus graph rendering correctly and strikecell clicks bridging to pane-store.openApp
  2. User can open the spirit creation chamber as a pane tab with full atmosphere canvas and manifestation flow for creating new spirits
**Plans**: TBD

Plans:
- [ ] 04-01: nexus-store.ts (NexusStateContext → Zustand migration, full dependency map audit before implementation)
- [ ] 04-02: NexusTab route + NexusCanvas port + NexusSpiritCompanion + strikecell adapter
- [ ] 04-03: SpiritCreationChamber pane tab + atmosphere canvas + manifestation flow

## Progress

**Execution Order:**
Phase 1 → Phase 2 → Phase 3 → Phase 4. Strict sequential dependency — each phase unblocks the next.

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Spirit + Observatory State Foundation | 3/3 | Complete   | 2026-03-18 |
| 2. R3F Infrastructure + Small Embeds | 0/3 | Not started | - |
| 3. Full Immersive Panes (Observatory + Forensics) | 0/4 | Not started | - |
| 4. Nexus + Spirit Creation | 0/3 | Not started | - |
