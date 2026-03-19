# Roadmap: ClawdStrike Workbench

## Milestones

- ✅ **v1.0 IDE Pivot** — Phases 1-4 (shipped 2026-03-18/19)
- ✅ **v2.0 Huntronomer Integration** — Phases 1-4 (shipped 2026-03-19)
- 🚧 **v3.0 Spirit & Observatory Evolution** — Phases 5-9 (in progress)

---

<details>
<summary>✅ v2.0 Huntronomer Integration (Phases 1-4) — SHIPPED 2026-03-19</summary>

## Overview

This milestone integrates the huntronomer 3D spirit companion, observatory world, cyber nexus, and forensics river from the standalone `apps/desktop` shell into the production IDE workbench at `apps/workbench`. All source features are implemented and running in the huntronomer source — the work is integration and adaptation across three strict tiers: Tier 1 (pure CSS + Zustand state, zero WebGL), Tier 2 (targeted R3F embeds with architecture contract locked), Tier 3 (full immersive pane tabs). The ordering is mandatory because every visual feature depends on `spirit-store.ts` and `observatory-store.ts`, which do not yet exist in the workbench.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (e.g., 1.1): Urgent insertions (marked with INSERTED)

- [x] **Phase 1: Spirit + Observatory State Foundation** — Two Zustand stores, CSS field stain, accent color, activity bar seam badges, route bridge, 5 commands (no R3F) (completed 2026-03-18)
- [x] **Phase 2: R3F Infrastructure + Small Embeds** — Install R3F packages, resolve WebGL Canvas architecture, spirit orb (CSS/SVG), spirit companion mini-canvas, spirit chamber pane tab (completed 2026-03-18)
- [x] **Phase 3: Full Immersive Panes (Observatory + Forensics)** — Observatory world as full editor pane with probe/flow-mode/character-controller, forensics river Tape tab (completed 2026-03-19)
- [x] **Phase 4: Nexus + Spirit Creation** — NexusStateContext → Zustand migration, cyber nexus Hunt Deck pane tab, spirit creation chamber with full atmosphere (completed 2026-03-19)

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
- [x] 01-01-PLAN.md — spirit-store.ts + observatory-store.ts (Zustand stores with createSelectors)
- [x] 01-02-PLAN.md — SpiritFieldInjector component + CSS vars injection in DesktopLayout
- [x] 01-03-PLAN.md — Activity bar seam badge integration + route bridge (station → openApp) + 5 commands

### Phase 2: R3F Infrastructure + Small Embeds
**Goal**: R3F packages are installed, the WebGL Canvas architecture is decided and validated in a spike, and the three Tier 2 surfaces are live: animated spirit orb in ActivityBar, mini spirit companion canvas in right sidebar, and spirit chamber pane tab
**Depends on**: Phase 1
**Requirements**: SPRT-03, SPRT-04, SPRT-05
**Success Criteria** (what must be TRUE):
  1. User sees an animated spirit orb CSS/SVG animation in the ActivityBar replacing the static icon when a spirit is bound (no R3F canvas — pure CSS/SVG)
  2. User sees a mini R3F spirit companion (~150px canvas, demand frameloop) in the right sidebar spirit-companion panel
  3. User can open spirit chamber as a pane tab via command palette (spirit.bind) and interact with the bind/unbind ritual
  4. The WebGL Canvas architecture decision (separate Canvas vs root Canvas + drei View) is documented and validated in a spike component before any further 3D tabs are built
**Plans**: 3 plans

Plans:
- [x] 02-01-PLAN.md — R3F package install + SpiritKind migration (sentinel/oracle/witness/specter) + Wave 0 test scaffolds
- [x] 02-02-PLAN.md — SpiritOrbIcon CSS orb + ActivityBar orbColor wiring + SpiritCompanionCanvas R3F + right sidebar Spirit panel
- [x] 02-03-PLAN.md — SpiritChamberTab form + /spirit-chamber route wiring + 02-ARCHITECTURE-DECISION.md ADR

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
**Plans**: 4 plans

Plans:
- [x] 03-01-PLAN.md — Observatory world foundation: world types/stations/deriveObservatoryWorld port + ObservatoryWorldCanvas port + ObservatoryTab store bridge + /observatory route swap (Wave 1)
- [x] 03-02-PLAN.md — Probe command + frameloop switching + ObservatoryProbeHud + flow mode toggle + CameraControls (Wave 2)
- [x] 03-03-PLAN.md — WASD character controller Easter-egg: Rapier+ecctrl install, character subsystem port, FlowModeController lazy-load, double-click activation (Wave 3)
- [x] 03-04-PLAN.md — ForensicsTapePanel CSS horizontal timeline + BottomPaneTab "tape" extension + Tape button in bottom-pane.tsx (Wave 1, independent)

### Phase 4: Nexus + Spirit Creation
**Goal**: The cyber nexus Hunt Deck pane tab is live (backed by nexus-store.ts after NexusStateContext migration), and the spirit creation chamber offers full atmosphere and manifestation canvas as a pane tab
**Depends on**: Phase 3
**Requirements**: NXS-01, SPRT-06
**Success Criteria** (what must be TRUE):
  1. User can open the cyber nexus as a "Hunt Deck" pane tab via command palette (nexus.open), with the nexus graph rendering correctly and strikecell clicks bridging to pane-store.openApp
  2. User can open the spirit creation chamber as a pane tab with full atmosphere canvas and manifestation flow for creating new spirits
**Plans**: 3 plans

Plans:
- [x] 04-01-PLAN.md — nexus types + nexus-store (minimal Zustand, DEMO_STRIKECELLS, STRIKECELL_BY_STATION, STRIKECELL_ROUTE_MAP) + Wave 0 test scaffolds (Wave 1)
- [x] 04-02-PLAN.md — NexusTab store bridge (ObservatoryWorldCanvas atlas mode, strikecell routing) + /nexus route swap (Wave 2, depends on 04-01)
- [x] 04-03-PLAN.md — SpiritCreationChamber port (canvas/model + SpiritManifestationCanvas + SpiritAtmosphereLayer) + replace SpiritChamberTab (Wave 1, independent)

## Progress

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Spirit + Observatory State Foundation | 4/4 | Complete | 2026-03-18 |
| 2. R3F Infrastructure + Small Embeds | 3/3 | Complete | 2026-03-18 |
| 3. Full Immersive Panes (Observatory + Forensics) | 4/4 | Complete | 2026-03-19 |
| 4. Nexus + Spirit Creation | 3/3 | Complete | 2026-03-19 |

</details>

---

## v3.0 Spirit & Observatory Evolution

**Milestone Goal:** Evolve the 3D integration from "ported and working" to "alive and rich" — spirits react to hunt activity, shape the code editor experience, gain XP and evolve visually; the observatory comes alive with GLB hero props, affinity rings, probe missions, and a minimap; evidence files open as 3D previews; the nexus renders as a physics-based force graph.

## Phases

- [x] **Phase 5: Spirit Reactivity & Editor Integration** — Mood reacts to hunt signals automatically; spirit kind shifts CodeMirror theme; observatory minimap in sidebar (completed 2026-03-19)
- [ ] **Phase 6: Observatory GLB Props + Spirit Affinity Rings** — Seven station-specific GLB 3D models replace fallback spheres; floor halo rings show active spirit affinity on stations
- [ ] **Phase 7: Spirit Evolution & Persistence** — Spirits gain XP from hunts, visually gain complexity; evolution state persists across sessions via localStorage
- [ ] **Phase 8: Observatory Missions + Evidence 3D Preview** — Multi-station probe mission sequences with HUD; receipt/evidence files open as 3D hero prop viewer tabs
- [ ] **Phase 9: Nexus Force Graph** — Nexus renders as force-directed layout with physics clustering and draggable nodes

## Phase Details

### Phase 5: Spirit Reactivity & Editor Integration
**Goal**: The spirit feels alive — its mood responds automatically to what the operator is doing, the code editor subtly shifts palette to match the bound spirit kind, and the observatory minimap provides a glanceable status overview in the sidebar
**Depends on**: Phase 4 (v2.0 spirit-store, SpiritCompanionCanvas, SpiritFieldInjector all exist)
**Requirements**: SPRT-10, SPRT-11, OBS-10
**Success Criteria** (what must be TRUE):
  1. Spirit mood transitions automatically when policy lint errors are present (mood becomes "alert"), when an observatory probe returns results (mood becomes "active"), and returns to "idle" when no signals are active — without the operator manually setting mood
  2. Binding a different spirit kind visibly shifts the CodeMirror editor palette within the same editor session without destroying the editor view (no cursor position loss, no flicker)
  3. User can see the observatory minimap in the sidebar panel showing station positions, current activity state, and artifact counts as a 2D SVG overview
**Plans**: 3 plans

Plans:
- [x] 05-01-PLAN.md — deriveSpiritMood pure fn + SpiritMoodReactor (auto mood from lint/probe signals)
- [ ] 05-02-PLAN.md — YamlEditor Compartment spirit theme (themeCompartment + highlightCompartment, no flicker)
- [x] 05-03-PLAN.md — ObservatoryMinimapPanel SVG + Observatory activity bar item + CommandCategory

### Phase 6: Observatory GLB Props + Spirit Affinity Rings
**Goal**: The observatory world looks like a real 3D environment — each station has its specific industrial/sci-fi 3D prop model loaded from a GLB file; floor halo rings beneath stations glow in the bound spirit's accent color weighted by affinity
**Depends on**: Phase 5 (spirit accent color patterns established; observatory world stable)
**Requirements**: OBS-09, SPRT-14
**Success Criteria** (what must be TRUE):
  1. Each of the 7 observatory stations renders its station-specific GLB 3D model (signal-dish-tower, subjects-lattice-anchor, operations-scan-rig, evidence-vault-rack, judgment-dais, watchfield-sentinel-beacon, operator-drone) instead of the fallback procedural sphere
  2. Fallback procedural geometry still renders correctly for any station whose GLB fails to load or is unavailable
  3. Floor halo rings appear beneath observatory stations, glowing in the bound spirit's accent color; ring intensity scales with spirit affinity at each station
**Plans**: 2 plans

Plans:
- [ ] 06-01-PLAN.md — Copy 7 GLBs to public/observatory-props/, flip propAssets.ts availability, HeroPropMesh with useGLTF + bob animation
- [ ] 06-02-PLAN.md — blendHex into spirit/scene-math.ts; AffinityRingMesh + stationAffinities in ObservatoryWorldCanvas; ObservatoryTab wiring

### Phase 7: Spirit Evolution & Persistence
**Goal**: Spirits grow with the operator — XP accumulates from hunt activity, visual complexity increases at each level (shadow ring, orbit torus, pulse ring, orbit shards), and progress survives across workbench sessions
**Depends on**: Phase 5 (mood reactivity establishes the XP signal patterns; active mood is itself an XP signal)
**Requirements**: SPRT-12, SPRT-13
**Success Criteria** (what must be TRUE):
  1. Completing meaningful hunt actions (successful policy validation, observatory probe returning findings, simulation run completing) grants XP to the bound spirit, visible in the spirit companion panel
  2. Spirit companion canvas renders additional visual layers as level increases — level 2 adds a shadow ring, level 3 adds an orbit torus, level 4 adds a pulse ring, level 5 adds orbit shards
  3. Spirit level and XP survive closing and reopening the workbench — each spirit kind independently retains its progression
  4. Level-up triggers a brief visual burst in the companion canvas without interrupting other IDE activity
**Plans**: TBD

Plans:
- [ ] 07-01: spirit-evolution-store.ts (Zustand, localStorage persistence keyed per SpiritKind) + SpiritExperienceTracker component (XP event wiring from probe/lint/simulation stores)
- [ ] 07-02: SpiritCompanionCanvas level-gated geometry layers (shadow ring, orbit torus, pulse ring, orbit shards) + level-up pulse animation

### Phase 8: Observatory Missions + Evidence 3D Preview
**Goal**: The observatory has purpose — sequential multi-station probe missions guide operators through the world with a HUD showing objectives; receipt and evidence files open as atmospheric 3D prop viewers instead of plain text
**Depends on**: Phase 6 (GLB props present for full mission objective highlight; evidence viewer reuses hero prop geometry)
**Requirements**: OBS-11, OBS-12, EVID-01
**Success Criteria** (what must be TRUE):
  1. User can start a probe mission sequence that guides them through 5 sequential station objectives, with the probe target automatically set to the current mission objective station
  2. Mission HUD overlay shows the current objective title, hint text, and action label at all times while a mission is active
  3. Mission completion state persists while the observatory tab is open — completed objectives stay completed and the sequence advances correctly
  4. User can open a .receipt or .hush evidence file from the file tree and see a 3D hero prop viewer tab (evidence-vault-rack model with orbit controls, metadata panel showing verdict, policy, and signature)
**Plans**: TBD

Plans:
- [ ] 08-01: Port missionLoop.ts from huntronomer source; add mission state to observatory-store; wire probe target to follow active mission objective
- [ ] 08-02: ObservatoryMissionHud component (current objective display, hint, action label); mission start/reset commands
- [ ] 08-03: Add "receipt" to FileType union; build ReceiptPreviewTab (R3F canvas + OrbitControls + metadata overlay); wire pane-store to open receipt files as ReceiptPreviewTab

### Phase 9: Nexus Force Graph
**Goal**: The cyber nexus Hunt Deck stops being a static atlas and becomes a living force-directed graph — strikecell nodes cluster by physics, edges show connection strength, and operators can drag nodes to explore the topology
**Depends on**: Phase 4 (nexus-store exists with strikecells + connections; NexusTab layout mode type already anticipates "force-directed")
**Requirements**: NXS-02
**Success Criteria** (what must be TRUE):
  1. The Nexus Hunt Deck renders strikecell nodes in a force-directed layout with physics-based clustering, visually distinct from the fixed-ring atlas mode
  2. User can drag individual strikecell nodes to reposition them; the graph reheats and re-stabilizes around the dragged position
  3. Clicking a node in the force graph navigates to the same strikecell destination as clicking in atlas mode (STRIKECELL_ROUTE_MAP preserved)
  4. User can toggle between atlas layout and force-directed layout via the layout mode control in NexusTab
**Plans**: TBD

Plans:
- [ ] 09-01: Add r3f-forcegraph (or three-forcegraph) dependency; add connections to nexus-store; create NexusForceCanvas component with OrbitControls + R3fForceGraph wired to strikecells + connections
- [ ] 09-02: Wire layoutMode toggle in NexusTab (atlas → ObservatoryWorldCanvas, force-directed → NexusForceCanvas); wire onNodeClick to existing STRIKECELL_ROUTE_MAP

## Progress

**Execution Order:**
Phase 5 → Phase 6 → Phase 7 → Phase 8 → Phase 9. Phases 5 and 6 have no mutual dependency and can be interleaved; Phase 7 depends on Phase 5 signals; Phase 8 depends on Phase 6 props; Phase 9 is fully independent.

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 5. Spirit Reactivity & Editor Integration | 3/3 | Complete   | 2026-03-19 |
| 6. Observatory GLB Props + Spirit Affinity Rings | 0/2 | Not started | - |
| 7. Spirit Evolution & Persistence | 0/2 | Not started | - |
| 8. Observatory Missions + Evidence 3D Preview | 0/3 | Not started | - |
| 9. Nexus Force Graph | 0/2 | Not started | - |
