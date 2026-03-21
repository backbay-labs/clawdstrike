# Roadmap: ClawdStrike Workbench

## Milestones

- ✅ **v1.0 IDE Pivot** — Phases 1-4 (shipped 2026-03-18/19)
- ✅ **v2.0 Huntronomer Integration** — Phases 1-4 (shipped 2026-03-19)
- ✅ **v3.0 Spirit & Observatory Evolution** — Phases 5-9 (shipped 2026-03-19)
- ✅ **v4.0 AAA Observatory Experience** — Phases 10-14 (shipped 2026-03-19)
- ✅ **v5.0 Observatory Analyst Experience** — Phases 15-19 (shipped 2026-03-20)
- ✅ **v6.0 Observatory Space Flight** — Phases 20-27 (shipped 2026-03-20)
- 🚧 **v7.0 Observatory Production HUD** — Phases 28-31 (in progress)

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

<details>
<summary>✅ v3.0 Spirit & Observatory Evolution (Phases 5-9) — SHIPPED 2026-03-19</summary>

**Milestone Goal:** Evolve the 3D integration from "ported and working" to "alive and rich" — spirits react to hunt activity, shape the code editor experience, gain XP and evolve visually; the observatory comes alive with GLB hero props, affinity rings, probe missions, and a minimap; evidence files open as 3D previews; the nexus renders as a physics-based force graph.

## Phases

- [x] **Phase 5: Spirit Reactivity & Editor Integration** — Mood reacts to hunt signals automatically; spirit kind shifts CodeMirror theme; observatory minimap in sidebar (completed 2026-03-19)
- [x] **Phase 6: Observatory GLB Props + Spirit Affinity Rings** — Seven station-specific GLB 3D models replace fallback spheres; floor halo rings show active spirit affinity on stations (completed 2026-03-19)
- [x] **Phase 7: Spirit Evolution & Persistence** — Spirits gain XP from hunts, visually gain complexity; evolution state persists across sessions via localStorage (completed 2026-03-19)
- [x] **Phase 8: Observatory Missions + Evidence 3D Preview** — Multi-station probe mission sequences with HUD; receipt/evidence files open as 3D hero prop viewer tabs (completed 2026-03-19)
- [x] **Phase 9: Nexus Force Graph** — Nexus renders as force-directed layout with physics clustering and draggable nodes (completed 2026-03-19)

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
- [x] 05-02-PLAN.md — YamlEditor Compartment spirit theme (themeCompartment + highlightCompartment, no flicker)
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
- [x] 06-01-PLAN.md — Copy 7 GLBs to public/observatory-props/, flip propAssets.ts availability, HeroPropMesh with useGLTF + bob animation
- [x] 06-02-PLAN.md — blendHex into spirit/scene-math.ts; AffinityRingMesh + stationAffinities in ObservatoryWorldCanvas; ObservatoryTab wiring

### Phase 7: Spirit Evolution & Persistence
**Goal**: Spirits grow with the operator — XP accumulates from hunt activity, visual complexity increases at each level (shadow ring, orbit torus, pulse ring, orbit shards), and progress survives across workbench sessions
**Depends on**: Phase 5 (mood reactivity establishes the XP signal patterns; active mood is itself an XP signal)
**Requirements**: SPRT-12, SPRT-13
**Success Criteria** (what must be TRUE):
  1. Completing meaningful hunt actions (successful policy validation, observatory probe returning findings, simulation run completing) grants XP to the bound spirit, visible in the spirit companion panel
  2. Spirit companion canvas renders additional visual layers as level increases — level 2 adds a shadow ring, level 3 adds an orbit torus, level 4 adds a pulse ring, level 5 adds orbit shards
  3. Spirit level and XP survive closing and reopening the workbench — each spirit kind independently retains its progression
  4. Level-up triggers a brief visual burst in the companion canvas without interrupting other IDE activity
**Plans**: 2 plans

Plans:
- [x] 07-01-PLAN.md — spirit-evolution-store.ts (Zustand + localStorage persist, grantXp per SpiritKind) + SpiritExperienceTracker (probe/lint XP wiring) + desktop-layout mount
- [x] 07-02-PLAN.md — SpiritCompanionCanvas level-gated geometry layers (shadow ring, orbit torus, pulse ring, orbit shards) + level-up burst animation

### Phase 8: Observatory Missions + Evidence 3D Preview
**Goal**: The observatory has purpose — sequential multi-station probe missions guide operators through the world with a HUD showing objectives; receipt and evidence files open as atmospheric 3D prop viewers instead of plain text
**Depends on**: Phase 6 (GLB props present for full mission objective highlight; evidence viewer reuses hero prop geometry)
**Requirements**: OBS-11, OBS-12, EVID-01
**Success Criteria** (what must be TRUE):
  1. User can start a probe mission sequence that guides them through 5 sequential station objectives, with the probe target automatically set to the current mission objective station
  2. Mission HUD overlay shows the current objective title, hint text, and action label at all times while a mission is active
  3. Mission completion state persists while the observatory tab is open — completed objectives stay completed and the sequence advances correctly
  4. User can open a .receipt or .hush evidence file from the file tree and see a 3D hero prop viewer tab (evidence-vault-rack model with orbit controls, metadata panel showing verdict, policy, and signature)
**Plans**: 3 plans

Plans:
- [x] 08-01-PLAN.md — Port missionLoop.ts from huntronomer source; extend observatory-store with mission state + actions (Wave 1)
- [x] 08-02-PLAN.md — ObservatoryMissionHud overlay + ObservatoryTab probe target wiring + mission start/reset commands (Wave 2)
- [x] 08-03-PLAN.md — Add "receipt" to FileType union; ReceiptPreviewTab R3F canvas + metadata panel; /receipt-preview route + command (Wave 1, independent)

### Phase 9: Nexus Force Graph
**Goal**: The cyber nexus Hunt Deck stops being a static atlas and becomes a living force-directed graph — strikecell nodes cluster by physics, edges show connection strength, and operators can drag nodes to explore the topology
**Depends on**: Phase 4 (nexus-store exists with strikecells + connections; NexusTab layout mode type already anticipates "force-directed")
**Requirements**: NXS-02
**Success Criteria** (what must be TRUE):
  1. The Nexus Hunt Deck renders strikecell nodes in a force-directed layout with physics-based clustering, visually distinct from the fixed-ring atlas mode
  2. User can drag individual strikecell nodes to reposition them; the graph reheats and re-stabilizes around the dragged position
  3. Clicking a node in the force graph navigates to the same strikecell destination as clicking in atlas mode (STRIKECELL_ROUTE_MAP preserved)
  4. User can toggle between atlas layout and force-directed layout via the layout mode control in NexusTab
**Plans**: 2 plans

Plans:
- [x] 09-01-PLAN.md — Install r3f-forcegraph (peer deps verified: three >=0.154, no R3F constraint); DEMO_CONNECTIONS (13 edges); nexus-store connections slice; NexusForceCanvas with OrbitControls + draggable nodes (Wave 1)
- [x] 09-02-PLAN.md — nexus-store layoutMode field; NexusTab toggle button (atlas/force-directed); conditional render ObservatoryWorldCanvas vs NexusForceCanvas; extended tests (Wave 2)

## Progress

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 5. Spirit Reactivity & Editor Integration | 3/3 | Complete | 2026-03-19 |
| 6. Observatory GLB Props + Spirit Affinity Rings | 2/2 | Complete | 2026-03-19 |
| 7. Spirit Evolution & Persistence | 2/2 | Complete | 2026-03-19 |
| 8. Observatory Missions + Evidence 3D Preview | 3/3 | Complete | 2026-03-19 |
| 9. Nexus Force Graph | 2/2 | Complete | 2026-03-19 |

</details>

---

<details>
<summary>✅ v4.0 AAA Observatory Experience (Phases 10-14) — SHIPPED 2026-03-19</summary>

**Milestone Goal:** Transform the observatory from functional demo to AAA-quality immersive experience — post-processing pipeline, cinematic camera system, particle effects, polished character animation, world detail with NPCs, and production UI. Bloom transforms all subsequent visual work; phases 11 and 12 can run in parallel after Phase 10 lands.

## Phases

- [x] **Phase 10: Post-Processing Foundation** — EffectComposer with bloom, vignette, SMAA, tone mapping, conditional DOF on hero props, per-spirit LUT color grading (completed 2026-03-19)
- [x] **Phase 11: Camera Cinematics + Shake** — Spawn fly-by with letterbox bars, dynamic FOV during sprint and probe scan, screen shake on probe dispatch and landing, focus pull to mission objectives (completed 2026-03-19)
- [x] **Phase 12: Particle Effects** — Landing dust, probe energy discharge shell, station ambient motes, spirit companion trail, thruster exhaust on avatar backpack (completed 2026-03-19)
- [x] **Phase 13: Character Polish** — Weight-based locomotion blending, landing squash-stretch with overshoot, idle breathing layer, sprint lean, flip easing, footstep event detection (completed 2026-03-19)
- [x] **Phase 14: World Detail + NPCs + UI** — HDR skybox, procedural district geometry, ground surface variety, environmental props, instanced NPC crews with patrol + reactions, 3D waypoint beacons, probe charge ring, tooltip system, achievement popups (completed 2026-03-19)

## Phase Details

### Phase 10: Post-Processing Foundation
**Goal**: The observatory scene is visually transformed by a production post-processing pipeline — emissive surfaces bloom, edges vignette, anti-aliasing is SMAA-quality, tone mapping ensures correct HDR response, and each spirit kind applies its own LUT color grade to the final frame
**Depends on**: Phase 9 (observatory world stable, GLB props loaded, spirit-store has active spirit kind)
**Requirements**: PP-01, PP-02, PP-03, PP-04
**Success Criteria** (what must be TRUE):
  1. Spirit shell, station halos, and probe beam materials glow with visible bloom when emissiveIntensity > 1, with no bloom on non-emissive geometry
  2. Vignette, SMAA, and ACES filmic tone mapping are always active — the scene has darker edges, clean anti-aliasing, and correct HDR response at rest
  3. Interacting with a hero prop (entering the active state) pulls focus toward the prop's world position with a visible bokeh effect on background geometry; DOF deactivates when no prop is active
  4. Switching the bound spirit kind changes the visible color grade of the entire scene within one frame — warm amber for Architect, cold blue for Sentinel, high-contrast cyan-purple for Phantom, desaturated green for Wraith
**Plans**: 3 plans

Plans:
- [x] 10-01-PLAN.md — Package install + ObservatoryPostFX component (EffectComposer + Bloom + Vignette + ToneMapping + SMAA) + Canvas antialias:false (Wave 1)
- [x] 10-02-PLAN.md — Emissive material upgrades (toneMapped=false + emissiveIntensity boosts) + Autofocus DOF wiring via activeHeroInteraction (Wave 2)
- [x] 10-03-PLAN.md — buildSpiritLut utility (programmatic Data3DTexture per spirit kind) + LUT component in EffectComposer + spirit kind wiring (Wave 3)

### Phase 11: Camera Cinematics + Shake
**Goal**: The camera system is cinematic — the observatory opens with an automated flyover that establishes the world before handing control to the user, sprinting widens the FOV and probe scanning narrows it, kinetic events create screen shake, and starting a mission snaps camera attention to the objective station
**Depends on**: Phase 10 (post-processing pipeline in place; bloom and DOF transform the visual impact of camera moves)
**Requirements**: CAM-01, CAM-02, CAM-03, CAM-04
**Success Criteria** (what must be TRUE):
  1. Opening the observatory tab for the first time in a session triggers a 4–5 second automated camera sweep across the station ring with CSS letterbox bars framing the sequence; bars dissolve and user control resumes when the fly-by completes
  2. Sprinting in flow mode visibly widens the camera FOV (42 → 52) with a smooth transition; activating a probe scan visibly narrows the FOV (42 → 35); FOV returns to 42 at rest
  3. Dispatching a probe causes a perceptible camera shake (fast decay); the character landing from a jump causes a heavier, slower shake
  4. Starting a mission objective causes the camera to fly to and briefly hold on the target station before resuming normal tracking behavior
**Plans**: 3 plans

Plans:
- [x] 11-01-PLAN.md — FovController (sprint/probe FOV) + CameraShake (probe dispatch + landing shake) + OrbitControls makeDefault (Wave 1)
- [x] 11-02-PLAN.md — Spawn fly-by waypoint sequence in WorldCameraRig + letterbox bars + frameloop-always + skip handler (Wave 2)
- [x] 11-03-PLAN.md — Mission focus pull with 1.8s dwell: missionFocusDwellMs in ObservatoryCameraRecipe + dwellRef in WorldCameraRig + mission objective activeStationId (Wave 3)

### Phase 12: Particle Effects
**Goal**: The observatory feels alive with physical feedback — character footfalls stir dust, probe launches expand particle shells, station props breathe with ambient motes, the spirit orb leaves a glowing trail, and avatar thrusters fire during sprinting and jumping
**Depends on**: Phase 10 (post-processing pipeline; bloom on emissive particle materials elevates particle visual quality); install wawa-vfx
**Requirements**: PFX-01, PFX-02, PFX-03, PFX-04, PFX-05
**Success Criteria** (what must be TRUE):
  1. Character landing from a jump emits a burst of ground-level dust particles at the contact point; the burst is proportional — harder landings produce denser clouds
  2. Probe dispatch expands a particle shell outward from the probe dispatch point and fades within 1.2 seconds; exactly one shell per dispatch event
  3. Each station hero prop has continuously floating ambient motes visible at close range; motes are frustum-culled and distance-gated so they impose no cost on distant stations
  4. The spirit companion orb leaves an accent-colored particle trail as it moves; trail fades along its length
  5. Avatar backpack thrusters emit stretched-billboard exhaust particles during sprint and jump; exhaust is absent during idle and walk states
**Plans**: 4 plans

Plans:
- [x] 12-01-PLAN.md — Install wawa-vfx + ObservatoryVFXPools (landing-dust + thruster-exhaust pool declarations) (Wave 1)
- [x] 12-02-PLAN.md — Spirit Trail (PFX-04): drei Trail wrapping orb mesh in SpiritCompanionCanvas (Wave 1, independent)
- [x] 12-03-PLAN.md — ProbeDischargeVFX InstancedMesh (PFX-02) + Station Sparkles motes (PFX-03) in ObservatoryWorldCanvas (Wave 1)
- [x] 12-04-PLAN.md — CharacterVFX landing dust (PFX-01) + thruster exhaust (PFX-05) + mount all pools (Wave 2)

### Phase 13: Character Polish
**Goal**: The character controller feels weighted and alive — locomotion blends smoothly across speed tiers, landings compress and spring back, the character breathes at idle, leans forward at speed, flips with elastic snap, and footsteps can drive particle and SFX events
**Depends on**: Phase 12 (footstep events from CHR-06 drive PFX-01 landing dust and PFX-05 thruster; particle pools must exist before footstep callback wiring)
**Requirements**: CHR-01, CHR-02, CHR-03, CHR-04, CHR-05, CHR-06
**Success Criteria** (what must be TRUE):
  1. Transitioning from idle to walk to run is visually smooth — no discrete clip snap; blend weights shift continuously with velocity so intermediate speeds show intermediate postures
  2. Landing from a jump visibly compresses the character (Y squash) and springs back past neutral (overshoot) before settling — the effect reads as weight, not a snap to standing
  3. The character's torso oscillates subtly at idle with a breathing cadence visible in the shoulder line; breathing scales to zero when moving
  4. The character's body tilts forward during sprint proportional to speed, returning upright at walk and idle speeds
  5. Front-flips and back-flips snap to the landed orientation with a micro-overshoot bounce on the settle phase rather than decelerating evenly to a stop
  6. Each footstrike in walk and run fires a detectable event (callback or observable) at the correct cycle moment — usable by particle and SFX systems without guessing at frame timing
**Plans**: 2 plans

Plans:
- [x] 13-01-PLAN.md — moveSet.ts: flip easing (CHR-05) + landing squash-stretch with easeOutBack overshoot (CHR-02) — TDD plan (Wave 1)
- [x] 13-02-PLAN.md — useObservatoryPlayerAnimation.ts: weight-based locomotion blending (CHR-01) + breathing layer (CHR-03) + sprint lean (CHR-04) + footstep events (CHR-06) (Wave 2)

### Phase 14: World Detail + NPCs + UI
**Goal**: The observatory world is a populated environment — an HDR skybox replaces flat stars, districts around stations have procedural architecture and varied ground surfaces, environmental props provide storytelling context, instanced NPC crews patrol and react to the player, and the UI communicates state through 3D beacons, charge indicators, contextual tooltips, and mission achievement popups
**Depends on**: Phase 10 (HDR skybox and environment lighting require the post-processing pipeline to display correctly; bloom on emissive building accents needs Phase 10); Phase 12 and 13 can be parallel with Phase 14
**Requirements**: WLD-01, WLD-02, WLD-03, WLD-04, NPC-01, NPC-02, NPC-03, UIP-01, UIP-02, UIP-03, UIP-04
**Success Criteria** (what must be TRUE):
  1. The observatory background is a space nebula HDR skybox — flat procedural Stars are replaced; the skybox is visible in both atlas and flow modes with consistent ambient lighting
  2. Each station zone has 4-8 procedurally generated buildings and structures seeded to that station, creating distinct districts; ground surfaces use per-zone emissive tints
  3. Environmental prop clusters appear near each station (monitors, crates, cable runs) providing storytelling context without blocking navigation
  4. 24 NPC crew members (4 per station) are visible as instanced mesh figures; they follow 4-waypoint patrol loops within their station zone and turn to face and wave when the player approaches within 5 units
  5. 3D waypoint beacons (Billboard + Text) mark active mission objective stations; the circular probe charge ring replaces the text HUD readout; interactable props show tooltip overlays on hover; mission completion triggers an achievement popup in the IDE shell layer
**Plans**: 3 plans

Plans:
- [x] 14-01-PLAN.md — HDR skybox + district buildings + ground tints + env props (WLD-01–04)
- [x] 14-02-PLAN.md — Instanced NPC crew: patrol loops + proximity wave reaction (NPC-01–03)
- [x] 14-03-PLAN.md — UI polish: beacons + probe charge ring + tooltips + achievement popups (UIP-01–04)

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 10. Post-Processing Foundation | v4.0 | 3/3 | Complete | 2026-03-19 |
| 11. Camera Cinematics + Shake | v4.0 | 3/3 | Complete | 2026-03-19 |
| 12. Particle Effects | v4.0 | 4/4 | Complete | 2026-03-19 |
| 13. Character Polish | v4.0 | 2/2 | Complete | 2026-03-19 |
| 14. World Detail + NPCs + UI | v4.0 | 3/3 | Complete | 2026-03-19 |

</details>

---

<details>
<summary>✅ v5.0 Observatory Analyst Experience (Phases 15-19) — SHIPPED 2026-03-20</summary>

**Milestone Goal:** Turn the observatory into an operator-grade hunt analysis surface with
explainable telemetry, guided probes and compound missions, replay intelligence, collaborative
timeline markers, and a leaner runtime architecture that can support more context-heavy features.

## Phases

- [x] **Phase 15: Explainability + Multi-Lane Pressure** — district explanation model, ranked
  causes, multi-lane pressure, smoothing, hysteresis
- [x] **Phase 16: Guided Probes + Compound Missions + Analyst Presets** — recommendation-driven
  probe UX, compound mission synthesis, route shortcuts, analyst view lenses
- [x] **Phase 17: Replay Intelligence + Cooperative Timeline** — bookmarks, jump-to-spike,
  annotations, compare-now-vs-then, collaborative markers
- [x] **Phase 18: Runtime Decomposition + Performance Envelope** — deeper canvas split,
  event-driven invalidation, LOD tiers, pooled route resources
- [x] **Phase 19: Cinematic Context + Ghost Memory + Hunt Weather** — `Why this matters`
  cinematics, case-note ghosts, telemetry-driven ambience

## Phase Details

### Phase 15: Explainability + Multi-Lane Pressure
**Goal**: Every district state becomes explainable and stable enough to drive recommendations,
missions, replay, and cinematic context
**Depends on**: Phase 14 (world detail, UI polish, and runtime visual substrate exist)
**Requirements**: OBSX-01, OBSX-02, OBSX-03
**Success Criteria** (what must be TRUE):
  1. User can select a district/station and see a ranked explanation of what made it hot, including
     receipts, anomalies, investigations, findings, or policy drift
  2. The telemetry model can represent more than one meaningful hot station at a time instead of
     collapsing the hunt state into a single dominant winner
  3. Pressure near thresholds no longer causes visible UI/world thrash under live churn or replay
     scrubbing
**Plans**: 2 plans

Plans:
- [x] 15-01-PLAN.md — Multi-lane telemetry + smoothing/hysteresis + shared explanation types
- [x] 15-02-PLAN.md — Explainability panel shell + integration tests

### Phase 16: Guided Probes + Compound Missions + Analyst Presets
**Goal**: The observatory tells the operator what to do next, not just what is happening
**Depends on**: Phase 15
**Requirements**: OBSX-04, OBSX-05, OBSX-06
**Success Criteria** (what must be TRUE):
  1. After a probe, the operator sees what changed, why it matters, and at least one direct next
     action when the hunt context supports it
  2. Missions can synthesize compound objectives spanning multiple telemetry categories in one plan
  3. Analyst presets can refocus overlays and camera emphasis around named lenses such as `Threat`,
     `Evidence`, `Receipts`, and `Nexus`
**Plans**: 3 plans

Plans:
- [x] 16-01-PLAN.md — Recommendation contract + probe delta summaries
- [x] 16-02-PLAN.md — Compound mission synthesis + mission HUD upgrades
- [x] 16-03-PLAN.md — Analyst presets + route shortcuts

### Phase 17: Replay Intelligence + Cooperative Timeline
**Goal**: Replay becomes an investigation tool rather than a simple time scrubber
**Depends on**: Phase 15
**Requirements**: OBSX-07, OBSX-08, OBSX-09
**Success Criteria** (what must be TRUE):
  1. Replay can jump to derived spikes and let the operator bookmark meaningful moments
  2. The operator can annotate replay and compare a chosen snapshot against current state per
     district
  3. Multiple investigation or analyst markers can coexist on the replay timeline
**Plans**: 3 plans

Plans:
- [x] 17-01-PLAN.md — Replay snapshot model + spike detection
- [x] 17-02-PLAN.md — Replay bookmarks/annotations + compare panel
- [x] 17-03-PLAN.md — Cooperative timeline markers + persistence strategy

### Phase 18: Runtime Decomposition + Performance Envelope
**Goal**: The observatory is structurally cheaper to evolve and operationally cheaper to render
**Depends on**: Phase 15 for shared contracts; can overlap with Phase 16
**Requirements**: OBSX-13, OBSX-14, OBSX-15, OBSX-16
**Success Criteria** (what must be TRUE):
  1. `ObservatoryWorldCanvas.tsx` shrinks into a composition root with extracted controllers and
     modules
  2. Idle states avoid unnecessary full-scene churn via event-driven invalidation
  3. Distant or low-relevance world simulation runs in cheaper LOD tiers
  4. Route pulses, eruptions, and other repeated effects avoid avoidable per-event allocation churn
**Plans**: 3 plans

Plans:
- [x] 18-01-PLAN.md — Canvas decomposition into extracted world controllers
- [x] 18-02-PLAN.md — Invalidation zones + LOD policy
- [x] 18-03-PLAN.md — Resource pooling/memoization + perf harness extensions

### Phase 19: Cinematic Context + Ghost Memory + Hunt Weather
**Goal**: The world adds richer context and memory without sacrificing actionability
**Depends on**: Phases 16-18
**Requirements**: OBSX-10, OBSX-11, OBSX-12
**Success Criteria** (what must be TRUE):
  1. Critical or probe-driven spikes can trigger a brief, skippable `Why this matters` framing
     sequence with causal overlay and route jump
  2. Prior findings or receipt traces can appear as readable in-world ghosts that enrich, rather
     than obstruct, the scene
  3. Hunt weather reflects telemetry quality and intensity while preserving readability and
     navigation
**Plans**: 3 plans

Plans:
- [x] 19-01-PLAN.md — Spike cinematic framing + recommendation handoff
- [x] 19-02-PLAN.md — Case-note ghosts + memory-layer contracts
- [x] 19-03-PLAN.md — Hunt weather controller + readability guardrails

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 15. Explainability + Multi-Lane Pressure | v5.0 | 2/2 | Complete | 2026-03-20 |
| 16. Guided Probes + Compound Missions + Analyst Presets | v5.0 | 3/3 | Complete | 2026-03-20 |
| 17. Replay Intelligence + Cooperative Timeline | v5.0 | 3/3 | Complete | 2026-03-20 |
| 18. Runtime Decomposition + Performance Envelope | v5.0 | 3/3 | Complete | 2026-03-20 |
| 19. Cinematic Context + Ghost Memory + Hunt Weather | v5.0 | 3/3 | Complete | 2026-03-20 |

</details>

---

<details>
<summary>✅ v6.0 Observatory Space Flight (Phases 20-27) — SHIPPED 2026-03-20</summary>

**Milestone Goal:** Transform the observatory from a ground-level station ring into an immersive space environment where analysts fly a ship between floating space stations — the journey between stations is as engaging as the destination.

## Phases

- [x] **Phase 20: Spatial Foundation** — Bump three to 0.171+, WebGPU renderer swap, space-scale world (200-500 unit radius), logarithmic depth buffer, floating station geometry replacing ground buildings (completed 2026-03-20)
- [x] **Phase 21: Flight Controller** — Ship mesh, velocity+quaternion flight, damping, three speed tiers (cruise/boost/dock), chase camera, thruster particle trails (completed 2026-03-20)
- [x] **Phase 22: Space Environment Art** — 3-layer starfield, billboard nebula clouds, void depth fog, emissive space lanes, lane particle streams (completed 2026-03-20)
- [x] **Phase 23: Station Detail + Docking** — 4-tier LOD, beacon lights, Fresnel rim glow, docking ring geometry, three-zone docking system with automated docking sequence (completed 2026-03-20)
- [x] **Phase 24: Space Flight HUD** — Speed indicator, heading compass, target brackets, off-screen arrows, distance readouts, ref-mutation 60fps updates (completed 2026-03-20)
- [x] **Phase 25: Star Chart + Transitions** — Star chart minimap, flight path trail, click-to-autopilot, station status icons, boost FOV punch, warp speed lines, arrival name card, bloom spike, proximity fade (completed 2026-03-20)
- [x] **Phase 26: Discovery + Missions** — Progressive station reveal, discovery animation, mission waypoint path, mission-guided flight flow (completed 2026-03-20)
- [x] **Phase 27: Flight State Bridge + Autopilot Wiring** — FlightState store bridge + autopilot ref bridge (gap closure) (completed 2026-03-20)

## Phase Details

### Phase 20: Spatial Foundation
**Goal**: The observatory world exists at space scale — stations float at 200-500 unit radius with varied elevations, the renderer runs on WebGPU (with WebGL2 fallback), and the logarithmic depth buffer prevents Z-fighting across the vast depth range
**Depends on**: Phase 19 (v5.0 runtime decomposition and world substrate stable)
**Requirements**: SPC-01, STN-01
**Success Criteria** (what must be TRUE):
  1. Observatory opens and stations are positioned in a 200-500 unit sphere at varied Y elevations (-15 to +60) — the flat ground ring is gone
  2. The renderer runs on WebGPU where the browser supports it, falling back to WebGL2 transparently — existing MeshStandardMaterial and postprocessing render correctly in both paths
  3. Logarithmic depth buffer is active — no Z-fighting artifacts visible at any camera distance within the expanded world
  4. Each station displays composable primitive geometry (torus habitat ring, cylinder hub, plane solar panels, box docking bay) driven by a per-station seed, replacing the former ground-level buildings
  5. All existing observatory tests continue to pass after the renderer swap and scale change
**Plans**: 2 plans

Plans:
- [x] 20-01-PLAN.md — three 0.171+ upgrade + WebGPU renderer swap + logarithmic depth buffer + space-scale world constants + elevation type (SPC-01)
- [x] 20-02-PLAN.md — SpaceStationMesh composable primitives (torus/cylinder/panel/bay) seeded per station, wired into scene (STN-01)

### Phase 21: Flight Controller
**Goal**: Analysts pilot a ship through space — velocity-based flight with quaternion rotation, configurable damping, three speed tiers, and a chase camera that follows the ship with smooth lag; thruster particles fire with thrust intensity
**Depends on**: Phase 20 (space-scale world and station geometry must exist before flight is meaningful)
**Requirements**: FLT-01, FLT-02, FLT-03, FLT-04, FLT-05, FLT-06
**Success Criteria** (what must be TRUE):
  1. A ship mesh (with thruster geometry) is visible in the scene — the capsule avatar is replaced; the ship is the player's vessel
  2. WASD applies thrust and strafe; mouse controls pitch and yaw via quaternion rotation; releasing controls damps velocity smoothly to a stop (no gravity, no Rapier)
  3. Tapping boost activates 3x speed with a visible FOV punch and enters boost cooldown — the analyst cannot chain boosts without a cooldown gap; entering station proximity automatically caps speed to dock approach tier
  4. The chase camera follows behind and above the ship with smooth lerp lag — the ship leads the camera, not the other way around
  5. Thruster particle exhaust scales visibly with thrust intensity via wawa-vfx stretchBillboard — idle ship shows no exhaust, full thrust shows bright stretched trails
**Plans**: 4 plans

Plans:
- [x] 21-01-PLAN.md — Flight types + ShipMesh + observatory-store flight slice (FLT-01) — completed 2026-03-20
- [x] 21-02-PLAN.md — SpaceFlightController + useFlightInput + useFlightLoop (FLT-02, FLT-03)
- [x] 21-03-PLAN.md — Speed tiers: cruise/boost/dock caps + boost cooldown + dock proximity (FLT-04)
- [x] 21-04-PLAN.md — Chase camera + thruster exhaust VFX (FLT-05, FLT-06)

### Phase 22: Space Environment Art
**Goal**: The void between stations feels like deep space — a 3-layer starfield fills the background, nebula cloud patches float near stations, depth fog fades distant geometry, emissive lanes connect stations, and particle streams flow along those lanes
**Depends on**: Phase 20 (world scale established; star and lane positions depend on station coordinates at space scale)
**Requirements**: SPC-02, SPC-03, SPC-04, SPC-05, SPC-06
**Success Criteria** (what must be TRUE):
  1. Three distinct star layers are visible — a procedural Star Nest shader sphere in the far background, 15K InstancedMesh mid-field stars distributed across dual hemispheres, and drei Sparkles near-dust; parallax between layers is perceptible during flight
  2. Billboard nebula cloud patches appear near stations — colored point lights make them glow through bloom; patches are visible from approach distance
  3. Depth fog scales correctly to the new world radius — distant stations fade into void rather than hard-cutting at a fog plane
  4. Emissive CatmullRom tube lanes connect adjacent stations with animated dash-offset energy flow visible during flight
  5. Instanced particles stream along lane curves using wawa-vfx stretchBillboard — flow direction matches lane orientation
**Plans**: 3 plans

Plans:
- [x] 22-01-PLAN.md — 3-layer starfield (Star Nest shader + 15K InstancedMesh + Sparkles) + FogExp2 depth fog (SPC-02, SPC-04)
- [x] 22-02-PLAN.md — Billboard nebula cloud patches + station-colored point lights (SPC-03)
- [x] 22-03-PLAN.md — Emissive CatmullRom TubeGeometry space lanes + animated dash-offset + wawa-vfx lane particle streams (SPC-05, SPC-06)

### Phase 23: Station Detail + Docking
**Goal**: Stations are navigational destinations with visual depth — four LOD tiers shift geometry complexity with distance, beacon lights pulse at extreme range, Fresnel rim glow halos near stations, docking rings guide approach, and a three-zone docking system automates the final landing sequence
**Depends on**: Phase 21 (flight controller must exist for docking zones to be meaningful; approach speed tier triggers from FLT-04); Phase 20 (station geometry exists from STN-01)
**Requirements**: STN-02, STN-03, STN-04, STN-05, DCK-01, DCK-02, DCK-03, DCK-04
**Success Criteria** (what must be TRUE):
  1. Stations visually shift complexity as the ship approaches — far range shows a billboard sprite and point light; mid range shows a simplified hub+ring; near range shows full geometry with Fresnel rim glow; beacon light is always visible at extreme distance
  2. Flying within 50 units of a station's docking axis causes the ship to drift gently toward the dock point (magnet-pull zone); the pull strengthens as distance decreases
  3. Closing within 15 units triggers an automated 1-second camera transition to docked view, flight controls disable, and the station's docked state activates
  4. Triggering undock pushes the ship away from the station with launch velocity and re-enables full flight controls
**Plans**: 3 plans

Plans:
- [x] 23-01-PLAN.md — 4-tier LOD (drei Detailed) + beacon lights + Fresnel rim glow (STN-02, STN-03, STN-04)
- [x] 23-02-PLAN.md — Docking ring geometry + flanking guide lights per station (STN-05)
- [x] 23-03-PLAN.md — Three-zone docking system: approach, magnet-pull, dock lock + undock (DCK-01, DCK-02, DCK-03, DCK-04)

### Phase 24: Space Flight HUD
**Goal**: Analysts always know where they are, how fast they are moving, and where their target is — a DOM-based HUD updates at 60fps via ref mutation with a speed bar, heading compass, target brackets, off-screen arrows, and distance readouts
**Depends on**: Phase 21 (flight controller provides velocity, speed tier, and heading data; HUD elements are meaningless without flight state)
**Requirements**: HUD-01, HUD-02, HUD-03, HUD-04, HUD-05, HUD-06
**Success Criteria** (what must be TRUE):
  1. A vertical speed bar is always visible during flight, reflecting current velocity relative to the active speed tier cap — it fills as the ship accelerates and empties as it decelerates
  2. A horizontal compass strip at the top of the view shows cardinal directions and station labels at their angular positions relative to the ship's heading — labels shift as the ship rotates
  3. The selected station has diamond/L-corner bracket markers scaled inversely with distance and color-coded by status (unvisited, active mission, docked)
  4. Stations outside the camera frustum show directional arrows at screen edges with station name and distance; arrows vanish when the station enters view
  5. Numeric distance readouts attached to station markers fade in during approach and are legible at near-dock range — no setState calls in the HUD update loop
**Plans**: 2 plans

Plans:
- [x] 24-01-PLAN.md — Camera bridge + SpeedIndicator + HeadingCompass (HUD-01, HUD-02, HUD-06)
- [x] 24-02-PLAN.md — TargetBrackets + OffScreenArrows + distance readouts + ObservatoryTab wiring (HUD-03, HUD-04, HUD-05)

### Phase 25: Star Chart + Transitions
**Goal**: Analysts can navigate by map and feel the drama of space travel — a star chart minimap replaces the SVG ring, click-to-autopilot guides flight, boost launches punch FOV and bloom, station arrivals play name cards, and proximity reveals station detail progressively
**Depends on**: Phase 21 (flight controller for autopilot navigation and boost FOV punch); Phase 23 (docking system for arrival sequence trigger)
**Requirements**: MAP-01, MAP-02, MAP-03, MAP-04, TRN-01, TRN-02, TRN-03, TRN-04, TRN-05
**Success Criteria** (what must be TRUE):
  1. The observatory minimap is a star chart — station positions, the player location with facing indicator, and lane connections are rendered; the SVG ring minimap is replaced
  2. Clicking a station on the chart engages auto-navigation toward it — the ship turns and begins flying to the target without manual steering
  3. Station status is readable on the chart — mission active, artifacts pending, docked, and unvisited are visually distinct
  4. Activating boost animates FOV from 60 to 90 and back over 1.1s, fires instanced tube speed-line particles from screen center, and spikes bloom intensity — all three effects resolve before boost cooldown ends
  5. First entering dock proximity plays a 1.2s letterbox + station name slide-in card; approaching a station progressively reveals sub-elements (artifact counts, threat level, NPC visibility) while fading the distance marker
**Plans**: 4 plans

Plans:
- [x] 25-01-PLAN.md — StarChartMinimap component — replaces SVG ring, renders station dots + player arrow + lane connections + status icons (MAP-01, MAP-04)
- [x] 25-02-PLAN.md — Flight path trail on star chart + click-to-autopilot navigation engagement (MAP-02, MAP-03)
- [x] 25-03-PLAN.md — Boost transition effects — FOV punch animation + warp speed line particles + bloom spike (TRN-01, TRN-02, TRN-04)
- [x] 25-04-PLAN.md — Station arrival name card (ObservatoryCinematicOverlay letterbox + name slide) + proximity detail fade (TRN-03, TRN-05)

### Phase 26: Discovery + Missions
**Goal**: The space environment rewards exploration — stations are hidden until discovered, powering on dramatically on first approach; mission objectives draw glowing paths through space and direct analysts to specific stations with narrative hooks
**Depends on**: Phase 23 (station geometry and docking needed for discovery animation and mission arrival); Phase 21 (flight controller needed for mission waypoint path visibility during flight)
**Requirements**: DSC-01, DSC-02, DSC-03, DSC-04
**Success Criteria** (what must be TRUE):
  1. Opening the observatory shows only the starting hub and 2 nearest stations; other stations appear as dim uncharted markers — the full station ring is not immediately revealed
  2. Flying within discovery range of an uncharted station triggers a lights-power-on + structures-unfold animation before the station appears at full detail
  3. When a mission is active, a glowing trail from the player's ship to the objective station is visible during flight — analysts can follow it without consulting the star chart
  4. Mission text directs analysts between stations with narrative framing ("Signal detected at Horizon, investigate") and the active mission waypoint updates when objectives advance
**Plans**: 2 plans

Plans:
- [x] 26-01-PLAN.md — Progressive station reveal + discovery animation (DSC-01, DSC-02)
- [x] 26-02-PLAN.md — Mission waypoint trail + narrative flight directives (DSC-03, DSC-04)

### Phase 27: Flight State Bridge + Autopilot Wiring
**Goal**: The flight controller's runtime state (position, quaternion, speed tier, current speed) propagates to the Zustand store so all downstream consumers (HUD, star chart trail, boost transitions, station arrival cinematics, discovery proximity, NPC proximity fade) receive live data; click-to-autopilot on the star chart engages actual ship navigation
**Depends on**: Phase 21 (flight controller), Phase 25 (star chart autopilot)
**Requirements**: MAP-02, MAP-03
**Success Criteria** (what must be TRUE):
  1. `store.flightState` updates at 60fps with live position, quaternion, speedTier, and currentSpeed from the flight controller — no stale DEFAULT_FLIGHT_STATE values persist after entering flow mode
  2. Clicking a station on the star chart minimap causes the ship to turn toward and fly to the target station — the autopilot slerp block in useFlightLoop executes; WASD input cancels autopilot
  3. Boost activation triggers FOV punch (60→90→60), warp speed lines, and bloom spike simultaneously — all three effects visible because store.flightState.speedTier correctly reports "boost"
  4. Flying within 200 units of an uncharted station triggers the discovery animation — StationLodWrapper proximity check fires because store.flightState.position reflects real ship position
  5. Star chart trail renders the ship's recent trajectory as a fading line — trail buffer receives changing positions from store
**Plans**: 1 plan

Plans:
- [x] 27-01-PLAN.md — FlightState store bridge (onStateChange prop chain) + autopilot ref bridge (MAP-02, MAP-03)

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 20. Spatial Foundation | v6.0 | 2/2 | Complete | 2026-03-20 |
| 21. Flight Controller | v6.0 | 4/4 | Complete | 2026-03-20 |
| 22. Space Environment Art | v6.0 | 3/3 | Complete | 2026-03-20 |
| 23. Station Detail + Docking | v6.0 | 3/3 | Complete | 2026-03-20 |
| 24. Space Flight HUD | v6.0 | 2/2 | Complete | 2026-03-20 |
| 25. Star Chart + Transitions | v6.0 | 4/4 | Complete | 2026-03-20 |
| 26. Discovery + Missions | v6.0 | 2/2 | Complete | 2026-03-20 |
| 27. Flight State Bridge + Autopilot Wiring | v6.0 | 1/1 | Complete | 2026-03-20 |

</details>

---

## v7.0 Observatory Production HUD

**Milestone Goal:** Transform the observatory's overlapping panel chaos into a clean cockpit HUD — glassmorphism left drawer (one panel at a time), persistent status strip with analyst presets, hotkey-driven panel switching, and a full panel inventory audit to cut what doesn't earn its space.

## Phases

- [ ] **Phase 28: Design Tokens + Panel Audit** — Define glassmorphism CSS custom properties, remove all 10 legacy overlay components from the render tree, and delete their dead code from the codebase
- [ ] **Phase 29: Status Strip + Panel Registry** — Persistent glassmorphism bottom strip with live speed/heading/station data, analyst preset toggle segments, and a Zustand panel registry slice that enforces one-panel-at-a-time mutual exclusion
- [ ] **Phase 30: Left Drawer + Hotkeys + Flight HUD Restyle** — Sliding left-drawer panel container with CSS transition, hotkey bindings (E/R/M/G/Escape), station-click-to-explainability wiring, and flight HUD restyled to match glassmorphism treatment
- [ ] **Phase 31: Rebuilt Panels** — Explainability, Mission, Replay, and Ghost Memory panels rebuilt for the left drawer format with compact vertical layouts and glassmorphism styling

## Phase Details

### Phase 28: Design Tokens + Panel Audit
**Goal**: The observatory has a clean slate and a unified visual language — all legacy overlay clutter is gone, the codebase has no dead panel code, and every future HUD surface has shared CSS tokens to draw from
**Depends on**: Phase 27 (v6.0 complete; space flight and all overlapping panels are the baseline to clean up)
**Requirements**: CLN-01, CLN-03, VIS-01
**Success Criteria** (what must be TRUE):
  1. Opening the observatory in flow mode shows only the 3D scene and the v6.0 flight HUD — no Hunt Loop panel, no Explainability panel, no Mission Overlay, no Analyst Preset bar, no Ghost Layer, no Weather Layer, no Cinematic Overlay, no Probe HUD, no Replay HUD visible
  2. CSS custom properties `--hud-bg`, `--hud-border`, `--hud-shadow`, `--hud-text`, `--hud-text-muted`, `--hud-accent` are defined in the observatory stylesheet and resolve to the glassmorphism values — any element using them renders with the correct treatment
  3. The 10 removed component files no longer exist anywhere in `apps/workbench/src` — grep for their filenames returns nothing
**Plans**: 2 plans

Plans:
- [ ] 28-01-PLAN.md — Delete 10 legacy overlay components from render tree and codebase (CLN-01, CLN-03)
- [ ] 28-02-PLAN.md — Define glassmorphism CSS custom properties as observatory design tokens (VIS-01)

### Phase 29: Status Strip + Panel Registry
**Goal**: The observatory has a persistent cockpit footer — a glassmorphism strip anchored to the bottom of the canvas shows live telemetry at 60fps, analyst preset toggles let the operator switch investigative lenses, and the Zustand panel registry enforces that only one left-drawer panel can be open at a time
**Depends on**: Phase 28 (CSS tokens must exist before strip styling is applied; clean scene required for unobstructed strip)
**Requirements**: HUD-10, HUD-11, HUD-12, HUD-17, VIS-02, VIS-04
**Success Criteria** (what must be TRUE):
  1. A glassmorphism status strip is permanently visible at the bottom of the observatory canvas — it does not appear/disappear with panel state
  2. Speed, heading cardinal direction, and station count in the strip update at 60fps via ref-mutation with no React setState calls in the frame loop
  3. Clicking a preset segment (THREAT, EVIDENCE, RECEIPTS, GHOST) activates that lens; clicking the active segment deactivates it; only one segment can be active at a time
  4. The panel registry Zustand slice correctly enforces mutual exclusion — calling `open('mission')` when `'replay'` is active closes replay first; `getActivePanel()` always returns at most one panel ID or null
  5. When a panel is open, its corresponding trigger in the status strip shows a visible active indicator (glow or underline) that clears when the panel closes
**Plans**: TBD

Plans:
- [ ] 29-01: Zustand panel registry slice (open/close/toggle, mutual exclusion) + unit tests (HUD-17)
- [ ] 29-02: ObservatoryStatusStrip component — glassmorphism layout, rAF telemetry update, analyst preset segments (HUD-10, HUD-11, HUD-12, VIS-02, VIS-04)

### Phase 30: Left Drawer + Hotkeys + Flight HUD Restyle
**Goal**: Analysts control panels with their keyboard — hotkeys slide the left drawer open to the correct panel or close it entirely, station clicks drive straight to Explainability, and the v6.0 flight HUD chrome is updated to share the glassmorphism treatment without fighting the new status strip
**Depends on**: Phase 29 (panel registry must exist before hotkey bindings can call open/close/toggle; status strip position must be established before flight HUD repositioning)
**Requirements**: HUD-13, HUD-14, HUD-15, HUD-16, CLN-02, VIS-03
**Success Criteria** (what must be TRUE):
  1. A 300-400px wide glassmorphism panel slot slides in from the left edge of the canvas when any panel is opened — the 3D scene is still visible to the right
  2. Pressing E, R, M, or G opens the corresponding panel (Explainability, Replay, Mission, Ghost) if it is not open; pressing the same key again closes it; pressing a different key switches panels without overlap
  3. Pressing Escape closes any open left-drawer panel and returns to the clean scene view
  4. Clicking a station in the 3D scene opens the Explainability panel for that station in the left drawer
  5. The flight HUD elements (speed bar, compass, target brackets, off-screen arrows) are restyled with glassmorphism treatment and repositioned so they do not overlap the status strip
  6. Panel open/close transitions animate at 200-300ms ease-out — the drawer slides in smoothly and content fades in after the drawer reaches its open position
**Plans**: TBD

Plans:
- [ ] 30-01: ObservatoryLeftDrawer container — CSS slide transition, panel slot, glassmorphism shell (HUD-13, VIS-03)
- [ ] 30-02: Hotkey bindings (E/R/M/G/Escape) wired to panel registry + station click → explainability (HUD-14, HUD-15, HUD-16)
- [ ] 30-03: Flight HUD glassmorphism restyle + reposition to avoid status strip conflict (CLN-02)

### Phase 31: Rebuilt Panels
**Goal**: The four core analyst panels exist as production-quality components sized for the left drawer — Explainability shows ranked threat causes, Mission shows active objectives, Replay gives timeline controls, and Ghost Memory surfaces prior findings — all styled with glassmorphism and drawing from existing observatory-store data
**Depends on**: Phase 30 (left drawer container must exist and accept panel content; hotkeys must be wired before panels are meaningful to test end-to-end)
**Requirements**: PNL-01, PNL-02, PNL-03, PNL-04
**Success Criteria** (what must be TRUE):
  1. Pressing E (or clicking a station) opens the Explainability panel showing the selected station's name, ranked pressure causes, and top anomalies sourced from observatory-store — a "Probe" action button dispatches a probe for that station
  2. Pressing M opens the Mission panel showing the active objective title, waypoint guidance text, narrative directive, and objective completion checkmarks sourced from the mission loop state
  3. Pressing R opens the Replay panel showing a timeline scrubber, bookmark list, a jump-to-spike button, and a compare-now-vs-then toggle — all controls work against the existing replay store
  4. Pressing G opens the Ghost Memory panel showing prior findings as a scrollable list with timestamps, receipt traces, and case-note text sourced from observatory ghost memory state
**Plans**: TBD

Plans:
- [ ] 31-01: ExplainabilityDrawerPanel (station name, ranked causes, anomalies, probe button) (PNL-01)
- [ ] 31-02: MissionDrawerPanel (active objective, waypoints, narrative, completion state) (PNL-02)
- [ ] 31-03: ReplayDrawerPanel (scrubber, bookmarks, jump-to-spike, compare toggle) (PNL-03)
- [ ] 31-04: GhostMemoryDrawerPanel (findings list, receipt traces, case-notes, timestamps) (PNL-04)

## Progress

**Execution Order:**
Phase 28 first — clean slate and design tokens before anything is built. Phase 29 requires Phase 28 tokens. Phase 30 requires Phase 29 panel registry. Phase 31 requires Phase 30 drawer container.

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 28. Design Tokens + Panel Audit | 1/2 | In Progress|  | - |
| 29. Status Strip + Panel Registry | v7.0 | 0/2 | Not started | - |
| 30. Left Drawer + Hotkeys + Flight HUD Restyle | v7.0 | 0/3 | Not started | - |
| 31. Rebuilt Panels | v7.0 | 0/4 | Not started | - |
