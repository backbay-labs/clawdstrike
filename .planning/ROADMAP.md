# Roadmap: ClawdStrike Workbench

## Milestones

- ✅ **v1.0 IDE Pivot** — Phases 1-4 (shipped 2026-03-18/19)
- ✅ **v2.0 Huntronomer Integration** — Phases 1-4 (shipped 2026-03-19)
- ✅ **v3.0 Spirit & Observatory Evolution** — Phases 5-9 (shipped 2026-03-19)
- ✅ **v4.0 AAA Observatory Experience** — Phases 10-14 (shipped 2026-03-19)
- ✅ **v5.0 Observatory Analyst Experience** — Phases 15-19 (shipped 2026-03-20)
- ✅ **v6.0 Observatory Space Flight** — Phases 20-27 (shipped 2026-03-20)
- ✅ **v7.0 Observatory Production HUD** — Phases 28-31 (shipped 2026-03-21)
- ✅ **v8.0 Observatory Visual Polish** — Phases 32-34 (shipped 2026-03-22)
- ✅ **v9.0 Observatory 3D World Polish** — Phases 35-38 (shipped 2026-03-22)
- 🚧 **v10.0 Observatory Analyst Toolkit** — Phases 39-43 (in progress)

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

<details>
<summary>✅ v7.0 Observatory Production HUD (Phases 28-31) — SHIPPED 2026-03-21</summary>

## v7.0 Observatory Production HUD

**Milestone Goal:** Transform the observatory's overlapping panel chaos into a clean cockpit HUD — glassmorphism left drawer (one panel at a time), persistent status strip with analyst presets, hotkey-driven panel switching, and a full panel inventory audit to cut what doesn't earn its space.

## Phases

- [x] **Phase 28: Design Tokens + Panel Audit** — Define glassmorphism CSS custom properties, remove all 10 legacy overlay components from the render tree, and delete their dead code from the codebase (completed 2026-03-21)
- [x] **Phase 29: Status Strip + Panel Registry** — Persistent glassmorphism bottom strip with live speed/heading/station data, analyst preset toggle segments, and a Zustand panel registry slice that enforces one-panel-at-a-time mutual exclusion (completed 2026-03-21)
- [x] **Phase 30: Left Drawer + Hotkeys + Flight HUD Restyle** — Sliding left-drawer panel container with CSS transition, hotkey bindings (E/R/M/G/Escape), station-click-to-explainability wiring, and flight HUD restyled to match glassmorphism treatment (completed 2026-03-21)
- [x] **Phase 31: Rebuilt Panels** — Explainability, Mission, Replay, and Ghost Memory panels rebuilt for the left drawer format with compact vertical layouts and glassmorphism styling (completed 2026-03-21)

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
**Plans**: 2 plans

Plans:
- [ ] 29-01-PLAN.md — Zustand panel registry slice (open/close/toggle, mutual exclusion) + unit tests (HUD-17)
- [ ] 29-02-PLAN.md — ObservatoryStatusStrip component — glassmorphism layout, rAF telemetry update, analyst preset segments (HUD-10, HUD-11, HUD-12, VIS-02, VIS-04)

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
**Plans**: 3 plans

Plans:
- [ ] 30-01: ObservatoryLeftDrawer container — CSS slide transition, panel slot, glassmorphism shell (HUD-13, VIS-03)
- [x] 30-02: Hotkey bindings (E/R/M/G/Escape) wired to panel registry + station click → explainability (HUD-14, HUD-15, HUD-16)
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
**Plans**: 2 plans

Plans:
- [ ] 31-01-PLAN.md — All 4 panel components (Explainability, Mission, Replay, Ghost Memory) + unit tests (PNL-01, PNL-02, PNL-03, PNL-04)
- [ ] 31-02-PLAN.md — Wire panels into ObservatoryLeftDrawer + update drawer tests (PNL-01, PNL-02, PNL-03, PNL-04)

## Progress

**Execution Order:**
Phase 28 first — clean slate and design tokens before anything is built. Phase 29 requires Phase 28 tokens. Phase 30 requires Phase 29 panel registry. Phase 31 requires Phase 30 drawer container.

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 28. Design Tokens + Panel Audit | 2/2 | Complete    | 2026-03-21 | - |
| 29. Status Strip + Panel Registry | 2/2 | Complete    | 2026-03-21 | - |
| 30. Left Drawer + Hotkeys + Flight HUD Restyle | 2/3 | Complete    | 2026-03-21 | - |
| 31. Rebuilt Panels | 2/2 | Complete    | 2026-03-21 | - |


</details>

---

## v8.0 Observatory Visual Polish

**Milestone Goal:** Fix the 6 visual/UX issues identified during dogfooding — 3D scene renders on load, glassmorphism blur is visible, panel empty states have structure, status strip has presence, ATLAS button relocated, and drawer has a close affordance.

## Phases

- [x] **Phase 32: Scene & Status Strip Polish** — Fix blank 3D scene on initial load/fly-by, relocate ATLAS toggle into status strip, sharpen status strip border and text contrast (SCN-01, SCN-02, STS-01, STS-02) (completed 2026-03-22)
- [x] **Phase 33: Drawer Chrome & Glassmorphism** — Make left drawer backdrop-filter blur perceptible, add visible top edge treatment, add header bar with panel name and close button (GLS-01, GLS-02, DRW-01, DRW-02) (completed 2026-03-22)
- [x] **Phase 34: Panel Empty States** — Replace bare placeholder text in Explainability, Mission, and Ghost Memory panels with structured empty states and contextual hints (EMP-01, EMP-02, EMP-03) (completed 2026-03-22)

## Phase Details

### Phase 32: Scene & Status Strip Polish
**Goal**: The 3D scene is visible from the first frame and the status strip commands attention — no blank black rectangle during fly-by, ATLAS toggle lives in the strip, and the strip's border + text are legible at a glance
**Depends on**: Phase 31 (ObservatoryWorldCanvas, ObservatoryStatusStrip, and ObservatoryTab exist from v7.0)
**Requirements**: SCN-01, SCN-02, STS-01, STS-02
**Success Criteria** (what must be TRUE):
  1. Opening the observatory tab shows stars, stations, or a loading indicator within the first rendered frame — no blank black rectangle at any point during initial load or fly-by transitions
  2. The ATLAS mode toggle button no longer appears in the orphaned top-right corner; it appears as a labeled segment in the status strip alongside THREAT/EVIDENCE/RECEIPTS/GHOST
  3. The status strip has a visible 1px top border with enough contrast to visually separate it from the 3D scene above it
  4. Speed, heading, and station count text in the status strip is legible at a glance — minimum 11px monospace at opacity >= 0.8
**Plans**: 2 plans

Plans:
- [ ] 32-01-PLAN.md — Fix ObservatoryWorldCanvas blank-scene regression (loading guard + ensure scene content present on first frame) + ATLAS segment wired into ObservatoryStatusStrip (SCN-01, SCN-02)
- [ ] 32-02-PLAN.md — Status strip top border + text legibility pass (STS-01, STS-02)

### Phase 33: Drawer Chrome & Glassmorphism
**Goal**: The left drawer has visual depth and chrome — backdrop-filter blur is perceptible against the 3D scene, the top edge distinguishes the drawer from the background, and operators can close the drawer with a mouse click on the header X button
**Depends on**: Phase 31 (ObservatoryLeftDrawer exists with translateX slide transition)
**Requirements**: GLS-01, GLS-02, DRW-01, DRW-02
**Success Criteria** (what must be TRUE):
  1. When the drawer is open and the 3D scene is rendering behind it, the backdrop-filter blur effect is perceptibly visible — the scene geometry blurs rather than showing through as sharp pixels
  2. The drawer has a visible top edge treatment (border or subtle edge glow) that distinguishes it from the scene behind it — it does not appear to float borderlessly
  3. The drawer header bar shows the active panel name in uppercase monospace (e.g., EXPLAINABILITY, MISSION, REPLAY, GHOST MEMORY)
  4. The drawer header bar has a functional close button that calls closePanel() and slides the drawer shut — provides a mouse-based close affordance alongside the Escape hotkey
**Plans**: 2 plans

Plans:
- [ ] 33-01-PLAN.md — ObservatoryLeftDrawer glassmorphism fix — backdrop-filter blur perceptibility + top border/edge glow treatment (GLS-01, GLS-02)
- [ ] 33-02-PLAN.md — Drawer header bar — panel name label + close button wired to closePanel() (DRW-01, DRW-02)

### Phase 34: Panel Empty States
**Goal**: Explainability, Mission, and Ghost Memory panels show structured placeholder content when no data is present — section outlines, muted icons, and contextual hints guide operators rather than leaving them with bare single-line messages
**Depends on**: Phase 31 (Explainability, Mission, and Ghost Memory panel components exist)
**Requirements**: EMP-01, EMP-02, EMP-03
**Success Criteria** (what must be TRUE):
  1. The Explainability panel empty state shows structured placeholder content with section headers (Station, Pressure, Anomalies), muted icons, and a hint: "Click a station or press E while hovering"
  2. The Mission panel empty state shows a structured section outline (Briefing, Objectives, Narrative) with muted labels and a hint: "Start a mission from the command palette"
  3. The Ghost Memory panel empty state shows a "0 traces" header with a muted explanation of what ghost memory records and when traces appear
**Plans**: 1 plan

Plans:
- [ ] 34-01-PLAN.md — Rich empty states for Explainability, Mission, and Ghost Memory panels (EMP-01, EMP-02, EMP-03)

## Progress

**Execution Order:**
Phases 32 and 34 have no file overlap and can execute in parallel. Phase 33 is also independent. All three phases are pure polish with no cross-dependencies — execute in any order.

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 32. Scene & Status Strip Polish | 2/2 | Complete    | 2026-03-22 | - |
| 33. Drawer Chrome & Glassmorphism | 2/2 | Complete    | 2026-03-22 | - |
| 34. Panel Empty States | 1/1 | Complete    | 2026-03-22 | - |


---

## v9.0 Observatory 3D World Polish

**Milestone Goal:** Make the observatory world visually alive and responsive — ghost traces glow at stations where past findings occurred, mission objective beacons pulse at target stations, analyst presets transform the scene visual mood, and weather effects respond to hunt telemetry.

## Phases

- [x] **Phase 35: Ghost Trace Markers** — Translucent holographic markers at stations with prior findings, sourced from deriveObservatoryGhostMemories(), with GHOST preset opacity gating (GHO-01, GHO-02, GHO-03, GHO-04) (completed 2026-03-22)
- [x] **Phase 36: Mission Objective Beacons** — Emissive vertical beacon columns on active mission targets with breathing pulse animation, visible 500+ units, clean removal when no mission active (MSN-01, MSN-02, MSN-03, MSN-04) (completed 2026-03-22)
- [x] **Phase 37: Analyst Preset Overlays** — THREAT red wash + danger particles, EVIDENCE gold halos, RECEIPTS verdict badge markers, GHOST world dim + full ghost trace reveal, instant neutral restore on deactivate (APR-01, APR-02, APR-03, APR-04, APR-05) (completed 2026-03-22)
- [x] **Phase 38: Weather Layer Revival** — Mount the existing weather system in the 3D scene, telemetry-driven fog/particles/lighting, performance profile gating (WTH-01, WTH-02, WTH-03) (completed 2026-03-22)

## Phase Details

### Phase 35: Ghost Trace Markers
**Goal**: Stations with prior findings are visually marked in 3D space — spectral holographic indicators render at station positions, show finding type glyphs at mid-range, and respond to the GHOST analyst preset for opacity
**Depends on**: Phase 34 (v8.0 complete — observatory world substrate, ghost memory store, and GHOST preset toggle all stable)
**Requirements**: GHO-01, GHO-02, GHO-03, GHO-04
**Success Criteria** (what must be TRUE):
  1. Stations with prior findings display translucent holographic meshes at their 3D positions — the markers are visually distinct from station geometry (spectral glow, not solid) and visible without activating any preset
  2. Ghost markers show a small icon or glyph representing the finding type (receipt verdict, probe result, case-note) that is readable when the camera is within 60-180 units of the station
  3. When the GHOST analyst preset is active, ghost markers render at full opacity; when inactive, they dim to 20% opacity — the transition is immediate and does not linger
  4. Ghost marker data comes exclusively from deriveObservatoryGhostMemories() — no new data fetching, no new store slices
**Plans**: 2 plans

Plans:
- [ ] 35-01-PLAN.md — GhostTraceLayer component (holographic ring + glyph meshes at station positions)
- [ ] 35-02-PLAN.md — Wire GhostTraceLayer into ObservatoryWorldCanvas with GHOST preset opacity gating

### Phase 36: Mission Objective Beacons
**Goal**: Active mission targets are clearly identifiable from across the space environment — emissive beacon columns extend upward from target stations with a breathing pulse animation, dim when completed, and vanish entirely when no mission is active
**Depends on**: Phase 34 (v8.0 complete — mission store and ObservatoryWorldCanvas are stable)
**Requirements**: MSN-01, MSN-02, MSN-03, MSN-04
**Success Criteria** (what must be TRUE):
  1. Active mission objective stations display a vertical emissive beacon column extending upward from the station, visible from 500+ units even through fog
  2. The active objective beacon pulses with a breathing opacity oscillation on approximately a 2-second cycle — completed objective beacons shift to a static, muted desaturated glow without pulsing
  3. Beacon color matches the station accent color for active objectives; completed objectives use a muted desaturated version of that color
  4. When no mission is active, zero beacon geometry renders in the scene — the world has no leftover mission markers
**Plans**: 2 plans

Plans:
- [ ] 36-01-PLAN.md — MissionObjectiveBeacons component (beacon geometry, animation, pure helpers)
- [ ] 36-02-PLAN.md — Mount in ObservatoryWorldCanvas + visual smoke test

### Phase 37: Analyst Preset Overlays
**Goal**: Each analyst preset transforms the visual mood of the observable world — THREAT districts turn red and emit danger particles, EVIDENCE stations glow gold, RECEIPTS stations show verdict badges, GHOST dims the world and reveals traces, and deactivating any preset instantly restores the neutral scene
**Depends on**: Phase 35 (ghost trace markers must exist before GHOST preset can reveal them at full opacity via APR-04 cross-referencing GHO-03)
**Requirements**: APR-01, APR-02, APR-03, APR-04, APR-05
**Success Criteria** (what must be TRUE):
  1. Activating THREAT preset tints active-pressure district regions with a red emissive wash and spawns subtle danger particle motes around high-pressure stations
  2. Activating EVIDENCE preset renders gold emissive halos around stations with receipt data, reusing the affinity ring geometry pattern from v3.0
  3. Activating RECEIPTS preset renders small floating verdict badge markers (ALLOW/DENY/AUDIT icons) near stations that have receipt history
  4. Activating GHOST preset reduces world ambient light by 40%, desaturates non-ghost scene geometry, and elevates ghost trace markers to full opacity
  5. Deactivating any preset returns ambient light, saturation, particles, halos, and badge markers to their neutral baseline within one frame — no tint or particle linger
**Plans**: 2 plans

Plans:
- [ ] 37-01-PLAN.md — ThreatPresetOverlay, EvidencePresetOverlay, ReceiptsPresetOverlay components + unit tests
- [ ] 37-02-PLAN.md — GhostPresetOverlay + wire all four overlays into ObservatoryWorldScene

### Phase 38: Weather Layer Revival
**Goal**: The observatory world has atmospheric conditions driven by hunt telemetry — fog density, ambient lighting, and particle weather effects mount into the 3D scene, scale with pressure, and respect the performance profile
**Depends on**: Phase 34 (v8.0 complete — observatory world substrate and performance profile system stable; weather system implementation exists from v5.0 hunt weather controller)
**Requirements**: WTH-01, WTH-02, WTH-03
**Success Criteria** (what must be TRUE):
  1. The weather layer renders in the 3D scene — fog, ambient light intensity, and atmospheric particles respond to the weatherState from observatory-store and update when hunt telemetry changes
  2. Weather intensity visibly scales with hunt telemetry pressure — a calm hunt shows clear skies with minimal fog, a high-pressure hunt shows denser fog and more active atmospheric particles
  3. On low-quality performance profile settings, weather effects are reduced or disabled — the scene remains usable and does not drop below target frame rate due to weather geometry
**Plans**: 1 plan

Plans:
- [ ] 38-01-PLAN.md — Build ObservatoryWeatherLayer + mount in ObservatoryWorldCanvas

## Progress

**Execution Order:**
Phases 35, 36, and 38 are independent and can execute in parallel. Phase 37 depends on Phase 35 (ghost trace markers must exist before the GHOST preset can reveal them at full opacity).

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 35. Ghost Trace Markers | 2/2 | Complete    | 2026-03-22 | - |
| 36. Mission Objective Beacons | 2/2 | Complete    | 2026-03-22 | - |
| 37. Analyst Preset Overlays | 2/2 | Complete    | 2026-03-22 | - |
| 38. Weather Layer Revival | 1/1 | Complete    | 2026-03-22 | - |

---

## v10.0 Observatory Analyst Toolkit

**Milestone Goal:** Transform the observatory from a visual experience into a full analyst control surface — threat heatmaps project pressure onto the world, probe delta cards surface what changed and why, constellation routes memorialize completed investigations, spirit trails reveal hidden connections, replay annotations let operators mark moments in 3D space, and station interiors add depth to each investigation node.

## Phases

- [ ] **Phase 39: Store, Persistence, and Derivation Foundations** — Extend observatory-store with annotation/constellation/interior state, bump persistence schema to v2 with migration, write pure derivation utilities, extend ObservatoryInvalidationController for all new visual sources (enables all v10.0 features)
- [ ] **Phase 40: Threat Heatmap + Probe Delta Cards** — Ground-plane GLSL heatmap driven by station pressure, analyst-preset integration, floating 3D probe delta cards post-fire with auto-dismiss (HEAT-01..05, PRBI-01..06)
- [ ] **Phase 41: Constellation Routes + Spirit Trails** — Permanent mission-trace constellations in the starfield with persistence and minimap click, level-gated spirit luminous trails with hidden resonance connections at level 5 (CNST-01..05, SPRT-01..05)
- [ ] **Phase 42: Replay Annotation Canvas** — Click 3D space during replay to drop named pins with text, drawer list with jump-to-frame, delete, localStorage persistence (ANNO-01..06)
- [ ] **Phase 43: Station Interior Zones** — Seamless camera-push transition into 6 unique per-station interiors, NPC activity, hero prop interaction, exit back to exterior (INTR-01..06)

## Phase Details

### Phase 39: Store, Persistence, and Derivation Foundations
**Goal**: The TypeScript data contracts for all five new visual systems are locked and tested — store slices for annotation pins, constellation routes, and interior state exist; localStorage schema is bumped to v2 with a migration stub; derivation utilities are written and unit-tested; invalidation controller is extended for every new visual source
**Depends on**: Phase 38 (v9.0 complete — observatory-store, types.ts, observatory-replay-persistence.ts, and ObservatoryInvalidationController are the stable baseline)
**Requirements**: (foundation phase — enables phases 40-43; no direct v10.0 requirement is solely deliverable here)
**Success Criteria** (what must be TRUE):
  1. `ObservatoryAnnotationPin`, `ConstellationRoute`, and `ObservatoryInteriorState` types compile cleanly and are exported from the observatory types barrel
  2. The observatory-store exposes annotation, constellation, and interior state slices — add/remove/clear actions round-trip correctly in unit tests
  3. `observatory-replay-persistence.ts` loads both v1 and v2 schemas without throwing — the migration path from v1 is exercised in a unit test
  4. `deriveConstellationFromMission`, `deriveSpiritResonanceConnections`, and `deriveHeatmapDataTexture` all have passing unit tests against typed inputs
  5. `ObservatoryInvalidationController.sourceKey` includes `annotationDropCount`, `heatmapPulseVersion`, `spiritTrailSegmentCount`, `constellationCount`, and `interiorTransitionPhase`
**Plans**: 3 plans

Plans:
- [ ] 39-01-PLAN.md — v10.0 type contracts + store slices (annotation pins, constellations, interior state)
- [ ] 39-02-PLAN.md — localStorage v2 persistence schema with v1 migration
- [ ] 39-03-PLAN.md — Derivation utilities + invalidation controller extension

### Phase 40: Threat Heatmap + Probe Delta Cards
**Goal**: The observatory world has two new data-reactive visual layers — a ground-plane heatmap projects threat pressure as a continuous color gradient across the station ring, and floating delta cards appear near stations after probes fire, showing what changed and what to do next
**Depends on**: Phase 39 (heatmap gating requires `weatherBudget` hook from store; delta card invalidation requires extended sourceKey; `deriveHeatmapDataTexture` utility must exist before ThreatTopologyHeatmap can consume it)
**Requirements**: HEAT-01, HEAT-02, HEAT-03, HEAT-04, HEAT-05, PRBI-01, PRBI-02, PRBI-03, PRBI-04, PRBI-05, PRBI-06
**Success Criteria** (what must be TRUE):
  1. A ground-plane color gradient mesh is visible below the station ring during observatory use — blue/teal regions indicate low pressure stations, amber/red regions indicate high-pressure stations, matching SOC-standard ramp
  2. The heatmap visibly shifts and pulses when hunt telemetry updates arrive — smooth interpolation is perceptible between telemetry states rather than a hard cut
  3. Activating the THREAT analyst preset intensifies the heatmap colors; activating any other preset or deactivating all presets returns the heatmap to its baseline intensity
  4. On a low-quality performance profile (weatherBudget=off), no heatmap mesh renders in the scene — the feature is completely absent rather than degraded
  5. After a probe fires and completes, a floating card appears near the target station showing pressure shift direction, an explanation sentence, and a clickable recommended next action — the card auto-dismisses after 8 seconds
**Plans**: TBD

### Phase 41: Constellation Routes + Spirit Trails
**Goal**: Investigation history becomes permanently visible in the star layer — each completed mission traces a named constellation curve through the starfield, and the bound spirit leaves luminous trails between stations as the analyst navigates, revealing hidden connections at level 5
**Depends on**: Phase 39 (constellation persistence and `deriveConstellationFromMission` utility must exist; `deriveSpiritResonanceConnections` must exist for level-5 hidden connections)
**Requirements**: CNST-01, CNST-02, CNST-03, CNST-04, CNST-05, SPRT-01, SPRT-02, SPRT-03, SPRT-04, SPRT-05
**Success Criteria** (what must be TRUE):
  1. Completing a mission causes a luminous curve to appear in the starfield connecting the stations visited during that mission — the constellation is visible from anywhere in the observatory and persists across tab close/reopen
  2. Clicking a constellation on the star chart minimap shows a tooltip with the constellation name and the date it was created
  3. After multiple completed missions, the starfield shows multiple constellations accumulating as a visible investigation history
  4. With a spirit bound, navigating between stations leaves a luminous trail — trail color and intensity reflect the spirit's current mood, and trail brightness scales visibly with spirit XP level (level 1 faint, level 5 vivid)
  5. At spirit level 5, additional glowing connections appear between stations that are not part of the normal transit network — these hidden resonance connections are distinct from the transit lane geometry
**Plans**: TBD

### Phase 42: Replay Annotation Canvas
**Goal**: The replay timeline becomes a writable investigation surface — analysts drop named pins directly in 3D space during replay, attach text notes, manage annotations from the Replay drawer, and their work survives across sessions
**Depends on**: Phase 39 (annotation store slice and localStorage v2 persistence must exist before the R3F pointer layer can write to them; ANNO-03 requires the persistence layer from Phase 39)
**Requirements**: ANNO-01, ANNO-02, ANNO-03, ANNO-04, ANNO-05, ANNO-06
**Success Criteria** (what must be TRUE):
  1. Clicking a point in 3D space during replay places a visible pin marker at that world position — the pin is distinguishable from station geometry (distinctive icon or glow, not a floating dot)
  2. Clicking a placed pin opens an inline input field where the analyst can type a text note and confirm it — the note text is then visible as a label near the pin
  3. All pins created during a replay session are listed in the Replay drawer panel as a scrollable list with their note text
  4. Clicking a pin in the Replay drawer jumps the replay timeline to the frame when that pin was dropped and moves the camera to focus on the pin's 3D position
  5. After closing and reopening the workbench, previously dropped pins for that replay are still present in both the 3D scene and the Replay drawer
  6. Deleting a pin from the Replay drawer or by clicking it in 3D space removes it from the scene, the drawer list, and localStorage immediately
**Plans**: TBD

### Phase 43: Station Interior Zones
**Goal**: Each station is a navigable destination with interior depth — analysts push the camera inside any station to explore a unique room layout with active NPCs, interact with the station hero prop to complete mission objectives, and exit cleanly back to the exterior observatory
**Depends on**: Phase 39 (interior state machine entry in observatory-store must exist; `interiorTransitionPhase` invalidation key must be registered); Phase 40 (probe delta cards wired into ObservatoryWorldScene — prop interface must be stable before adding interior layer)
**Requirements**: INTR-01, INTR-02, INTR-03, INTR-04, INTR-05, INTR-06
**Success Criteria** (what must be TRUE):
  1. Triggering an interior transition from any station smoothly pushes the camera from the exterior view into the station interior without a visible cut or flash — the transition feels seamless
  2. Each of the 6 stations has a visually distinct interior room — the Signal station looks like a radar room, the Receipts station looks like a vault; room geometry is unique per station, not reused
  3. NPCs in the interior perform visible station-specific activities (typing, examining equipment, patrolling) rather than standing idle
  4. While inside a station, interacting with the hero prop completes mission objectives the same as the exterior interaction — analysts do not need to exit to advance the mission
  5. Pressing Escape or clicking a back affordance exits the interior and smoothly returns the camera to the exterior observatory view
  6. Interior geometry has no z-fighting artifacts — the camera near plane is reduced to 0.02 on interior entry and restored to the exterior value on exit
**Plans**: TBD

## Progress

**Execution Order:**
Phase 39 first (store contracts and invalidation controller). Phase 40 and 41 can execute in parallel after Phase 39 (both depend only on Phase 39 foundations, no cross-dependency). Phase 42 depends only on Phase 39. Phase 43 depends on Phase 39 and Phase 40 (prop interface stability from Phase 40 before adding interior layer).

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 39. Store, Persistence, and Derivation Foundations | 2/3 | In Progress|  | - |
| 40. Threat Heatmap + Probe Delta Cards | v10.0 | 0/TBD | Not started | - |
| 41. Constellation Routes + Spirit Trails | v10.0 | 0/TBD | Not started | - |
| 42. Replay Annotation Canvas | v10.0 | 0/TBD | Not started | - |
| 43. Station Interior Zones | v10.0 | 0/TBD | Not started | - |
