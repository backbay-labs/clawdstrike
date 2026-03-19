---
gsd_state_version: 1.0
milestone: v3.0
milestone_name: Spirit & Observatory Evolution
status: executing
stopped_at: Completed 06-observatory-glb-props-spirit-affinity-rings 06-01-PLAN.md
last_updated: "2026-03-19T13:04:49.215Z"
last_activity: "2026-03-19 — Plan 05-03 complete: ObservatoryMinimapPanel SVG + polarToSvg + 13 tests + Observatory activity bar + CATEGORY_ORDER (OBS-10)"
progress:
  total_phases: 5
  completed_phases: 1
  total_plans: 5
  completed_plans: 4
  percent: 67
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-18)

**Core value:** Security operators get an immersive IDE with spirit-driven 3D layers woven into IDE surfaces
**Current focus:** Phase 1 — Spirit + Observatory State Foundation

## Current Position

Phase: 5 of 5 (Spirit Reactivity & Editor Integration)
Plan: 3 of 3 in current phase — 05-01, 05-03 complete
Status: In Progress — Phase 5 active
Last activity: 2026-03-19 — Plan 05-03 complete: ObservatoryMinimapPanel SVG + polarToSvg + 13 tests + Observatory activity bar + CATEGORY_ORDER (OBS-10)

Progress: [██████░░░░] 67%

## Previous Milestone (v1.1 — IDE Completeness)

Completed: 2026-03-18 (phases 1-5 of 7; phases 6-7 handled by separate agent)
Phases: 5/7 | Plans: 9/9 | Requirements: 18/29
Summary: Added in-file search, global search, quick navigation, file tree mutations, tab overflow, terminal splits

## Previous Milestone (v1.0 — IDE Pivot)

Completed: 2026-03-18
Phases: 4/4 | Plans: 9/9 | Requirements: 45/45
Summary: Delivered IDE shell — activity bar, 7 sidebar panels, pane tab system, right sidebar, bottom panels, 80+ commands, lab decomposition

## Performance Metrics

**Velocity (recent — v1.1):**
- Total plans completed: 10
- Average duration: ~3 min
- Total execution time: ~30 min

*Updated after each plan completion*

## Accumulated Context

### Decisions

v1.0 decisions carried forward:
- openApp searches all pane groups for route dedup
- navigate-commands uses Zustand getState() (no react-router dependency)
- Lab sub-apps independently routable at /swarm-board, /hunt, /simulator

v2.0 decisions:
- Mini R3F canvas lives in right sidebar (already has resize handle)
- Observatory is a TAB/PANE not a panel (like VS Code Markdown Preview)
- deriveObservatoryWorld survives — powers both full tab and minimap
- Character controller is opt-in Easter-egg in observatory tab flow mode only
- WebGL Canvas architecture (separate Canvas vs root Canvas + drei View) — OPEN, resolve in Phase 2 spike
- [Phase 02-01]: @react-three/fiber pinned at ^9.0.0 (not ^9.5.0) for React 19.2.4 compatibility
- [Phase 02-01]: three pinned at ^0.170.0 to match huntronomer target
- [Phase 02-01]: SpiritKind = sentinel | oracle | witness | specter (huntronomer names; ember/tide/verdant/void/neutral retired)
- [Phase 02-01]: SPIRIT_ACCENT_MAP: sentinel=#3dbf84, oracle=#7b68ee, witness=#d4a84b, specter=#c45c5c
- [Phase 02-01]: Wave 0 test scaffolds use @ts-expect-error to allow runtime testing before type extension
- [Phase 01]: Spirit store uses no-immer create() pattern; SPIRIT_ACCENT_MAP is module-level const not in state
- [Phase 01]: Observatory setStations recomputes artifactCount aggregate inline to keep seamSummary consistent with stations array
- [Phase 01]: SpiritFieldInjector subscribes to kind+accentColor only; fieldStrength reserved for future intensity scaling
- [Phase 01]: CSS fallback var(--spirit-field-stain, transparent) prevents flash before injector mounts
- [Phase 01]: SpiritFieldInjector mounted as first child in DesktopLayout before InitCommands
- [Phase 01]: ActivityBarItem badge prop is sparse (undefined = no badge, number > 0 = render green pulse dot); liveness color split deferred to later phase
- [Phase 01]: PlaceholderPane is inline in workbench-routes.tsx for transitional routes (/observatory, /spirit-chamber, /nexus)
- [Phase 01]: hunt.bindSpirit opens /spirit-chamber as proxy until dedicated bind-spirit flow built in Phase 3
- [Phase 01]: Inline style borderColor used for --spirit-accent in HuntLayout (CSS vars dynamic; Tailwind JIT cannot evaluate at build time)
- [Phase 01]: spirit-field-stain-host applied to sidebar-panel, pane-root, bottom-pane root elements; no cn() wrapper — matched existing bare-string className pattern
- [Phase 02]: SpiritChamberTab: kind selector hidden when bound + Bind/Unbind mutually exclusive (test contract compliance)
- [Phase 02-02]: SpiritOrbIcon uses CSS custom property --spirit-orb-color to preserve raw hex in style attribute (jsdom normalizes hex in gradient stops to rgb())
- [Phase 02-02]: SpiritCompanionCanvas returns null when accentColor is null — prevents WebGL context creation when no spirit is bound
- [Phase 02-02]: RightSidebarPanel extended to "speakeasy" | "spirit"; Wave 0 @ts-expect-error guards removed after type extension
- [Phase 02]: Separate Canvas per pane tab (not root Canvas + drei View) — drei View #2471 z-index issue, WebGL context-disposes verified by code review, deferred to Phase 3 for full Tauri runtime confirmation
- [Phase 03-04]: ForensicsTapePanel CSS-only with 4 mock events — glia-three deferred pending audit; BottomPaneTab extended to 5 members (terminal|problems|output|audit|tape)
- [Phase 03-01]: probeConsequences.ts missionLoop dependency stripped; buildMissionRead simplified to not accept mission parameter
- [Phase 03-01]: ObservatoryWorldCanvas Physics deferred to 03-03 (Physics always-on overhead pitfall)
- [Phase 03-01]: All hero prop assets set to availability=slot — GLB assets not in workbench; fallback procedural geometry only in Phase 3
- [Phase 03-01]: [Phase 03-01]: ObservatoryTab as Store Bridge — reads workbench stores, builds HuntObservatorySceneState, passes to ObservatoryWorldCanvas as props
- [Phase 03-full-immersive-panes-observatory-forensics]: ObservatoryWorldCanvas probeState moved to prop: canvas is pure renderer, probe lifecycle owned by ObservatoryTab
- [Phase 03-02]: CameraControls (drei) used in flow mode, OrbitControls in atlas mode; WorldCameraRig handles bezier camera lerp on mode transition
- [Phase 03-03]: Inline transient notification instead of useToast to avoid ToastProvider context in tests
- [Phase 03-03]: moveSet.ts ported alongside runtime.ts (required dependency for flip physics)
- [Phase 03-03]: FlowModeController API uses test contract (characterControllerEnabled+onEnable) rather than plan spec (enabled+paneIsActive)
- [Phase 04-01]: STRIKECELL_BY_STATION placed in types.ts (not NexusCanvas) — workbench has no NexusCanvas yet, routing map belongs at types layer
- [Phase 04-01]: Wave 0 tests fail with Vite module resolution error (not syntax error) — @ts-expect-error guards NexusTab import, Vite transform-time error is expected Wave 0 failure mode
- [Phase 04-01]: DEMO_STRIKECELLS all status=offline, nodes=[] — workbench has no live backend, demo data is placeholder only
- [Phase 04-03]: HuntSpiritKind/RuntimeState/Meta inlined into model.ts; createHuntSpiritState + deriveHuntSpiritRuntimeState stubbed with stable motion envelope from confidenceScore
- [Phase 04-03]: SpiritBindContext/Candidate defined as workbench-local types; no huntronomer Hunt/Artifact imports
- [Phase 04-03]: SPIRIT_ACCENT_MAP duplicated locally in spirit-chamber-tab.tsx to avoid import coupling with spirit-store internals
- [Phase 04-02]: NexusTab mode fixed to atlas (no mode toggle) — nexus is an overview surface, not a walkable world
- [Phase 04-02]: resolveNexusObservatoryStationId ported inline to keep workbench self-contained (no huntronomer import)
- [Phase 05-01]: deriveSpiritMood priority order: dormant > alert > active > idle (lint errors beat probe active)
- [Phase 05-01]: SpiritMoodReactor debounces setMood calls by 500ms via useRef<setTimeout> to prevent mood thrashing
- [Phase 05-01]: hasLintErrors = tabs.some(t => t.validation.errors.length > 0); probeActive = seamSummary.activeProbes > 0
- [Phase 05-03]: polarToSvg exported as named export from observatory-minimap-panel.tsx for pure unit testing (no component mount needed)
- [Phase 05-03]: "Observatory" CommandCategory placed between "Hunt" and "Test" in CATEGORY_ORDER
- [Phase 05-03]: Artifact badge: SVG text at (x+7, y-5) with fontWeight=bold — rendered only when artifactCount > 0
- [Phase 05-spirit-reactivity-editor-integration]: Compartment reconfigure approach: avoids editor flicker, preserves cursor and scroll position on spirit change
- [Phase 05-spirit-reactivity-editor-integration]: Token tinting: t=0.35 blend factor for prop/keyword/operator, t=0.25 for strings — subtle shift toward spirit accent without full palette replacement
- [Phase 06]: scene.clone() used in HeroPropMesh to prevent shared Three.js scene graph mutation
- [Phase 06]: Hero props rendered additively above StationSphere (sphere stays as clickable hit target below GLB prop)
- [Phase 06]: useGLTF.preload() called at module level for all 7 ready assets to reduce first-open load time

### Pending Todos

None yet.

### Blockers/Concerns

- [Phase 2]: KEY DECISION — WebGL Canvas architecture must be resolved before any Canvas placement. Audit drei@^10.0.0 issue #2471 status and test Tauri WebKit context ceiling in Phase 2 spike.
- [Phase 3]: glia-three RiverView may own its own Canvas — audit package source before committing to ForensicsTapeTab implementation.
- [Phase 4]: NexusStateContext full dependency mapping required before migration begins — do not start Phase 4 without this audit.

## Session Continuity

Last session: 2026-03-19T13:04:49.212Z
Stopped at: Completed 06-observatory-glb-props-spirit-affinity-rings 06-01-PLAN.md
Resume file: None
