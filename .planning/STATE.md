---
gsd_state_version: 1.0
milestone: v10.0
milestone_name: Observatory Analyst Toolkit
status: planning
stopped_at: Completed 43-01-PLAN.md
last_updated: "2026-03-23T14:17:21.088Z"
last_activity: 2026-03-22 — Roadmap created; 5 phases (39-43), 33 requirements mapped
progress:
  total_phases: 12
  completed_phases: 11
  total_plans: 25
  completed_plans: 24
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-22)

**Core value:** Security operators work across multiple views simultaneously with a spirit-driven immersive layer
**Current focus:** v10.0 Observatory Analyst Toolkit — Phase 39 ready to plan

## Current Position

Phase: 39 of 43 (Store, Persistence, and Derivation Foundations)
Plan: — (not yet planned)
Status: Ready to plan
Last activity: 2026-03-22 — Roadmap created; 5 phases (39-43), 33 requirements mapped

Progress: [░░░░░░░░░░] 0%

## Performance Metrics

**Velocity (v9.0 baseline):**
- Total plans completed (v9.0): 7
- Average duration: ~5 min/plan
- Total execution time: ~35 min

*Updated after each plan completion*

| Phase | Plan | Duration | Tasks | Files |
|-------|------|----------|-------|-------|

## Accumulated Context
| Phase 39 P01 | 31s | 2 tasks | 3 files |
| Phase 39 P02 | 2min | 1 tasks | 2 files |
| Phase 39 P03 | 145s | 2 tasks | 4 files |
| Phase 40 P01 | 108s | 1 tasks | 2 files |
| Phase 40 P02 | 393 | 2 tasks | 3 files |
| Phase 40 P03 | 4min | 2 tasks | 4 files |
| Phase 41 P01 | 308 | 2 tasks | 5 files |
| Phase 41-constellation-routes-spirit-trails P03 | 269 | 1 tasks | 2 files |
| Phase 41-constellation-routes-spirit-trails P02 | 479 | 2 tasks | 5 files |
| Phase 42-replay-annotation-canvas P01 | 342 | 2 tasks | 5 files |
| Phase 42-replay-annotation-canvas P02 | 276 | 2 tasks | 4 files |
| Phase 43-station-interior-zones P01 | 307 | 2 tasks | 2 files |

### Decisions

- [Phase 28]: Glassmorphism tokens isolated to observatory-hud.css — `--hud-bg`, `--hud-blur`, `--hud-border`, etc.
- [Phase 35]: ghostOpacityScale derived in outer ObservatoryWorldCanvas, not inner scene
- [Phase 37]: GhostPresetOverlay replaces ambientLight via ternary — prevents double-lighting
- [Phase 38]: Fog delta capped at +0.0007; effectiveWeatherState=null guard prevents mount for budget=off
- [v10.0 Roadmap]: Split-Screen Compare deferred to v11.0 (dual Canvas WebGL context budget risk)
- [v10.0 Roadmap]: Phase 39 is pure TypeScript — no R3F work; all new scene layers prop-threaded from ObservatoryTab
- [Phase 39-01]: Duplicate-id rejection in addAnnotationPin/addConstellation uses early-return-state (matches addReplayBookmark precedent) rather than throwing
- [Phase 39-01]: clearInterior resets to explicit default object rather than spread to ensure all fields reset cleanly
- [Phase 39]: v2 load tries v2 key first then falls back to v1 migration — preserves all existing data without data loss
- [Phase 39]: v2 save writes only to v2 key — v1 key never updated once v2 schema is live
- [Phase 39-03]: RESONANCE_CONNECTIONS hardcoded as module-level constant — 3 cross-ring pairs (signal-receipts, targets-case-notes, run-watch) per plan spec
- [Phase 39-03]: All 5 new ObservatoryRuntimeActivitySources fields are optional (?) for backward compatibility with existing callers
- [Phase 40]: NormalBlending (not AdditiveBlending) for heatmap so dark background contrast is preserved
- [Phase 40]: Heatmap uPressure uniforms mutated via ref in useFrame to avoid material re-creation per frame
- [Phase 40]: ProbeDeltaCard committed in 40-01 test commit — file was created correctly, no re-write needed
- [Phase 40]: ProbeDeltaLayer uses two-timer pattern: 7500ms fade-start + 8000ms full removal for smooth auto-dismiss
- [Phase 40]: heatmapVisible = weatherBudget !== 'off' reuses weather budget as single gate for ground-plane effects (heatmap + weather layer share same performance budget)
- [Phase 40]: ProbeDeltaLayer always mounted in scene (no outer conditional) — internally returns null when probeGuidance is null
- [Phase 41]: CatmullRomCurve3 tension=0.4 + 64 sample points for smooth constellation arcs in star layer
- [Phase 41]: 30% spirit accent lerp on #e8e4f0 base for constellation color (depthWrite=false + toneMapped=false per locked CONTEXT.md)
- [Phase 41]: prevMissionStatusRef pattern detects mission completion; cap check at >= 12 before addConstellation fires eviction
- [Phase Phase 41]: CNST-04: Click (not hover) as primary interaction for constellation polylines on minimap — hover on small SVG polylines is imprecise
- [Phase Phase 41]: Constellation tooltip positioned at bottom-center of minimap div via absolute positioning; local useState (not store)
- [Phase 41]: SpiritTrailsLayer uses playerFocusRef (RefObject) not playerPosition (prop) to read position inside useFrame — avoids re-renders each frame
- [Phase 41]: Trail rendering suppressed when spiritMood=dormant or no spirit bound — prevents ghost trails from unbound state
- [Phase 42]: depthTest is not a valid prop on drei Text — removed; labels rely on natural draw order
- [Phase 42]: ReplayAnnotationLayer ground plane uses onPointerDown (not onClick) to avoid orbit control conflicts; replayEnabled guard prevents accidental drops
- [Phase 42]: Remove+add pattern for annotation pin note updates (store has no upsert action)
- [Phase 42]: Drawer dispatches window CustomEvent (observatory:camera-focus) for camera focus — decoupled from R3F scene tree
- [Phase 42]: Camera focus event listener in ObservatoryWorldScene snaps controlsRef.target; OrbitControls dampingFactor provides smooth transition naturally
- [Phase 43]: HuntStationId imported from ./types (world-local) not ../types — station-interior-config.ts lives inside world/
- [Phase 43]: InteriorNpcCrew uses Instances limit=4 — 3 NPCs + 1 spare slot per station interior

### Pending Todos

None.

### Blockers/Concerns

- [Phase 43]: Station Interior log-Z depth buffer mitigation: camera near-plane adjustment vs renderer mode swap needs prototype before building 6 interior geometry sets
- [Phase 41]: Level-5 hidden resonance connections (SPRT-04) need explicit product design decisions (which 3-4 inter-station pairs are "hidden") before `deriveSpiritResonanceConnections` can be written in Phase 39
- jsdom prints non-failing warnings for raw R3F tag casing in tests
- Some Three.js-based tests print non-failing multiple-instances warning

## Session Continuity

Last session: 2026-03-23T14:17:21.085Z
Stopped at: Completed 43-01-PLAN.md
Resume file: None
