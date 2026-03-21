---
gsd_state_version: 1.0
milestone: v7.0
milestone_name: Observatory Production HUD
status: planning
stopped_at: Completed 29-02-PLAN.md
last_updated: "2026-03-21T13:46:07.237Z"
last_activity: 2026-03-21 — v7.0 roadmap created, phases 28-31 defined
progress:
  total_phases: 4
  completed_phases: 2
  total_plans: 4
  completed_plans: 4
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-21)

**Core value:** Security operators work across multiple views simultaneously with a spirit-driven immersive layer
**Current focus:** Phase 28 — Design Tokens + Panel Audit (ready to plan)

## Current Position

Phase: 28 of 31 (Design Tokens + Panel Audit)
Plan: — (not started)
Status: Ready to plan
Last activity: 2026-03-21 — v7.0 roadmap created, phases 28-31 defined

Progress: [░░░░░░░░░░] 0%

## Performance Metrics

**Velocity (v6.0 baseline):**
- Total plans completed (v6.0): 21
- Average duration: ~7 min/plan
- Total execution time: ~147 min

*Updated after each plan completion*

| Phase | Plan | Duration | Tasks | Files |
|-------|------|----------|-------|-------|
| (v7.0 plans not yet started) | — | — | — | — |
| Phase 28 P02 | 4 | 1 tasks | 2 files |
| Phase 28-design-tokens-panel-audit P01 | 8 | 2 tasks | 16 files |
| Phase 29-status-strip-panel-registry P01 | 4 | 2 tasks | 5 files |
| Phase 29 P02 | 12 | 2 tasks | 4 files |

## Accumulated Context

### Decisions

- [Phase 24]: DOM-based HUD (not R3F overlays) — 60fps ref-mutation avoids React re-renders; CSS overlay doesn't fight Canvas
- [Phase 24]: rAF+getState() chosen over useSelector for HUD frame loop — zero subscriptions, zero React re-renders at 60fps
- [Phase 27]: handleFlightStateChange uses getState().actions.setFlightState (imperative write) — 60fps callback must not cause React re-renders
- [v7.0 roadmap]: Clean slate first — all 10 legacy overlay components deleted before framework is built (Phase 28 before 29)
- [v7.0 roadmap]: CSS custom properties for glassmorphism tokens defined once, shared across status strip, left drawer, and rebuilt panels
- [Phase 28]: Glassmorphism tokens isolated to observatory-hud.css, imported via globals.css — keeps HUD-specific properties out of main token namespace
- [Phase 28]: --hud-accent: var(--spirit-accent, #4af) — spirit-driven HUD theming with safe fallback, no hard dependency on spirit being bound
- [Phase 28]: Deleted all 10 legacy overlay components as clean slate — new panel framework builds from scratch in Phase 29
- [Phase 28]: ObservatoryRuntimeMonitors.tsx and ObservatoryTelemetryBridge.tsx preserved — R3F hooks and telemetry subscriber still needed
- [Phase 29]: Panel registry mutual exclusion via single activePanel field — overwrite is sufficient, no explicit close-then-open needed
- [Phase 29]: ObservatoryAnalystPresetId 'nexus' renamed to 'ghost' (THREAT/EVIDENCE/RECEIPTS/GHOST HUD-12 alignment); ObservatoryStationKind 'nexus' unchanged
- [Phase 29]: ObservatoryStatusStrip rAF mock call-count guard prevents jsdom stack overflow — synchronous cb(0) must not recurse
- [Phase 29]: Status strip bg rgba(8,12,24,0.88) not var(--hud-bg) — VIS-02 requires >= 0.85 opacity for text readability
- [Phase 29]: Preset buttons use React subscriptions not rAF — preset changes are rare user actions not per-frame, subscriptions appropriate

### Blockers/Concerns

- jsdom prints non-failing warnings for raw R3F tag casing in `observatory-ghost-layer.test.tsx`
- Some Three.js-based tests print a non-failing multiple-instances warning in the Vitest environment

## Session Continuity

Last session: 2026-03-21T13:42:16.625Z
Stopped at: Completed 29-02-PLAN.md
Resume file: None
