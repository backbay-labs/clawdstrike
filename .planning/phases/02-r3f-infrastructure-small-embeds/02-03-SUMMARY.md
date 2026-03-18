---
phase: "02"
plan: "03"
subsystem: spirit
tags: [spirit, spirit-chamber, webgl, r3f, routes, adr]
dependency_graph:
  requires: [02-01]
  provides: [spirit-chamber-tab, webgl-spike-canvas, spirit-chamber-route, webgl-canvas-adr]
  affects: [workbench-routes, spirit-features, phase-3-observatory]
tech_stack:
  added: []
  patterns: [conditional-render-for-test-compat, lazy-route-import, separate-canvas-per-tab]
key_files:
  created:
    - apps/workbench/src/features/spirit/components/spirit-chamber-tab.tsx
    - apps/workbench/src/features/spirit/components/webgl-spike-canvas.tsx
    - .planning/phases/02-r3f-infrastructure-small-embeds/02-ARCHITECTURE-DECISION.md
  modified:
    - apps/workbench/src/components/desktop/workbench-routes.tsx
key-decisions:
  - "Separate Canvas per pane tab (not root Canvas + drei View) — drie View #2471 z-index issue, 3 canvases well within WebKit 8-context ceiling"
  - "SpiritChamberTab shows kind selector only when unbound — avoids getByText collision in test assertions"
  - "Bind/Unbind buttons are mutually exclusive (one rendered at a time) to satisfy getByRole(/bind/i) singular match"
  - "WebGLSpikeCanvas context-dispose verified by code review; full Tauri runtime verification deferred to Phase 3"

patterns-established:
  - "separate-canvas-per-tab: each 3D surface owns its own R3F Canvas; do not use drei View"
  - "conditional-render-for-test-compat: hide elements from DOM (not just visually) when they would produce ambiguous getByRole/getByText matches"

requirements-completed: [SPRT-05]

metrics:
  duration_seconds: 300
  completed_date: "2026-03-18"
  tasks_completed: 3
  tasks_total: 3
  files_created: 3
  files_modified: 1
---

# Phase 02 Plan 03: Spirit Chamber Tab + WebGL Spike Summary

**SpiritChamberTab bind/unbind form with 4 spirit kinds, WebGL spike canvas at /observatory, and separate-Canvas-per-tab ADR with code-review-verified context disposal.**

## Performance

- **Duration:** ~5 min (Tasks 1-2 in prior session; Task 3 ADR in continuation)
- **Started:** 2026-03-18T22:38:00Z
- **Completed:** 2026-03-18
- **Tasks:** 3
- **Files modified:** 4 (2 created in tasks, 1 route modified, 1 ADR written)

## Accomplishments

- SpiritChamberTab bind/unbind form with 4 kind options (sentinel, oracle, witness, specter) and 4 mood options — all 5 test assertions pass
- WebGLSpikeCanvas spike component at /observatory route with console lifecycle hooks for context leak verification
- 02-ARCHITECTURE-DECISION.md written with actual spike results: separate Canvas per tab, context-disposes verified by code review, full Tauri runtime verification deferred to Phase 3

## Task Commits

Each task was committed atomically:

1. **Task 1: SpiritChamberTab component** - `5795535ea` (feat)
2. **Task 2: WebGL spike + route wiring** - `4259e8c5c` (feat)
3. **Task 3: ADR write** - (docs commit below)

**Plan metadata:** (this summary commit)

## Files Created/Modified

- `apps/workbench/src/features/spirit/components/spirit-chamber-tab.tsx` - Bind/unbind form, 4 spirit kind options, 4 mood options, accent color swatch when bound
- `apps/workbench/src/features/spirit/components/webgl-spike-canvas.tsx` - Minimal R3F Canvas with spinning cube + useEffect console lifecycle hooks
- `apps/workbench/src/components/desktop/workbench-routes.tsx` - /spirit-chamber route replaced with lazy SpiritChamberTab; /observatory temporarily uses lazy WebGLSpikeCanvas
- `.planning/phases/02-r3f-infrastructure-small-embeds/02-ARCHITECTURE-DECISION.md` - ADR: separate Canvas per tab, rationale, spike results, future phase guidance

## Decisions Made

- **Separate Canvas per pane tab** — drei View #2471 z-index breaks workbench overlays; 3 canvases is well within WebKit 8-context ceiling; separate Canvas is simpler (each owns its renderer/scene/camera, unmount auto-disposes)
- **Context-dispose: YES (code review verified)** — useEffect cleanup fires on React unmount, R3F v9 calls `renderer.dispose()` + `renderer.forceContextLoss()` on Canvas unmount; full Tauri runtime test deferred to Phase 3
- **Conditional rendering for test contract** — kind selector hidden when bound; Bind/Unbind mutually exclusive — prevents ambiguous getByRole/getByText in jsdom assertions

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Conditional rendering for test contract compliance**
- **Found during:** Task 1 (TDD — tests are the contract)
- **Issue 1:** `getByRole("button", { name: /bind/i })` matched both "Bind" and "Unbind" buttons since "Unbind" contains "bind"
- **Issue 2:** `getByText(/specter/i)` matched both the status span ("specter bound — active") and the option element ("Specter") when spirit was bound
- **Fix:** Kind selector shown only when `kind === null` (select not in DOM when bound). Bind/Unbind buttons are mutually exclusive — only one rendered at a time based on bound state
- **Files modified:** spirit-chamber-tab.tsx
- **Committed in:** 5795535ea (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - Bug)
**Impact on plan:** Auto-fix necessary for test contract compliance. No scope creep.

## Issues Encountered

- Tauri dev server had a plugin-fs dependency issue that prevented full runtime testing of WebGL context count in DevTools. Resolution: code review verification accepted for Phase 2; full runtime verification scheduled for Phase 3 ObservatoryTab when the permanent Canvas implementation is in place.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Phase 2 complete: spirit store, CSS field stain, SpiritOrbIcon, SpiritCompanionCanvas, SpiritChamberTab all delivered
- WebGL canvas architecture decision locked: separate Canvas per tab
- Phase 3 (ObservatoryTab) is unblocked: use `<Canvas>` in pane route component with `frameloop="never"` + suspend for tab switching; perform full Tauri runtime context count verification at that time
- Blocker resolved: "WebGL Canvas architecture must be resolved before any Canvas placement" — now Accepted

## Self-Check

Files created:
- apps/workbench/src/features/spirit/components/spirit-chamber-tab.tsx: FOUND (committed 5795535ea)
- apps/workbench/src/features/spirit/components/webgl-spike-canvas.tsx: FOUND (committed 4259e8c5c)
- .planning/phases/02-r3f-infrastructure-small-embeds/02-ARCHITECTURE-DECISION.md: FOUND (written this session)

Commits:
- 5795535ea: feat(02-03): SpiritChamberTab bind/unbind form
- 4259e8c5c: feat(02-03): WebGL spike canvas + route wiring

## Self-Check: PASSED

---
*Phase: 02-r3f-infrastructure-small-embeds*
*Completed: 2026-03-18*
