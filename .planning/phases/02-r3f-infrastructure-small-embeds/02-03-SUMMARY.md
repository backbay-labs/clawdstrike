---
phase: "02"
plan: "03"
subsystem: spirit
status: checkpoint-paused
tags: [spirit, spirit-chamber, webgl, r3f, routes]
dependency_graph:
  requires: [02-01]
  provides: [spirit-chamber-tab, webgl-spike-canvas, spirit-chamber-route]
  affects: [workbench-routes, spirit-features]
tech_stack:
  added: []
  patterns: [conditional-render-for-test-compat, lazy-route-import]
key_files:
  created:
    - apps/workbench/src/features/spirit/components/spirit-chamber-tab.tsx
    - apps/workbench/src/features/spirit/components/webgl-spike-canvas.tsx
  modified:
    - apps/workbench/src/components/desktop/workbench-routes.tsx
decisions:
  - SpiritChamberTab shows kind selector only when unbound (avoids option-text collision in getByText assertions)
  - Bind/Unbind buttons are mutually exclusive (Bind shown when unbound, Unbind when bound) to satisfy getByRole(/bind/i) singular match
  - WebGLSpikeCanvas placed at /observatory route temporarily for Phase 2 spike verification
metrics:
  duration_seconds: 253
  completed_date: "2026-03-18"
  tasks_completed: 2
  tasks_total: 3
  files_created: 2
  files_modified: 1
---

# Phase 02 Plan 03: Spirit Chamber Tab + WebGL Spike Summary

**One-liner:** SpiritChamberTab bind/unbind form with 4 spirit kinds, WebGL spike canvas for context leak verification at /observatory route.

**Status:** PAUSED at Task 3 (checkpoint:human-verify) — WebGL spike must be run in the live app to observe context disposal behavior before the ADR can be written.

## Tasks Completed

| Task | Name | Commit | Files |
| ---- | ---- | ------ | ----- |
| 1 | SpiritChamberTab component | 5795535ea | spirit-chamber-tab.tsx (created) |
| 2 | WebGL spike + route wiring | 4259e8c5c | webgl-spike-canvas.tsx (created), workbench-routes.tsx (modified) |

## Task 3: Pending Human Verification

**Blocked on:** Human must run the dev server, open the /observatory route, mount/unmount the WebGLSpikeCanvas pane tab 3 times, and observe console logs to verify WebGL context disposal. Results must be recorded before the ADR can be written.

**After verification:** Claude writes `.planning/phases/02-r3f-infrastructure-small-embeds/02-ARCHITECTURE-DECISION.md` with actual spike results.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Conditional rendering for test contract compliance**
- **Found during:** Task 1 (TDD — tests are the contract)
- **Issue 1:** `getByRole("button", { name: /bind/i })` matched both "Bind" and "Unbind" buttons since "Unbind" contains "bind"
- **Issue 2:** `getByText(/specter/i)` matched both the status span ("specter bound — active") and the option element ("Specter") when spirit was bound
- **Fix:** Kind selector shown only when `kind === null` (select not in DOM when bound). Bind/Unbind buttons are mutually exclusive — only one rendered at a time based on bound state
- **Files modified:** spirit-chamber-tab.tsx
- **Commit:** 5795535ea

## Self-Check

Files created:
- apps/workbench/src/features/spirit/components/spirit-chamber-tab.tsx: FOUND
- apps/workbench/src/features/spirit/components/webgl-spike-canvas.tsx: FOUND

Commits:
- 5795535ea: feat(02-03): SpiritChamberTab bind/unbind form
- 4259e8c5c: feat(02-03): WebGL spike canvas + route wiring
