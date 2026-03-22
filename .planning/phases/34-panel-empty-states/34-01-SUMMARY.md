---
phase: 34-panel-empty-states
plan: "01"
subsystem: ui
tags: [react, observatory, hud, drawer-panels, empty-states, vitest, tdd]

requires:
  - phase: 31-drawer-panels
    provides: ExplainabilityDrawerPanel, MissionDrawerPanel, GhostMemoryDrawerPanel with empty state guards + data-testid attributes
  - phase: 33-drawer-chrome-glassmorphism
    provides: Drawer glassmorphism tokens (--hud-drawer-bg, --hud-text-muted) and panel header bar

provides:
  - Structured empty state in ExplainabilityDrawerPanel showing STATION / PRESSURE LANES / ANOMALIES section placeholders + E-key hint
  - Structured empty state in MissionDrawerPanel showing BRIEFING / OBJECTIVES / NARRATIVE section placeholders + command palette hint
  - Explanatory empty state in GhostMemoryDrawerPanel with ghost memory purpose description and trace appearance trigger text
  - 3 new vitest tests (one per panel) verifying section headers and hint text

affects: [future-drawer-panel-work, observatory-analyst-ux]

tech-stack:
  added: []
  patterns:
    - "Structured empty states mirror populated panel section layout with muted placeholder content"
    - "Section header labels uppercase literal in JSX (textTransform visual-only in jsdom) so textContent assertions work without case coercion"
    - "Hint text pinned to panel bottom via flex spacer + borderTop separator"

key-files:
  created: []
  modified:
    - apps/workbench/src/features/observatory/components/hud/panels/ExplainabilityDrawerPanel.tsx
    - apps/workbench/src/features/observatory/components/hud/panels/MissionDrawerPanel.tsx
    - apps/workbench/src/features/observatory/components/hud/panels/GhostMemoryDrawerPanel.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-drawer-panels.test.tsx

key-decisions:
  - "EMP-01/EMP-02: Section header labels rendered as literal uppercase strings in JSX rather than relying on CSS textTransform so vitest textContent assertions work without .toUpperCase() coercion"
  - "EMP-03: Ghost Memory empty state uses explanatory paragraph approach (not section headers) matching its informational rather than structural nature"
  - "Hint row uses flex spacer + top border separator to pin naturally to the panel bottom without absolute positioning"

patterns-established:
  - "Panel empty state = mirrors populated section layout with muted/ghost placeholders + bottom hint"
  - "Uppercase section header literal strings in JSX for testability"

requirements-completed: [EMP-01, EMP-02, EMP-03]

duration: 2min
completed: 2026-03-22
---

# Phase 34 Plan 01: Panel Empty States Summary

**Replaced single-line italic fallback messages in 3 observatory drawer panels with structured placeholder layouts previewing each panel's section hierarchy and contextual operator hints.**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-22T04:09:14Z
- **Completed:** 2026-03-22T04:10:37Z
- **Tasks:** 1 (TDD — 2 commits: RED test + GREEN impl)
- **Files modified:** 4

## Accomplishments

- ExplainabilityDrawerPanel: STATION / PRESSURE LANES / ANOMALIES section skeleton with muted bars and "Click a station or press E while hovering" hint
- MissionDrawerPanel: BRIEFING / OBJECTIVES / NARRATIVE section skeleton with hollow circle rows and "Start a mission from the command palette" hint
- GhostMemoryDrawerPanel: explanatory two-paragraph description of ghost memory purpose + trace trigger conditions, replacing bare "No prior findings or receipts" line
- 21 tests pass (18 prior + 3 new), zero regressions

## Task Commits

1. **Task 1 (RED): Add failing tests** - `a7943acd1` (test)
2. **Task 1 (GREEN): Implement structured empty states** - `e6ade7f19` (feat)

## Files Created/Modified

- `apps/workbench/src/features/observatory/components/hud/panels/ExplainabilityDrawerPanel.tsx` — replaced centered italic with STATION/PRESSURE LANES/ANOMALIES column layout + hint row
- `apps/workbench/src/features/observatory/components/hud/panels/MissionDrawerPanel.tsx` — replaced centered italic with BRIEFING/OBJECTIVES/NARRATIVE column layout + hint row
- `apps/workbench/src/features/observatory/components/hud/panels/GhostMemoryDrawerPanel.tsx` — replaced "No prior findings or receipts" with two-paragraph explanatory empty state
- `apps/workbench/src/features/observatory/__tests__/observatory-drawer-panels.test.tsx` — added 3 new test cases (one "e." per describe block)

## Decisions Made

- Uppercase section header labels rendered as literal strings in JSX so vitest `textContent` assertions work without `.toUpperCase()` coercion (CSS `textTransform` is visual-only in jsdom)
- Ghost Memory empty state uses descriptive paragraphs rather than section skeleton because the panel has no fixed sections in its populated state
- Bottom hint row uses `flex: 1` spacer + `borderTop: 1px solid rgba(255,255,255,0.04)` separator, consistent with the probe button separator pattern in ExplainabilityDrawerPanel

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- All 3 EMP requirements satisfied; phase 34 is the final phase in v8.0 milestone
- Observatory panels now present production-quality empty states from the first frame

---

## Self-Check

Checking files exist and commits are present...

## Self-Check: PASSED

- FOUND: ExplainabilityDrawerPanel.tsx
- FOUND: MissionDrawerPanel.tsx
- FOUND: GhostMemoryDrawerPanel.tsx
- FOUND: observatory-drawer-panels.test.tsx
- FOUND: 34-01-SUMMARY.md
- FOUND: RED commit a7943acd1
- FOUND: GREEN commit e6ade7f19
