---
phase: 01-spirit-observatory-state-foundation
plan: "04"
subsystem: spirit-css-wiring
tags: [css, spirit, hunt, panel, gap-closure]
dependency_graph:
  requires: ["01-01", "01-02", "01-03"]
  provides: ["SPRT-01-complete", "SPRT-02-complete"]
  affects: ["sidebar-panel", "pane-root", "bottom-pane", "hunt-layout"]
tech_stack:
  added: []
  patterns:
    - spirit-field-stain-host CSS class on panel container root elements
    - inline style borderColor with CSS var for dynamic spirit accent
key_files:
  modified:
    - apps/workbench/src/features/activity-bar/components/sidebar-panel.tsx
    - apps/workbench/src/features/panes/pane-root.tsx
    - apps/workbench/src/features/bottom-pane/bottom-pane.tsx
    - apps/workbench/src/components/workbench/hunt/hunt-layout.tsx
  created: []
decisions:
  - "Inline style borderColor used for --spirit-accent in HuntLayout (CSS vars are dynamic; Tailwind JIT cannot evaluate at build time)"
  - "spirit-field-stain-host appended to existing className strings without cn() — matches each file's existing bare-string pattern"
metrics:
  duration: ~3min
  completed: "2026-03-18"
  tasks_completed: 2
  files_modified: 4
---

# Phase 01 Plan 04: CSS Gap Closure — Spirit Field Stain Host + Hunt Accent Summary

**One-liner:** Wired `spirit-field-stain-host` to three panel containers and `var(--spirit-accent)` border to HuntLayout, closing SPRT-01 and SPRT-02 gaps and bringing Phase 1 verification to 4/4.

## What Was Built

Two targeted CSS wiring fixes to close the gap between the injector (SpiritFieldInjector) and the consumers (panel surfaces + hunt chrome):

**Gap 1 (SPRT-01) — Spirit field stain on panel containers:**
The `.spirit-field-stain-host` class was defined in `globals.css` with the correct `::before` radial-gradient overlay but applied to zero panel containers. Applied to:
- `sidebar-panel.tsx` — root `<div>` (commit 79f0b1834)
- `pane-root.tsx` — `PaneRoot` outer `<div>` (commit 79f0b1834)
- `bottom-pane.tsx` — root `<section>` (commit 79f0b1834)

**Gap 2 (SPRT-02) — Spirit accent border on hunt chrome:**
`--spirit-accent` was injected into `:root` by `SpiritFieldInjector` but consumed by no components. Applied to `HuntLayout` outer div via:
- `border border-transparent` Tailwind classes to establish border layout slot (no reflow)
- `style={{ borderColor: "var(--spirit-accent)" }}` inline style for dynamic CSS var
- `transition-colors duration-[400ms] ease-out` matching UI-SPEC 400ms fade spec
(commit 287b8d753)

## Verification Results

```
Gap 1 closed — spirit-field-stain-host present in all three panel files
Gap 2 closed — spirit-accent consumed in hunt-layout.tsx
TypeScript — no new errors introduced (pre-existing unrelated errors unchanged)
```

## Decisions Made

- **Inline style for CSS var:** `var(--spirit-accent)` is dynamic; Tailwind JIT cannot evaluate it at build time. `style={{ borderColor: "var(--spirit-accent)" }}` is the correct pattern, consistent with `sidebar-panel.tsx` already using `style={{ width: ... }}`.
- **No cn() in sidebar-panel:** The existing codebase uses bare string className in these files; matched that pattern to minimize diff surface.
- **border-transparent slot:** `border border-transparent` establishes the border layout slot so the element does not reflow when spirit binds and accent appears.

## Deviations from Plan

None — plan executed exactly as written. All four files modified as specified. No new imports, no logic changes.

## Self-Check

Files exist:
- apps/workbench/src/features/activity-bar/components/sidebar-panel.tsx — FOUND
- apps/workbench/src/features/panes/pane-root.tsx — FOUND
- apps/workbench/src/features/bottom-pane/bottom-pane.tsx — FOUND
- apps/workbench/src/components/workbench/hunt/hunt-layout.tsx — FOUND

Commits exist:
- 79f0b1834 — FOUND (Task 1)
- 287b8d753 — FOUND (Task 2)

## Self-Check: PASSED
