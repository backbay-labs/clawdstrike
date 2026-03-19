---
phase: 05-spirit-reactivity-editor-integration
plan: "01"
subsystem: spirit
tags: [spirit, mood, reactivity, zustand, debounce, tdd]
dependency_graph:
  requires: []
  provides: [deriveSpiritMood, SpiritMoodReactor]
  affects: [desktop-layout, spirit-store, observatory-store, multi-policy-store]
tech_stack:
  added: []
  patterns: [zero-render-component, debounced-useEffect, pure-derivation-function, tdd-red-green]
key_files:
  created:
    - apps/workbench/src/features/spirit/mood.ts
    - apps/workbench/src/features/spirit/components/spirit-mood-reactor.tsx
    - apps/workbench/src/features/spirit/__tests__/spirit-mood-reactor.test.tsx
  modified:
    - apps/workbench/src/components/desktop/desktop-layout.tsx
decisions:
  - Pure deriveSpiritMood function with dormant > alert > active > idle priority order
  - 500ms debounce via useRef<setTimeout> prevents mood thrashing on rapid lint toggles
  - SpiritMoodReactor mounts in DesktopLayout immediately after SpiritFieldInjector
  - hasLintErrors derived from validation.errors.length > 0 across all policy tabs
  - probeActive derived from seamSummary.activeProbes > 0 in observatory-store
metrics:
  duration: "148s (~2m)"
  completed_date: "2026-03-19"
  tasks_completed: 2
  files_changed: 4
---

# Phase 5 Plan 01: Spirit Mood Reactor Summary

**One-liner:** Automatic spirit mood derivation via pure `deriveSpiritMood` mapping lint-error and probe-active signals to SpiritMood, debounced 500ms via `SpiritMoodReactor` null-render component mounted in DesktopLayout.

## What Was Built

### `mood.ts` — Pure derivation function

Exports `SpiritMoodSignals` interface and `deriveSpiritMood` function with priority ordering:

1. `kind === null` → `"dormant"`
2. `hasLintErrors` → `"alert"`
3. `probeActive` → `"active"`
4. otherwise → `"idle"`

### `SpiritMoodReactor` — Zero-render reactor component

Subscribes to three stores:
- `useSpiritStore.use.kind()` — for dormant detection
- `useObservatoryStore.use.seamSummary().activeProbes` — probe signal
- `useMultiPolicy().tabs` — lint error scan

Derives mood via `deriveSpiritMood`, debounces 500ms using `useRef<setTimeout>`, calls `setMood` on spirit-store. Returns `null`.

### DesktopLayout mount

`<SpiritMoodReactor />` inserted immediately after `<SpiritFieldInjector />` in the zero-render head of the layout.

## Tasks Completed

| Task | Name | Commit | Files |
| ---- | ---- | ------ | ----- |
| 1 (TDD RED) | Failing tests for deriveSpiritMood | e14d57bcf | spirit-mood-reactor.test.tsx |
| 1 (TDD GREEN) | deriveSpiritMood implementation | 4f0fde744 | mood.ts |
| 2 | SpiritMoodReactor + DesktopLayout | 486067068 | spirit-mood-reactor.tsx, desktop-layout.tsx |

## Verification Results

- 6/6 test cases pass for `deriveSpiritMood`
- TypeScript: 0 new errors introduced (18 pre-existing errors in unrelated files)
- `SpiritMoodReactor` confirmed in DesktopLayout: import line 22, JSX line 82

## Deviations from Plan

None — plan executed exactly as written. TDD flow followed: RED commit (e14d57bcf), GREEN commit (4f0fde744).

## Self-Check: PASSED

- [x] `apps/workbench/src/features/spirit/mood.ts` created
- [x] `apps/workbench/src/features/spirit/components/spirit-mood-reactor.tsx` created
- [x] `apps/workbench/src/features/spirit/__tests__/spirit-mood-reactor.test.tsx` created
- [x] `apps/workbench/src/components/desktop/desktop-layout.tsx` modified
- [x] All 3 feature commits exist: e14d57bcf, 4f0fde744, 486067068
