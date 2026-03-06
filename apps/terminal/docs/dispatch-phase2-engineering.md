# Dispatch Phase 2 Engineering Breakdown

## Summary

Phase 2 turns managed runs into a navigable system rather than a single active detail view.

Status:

- planned engineering breakdown
- assumes Phase 1 exists first

Goal:

- add a `Runs` index and make `review_ready` completion a first-class workflow

Phase 2 builds directly on the Phase 1 run model and run detail screen.

## 1. Data Structures

## Current Expected Starting Point

After Phase 1, the TUI should already have:

- `RunRecord`
- `RunListState`
- `activeRunId`
- `run-detail`

Phase 2 should extend those structures, not replace them.

## Required Additions

Add to the run model:

- `reviewReady: boolean` or equivalent derived state from `phase`
- `completedAt: string | null`
- `reviewRoute: "result" | "diff" | "report" | null`

Recommended approach:

- keep `review_ready` as a `RunPhase`
- add `completedAt`
- derive `reviewRoute` from `result` / `verification` data rather than persisting too much policy into state

Extend `RunListState` with:

- `filter: "active" | "review_ready" | "all"`
- `list: ListViewport`

That gives the `Runs` surface a proper navigation model using the same primitives already used by audit/history/hunt screens.

## AppState Changes

Add:

- `runsScreenFilter`

or, preferably, keep it inside `RunListState` to avoid splitting screen state across objects.

Add `InputMode`:

- `runs`

## 2. Screens And Components

## New Screen

Add:

- `apps/terminal/src/tui/screens/runs.ts`

This should be a supported screen.

## Runs Screen Layout

Recommended layout:

- left pane: active/recent run list
- right pane: selected run summary

Left pane fields:

- short title
- agent
- phase
- mode
- last activity

Right pane fields:

- full prompt
- routing summary
- execution/verification status
- review guidance
- actions

Recommended actions:

- `Enter` open selected run detail
- `r` open review if run is `review_ready`
- `c` cancel if run is active
- `f` cycle filter
- `Esc` back

## Existing Screens To Update

### Main Screen

Update [main.ts](../src/tui/screens/main.ts):

- add a visible path to the `Runs` surface
- do not overload the home screen with run lists
- keep the home screen as command center, not backlog manager

### Run Detail

Update `run-detail` from Phase 1:

- add action to open `Runs`
- when a run reaches `review_ready`, reflect that in footer affordances

### Result Screen

Keep [result.ts](../src/tui/screens/result.ts), but Phase 2 should stop treating it as the default landing place.

It becomes a review target chosen from:

- run detail
- runs screen

## Components To Reuse

Reuse:

- [scrollable-list.ts](../src/tui/components/scrollable-list.ts)
- [split-pane.ts](../src/tui/components/split-pane.ts)
- [box.ts](../src/tui/components/box.ts)

No new layout system is needed.

## 3. Dispatcher And Runtime Plumbing

## Current Runtime Need

Phase 2 does not need a new execution engine.

It needs:

- persistent run collection updates
- selection and reopen semantics
- review handoff rules

## Runtime Changes

In the TUI run runtime module from Phase 1:

- preserve completed runs in `RunListState.entries`
- mark runs `review_ready` when:
  - execution succeeded
  - and verification is done
  - regardless of whether gates passed cleanly, because failed gates still require review

Recommended rule:

- `completed` means operationally finished
- `review_ready` means finished and awaiting operator review

For TUI UX, `review_ready` is usually the better end state than `completed`.

## Telemetry Integration

Current `showRuns()` reads `Telemetry.getActive()` outside the main TUI flow in [app.ts](../src/tui/app.ts).

Phase 2 should stop depending on that external "rollouts" view for primary run navigation.

Instead:

- keep telemetry as backend truth
- use TUI run state as the primary UI model

Later, if needed, TUI runs can be hydrated from telemetry snapshots.

## Review Handoff Rules

When a run finishes:

- do not force-open result if the user is elsewhere
- mark run `review_ready`
- show status bar signal and/or home summary signal

When user opens review:

- route to `result` first in Phase 2
- preserve space for later diff-first or gate-first flows

## 4. Tests

Add or extend:

- [tui-screens.test.ts](../test/tui-screens.test.ts)
  - runs screen rendering
  - filter cycling
  - opening run detail
  - opening result from review-ready run
- `tui-runs.test.ts`
  - run enters `review_ready`
  - run remains reopenable after completion
  - status bar active count stays consistent

Add app-level tests:

- if user leaves run detail while run executes, completion does not hijack navigation
- completed run appears in runs list

## 5. Milestone PR Slices

### PR 1

- add `runs` input mode
- add `RunListState` filter/list state
- add screen registry entry

### PR 2

- implement `runs.ts`
- add list/detail rendering
- support open and cancel actions

### PR 3

- wire review-ready transitions into TUI run runtime
- update run detail and home/status summary

### PR 4

- route review from runs/detail into existing result screen
- remove any remaining direct assumptions that result is the only post-dispatch surface

## Recommended Cut Line

Do not cut:

- runs screen
- reopen flow
- review-ready state

Cut first:

- extra sorting/grouping niceties
- richer summary cards
- speculative run grouping

## Bottom Line

Phase 2 makes managed dispatch operationally usable:

- multiple runs can coexist
- finished work can be reopened
- review becomes explicit rather than incidental
