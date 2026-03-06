# Dispatch Phase 1 Engineering Breakdown

## Summary

This document turns Phase 1 of the dispatch UX plan into concrete implementation work against the current `apps/terminal` codebase.

Status:

- planned engineering breakdown
- not yet implemented unless a later PR explicitly references this doc

Phase 1 goal:

- replace "submit prompt, block, then jump to result" with "launch a managed run, transition to run detail, keep the TUI in control"

Current behavior is concentrated in:

- [app.ts](../src/tui/app.ts)
- [main.ts](../src/tui/screens/main.ts)
- [result.ts](../src/tui/screens/result.ts)
- [tools/index.ts](../src/tools/index.ts)

The largest constraint is that current dispatch is synchronous from the TUI point of view:

- `submitPrompt()` calls `executeTool("dispatch")`
- the TUI blocks on the promise
- `lastResult` is populated only at the end
- the UI jumps to `result`

Phase 1 should change that interaction model without overcommitting to PTY streaming or tmux integration yet.

## 1. Data Structures

## Current State

Current TUI dispatch state is too thin:

- `AppState.lastResult` stores only the final result snapshot
- `AppState.activeRuns` is just a count derived from telemetry
- there is no first-class run list or selected run
- there is no dispatch sheet state

Relevant files:

- [types.ts](../src/tui/types.ts)
- [app.ts](../src/tui/app.ts)

## Recommended New Types

Add to [types.ts](../src/tui/types.ts):

### `DispatchExecutionMode`

```ts
type DispatchExecutionMode = "managed" | "attach" | "external"
```

Phase 1 only implements `managed`, but the type should be introduced now so the dispatch sheet model does not need to be redesigned later.

### `RunPhase`

```ts
type RunPhase =
  | "draft"
  | "launching"
  | "routing"
  | "executing"
  | "verifying"
  | "review_ready"
  | "completed"
  | "failed"
  | "canceled"
```

This should stay deliberately coarser than future PTY-level state.

### `RunEvent`

```ts
interface RunEvent {
  timestamp: string
  kind: "status" | "log" | "warning" | "error"
  message: string
}
```

Phase 1 should use normalized events, not raw PTY bytes.

### `RunRecord`

```ts
interface RunRecord {
  id: string
  title: string
  prompt: string
  action: "dispatch" | "speculate"
  agentId: string
  agentLabel: string
  mode: DispatchExecutionMode
  phase: RunPhase
  createdAt: string
  updatedAt: string
  workcellId: string | null
  worktreePath: string | null
  routing: DispatchResultInfo["routing"] | null
  execution: DispatchResultInfo["execution"] | null
  verification: DispatchResultInfo["verification"] | null
  result: DispatchResultInfo | null
  error: string | null
  events: RunEvent[]
}
```

### `RunListState`

```ts
interface RunListState {
  entries: RunRecord[]
  selectedRunId: string | null
}
```

Even if the `Runs` screen lands in Phase 2, the state should exist in Phase 1 so the run detail screen has a backing collection instead of a singleton.

### `DispatchSheetState`

```ts
interface DispatchSheetState {
  open: boolean
  prompt: string
  action: "dispatch" | "speculate"
  mode: DispatchExecutionMode
  agentIndex: number
  focusedField: 0 | 1 | 2 | 3
  error: string | null
}
```

This should live in `AppState`, not as local screen state, because launching and canceling the sheet changes global navigation.

## AppState Changes

Extend [AppState](../src/tui/types.ts) with:

- `dispatchSheet: DispatchSheetState`
- `runs: RunListState`
- `activeRunId: string | null`

Keep `lastResult` in Phase 1 as a compatibility bridge for the existing result screen.

Do not remove `lastResult` yet. Populate both `RunRecord.result` and `lastResult` until result/review routing is moved cleanly onto run records.

## InputMode Changes

Add:

- `dispatch-sheet`
- `run-detail`

Do not add `runs` yet unless it actually lands in the same PR slice.

## AppController Changes

Extend [AppController](../src/tui/types.ts) with methods the screens will need:

- `openDispatchSheet(action: "dispatch" | "speculate"): void`
- `launchDispatchSheet(): void`
- `closeDispatchSheet(): void`
- `openRun(runId: string): void`
- `cancelRun(runId: string): void`

Phase 1 does not need attach/external methods yet.

## 2. Screens And Components

## Current State

Today:

- the home screen prompt submits directly into `submitPrompt()`
- the `commands` overlay already demonstrates a shared-screen overlay pattern
- the only post-dispatch surface is [result.ts](../src/tui/screens/result.ts)

## Phase 1 Screen Work

### Home Screen

Update [main.ts](../src/tui/screens/main.ts):

- `Enter` on a non-empty prompt should open dispatch sheet instead of directly dispatching
- `d` and `s` should open the sheet with preselected action, not launch immediately
- focus-aware help text should mention `Enter dispatch sheet`

### Dispatch Sheet Overlay

Recommended implementation:

- keep the overlay in [main.ts](../src/tui/screens/main.ts), similar to the existing `commands` overlay
- drive it with `inputMode: "dispatch-sheet"`

Reason:

- lowest surface-area change
- avoids inventing a new standalone screen for a lightweight confirmation step
- matches the current home-centered interaction model

The sheet should show:

- prompt preview
- action
- agent
- execution mode
- confirm/cancel hints

### Run Detail Screen

Add a new supported screen:

- `apps/terminal/src/tui/screens/run-detail.ts`

This screen should replace the immediate jump to `result`.

Required regions:

- header: run id, agent, phase, mode
- summary card: prompt, routing, workcell/worktree if known
- live events card: normalized event list
- status card: verification/result summary as it becomes available
- footer actions: back, cancel, review

### Components To Reuse

Reuse existing primitives:

- [box.ts](../src/tui/components/box.ts)
- [split-pane.ts](../src/tui/components/split-pane.ts)
- [surface-header.ts](../src/tui/components/surface-header.ts)
- [scrollable-list.ts](../src/tui/components/scrollable-list.ts)

Do not build a raw PTY viewer in Phase 1.

For the events pane, use a simple scrollable text list backed by `RunEvent[]`.

## Result Screen Compatibility

Keep [result.ts](../src/tui/screens/result.ts) in Phase 1.

Change the route into it:

- `Run Detail` should be the default landing screen
- `review` action from `Run Detail` should open `result`

This lets Phase 1 preserve existing value while changing dispatch flow.

## 3. Dispatcher And Runtime Plumbing

## Current State

Current flow in [app.ts](../src/tui/app.ts):

1. `submitPrompt()` reads `promptBuffer`
2. calls `executeTool("dispatch")`
3. waits for completion
4. stores `lastResult`
5. clears prompt and switches to `result`

That is the core behavior to replace.

## Recommended Runtime Layer

Add a small TUI-specific runtime module:

- `apps/terminal/src/tui/runs.ts`

This module should own:

- run creation
- run state updates
- background promise execution
- event appends
- compatibility mapping into `DispatchResultInfo`

## Why A TUI Runtime Layer

Do not bury run lifecycle logic inside `app.ts`.

`app.ts` should orchestrate screens and shared app state, not own detailed run transitions.

## Phase 1 Runtime Strategy

Use the existing tool layer for real execution, but run it in the background.

Concrete approach:

1. create `RunRecord`
2. set phase to `launching`
3. push a `RunEvent` like `Dispatch requested`
4. transition TUI to `run-detail`
5. start an async background task that calls `executeTool("dispatch")`
6. update the run as milestones are reached
7. when complete, set `lastResult` for compatibility and mark run `review_ready` or `failed`

## Important Constraint

`executeTool("dispatch")` currently returns only when done.

That means Phase 1 cannot offer true streaming execution logs without additional infrastructure.

Pragmatic Phase 1 answer:

- do not block Phase 1 on PTY streaming
- emit normalized lifecycle events from the TUI runtime itself
- show meaningful phases and completion data

Suggested lifecycle events:

- `Dispatch requested`
- `Routing task`
- `Acquiring workcell`
- `Running agent`
- `Running verification`
- `Run completed`
- `Run failed: ...`

## Optional Low-Risk Improvement

If you want slightly better fidelity without changing adapter APIs yet, expose more internal milestones from [tools/index.ts](../src/tools/index.ts) via a callback or event sink.

Example:

```ts
interface ToolContext {
  cwd: string
  projectId: string
  taskId?: string
  onEvent?: (event: DispatchToolEvent) => void
}
```

Then `dispatchTool.handler()` can emit:

- routing started
- workcell acquired
- execution finished
- verification finished

That is a better Phase 1 fit than PTY tailing.

## Workcell And Telemetry Plumbing

Current code already has the right lower-level pieces:

- workcell allocation in [tools/index.ts](../src/tools/index.ts)
- execution in [dispatcher/index.ts](../src/dispatcher/index.ts)
- rollout tracking in [telemetry/index.ts](../src/telemetry/index.ts)

Phase 1 should reuse those rather than introducing a second execution engine.

## Concrete App Changes

In [app.ts](../src/tui/app.ts):

- replace the current body of `submitPrompt()` with:
  - open sheet if not already open
  - otherwise call `launchDispatchSheet()`
- add `launchManagedRun()` that delegates to `tui/runs.ts`
- stop setting `inputMode = "result"` directly on launch completion
- set `inputMode = "run-detail"` when launch starts

## 4. Tests

## Existing Tests To Extend

### [tui-screens.test.ts](../test/tui-screens.test.ts)

Add:

- `Enter` on prompt opens dispatch sheet instead of immediate execution
- `d` and `s` open the sheet with correct action preselected
- dispatch sheet mode cycling
- cancel returns to main without clearing prompt
- run detail renders launch / running / review-ready states

### [tui-app.test.ts](../test/tui-app.test.ts)

Add:

- launching a managed run creates a `RunRecord`
- background completion updates `activeRunId`
- failed dispatch populates run error and does not crash the app
- completion populates both `RunRecord.result` and compatibility `lastResult`

### New Test File

Add:

- `apps/terminal/test/tui-runs.test.ts`

Use it for:

- run state transitions
- event append behavior
- launch-to-complete lifecycle
- compatibility mapping to `DispatchResultInfo`

## Test Strategy

Phase 1 does not need live PTY or tmux tests.

Mock:

- `executeTool`
- telemetry where needed
- workcell metadata only through tool results, not direct FS setup

## 5. Milestone PR Slices

Keep Phase 1 split into narrow, reviewable PRs.

## PR 1: Run State Scaffolding

Scope:

- add new TUI types
- add `dispatchSheet`, `runs`, and `activeRunId` to app state
- add `run-detail` input mode and screen registry stub

No behavior change beyond scaffolding.

## PR 2: Dispatch Sheet UX

Scope:

- main-screen overlay for dispatch sheet
- reroute `Enter`, `d`, and `s` through the sheet
- cancel / confirm behavior

Still no background run execution in this slice.

## PR 3: Managed Run Runtime

Scope:

- add `tui/runs.ts`
- create `RunRecord`
- background execute `dispatch`
- transition into run detail
- populate lifecycle events

This is the behavioral core of Phase 1.

## PR 4: Run Detail Screen

Scope:

- render active run state
- show normalized events and execution summary
- add back / cancel / review actions

Keep the screen read-only except for cancel and navigation.

## PR 5: Result Compatibility And Cleanup

Scope:

- route review action from run detail into existing result screen
- keep `lastResult` compatibility path
- remove direct `submitPrompt() -> result` jump
- tighten status-bar active-run behavior

## Suggested Order Of Merge

1. PR 1
2. PR 2
3. PR 3
4. PR 4
5. PR 5

## Recommended Phase 1 Cut Line

If time compresses, do not cut:

- dispatch sheet
- managed run records
- run detail screen

Cut instead:

- richer event fidelity
- refined result handoff polish
- any early tmux or external-terminal work

## Bottom Line

Phase 1 should ship a managed-run control flow, not a terminal-multiplexing experiment.

The concrete implementation path is:

1. add run state
2. add dispatch sheet
3. background the current dispatch tool
4. land a real run detail screen
5. keep `result` as a compatibility review surface until Phase 2
