# Dispatch Phase 3 Engineering Breakdown

## Summary

Phase 3 adds `attach here` as a first-class interactive mode on top of the managed run model.

Status:

- planned engineering breakdown
- depends on the managed run model from earlier phases

Goal:

- let the user temporarily hand the current terminal to a run PTY and then return to ClawdStrike cleanly

This phase should not introduce tmux or external terminal complexity yet.

## 1. Data Structures

Extend the run model with attachment state:

- `attached: boolean`
- `attachState: "detached" | "attaching" | "attached" | "returning"`
- `ptySessionId: string | null`
- `canAttach: boolean`

Do not store raw PTY transcript in core run state yet unless it is already needed by run detail.

If log transcript is needed, keep it bounded:

- `ptyTail: string[]`

not an unbounded buffer.

## Input And Screen State

No new top-level screen is required if attach is implemented as a handoff from `run-detail`.

But the app needs:

- a current attached run id
- a way to suspend normal TUI input handling while PTY control is active

Recommended app-level fields:

- `attachedRunId: string | null`
- `ptyHandoffActive: boolean`

## 2. Screens And Components

## Run Detail

This is the primary Phase 3 surface.

Add to `run-detail`:

- `a` attach when attach is available
- visible attach eligibility state
- a short explanation when attach is unavailable

Recommended footer actions:

- `a` attach
- `r` review
- `c` cancel
- `b` back

## Pre-Handoff Banner

Before attaching, show a small confirmation banner or sheet:

- which run is being attached
- detach instructions
- warning that terminal control is about to change

Example:

```text
Attach To Run

Run: #128 hushd reconnect investigation
Mode: managed -> attach
Detach: Ctrl+] or the agent's detach command

[Enter attach] [Esc cancel]
```

This can be implemented as a run-detail overlay instead of a new standalone screen.

## Post-Detach Return

After detach:

- restore alternate screen
- restore cursor mode
- restore input handlers
- reopen the same run detail screen

This return flow is the actual product value of Phase 3.

## 3. Dispatcher And Runtime Plumbing

## Core Requirement

Phase 3 needs a real PTY/session abstraction.

Do not fake this by:

- trying to render PTY directly inside the main TUI layout
- opening a second, unrelated process without run identity

## Recommended Runtime Layer

Add a narrow PTY/session module, for example:

- `apps/terminal/src/tui/pty.ts`

Responsibilities:

- spawn attachable session if not already present
- attach current terminal streams to that session
- detach cleanly
- report terminal lifecycle events back to the TUI run runtime

## Run Runtime Changes

The TUI run runtime should own:

- whether a run has an attachable session
- whether the current run is attached
- attach/detach events

The PTY module should not own run orchestration policy.

## Adapter/Dispatcher Constraint

Current dispatch uses the synchronous tool layer, which returns after execution completes.

That is not enough for Phase 3.

Phase 3 therefore likely requires one of these shifts:

1. a lower-level execution path beneath `executeTool("dispatch")`
2. a dispatcher mode that can spawn and retain an interactive process/session handle

Recommended direction:

- add a dedicated execution path for managed interactive runs beneath the TUI runtime
- keep `executeTool("dispatch")` as the high-level convenience path for non-interactive flows

Do not contort the existing tool API into being both synchronous summary API and interactive session manager.

## Cleanup Requirements

Attachment must cooperate with the existing TUI cleanup code in [app.ts](../src/tui/app.ts):

- reconnect timers
- cursor restoration
- alt-screen restoration
- input teardown

That means attach/detach needs explicit lifecycle hooks, not ad hoc `stdin` swapping.

## 4. Tests

Add:

- PTY attach state-machine tests
- detach returns to run-detail tests
- cleanup while attached tests
- resize propagation tests if the PTY layer supports resize

Screen-level tests:

- attach action visible only when attachable
- pre-handoff banner behavior
- attach unavailable messaging

Dogfood tests:

- attach to a real run
- detach without losing TUI control
- attached run completion returns to review path

## 5. Milestone PR Slices

### PR 1

- add run attachment fields
- add run detail affordances and disabled states

### PR 2

- add PTY/session abstraction
- implement attach/detach runtime flow

### PR 3

- integrate attach into run detail
- restore TUI state after detach

### PR 4

- add cleanup, resize, and failure-path hardening

## Recommended Cut Line

Do not cut:

- reliable detach/return
- cleanup correctness

Cut first:

- transcript persistence
- advanced resize/mouse behavior
- attach from multiple entry points besides run detail

## Bottom Line

Phase 3 should add interactive execution without changing the product center of gravity.

The user still comes back to ClawdStrike, to the same run, with the same review path.
