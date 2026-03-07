# Dispatch Phases 2-5 Overview

## Summary

Phase 1 establishes managed dispatch, a dispatch sheet, and a run detail screen.

Status:

- planned sequence for later phases
- not a description of currently shipped dispatch behavior

Phases 2-5 extend that foundation in a deliberate order:

1. `Phase 2`: make runs navigable and reviewable at scale
2. `Phase 3`: add interactive attach without leaving ClawdStrike
3. `Phase 4`: add tmux as an optional power-user adapter
4. `Phase 5`: add external terminal adapters and harden non-default execution modes

This ordering matters.

If the order is wrong:

- the run model fragments
- review gets bypassed
- tmux starts driving the product instead of supporting it

## Phase 2: Runs Index And Review Handoff

Purpose:

- turn one-off managed runs into a navigable backlog of active and recent work

Primary outcomes:

- a real `Runs` surface
- reopen and resume flow
- explicit `review_ready` state
- clean transition from run detail into result / diff / receipt review

Why it comes next:

- Phase 1 creates run detail for one active run
- without Phase 2, multiple runs become opaque and the status bar count is not actionable

Detailed breakdown:

- [Dispatch Phase 2 Engineering Breakdown](./dispatch-phase2-engineering.md)

## Phase 3: Attach Here

Purpose:

- support truly interactive agent sessions without abandoning the TUI

Primary outcomes:

- attach current terminal to a managed run PTY
- detach back into run detail
- preserve one run id, one audit trail, one review path

Why it waits for Phase 2:

- interactive attach only makes sense once runs are first-class and reopenable
- otherwise attach becomes a fragile one-way jump

Detailed breakdown:

- [Dispatch Phase 3 Engineering Breakdown](./dispatch-phase3-engineering.md)

## Phase 4: tmux Adapter

Purpose:

- support tmux users as an opt-in execution surface

Primary outcomes:

- `open in tmux split`
- optional `open in tmux window`
- tmux visibility only when `$TMUX` is present

Why it waits for Phase 3:

- tmux must sit on top of a working attach/run model
- it should reuse existing run semantics, not invent its own

Detailed breakdown:

- [Dispatch Phase 4 Engineering Breakdown](./dispatch-phase4-engineering.md)

## Phase 5: External Terminal Adapters

Purpose:

- support non-tmux external terminals without changing the default experience

Primary outcomes:

- adapter abstraction for supported terminal apps
- explicit configuration and fallback behavior
- release hardening for non-default execution surfaces

Why it is last:

- highest platform variance
- highest support cost
- easiest place for UX drift and execution/audit inconsistencies

Detailed breakdown:

- [Dispatch Phase 5 Engineering Breakdown](./dispatch-phase5-engineering.md)

## Cross-Phase Rules

These rules should hold across all later phases.

### One run model

Execution mode must not create a second class of run.

Every mode should preserve:

- one run id
- one workcell/worktree relationship
- one event trail
- one review handoff

### TUI remains the control plane

Even when the user attaches or opens tmux or an external terminal:

- ClawdStrike owns orchestration
- ClawdStrike owns status and review
- ClawdStrike remains the place the user returns to

### Review remains first-class

Completing a run should route into:

- result
- diff
- gates
- receipt / audit
- report generation when needed

not just a finished log buffer.

### Degraded states must stay explicit

Failures such as:

- attach unavailable
- tmux adapter failure
- external terminal launch failure
- stale log stream

must degrade back to run detail cleanly.

## Recommended Delivery Order

1. ship Phase 2 before any interactive or external execution work
2. ship Phase 3 before tmux
3. ship Phase 4 before generic terminal adapters
4. ship Phase 5 only when managed and attach flows are stable enough to preserve invariants

## Bottom Line

Phase 1 gives ClawdStrike a managed dispatch core.

Phases 2-5 should then extend that core outward, in this order:

- runs and review
- attach
- tmux
- external adapters

That sequence keeps the TUI as the product instead of turning it into a launcher.
