# Dispatch UX Implementation Plan

## Summary

Implement dispatch as a managed run workflow inside ClawdStrike TUI.

Status:

- this is a planned implementation sequence
- only the planning/docs work is complete at this point

Recommended reading order:

1. [Dispatch UX Spec](./dispatch-ux-spec.md)
2. [Dispatch Phase 1 Engineering Breakdown](./dispatch-phase1-engineering.md)
3. [Dispatch Phases 2-5 Overview](./dispatch-phases2-5-overview.md)
4. Phase-specific breakdowns linked below
5. Embedded PTY follow-on docs linked below

Concrete Phase 1 file-by-file breakdown:

- [Dispatch Phase 1 Engineering Breakdown](./dispatch-phase1-engineering.md)
- [Dispatch Phases 2-5 Overview](./dispatch-phases2-5-overview.md)
- [Dispatch Phase 2 Engineering Breakdown](./dispatch-phase2-engineering.md)
- [Dispatch Phase 3 Engineering Breakdown](./dispatch-phase3-engineering.md)
- [Dispatch Phase 4 Engineering Breakdown](./dispatch-phase4-engineering.md)
- [Dispatch Phase 5 Engineering Breakdown](./dispatch-phase5-engineering.md)
- [Embedded PTY Surface Spec](./embedded-pty-surface-spec.md)
- [Embedded PTY Surface Plan](./embedded-pty-surface-plan.md)
- [Embedded PTY Phase 6 Engineering Breakdown](./embedded-pty-phase6-engineering.md)

The plan deliberately avoids:

- making tmux mandatory
- spawning a new terminal window by default
- embedding a full terminal multiplexer into the TUI during phases 1-5

Follow-on embedded PTY planning now lives in:

- [Embedded PTY Surface Spec](./embedded-pty-surface-spec.md)
- [Embedded PTY Surface Plan](./embedded-pty-surface-plan.md)
- [Embedded PTY Phase 6 Engineering Breakdown](./embedded-pty-phase6-engineering.md)

## Scope

This plan covers:

- dispatch UX
- run lifecycle modeling
- run detail and runs index surfaces
- PTY attach / detach
- optional tmux integration

This plan does not cover:

- deep redesign of speculate
- broad terminal-adapter support beyond tmux
- replacing existing result / report surfaces

## Phase 1: Run Model And Managed Dispatch

### Goal

Make `dispatch` create a first-class managed run that stays visible in the TUI.

### Deliverables

- add a `runs` state model in the TUI
- add a `Run Detail` surface
- route home `dispatch` through a dispatch sheet instead of immediate launch
- support default `managed` execution mode
- stream basic run status and log tail into the new surface

### UX

- `Enter` on a prompt opens dispatch sheet
- `Enter` again confirms managed launch
- transition to run detail
- user can back out to main while run continues

### Code Areas

- `apps/terminal/src/tui/types.ts`
- `apps/terminal/src/tui/app.ts`
- `apps/terminal/src/tui/screens/main.ts`
- new run detail screen under `apps/terminal/src/tui/screens/`
- dispatcher integration in `apps/terminal/src/dispatcher/`
- telemetry / run state plumbing as needed

### Exit Criteria

- dispatch no longer feels like a hidden CLI jump
- active run remains visible after leaving the screen
- completed run can route into review / result

## Phase 2: Runs Index And Review Handoff

### Goal

Make multiple dispatches manageable.

### Deliverables

- add a `Runs` index screen
- support reopen of active and recent runs
- show review-ready runs clearly
- link completed runs into result / diff / gates / receipt surfaces

### UX

- status bar shows active-run count
- `Runs` screen lists active and recent tasks
- selecting a completed run opens result-first review, not raw logs

### Exit Criteria

- user can safely launch more than one run
- run history is navigable inside the TUI
- review-ready state is explicit

## Phase 3: Attach Here

### Goal

Support interactive agent sessions without requiring tmux or external windows.

### Deliverables

- implement PTY attach / detach on top of the same run model
- add a pre-handoff banner
- add deterministic return to run detail after detach
- record attach / detach events in telemetry

### UX

- from run detail, press `a` to attach
- ClawdStrike hands terminal control to the PTY
- detach returns to the same run detail screen

### Engineering Notes

- do not embed a fake terminal pane inside the main layout
- reuse the run id and workcell created by managed dispatch
- attachment should be reversible and resumable

### Exit Criteria

- interactive sessions work without losing TUI context
- detach path is reliable
- completion after attach still routes to review

## Phase 4: tmux Adapter

### Goal

Serve tmux power users without making tmux the default.

### Deliverables

- detect `$TMUX`
- add `open in tmux split`
- optionally add `open in tmux window`
- keep the same run id and run detail state inside ClawdStrike

### UX

- tmux options only appear when relevant
- launching into tmux still leaves the run visible in ClawdStrike
- user can reopen run detail even if execution is happening elsewhere

### Exit Criteria

- tmux users get a good workflow
- non-tmux users see no extra complexity

## Phase 5: External Terminal Adapters

### Goal

Add optional terminal-app adapters after the core UX is stable.

### Deliverables

- adapter interface for external terminals
- config-driven adapter selection
- no default automatic window spawning

### Candidates

- iTerm / Terminal on macOS
- WezTerm
- Kitty

### Exit Criteria

- external adapters do not affect the default managed workflow
- failures degrade cleanly back to managed / attach choices

## UX Decisions To Preserve

- default dispatch mode stays `managed`
- ClawdStrike remains the control plane
- review is a first-class completion path
- execution mode does not change run identity

## Risks

### Risk: run model sprawl

If dispatch, speculate, result, and report all invent different run representations, the TUI becomes inconsistent.

Mitigation:

- add one shared run state shape
- keep execution mode orthogonal to phase

### Risk: PTY handoff complexity

Terminal handoff can be fragile across resize, raw mode, and cleanup.

Mitigation:

- make attach a dedicated, narrow phase
- test detach / return heavily

### Risk: tmux becoming the product

If tmux integration lands too early, it can distort the main interaction model.

Mitigation:

- keep tmux in a late phase
- hide tmux affordances unless actually inside tmux

### Risk: review path gets bypassed

If dispatch ends in raw logs and never returns to review surfaces, operator value drops.

Mitigation:

- route completion into result / review-ready state
- keep log viewing secondary to decision and review

## Testing Plan

### Unit

- run state transitions
- dispatch sheet mode selection
- runs index selection and reopen behavior
- attach / detach state transitions

### Integration

- dispatch from home -> run detail
- managed run continues while user navigates away
- run detail -> attach -> detach -> review
- run detail -> tmux adapter when `$TMUX` exists

### Dogfood

- single managed run
- multiple concurrent managed runs
- interactive attach flow
- tmux split flow in real tmux
- failed launch and degraded logging states

## Suggested Milestone Order

### Milestone 1

- dispatch sheet
- run model
- run detail

### Milestone 2

- runs index
- review-ready handoff

### Milestone 3

- attach here

### Milestone 4

- tmux adapter

### Milestone 5

- external terminal adapters

## Release Bar

Do not call the dispatch UX release-ready until:

- managed dispatch works without leaving the TUI
- runs remain observable and resumable
- attach return path is reliable
- canceled / failed / degraded states are explicit
- review remains the default completion path
