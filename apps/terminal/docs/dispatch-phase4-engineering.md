# Dispatch Phase 4 Engineering Breakdown

## Summary

Phase 4 adds tmux as an optional adapter on top of the managed + attachable run model.

Status:

- planned engineering breakdown
- depends on working managed and attach flows first

Goal:

- support tmux users without making tmux the default execution path

tmux should remain an adapter, not a second product surface.

## 1. Data Structures

The run model should already exist.

Phase 4 only needs to extend it with minimal adapter metadata:

- `externalSurface: "none" | "tmux-split" | "tmux-window"`
- `externalRef: string | null`

Examples of `externalRef`:

- pane id
- window id

Do not add tmux-specific state all over the app.

Keep tmux-specific metadata grouped in one small part of the run record or in a nested field such as:

```ts
external?: {
  kind: "tmux-split" | "tmux-window"
  ref: string | null
}
```

## 2. Screens And Components

## Run Detail

Add tmux affordances only when `$TMUX` is present.

Recommended actions:

- `o` open external
- external submenu or overlay if more than one tmux target is supported

Do not show tmux hints globally on the home screen.

## Optional External Sheet

If needed, add a small selection sheet:

- `split`
- `window`
- `cancel`

This should be a run-detail overlay, not a full screen.

## Runs Screen

Show that a run is executing externally when relevant.

Example:

- `tmux split`
- `tmux window`

But do not make the list unreadable with adapter noise.

## 3. Dispatcher And Runtime Plumbing

## tmux Adapter Layer

Add a dedicated adapter module, for example:

- `apps/terminal/src/tui/external/tmux.ts`

Responsibilities:

- detect tmux availability and current session
- open split or window
- launch or attach the correct run session
- return an external reference for reopening/cleanup

The adapter should not own run lifecycle semantics.

It should be invoked by the TUI run runtime.

## Detection Rules

Offer tmux only when:

- `$TMUX` is present
- `tmux` binary exists

Graceful degradation:

- if tmux command fails, return to run detail with a visible error
- never strand the run in an unknown state

## Session Semantics

The same run must remain visible in ClawdStrike regardless of tmux surface.

That means:

- run state continues updating in the TUI
- run can still be reopened from `Runs`
- completion still becomes `review_ready`

## Avoid These Traps

- do not make tmux pane creation the only way to interactively run tasks
- do not rely on pane titles as the authoritative source of run identity
- do not let tmux-specific cleanup logic leak into core run state

## 4. Tests

Unit / integration:

- tmux availability detection
- split/window command construction
- adapter failure returns cleanly
- run remains present in `Runs` after tmux launch

Dogfood:

- launch run in split pane
- detach/close pane and reopen from ClawdStrike
- completion still routes to review

Use stubs for most tests and reserve a small amount of live tmux dogfooding for manual validation.

## 5. Milestone PR Slices

### PR 1

- add tmux adapter module
- add availability detection

### PR 2

- add run-detail tmux affordance
- support `open in tmux split`

### PR 3

- add optional `open in tmux window`
- add runs-screen external state labels

### PR 4

- harden cleanup and failure handling

## Recommended Cut Line

Do not cut:

- adapter failure fallback
- preserving run identity

Cut first:

- multiple tmux launch variants
- fancy pane naming/polish
- direct reopen of existing pane by keybinding

## Bottom Line

Phase 4 is successful when tmux users get a better workflow and everyone else notices almost nothing.
