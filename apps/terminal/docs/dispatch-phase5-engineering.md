# Dispatch Phase 5 Engineering Breakdown

## Summary

Phase 5 adds non-tmux external terminal adapters and hardens non-default execution surfaces for release use.

Status:

- planned engineering breakdown
- intentionally the last phase because it carries the most platform variance

Goal:

- support external terminal windows without changing the default managed flow

This is the highest-variance phase and should stay last.

## 1. Data Structures

Reuse the external-surface fields introduced in Phase 4.

Phase 5 should not need another new run model.

If needed, expand the external surface enum:

```ts
type ExternalSurfaceKind =
  | "none"
  | "tmux-split"
  | "tmux-window"
  | "terminal-app"
  | "wezterm"
  | "kitty"
```

Prefer a generic adapter id string if you want to avoid growing enums repeatedly.

Example:

```ts
external?: {
  kind: string
  ref: string | null
}
```

## 2. Screens And Components

## Run Detail

External execution choices should stay behind an explicit action.

Recommended behavior:

- `o` opens external execution sheet
- sheet lists only adapters available on the current machine
- managed remains the fallback

Do not add permanent per-terminal clutter to the default run detail UI.

## External Execution Sheet

This is the right Phase 5 addition.

It should list:

- available adapters
- short descriptions
- fallback behavior if launch fails

Example:

```text
Open External Execution

1. WezTerm
2. Kitty
3. Terminal.app

[Enter open] [Esc cancel]
```

## 3. Dispatcher And Runtime Plumbing

## Adapter Abstraction

Add a generic external adapter interface, for example:

```ts
interface ExternalTerminalAdapter {
  id: string
  label: string
  isAvailable(): Promise<boolean>
  launch(run: RunRecord): Promise<{ ref: string | null }>
}
```

Place it under a dedicated module, for example:

- `apps/terminal/src/tui/external/`

Suggested structure:

- `types.ts`
- `registry.ts`
- `tmux.ts`
- `wezterm.ts`
- `kitty.ts`
- `terminal-app.ts`

Phase 5 should reuse tmux through the same registry rather than keeping tmux special forever.

## Launch Semantics

External adapters must receive:

- run id
- cwd/worktree
- session reference or attach target

They must not invent a separate process model detached from the TUI run runtime.

## Release Hardening

This phase needs real fallback behavior.

If external launch fails:

- run remains alive
- TUI returns to run detail
- status message explains failure
- user can still use `managed` or `attach`

## Config Surface

Optional later config:

- preferred adapter
- whether to show external launch options by default

But Phase 5 should not require new config to function.

## 4. Tests

Add:

- adapter registry tests
- availability filtering tests
- failure fallback tests
- run identity preservation tests

Dogfood:

- one supported terminal adapter per platform target
- external open -> review-ready completion
- external launch failure -> clean fallback to run detail

## 5. Milestone PR Slices

### PR 1

- generic external adapter interface
- registry wiring

### PR 2

- port tmux onto the registry
- add first non-tmux adapter

### PR 3

- add external execution sheet in run detail
- add adapter availability filtering

### PR 4

- harden failures, cleanup, and docs

## Recommended Cut Line

Do not cut:

- explicit fallback to TUI
- adapter availability filtering

Cut first:

- multiple terminal adapters in one release
- per-adapter polish and customization

## Bottom Line

Phase 5 should make external terminal support possible without making it central.

If it cannot preserve the managed run invariants, it should not ship.
