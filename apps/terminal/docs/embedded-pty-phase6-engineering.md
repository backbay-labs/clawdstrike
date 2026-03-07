# Embedded PTY Phase 6 Engineering Breakdown

## Summary

This document breaks the embedded PTY surface into concrete engineering work against the current `apps/terminal` codebase.

Status:

- planned engineering breakdown
- follow-on to the current dispatch implementation

This is not a rewrite of dispatch. It is a replacement for the current raw attach presentation layer.

## 1. Data Structures

Add a new app-level interactive session model in [types.ts](../src/tui/types.ts).

Recommended additions:

```ts
type InteractiveSurfacePhase =
  | "connecting"
  | "ready"
  | "awaiting_first_input"
  | "running"
  | "returning"
  | "failed"

interface InteractiveViewportState {
  cols: number
  rows: number
  scrollOffset: number
  autoFollow: boolean
}

interface InteractiveSessionState {
  runId: string | null
  sessionId: string | null
  focus: "pty" | "controls" | "staged_task"
  phase: InteractiveSurfacePhase
  stagedTask: {
    text: string
    sent: boolean
    editable: boolean
  }
  viewport: InteractiveViewportState
  scrollback: string[]
  lastOutputAt: string | null
  lastHeartbeatAt: string | null
  error: string | null
}
```

Keep this separate from `RunRecord`.

`RunRecord` should only keep run identity and summarized session state, for example:

- `interactiveSessionId: string | null`
- `interactiveSurface: "none" | "embedded" | "tmux" | "external"`
- `interactivePhase: InteractiveSurfacePhase | null`

Do not store full scrollback in `RunRecord`.

## 2. Screens And Components

### New screen

Add:

- `apps/terminal/src/tui/screens/interactive-run.ts`

This should be a full supported surface, not an overlay on top of `run-detail`.

### New components

Add a small set of focused components under `apps/terminal/src/tui/components/`:

- `pty-viewport.ts`
- `staged-task-bar.ts`
- `interactive-control-bar.ts`
- optionally `interactive-session-rail.ts`

Responsibilities:

- `pty-viewport.ts`: render bounded scrollback and selection/follow state
- `staged-task-bar.ts`: render/send/edit the initial task affordance
- `interactive-control-bar.ts`: show `Ctrl+G` control hints and current focus
- `interactive-session-rail.ts`: compact run/session metadata

### Existing screens to update

- [run-detail.ts](../src/tui/screens/run-detail.ts)
  - replace raw attach handoff copy with `open interactive surface`
- [runs.ts](../src/tui/screens/runs.ts)
  - reopen into `interactive-run` when an embedded interactive session is active
- [main.ts](../src/tui/screens/main.ts)
  - no direct UI change required beyond status counts unless desired later

## 3. Runtime Plumbing

### Current limitation

The current attach path in [pty.ts](../src/tui/pty.ts) launches the agent with inherited stdio.

That is fundamentally incompatible with embedded rendering.

### Required replacement

Introduce a true PTY runtime module, either by replacing or splitting `pty.ts` into:

- `pty-runtime.ts`
- `pty-session.ts`

Required interface:

```ts
interface InteractivePtySession {
  id: string
  write(input: string): void
  resize(cols: number, rows: number): void
  kill(): void
  onOutput(cb: (chunk: string) => void): void
  onExit(cb: (code: number | null, signal: string | null) => void): void
}
```

### Runtime ownership

`app.ts` should own:

- starting the interactive session
- routing PTY output into `InteractiveSessionState.scrollback`
- routing user input into `session.write(...)`
- opening/closing the `interactive-run` screen
- returning to `run-detail`

The PTY runtime should not know about TUI navigation.

### Input routing

When `inputMode === "interactive-run"`:

- printable keys go to PTY when focus is `pty`
- `Ctrl+G` switches to controls overlay
- overlay commands are handled by the TUI, not written into PTY

### Resize

Reuse terminal resize handling in [app.ts](../src/tui/app.ts).

When the interactive surface is active:

- compute the PTY viewport size from the rendered layout
- call `session.resize(cols, rows)` on screen-size changes

## 4. Toolchain Behavior

### Claude

The current live behavior shows a blank prompt after launch.

Therefore:

- `interactive-run` should default to `focus: "staged_task"` or `phase: "awaiting_first_input"`
- the staged task must be visible and sendable explicitly
- do not assume positional prompt launch removes the need for UI guidance

### Codex

Codex can usually start with the prompt already consumed.

Therefore:

- allow direct PTY focus when the session is already active
- keep the staged-task bar minimized when redundant

Do not force Claude and Codex through identical first-input UX if their CLIs differ.

## 5. Failure And Recovery

If PTY startup fails:

- mark the run interactive phase as `failed`
- return to `run-detail`
- show an actionable error
- optionally offer raw attach fallback

If embedded PTY rendering fails mid-session:

- preserve the run
- keep backlog entry intact
- offer fallback to tmux or external if available

## 6. Tests

### Unit

Add:

- viewport wrapping and scrollback truncation tests
- staged-task send/edit tests
- control overlay state tests
- input-routing tests for `pty` vs `controls` focus

### Integration

Add:

- `run-detail -> interactive-run`
- `interactive-run -> return to run-detail`
- `interactive-run -> review-ready result`
- repeated open/close cycles without listener leaks
- resize propagation through mocked PTY session

### Live dogfood gates

Require manual/live checks for:

- Claude first-input clarity
- Codex first-input clarity
- no stale TUI content during open/close
- no terminal corruption after return

## 7. Milestone PR Slices

### PR 1

- add `InteractiveSessionState`
- add `interactive-run` mode and screen shell
- no real PTY yet

### PR 2

- add PTY runtime abstraction
- wire output buffering and exit handling

### PR 3

- wire staged-task bar and focus model
- implement `Ctrl+G` controls overlay

### PR 4

- convert attach entry points to open embedded surface
- keep raw attach as fallback behind a flag

### PR 5

- add resize/liveness/failure hardening
- live dogfood fixes for Claude and Codex

## Recommended Cut Line

Do not cut:

- explicit first-input UX
- reliable return to run-detail
- resize and cleanup correctness

Cut first:

- fancy scrollback search
- copy mode
- extra session rail polish
- adapter escalation from inside the embedded surface

## Bottom Line

If ClawdStrike wants interactive runs to feel native, Phase 6 should build one embedded PTY surface with strong control boundaries.

It should not try to become tmux.
