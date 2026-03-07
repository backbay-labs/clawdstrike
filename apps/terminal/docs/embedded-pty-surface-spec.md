# Embedded PTY Surface Spec

## Summary

This document defines a follow-on design for an embedded PTY surface inside ClawdStrike TUI.

Status:

- planned product/design revision
- not part of the original dispatch phases 1-5
- motivated by live dogfooding of raw attach handoff

The original dispatch plan intentionally avoided building a terminal multiplexer inside the TUI. That was the right scope cut for the first implementation. Live attach dogfooding showed a real product gap: raw terminal takeover is functional, but it does not feel like a coherent in-product interactive surface.

This spec covers a narrower answer than “build tmux inside ClawdStrike”:

- one embedded interactive surface
- one active PTY at a time
- one run identity
- one clear return path back to review and run detail

## Problem

The current `attach` flow has three UX weaknesses even when it works technically:

1. it temporarily ejects the user out of the TUI instead of feeling like part of it
2. the first action is unclear for toolchains like Claude that start at a blank prompt
3. the return path depends on terminal takeover semantics rather than a first-class in-app interaction model

The result is usable for power users, but it does not feel native or polished.

## Goals

- keep the user visually inside ClawdStrike during interactive runs
- preserve one run model across managed, embedded, tmux, and external execution
- make first input obvious, especially for blank-prompt agents
- allow direct typing into the agent without fighting TUI keybindings
- keep review/result/audit handoff first-class after interaction ends
- improve perceived quality without turning ClawdStrike into a general-purpose multiplexer

## Non-Goals

- building full tmux feature parity
- multiple panes or arbitrary pane layout management
- generic shell hosting unrelated to a run
- background tabs or window manager behavior
- replacing tmux or external adapters for users who prefer those workflows

## Design Principles

### One active interactive surface

ClawdStrike should support one focused embedded PTY at a time.

That keeps the interaction model simple:

- one active run
- one visible PTY viewport
- one clear control overlay

### Runs stay first-class

The embedded surface is another view over the same run, not a different execution mode with a different identity.

The same run keeps:

- one `run_id`
- one event stream
- one workcell/worktree association
- one review/result path
- one audit/receipt trail

### Shell passthrough must be explicit

When the embedded PTY is focused, printable keys go to the agent.

ClawdStrike controls should be available through an explicit control chord or overlay, not by stealing ordinary keys from the session.

### First-input affordance matters

For agents that open at a blank prompt, the product must explain what to do next.

ClawdStrike should not assume users infer hidden terminal state.

## Proposed Surface

Add a dedicated `interactive-run` surface.

This is not a floating overlay on top of `run-detail`. It is a separate supported screen optimized around the active PTY.

## Surface Layout

### Header

Show:

- run title / id
- agent and model if known
- execution mode: `interactive`
- session state: `connecting`, `ready`, `awaiting_input`, `running`, `returning`, `failed`
- elapsed time

### PTY Viewport

Primary center panel.

Behavior:

- renders PTY output with scrollback
- supports resize with terminal size changes
- keeps selection/focus state internal to the embedded surface
- becomes the default keyboard target after the session is ready

### Session Rail

A compact side or bottom rail showing:

- staged task summary
- worktree path
- attach/external/tmux origin
- live run events summary
- connection / liveness status
- return / review affordances

This rail must stay secondary to the PTY viewport.

### Control Bar

A small persistent control hint, for example:

```text
Ctrl+G controls   Ctrl+X return   Ctrl+R review   Ctrl+O external   PgUp/PgDn scrollback
```

This bar exists so users do not have to guess how ClawdStrike regains focus.

## Staged Prompt UX

The product gap is worst for toolchains that open at a blank prompt.

The embedded PTY surface should solve that directly.

### Required behavior

When an interactive run opens, ClawdStrike shows the staged task above or below the PTY with an explicit action:

```text
Staged Task
reply with ok

Enter send task   Tab edit task   Esc cancel interactive launch
```

After the staged task is sent once, the bar can collapse into a smaller reminder such as:

```text
Task sent to Claude • Ctrl+G for ClawdStrike controls
```

### Toolchain-specific behavior

- `claude`: do not assume a positional prompt is enough; support explicit send of the staged task into the PTY
- `codex`: if the CLI already consumes the prompt at launch, show a lighter “session attached” banner and skip redundant task send

The UI should adapt to the agent, not force one attach mental model on every toolchain.

## Focus Model

### Default focus

Once the embedded session is ready, focus belongs to the PTY viewport.

### ClawdStrike controls

Use an explicit control chord, recommended:

- `Ctrl+G` opens a lightweight ClawdStrike control overlay

The overlay should offer:

- `x` return to run detail
- `r` open review when available
- `o` open external adapter
- `t` open tmux adapter when relevant
- `c` cancel run
- `?` help
- `Esc` close overlay and return focus to PTY

Do not overload printable keys while PTY focus is active.

## State Model

Add an embedded session state distinct from raw attach state.

Recommended high-level shape:

```ts
interface InteractiveRunState {
  runId: string
  sessionId: string | null
  surface: "embedded"
  phase:
    | "connecting"
    | "ready"
    | "awaiting_first_input"
    | "running"
    | "returning"
    | "failed"
  focus: "pty" | "controls" | "staged_task"
  stagedTask: {
    text: string
    sent: boolean
    editable: boolean
  }
  viewport: {
    cols: number
    rows: number
    scrollOffset: number
  }
  liveness: {
    lastOutputAt: string | null
    lastHeartbeatAt: string | null
  }
  error: string | null
}
```

This state should live beside the run model, not replace it.

## Runtime Model

The current attach implementation uses raw terminal takeover through inherited stdio.

That is not enough for an embedded surface.

An embedded PTY surface requires a real PTY runtime that supports:

- output streaming into TUI buffers
- input writes from the embedded surface
- resize propagation
- process exit detection
- optional liveness heartbeat or output timestamps

## Product Invariants

The embedded PTY surface must preserve:

- same run id before and after entering the surface
- same workcell/worktree
- same result/review route
- same runs backlog entry
- same audit trail

If the PTY surface dies, ClawdStrike should return to run detail with a visible error, not strand the user in a blank screen.

## Relationship To tmux And External

Embedded PTY is not a replacement for tmux or external adapters.

Recommended model:

- `managed`: default
- `interactive embedded`: first-class in-product interactive mode
- `tmux`: power-user adapter
- `external terminal`: optional adapter

If embedded PTY lands well, raw terminal takeover can become a compatibility fallback rather than the primary attach experience.

## Success Criteria

This feature is successful when:

- interactive runs feel like part of ClawdStrike, not an exit from it
- new users do not have to guess what to type first
- Claude blank-prompt behavior is handled explicitly
- returning to run detail and review is obvious and reliable
- tmux users still get their adapter path without forcing tmux on everyone

## Failure Criteria

This feature has failed if it becomes:

- a half-built tmux clone
- a second UI with different run semantics
- a source of broken PTY cleanup or unrecoverable terminal state
- a reason the rest of the TUI becomes keyboard-hostile
