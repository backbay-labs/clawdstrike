# Embedded PTY Surface Plan

## Summary

Implement a dedicated embedded PTY surface as a follow-on to the current dispatch/attach system.

Status:

- planned follow-on work
- not included in original dispatch phases 1-5
- created after live dogfooding showed that raw attach handoff is technically correct but UX-poor

This plan treats embedded PTY as a new phase after the existing dispatch work, not a rewrite of the current run model.

## Why This Exists

The original plan deliberately avoided embedding a multiplexer into the TUI.

That decision reduced scope and made the first dispatch system shippable.

Live dogfooding exposed a different reality:

- raw attach is hard to make feel polished
- Claude-style blank-prompt sessions are confusing in takeover mode
- users expect something closer to an in-app interactive surface than a full-screen terminal jump

The correct response is a scoped embedded PTY feature, not a full tmux clone.

## Scope

This plan covers:

- one embedded interactive surface
- PTY runtime and viewport plumbing
- staged-task UX for blank-prompt agents
- control overlay and focus model
- review/run-detail return path

This plan does not cover:

- multi-pane layout management
- shell tabs
- arbitrary shell hosting
- replacing tmux/external adapters

## Delivery Shape

Treat this as `Phase 6` after the current dispatch phases.

### Phase 6A: PTY Runtime Foundation

Goal:

- replace raw `stdin/stdout inherit` takeover with a real attachable PTY runtime that can be rendered inside the TUI

Deliverables:

- PTY runtime abstraction with write/read/resize/exit hooks
- bounded scrollback buffer
- run-linked session lifecycle
- cleanup and terminal restore guarantees

Exit criteria:

- ClawdStrike can receive PTY output and render it in-memory without giving up the whole terminal

### Phase 6B: Interactive Run Surface

Goal:

- add a dedicated `interactive-run` screen centered on the PTY viewport

Deliverables:

- new screen registration
- PTY viewport component
- compact run/session rail
- control bar

Exit criteria:

- a run can be opened into a visually coherent embedded session surface

### Phase 6C: First-Input UX

Goal:

- remove ambiguity around what to do first in attached sessions

Deliverables:

- staged-task bar
- explicit send/edit flow for Claude-like agents
- lighter session-ready banner for Codex-like agents
- clear state transitions: `ready`, `awaiting_first_input`, `running`

Exit criteria:

- users can understand the first action without guessing from terminal output

### Phase 6D: Controls And Return Path

Goal:

- let users move between PTY and ClawdStrike controls without breaking typing

Deliverables:

- `Ctrl+G` control overlay
- return to run detail
- review shortcut when ready
- external/tmux escalation from the embedded session when useful

Exit criteria:

- keyboard interaction is predictable and does not steal printable keys from the PTY

### Phase 6E: Hardening And Migration

Goal:

- decide whether embedded PTY replaces raw attach by default

Deliverables:

- live dogfood on Claude and Codex
- resize/cleanup/liveness hardening
- fallback behavior when embedded PTY fails
- decision record for default attach behavior

Exit criteria:

- embedded PTY is stable enough to become the default interactive surface

## Product Decisions To Preserve

- `managed` remains the default dispatch mode
- ClawdStrike remains the control plane
- tmux stays optional
- external terminals stay optional
- one run model spans every execution surface

## Recommended Runtime Decision

The current `Bun.spawn(... stdin/stdout/stderr: "inherit")` path is not sufficient for embedded PTY.

Before implementation starts, choose one of:

1. a Bun-compatible PTY library with resize/input/output hooks
2. a small Rust/PTTY shim surfaced through the existing CLI/runtime stack

Decision rule:

- pick the smallest option that gives reliable output streaming and resize control on macOS and Linux
- do not accept a solution that only works by hijacking the whole terminal again

## Testing Plan

### Unit

- PTY buffer append/truncate
- viewport scroll behavior
- staged-task send state
- control overlay state transitions

### Integration

- managed run -> interactive-run
- interactive-run -> run-detail
- interactive-run -> review
- interactive-run -> external/tmux escalation
- resize propagation through the PTY runtime

### Live Dogfood

- Claude blank-prompt flow
- Codex prompt-at-launch flow
- repeated attach/return cycles
- failed PTY startup
- external/tmux escalation from the embedded surface

## Risks

### Risk: accidental tmux clone

Mitigation:

- one embedded PTY only
- no pane manager
- no tabs
- no shell workspace features beyond the active run

### Risk: keyboard conflicts

Mitigation:

- PTY gets printable keys by default
- ClawdStrike controls only through explicit chord/overlay

### Risk: cleanup regressions

Mitigation:

- preserve raw attach fallback until embedded PTY is proven
- add explicit liveness/exit/recovery tests

### Risk: toolchain-specific prompt behavior diverges

Mitigation:

- make staged-task UX adapter-aware
- do not force one attach model onto every CLI

## Bottom Line

The original design was correct to avoid multiplexer scope during the first dispatch implementation.

Now that the base run model exists, embedded PTY is the right next design if the goal is to make interactive runs feel native instead of merely functional.
