# Dispatch UX Spec

## Summary

`dispatch` should create a managed run inside ClawdStrike TUI, not immediately eject the user into another terminal.

Status:

- this document describes the planned target UX
- current implementation still dispatches directly and then routes into the existing result surface

The TUI remains the control plane for:

- task composition
- run launch
- live run monitoring
- review and result handoff
- cancellation and re-attachment

External terminals and tmux are supported as optional execution surfaces, not the default interaction model.

## Problem

The current `dispatch` concept is under-specified from a user-experience perspective.

There are three competing models:

1. launch work in the background and monitor it in TUI
2. hand the user to an interactive PTY immediately
3. open a separate terminal window or tmux pane

If the default is wrong, the TUI stops feeling like the product and becomes a launcher.

## Goals

- keep the user anchored in ClawdStrike after dispatch
- make runs observable without requiring PTY attachment
- preserve a clean review-first workflow
- support interactive agent sessions when needed
- support power-user tmux workflows without making tmux mandatory
- keep the run model consistent across managed, attached, and external execution

## Non-Goals

- building a terminal multiplexer inside ClawdStrike during the initial dispatch phases
- treating embedded PTY as solved by raw attach handoff
- making tmux a hard dependency
- opening a new OS terminal window for every dispatch by default
- replacing the existing result, audit, or report workflows

Follow-on design work for an embedded PTY surface now lives in:

- [Embedded PTY Surface Spec](./embedded-pty-surface-spec.md)
- [Embedded PTY Surface Plan](./embedded-pty-surface-plan.md)

## Design Principles

### ClawdStrike stays home base

Dispatch should not mean "leave the product."

The user should be able to:

- launch a run
- watch it progress
- step away to other surfaces
- return to the same run
- review outputs in the same TUI

### Execution mode does not change the run model

All runs should have the same identity and life cycle regardless of where execution is shown.

Each run should keep:

- one `run_id`
- one workcell / worktree association
- one event stream
- one audit / receipt trail
- one result entry

### Default for the median user, optional upgrades for power users

The default should optimize for clarity and control, not terminal cleverness.

Power-user affordances such as tmux pane launch should be optional adapters layered on top.

## Dispatch Modes

ClawdStrike should support three execution modes.

### `managed`

Default mode.

Behavior:

- create a run
- launch execution in a managed background workcell / PTY
- stream status and logs back into the TUI
- leave the user in a `Run Detail` surface

This is the primary and recommended experience.

### `attach`

Interactive mode.

Behavior:

- create the same managed run
- immediately attach the current terminal to the run PTY
- provide a clear detach / return affordance
- return to the same run detail surface after detach or completion

This is for runs that require human input or direct interaction.

### `external`

Power-user mode.

Behavior:

- create the same managed run
- launch the PTY in an external execution surface
- keep the run visible and traceable inside the TUI

External execution surfaces:

- tmux split or window if already inside tmux
- optional later adapters for supported terminal apps

This should not be the default.

## Primary User Flow

### 1. Compose

User lands on home and types a task into the prompt box.

### 2. Open Dispatch Sheet

Pressing `Enter` on a non-empty prompt opens a small dispatch sheet rather than immediately launching.

The sheet should show:

- prompt summary
- selected agent / profile
- workspace target
- execution mode
- confirmation actions

Example:

```text
Dispatch Task

Prompt: investigate hushd reconnect failures
Agent: Claude
Workspace: worktree
Mode: Managed

[Enter dispatch] [Tab edit] [m managed] [a attach] [o external] [Esc cancel]
```

### 3. Launch

Confirming dispatch creates a run and transitions to `Run Detail`.

### 4. Monitor

The user can stay on the run detail screen or navigate away while the run continues.

### 5. Review

When the run completes, the TUI routes the user into result / diff / gates / receipt / report workflows.

## Run Detail Screen

`Run Detail` is the main surface missing from the current dispatch story.

It should be a supported beta surface.

## Run Detail Goals

- show enough live state that most runs do not require PTY attachment
- make cancellation and takeover obvious
- make review the next step, not an afterthought

## Screen Regions

### Header

- run id
- task title
- agent / model
- execution mode
- workspace / worktree
- elapsed time

### Status Rail

- current phase: `queued`, `planning`, `editing`, `running_gates`, `awaiting_input`, `completed`, `failed`, `canceled`
- connection state
- step count if available
- last activity timestamp

### Live Log Tail

- concise normalized event stream
- raw PTY tail if available
- dropped-line indicator if stream parsing fails

### Change Summary

- files changed
- insertions / deletions
- patch status
- gate status

### Actions

- `a` attach
- `o` open external
- `c` cancel
- `r` review result
- `b` back to dashboard

## Background Run Behavior

Managed dispatch should not trap the user in the run detail screen.

The user should be able to:

- go back to main
- open audit / security / integrations
- reopen the run later from a runs list

The status bar should indicate active runs at all times.

## Runs Surface

The TUI should add a `Runs` surface for active and recent dispatches.

This becomes the index for:

- in-progress runs
- completed runs pending review
- canceled or failed runs

Each row should show:

- run id
- short title
- mode
- agent
- phase
- last activity

## PTY Attachment

`attach` should not be implemented as a fake tmux pane inside the TUI.

Instead:

- ClawdStrike temporarily gives the terminal to the run PTY
- detaching returns to ClawdStrike
- the run remains the same run object

Important requirements:

- a clear banner before handoff
- a clear detach chord or detach command
- deterministic return to the originating run detail screen

## tmux Integration

tmux should be treated as an optional adapter, not a core dependency.

When `$TMUX` is set, ClawdStrike may offer:

- `open in tmux split`
- `open in tmux window`
- `attach to tmux run`

This should only be shown when tmux is already available in the current session.

Reasons not to make tmux the default:

- non-portable default
- extra mental model for new users
- makes the TUI feel secondary
- creates support complexity around pane focus, copy mode, and environment inheritance

## External Terminal Integration

Opening a new terminal window should be optional and adapter-based.

Use cases:

- user wants a dedicated full terminal for a long interactive run
- user is working across multiple monitors
- user prefers terminal-native copy / search / scrollback

It should not be automatic because:

- it is disruptive
- it is platform-specific
- it weakens the main TUI experience
- it scales poorly for multiple concurrent runs

## Mode Selection Rules

Recommended defaults:

- default mode: `managed`
- if user explicitly requests interactivity: `attach`
- if inside tmux: offer `external -> tmux split`
- otherwise: hide or de-emphasize external adapters unless configured

## Keyboard Model

Home screen:

- `Enter`: open dispatch sheet
- `Tab`: move focus
- `Esc`: cancel sheet or exit focus mode

Dispatch sheet:

- `Enter`: confirm dispatch
- `m`: managed
- `a`: attach
- `o`: external
- `Tab`: cycle fields
- `Esc`: cancel

Run detail:

- `a`: attach
- `o`: external
- `c`: cancel
- `r`: review
- `b`: back

## Data Model Requirements

Dispatch needs a first-class run model in the TUI.

Suggested run fields:

- `run_id`
- `title`
- `prompt`
- `agent`
- `model`
- `workspace_mode`
- `execution_mode`
- `phase`
- `started_at`
- `updated_at`
- `worktree_path`
- `pty_session_id`
- `attached`
- `result_status`
- `gate_status`
- `receipt_id`
- `audit_refs`

## State Model

Suggested phase state machine:

- `draft`
- `launching`
- `queued`
- `planning`
- `running`
- `awaiting_input`
- `review_ready`
- `completed`
- `failed`
- `canceled`

Separate from phase:

- connection state
- PTY attachment state
- external-surface state

## Failure and Degraded States

The UX must make degraded states explicit.

Examples:

- workcell launch failed
- PTY attach failed
- external terminal adapter unavailable
- tmux requested but not present
- run still executing but log stream unavailable

These should not dump raw infra errors into the home screen.

## Review Handoff

The end of dispatch should route into review, not just "completed."

For successful runs, the next actions should be:

- inspect diff
- inspect gates
- inspect receipt / audit trail
- generate report if needed
- accept / discard / continue

## Telemetry / Audit Expectations

Dispatch should record:

- run created
- mode selected
- attach / detach events
- external open events
- cancel events
- completion status

This matters because execution mode becomes an operator decision worth tracing.

## Success Criteria

The dispatch UX is successful when:

- most users can launch and monitor a run without leaving the TUI
- attach is available for interactive cases without breaking flow
- tmux users can opt into split-pane workflows without everyone else paying that complexity cost
- review remains the main value path after execution completes

## Recommendation

Ship in this order:

1. `managed` dispatch with a real run detail screen
2. `attach here` PTY handoff
3. `runs` index and reopen flow
4. tmux adapter when `$TMUX` is present
5. other external terminal adapters later
