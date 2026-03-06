---
name: clawdstrike-tui-dogfood-loop
description: Use when the ClawdStrike TUI needs live dogfooding, reproduction, or workflow validation across the main dashboard, security surfaces, hunt loop, release wrapper, or local runtime states.
---

# ClawdStrike TUI Dogfood Loop

Use this skill when the job is to prove what the terminal app actually does, not what the code seems like it should do.

## Outcomes

Drive toward:

- exact reproduction steps
- screen-level evidence from a live PTY session
- clear separation between runtime failures, data-state failures, and layout problems
- the smallest follow-up fix or verification plan

## Workflow

1. Launch the real surface first.
2. Prefer `clawdstrike tui` for release-path checks and `bun run cli` in `apps/terminal` for fast iteration.
3. Drive the TUI with exact key sequences instead of static reasoning.
4. Cover the operator loop that matches the issue: main, integrations, security, audit, watch, scan, timeline, query, report, history.
5. Capture footer text, status-bar state, empty-state copy, and any stderr or transport failures.
6. Classify the issue before editing: bootstrap, wrapper, local daemon, cluster stream, data contract, layout, or polish.
7. After a fix, rerun the smallest live dogfood pass that proves the issue is gone.

## Required Verification

When code changes land, run the narrowest relevant set from:

- `cd apps/terminal && bun run typecheck`
- `cd apps/terminal && bun test`
- `cargo test -p hush-cli tui::tests -- --nocapture`
- `cargo test -p hush-cli test_tui_command_parses_with_passthrough_args -- --nocapture`

## Guardrails

- Do not treat screenshots alone as proof; reproduce the behavior in a PTY.
- Do not jump straight to implementation when the runtime state is still unclear.
- Keep supported beta screens held to a higher standard than experimental screens.
