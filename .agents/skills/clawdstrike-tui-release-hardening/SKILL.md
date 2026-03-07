---
name: clawdstrike-tui-release-hardening
description: Use when the ClawdStrike TUI needs release-candidate hardening around bootstrap, doctor/init, installed runtime packaging, local agent connectivity, cluster watch connectivity, or evidence export traceability.
---

# ClawdStrike TUI Release Hardening

Use this skill when the work is about making `clawdstrike tui` shippable and boringly dependable.

## Outcomes

Drive toward:

- reproducible `init` and `doctor`
- working installed-runtime launch path
- clear local-versus-cluster operator state
- traceable report export and audit handoff
- release docs that match the real product surface

## Workflow

1. Prefer the public entrypoint: `clawdstrike tui`.
2. Validate bootstrap first: `doctor`, `init`, wrapper resolution, Bun/runtime detection.
3. Check the operator surfaces that must work in beta: integrations, security, audit, watch, report, history.
4. Verify local daemon and desktop-agent state separately from cluster-backed watch state.
5. If packaging changes, test both repo-local and staged installed-runtime paths.
6. Keep docs and product language honest about supported versus experimental screens.

## Required Verification

Use the relevant subset of:

- `cd apps/terminal && bun run build:tui-runtime`
- `cd apps/terminal && bun run typecheck`
- `cd apps/terminal && bun test`
- `cargo test -p hush-cli tui::tests -- --nocapture`
- `cargo test -p hush-cli test_tui_command_parses_with_passthrough_args -- --nocapture`

## Guardrails

- A graceful degraded state is acceptable; a misleading healthy state is not.
- Do not claim cluster watch works unless the live transport connects.
- Do not leave docs ahead of implementation.
