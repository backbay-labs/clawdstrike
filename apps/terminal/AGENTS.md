# Terminal TUI Working Agreement

This subtree is the ClawdStrike beta operator cockpit.

## Primary bar

- Make the TUI reliable and legible before making it broader.
- Prefer live PTY dogfooding over static reasoning for UI and workflow issues.
- Hold supported beta screens to release quality: main, integrations, security, audit, policy, result, watch, scan, timeline, query, report, history.
- Keep experimental screens visible but clearly secondary.

## Commands

Use the narrowest relevant verification set:

- `bun run typecheck`
- `bun test`
- `bun run build:tui-runtime`
- `cargo test -p hush-cli tui::tests -- --nocapture`
- `cargo test -p hush-cli test_tui_command_parses_with_passthrough_args -- --nocapture`

## Dogfood bias

- Prefer `clawdstrike tui` when validating the release path.
- Use `bun run cli` for fast local iteration inside `apps/terminal`.
- Validate healthy, degraded, and offline states explicitly when touching operator surfaces.
- Copy exact footer/status text into findings when a failure is user-visible.

## UI bias

- Fix ANSI width and shell geometry problems at the component/helper level when possible.
- Reduce noise before adding decoration.
- Avoid ad hoc spacing fixes that only work at one terminal width.

## Scope control

- Do not expand product scope during polish or RC hardening.
- Do not claim a workflow is working unless it has been exercised live.
