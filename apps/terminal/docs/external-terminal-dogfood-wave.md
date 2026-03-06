# External Terminal Dogfood Wave

## Goal
Use a dedicated swarm wave to harden the live user experience for:

- external terminal execution
- tmux split/window execution
- reopen/focus behavior
- launch failure messaging
- completion and timeout states

## Scope
- Dogfood the current `external` dispatch mode on a live workstation.
- Exercise `tmux split` and `tmux window` paths from inside a real tmux client.
- Exercise non-tmux adapters where available (`wezterm`, `kitty`, `Terminal.app`).
- Tighten the UX on:
  - dispatch sheet wording
  - external adapter picker wording
  - run-detail status language
  - runs backlog labels for externally executing runs
  - failure / retry / reopen flows

## Explicit Checks
- `dispatch -> external -> adapter picker -> launch`
- `run detail -> reopen external surface`
- `tmux split` reopen focuses the same pane
- `tmux window` reopen focuses the same window
- launcher never hangs forever when the external surface fails to start
- failed external launches leave a recoverable run, not broken global state

## Lane Split
- `p6`: live dogfood + UX hardening for external and tmux execution
- `p7`: investigate detached `codex exec` background exit behavior and test whether explicit `codex` sandbox/approval flags affect it

## Codex Runtime Note
The swarm launcher now accepts extra `codex` CLI args through:

```bash
export CLAWDSTRIKE_SWARM_CODEX_ARGS='-s danger-full-access -a never'
```

Those args must be applied before the `exec` subcommand so global flags like `-a/--ask-for-approval` are parsed correctly.

This is for investigation only. It should not become the default lane policy without clear evidence.
