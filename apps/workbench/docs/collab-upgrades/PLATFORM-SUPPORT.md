# Platform Support Policy: tmux Persistent Sessions

Last updated: 2026-03-25

## Overview

tmux-backed persistent terminal sessions are a macOS and Linux feature.
Windows uses the existing direct-PTY path with no persistence across
app restarts.

## macOS

- **tmux source:** Bundled static binary in `src-tauri/resources/bin/tmux`
  (release builds). In dev mode, uses system tmux (install via `brew install tmux`).
- **Minimum version:** 3.3a (for `allow-passthrough on` support).
- **Dev prerequisite:** `brew install tmux` if not already installed.
- **Feature flag:** `supports_tmux_persistence()` returns `true` on macOS.

## Linux

- **tmux source:** System-installed tmux via package manager.
- **Minimum version:** 3.2a for basic functionality, 3.3a for full feature set.
- **Version detection:** The app detects the installed tmux version at runtime.
  If tmux < 3.3a, the `allow-passthrough on` config option is skipped
  (via `if-shell` conditional in `tmux.conf`). This loses OSC passthrough
  for image protocols but does not affect core session persistence.
- **Feature flag:** `supports_tmux_persistence()` returns `true` on Linux.
- **Distro matrix:**

  | Distribution     | Default tmux | allow-passthrough |
  |------------------|-------------|-------------------|
  | Ubuntu 24.04 LTS | 3.4         | Yes               |
  | Debian 12        | 3.3a        | Yes               |
  | Ubuntu 22.04 LTS | 3.2a        | No (skipped)      |
  | RHEL 9 / Rocky 9 | 3.2a        | No (skipped)      |

## Windows

- **tmux source:** Not available. tmux does not run on Windows.
- **Fallback:** Direct-PTY path via `portable-pty`. Sessions do not persist
  across app restarts.
- **Feature flag:** `supports_tmux_persistence()` returns `false` on Windows.
- **User-facing:** Operators on Windows who rely on session persistence must
  be told it is not available, not silently degraded. The workbench should
  surface a note in session metadata or documentation.

## Feature Flag

tmux persistence is controlled by `supports_tmux_persistence()` in
`terminal.rs`. This function returns `true` on macOS and Linux, `false`
on Windows. The feature flag remains enabled-by-default on supported
platforms until recovery is battle-tested, at which point it may be
promoted to unconditional.

The feature flag is NOT user-togglable in this phase. It is a compile-time
platform check. A future phase may add a runtime preference.

## Session Limits

| Limit | Value | Scope |
|-------|-------|-------|
| MAX_ACTIVE_SESSIONS (backend) | 64 | Total PTY sessions across all modes |
| MAX_ACTIVE_TERMINALS (frontend) | 8 | Simultaneously attached terminal renderers |

The 8-attached / 64-total tiered model uses lazy attach and detach:
- When a node scrolls out of viewport or the operator selects another node,
  the PTY client can be detached (freeing a renderer slot) while the tmux
  session persists.
- When the node is selected again, `terminal_reconnect` reattaches.

## Orphan Cleanup

If the app crashes, tmux sessions persist on the `clawdstrike` socket.
On next launch, `terminal_discover` cross-references metadata with live
tmux sessions. Sessions with no matching metadata are considered orphans
and the tmux server is killed.

## Scrollback Discrepancy

tmux stores up to 200,000 lines of scrollback (`history-limit 200000`).
ghostty-web's renderer has a 1,000-line scrollback buffer. On reconnect,
only the last ~1,000 lines are visible in the terminal UI. Full scrollback
is accessible via `terminal_preview` with a large line count.
