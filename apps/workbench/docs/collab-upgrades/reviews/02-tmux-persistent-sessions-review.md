# Review: 02 -- tmux-Backed Persistent Terminal Sessions

| Field       | Value                                      |
|-------------|--------------------------------------------|
| Reviewer    | Systems Architecture Review                |
| Date        | 2026-03-25                                 |
| Verdict     | **APPROVE WITH CHANGES**                   |

---

## Executive Summary

The spec is well-researched and the Collaborator reference port is a sound
strategy. The core idea -- wrap shell processes in tmux sessions, use
`portable-pty` to spawn `tmux attach-session` instead of a bare shell -- is
proven by the Collaborator codebase and mechanically straightforward. However,
the spec has several factual inaccuracies about the target codebase, a
significant gap in how the swarm engine orchestrator interacts with tmux, an
incorrect Tauri 2 API usage, and underspecifies environment variable passthrough.
None of these are design-breaking, but they need resolution before
implementation begins.

---

## 1. Factual Accuracy

### 1.1 `MAX_ACTIVE_SESSIONS` value and description -- CORRECT

The spec (line 29, line 415) states the backend constant is 32 and cites
`terminal.rs:45`. Verified:

```
terminal.rs:45  const MAX_ACTIVE_SESSIONS: usize = 32;
```

The semaphore pattern is also accurately described. `session_limiter()` returns
an `Arc<Semaphore>` initialized with `MAX_ACTIVE_SESSIONS`, and
`terminal_create` calls `try_acquire_owned()` on it (lines 352-356, 408-413 of
`terminal.rs`). The spec correctly identifies this as a capacity-reservation
pattern rather than a racy `sessions.len()` check.

### 1.2 `MAX_ACTIVE_TERMINALS` frontend cap -- CORRECT

The spec says the frontend cap is 8 at `swarm-board-store.tsx:45`. Verified:

```
swarm-board-store.tsx:45  export const MAX_ACTIVE_TERMINALS = 8;
```

### 1.3 `loadPersistedBoard` session stripping -- CORRECT

The spec (Section 6.4) accurately reproduces the code at
`swarm-board-store.tsx:137-150` that strips `sessionId` and resets status to
`"idle"` on reload. Line numbers match.

### 1.4 `spawnSession` flow -- MOSTLY CORRECT

The spec cites `swarm-board-store.tsx:1254` for the `terminalService.create()`
call. Verified at line 1254. However, the spec refers to
`SwarmBoardProvider.spawnSession()` and `SwarmBoardProvider.spawnClaudeSession()`
-- these are actually callbacks defined inside the `SwarmBoardProvider`
component body via `useCallback`, not class methods. Minor naming imprecision,
not a blocker.

### 1.5 `killSession` line reference -- CORRECT

The spec references `line 1425-1470` for `killSession`. Verified: the
`killSession` callback starts at line 1425 and the closing brace of the outer
`useCallback` is at line 1470.

### 1.6 `portable-pty` crate API -- CORRECT

The spec correctly describes the API surface: `native_pty_system()`,
`openpty(PtySize{...})`, `CommandBuilder::new()`, `slave.spawn_command()`,
`master.take_writer()`, `master.try_clone_reader()`, `master.resize()`. All
verified in `terminal.rs`. The crate version is `0.8` per `Cargo.toml:19`.

### 1.7 Tauri 2 `resource_dir` API -- INCORRECT

**The spec's `tmux_bin()` example (Section 3.3, line 271) uses
`tauri::api::path::resource_dir(...)`. This API does not exist in Tauri 2.**

The Tauri 2 API for resource resolution uses `app.path().resource_dir()`, as
demonstrated in the codebase itself:

```
mcp_sidecar.rs:174  let resource_dir = app.path().resource_dir().ok()?;
```

The `tmux_bin()` function needs an `AppHandle` parameter, not a bare function
call. This is not a design issue -- it is a code snippet error that will
confuse implementers.

### 1.8 Reference to `tauri.conf.json:44-47` for bundle resources -- CORRECT

Verified at `tauri.conf.json:44-47`:

```json
"resources": [
  "resources/*",
  "resources/**/*"
]
```

---

## 2. Feasibility

### 2.1 Spawning `tmux attach-session` through `portable-pty` -- FEASIBLE

`portable-pty`'s `CommandBuilder` takes any executable path and arguments. The
Collaborator does exactly this with `node-pty` (`pty.ts:75-78`):

```typescript
const ptyProcess = pty.spawn(
  tmuxBin,
  ["-L", getSocketName(), "-u", "attach-session", "-t", name],
  { name: "xterm-256color", cols, rows, env: utf8Env() },
);
```

The Rust equivalent would be:

```rust
let mut cmd = CommandBuilder::new(tmux_bin);
cmd.args(["-L", &socket_name, "-u", "-f", &tmux_conf, "attach-session", "-t", &session_name]);
cmd.cwd(cwd);
cmd.env("TERM", "xterm-256color");
```

This is mechanically identical to how shells are spawned today. The PTY pair
does not care what process is on the slave end.

### 2.2 Ghostty Web renderer compatibility -- FEASIBLE, NO CHANGES NEEDED

The renderer (`terminal-renderer.tsx`) subscribes to `terminal:output:{id}`
events and calls `term.write(data)`. It does not inspect or interpret the data
beyond passing it to ghostty-web's VT100 parser. The data source (shell vs.
tmux attach client) is transparent to the renderer.

The scrollback restoration proposal (Section 3.4) of writing captured pane data
via `term.write(scrollbackData)` followed by a viewport clear
(`\x1b[2J\x1b[H`) on first live data is the same approach the Collaborator
uses with xterm.js. ghostty-web uses Ghostty's VT100 parser which handles ANSI
escapes identically. This will work.

### 2.3 Scrollback capture with ghostty-web terminal state -- WORKS WITH CAVEAT

The `tmux capture-pane -p -e -S -200000` command captures the pane content with
ANSI escape sequences preserved (`-e` flag). This is what gets written into the
terminal on reconnect.

**Caveat**: ghostty-web maintains its own scrollback buffer (configured at
`scrollback: 1000` on line 123 of `terminal-renderer.tsx`). After reconnect, the
ghostty-web instance will contain the captured scrollback in its buffer.
However, any scrollback beyond ghostty-web's 1000-line limit will be lost from
the renderer's perspective, even though tmux retains 200,000 lines. The spec
should explicitly note this discrepancy and recommend either:
- Increasing ghostty-web's scrollback limit for reconnected sessions, or
- Documenting that deep scrollback is only accessible via `tmux capture-pane`
  (e.g., a "Copy full history" button that calls the backend directly).

---

## 3. Architecture Gaps

### 3.1 Swarm Engine Orchestrator Integration -- MAJOR GAP

The spec does not address how the `SwarmOrchestrator` (from
`@clawdstrike/swarm-engine`, wired up in `swarm-engine-provider.tsx`) interacts
with tmux session lifecycle. The orchestrator has its own agent lifecycle:

```typescript
// swarm-engine-provider.tsx:69
// Wraps a spawnSession call with guard pipeline evaluation and receipt node creation.
spawnEngineSession: (spawnFn, opts) => Promise<Node<SwarmBoardNodeData>>;
```

When the orchestrator spawns an agent, it calls `spawnEngineSession` which
wraps the board's `spawnSession`. The spec's modifications to `terminal_create`
are at the Rust layer, which is correct -- the orchestrator calls down through
the same `terminalService.create()` path. But the recovery flow is not
orchestrator-aware:

- On restart, the spec proposes reconciling discovered tmux sessions with
  persisted board nodes (Section 6.5). But the orchestrator has its own state
  (`AgentRegistry`, `TaskGraph`, `TopologyManager`) that also needs
  reconciliation. If the orchestrator thinks an agent is dead but the tmux
  session is alive, there is a state divergence.
- The spec's `useEffect` recovery (Section 6.5) only updates board node status.
  It does not re-register agents with the orchestrator or resume task graph
  execution.

**Recommendation**: Add a Section 6.6 "Orchestrator Recovery" that either:
(a) Documents that orchestrator recovery is out of scope for this spec and
    sessions are reconnected in "manual mode" (no orchestrator), or
(b) Defines the API for the orchestrator to re-adopt recovered sessions.

### 3.2 Environment Variable Passing -- SIGNIFICANT GAP

The current `terminal.rs` has a strict env var allowlist (`ALLOWED_EXTRA_ENV_VARS`
at line 122-140) limited to `TERM`, `LANG`, locale vars, `PAGER`, `EDITOR`, etc.
Agent sessions spawned by the orchestrator or Claude sessions often need
additional env vars (e.g., API keys, session-specific identifiers,
`CLAUDE_CODE_*` vars).

The Collaborator handles this by using `tmux set-environment` to inject
session-specific vars after creation (`pty.ts:146-153`):

```typescript
tmuxExec("set-environment", "-t", name, "COLLAB_PTY_SESSION_ID", sessionId);
tmuxExec("set-environment", "-t", name, "SHELL", shell);
```

The spec mentions this pattern in Section 2.3 but does not propose how the
swarm board should handle it. Specifically:

1. The `ALLOWED_EXTRA_ENV_VARS` allowlist is too restrictive for agent sessions.
   The tmux `set-environment` approach bypasses the PTY env passing entirely
   (it sets vars in the tmux session's environment, which the shell inherits).
   But the spec does not propose adding a `tmux set-environment` call to the
   Rust `tmux.rs` module's API.

2. When reconnecting to a tmux session, the environment is already set (it was
   set at creation time and persists in tmux). This is a benefit the spec should
   explicitly call out -- environment state survives restarts for free.

**Recommendation**: Add `set_environment(id, key, value)` to the `tmux.rs`
public API. Define which vars the swarm board sets (at minimum: a session
identifier like `CLAWDSTRIKE_SESSION_ID` and `SHELL`). Consider whether the
allowlist should be relaxed for tmux mode since `tmux set-environment` does
not go through `portable-pty`'s `CommandBuilder`.

### 3.3 Shell and Working Directory Mismatch on Reconnect -- NOT ADDRESSED

The spec mentions metadata persistence (Section 4.2, step 2: write JSON with
shell and cwd) but does not address what happens if:

- The original cwd no longer exists (e.g., a worktree was deleted while the app
  was closed). The tmux session is still alive, running a shell in a now-deleted
  directory. Reconnect will succeed, but the shell may be in an error state.
- The user's default shell changed between restarts. The tmux session still runs
  the original shell, which is correct behavior, but the metadata might confuse
  the frontend if it uses `meta.shell` for UI display.

These are edge cases, not blockers. But the reconnect flow should at least
check whether the cwd is still valid and surface a warning.

### 3.4 Session Cleanup: Orphaned tmux Sessions After Crash -- PARTIALLY ADDRESSED

The spec addresses this in Section 8.3 and 8.4. The `discover_sessions`
function cleans orphans on next launch. However, there is a gap:

**What if the user never relaunches the app?** Orphaned tmux sessions will
persist indefinitely, consuming memory (~1MB per session per the spec's own
estimate). With 64 sessions (the proposed `MAX_TOTAL_SESSIONS`), this is 64MB
of tmux server memory sitting idle on the host with no cleanup path.

The Collaborator has the same issue. It is inherent to tmux-based persistence.
The spec should acknowledge this explicitly and recommend:
- A tmux session idle timeout (e.g., `set -g destroy-unattached off` is the
  default, which is what we want, but there is no built-in idle-kill).
- A cron-like cleanup that `tmux kill-server -L clawdstrike` after detecting
  the server has been idle for >24h. This could be a Tauri startup check.

### 3.5 `detach_all_sessions` Does Not Wait for Reader Tasks -- BUG

The proposed `detach_all_sessions()` in Section 4.4 does:

```rust
for (_, session) in manager.sessions.drain() {
    session.alive.store(false, Ordering::SeqCst);
    let _ = session.child.kill();
}
```

Compare with the existing `kill_all_sessions()` at `terminal.rs:809-837`, which
carefully aborts reader tasks and waits for them before proceeding. The proposed
detach function drops sessions without waiting for the reader tasks to finish.
This means:

1. The reader task may still be emitting Tauri events to a closing frontend.
2. The ring buffer cleanup is skipped (memory leak on shutdown -- minor, since
   the process is exiting, but indicates the function was written without
   consulting the existing cleanup discipline).

**Recommendation**: Port the reader task abort+await pattern from
`kill_all_sessions` into `detach_all_sessions`.

---

## 4. Platform Concerns

### 4.1 macOS Does NOT Ship tmux -- CORRECTLY IDENTIFIED BUT UNDERSPECIFIED

The spec acknowledges this (Section 3.3, 8.2) and proposes bundling a static
binary for release builds. This is the right approach. However:

- The spec's Phase 1 says "Test: sessions survive `cargo tauri dev` restart"
  which implies dev mode uses system tmux. System tmux on macOS requires
  Homebrew (`brew install tmux`). This should be documented as a dev
  prerequisite.

- The static build proposal mentions libevent and ncurses as dependencies but
  does not specify the tmux version. The Collaborator bundles tmux -- the spec
  should reference the exact version the Collaborator uses and confirm the
  bundled `tmux.conf` options are compatible. Notably, `allow-passthrough on`
  requires tmux >= 3.3a (Dec 2022). The proposed `tmux 3.5a` in the build
  script (Section 8.2) satisfies this.

- The `terminfo` bundling is mentioned but the specific entries needed are not
  listed. At minimum: `xterm-256color`. The Collaborator bundles a full
  `terminfo` directory.

### 4.2 Linux tmux Version Fragmentation

The spec mentions "distro packages" for Linux (Section 3.3) but does not
address the version spread:

| Distro | Default tmux version |
|--------|---------------------|
| Ubuntu 22.04 LTS | 3.2a |
| Ubuntu 24.04 LTS | 3.4 |
| Debian 12 | 3.3a |
| RHEL 9 / Rocky 9 | 3.2a |

`allow-passthrough on` requires >= 3.3a. Ubuntu 22.04 and RHEL 9 ship 3.2a,
which will fail on this config option. The `tmux.conf` must either:
- Drop `allow-passthrough on` (losing OSC passthrough for image protocols), or
- Use conditional config (`if-shell "tmux -V | ..." "set ..."` -- fragile), or
- Bundle tmux on Linux as well (the cleaner solution).

**Recommendation**: Bundle tmux on Linux too, at least for release builds.
Document the minimum required version (3.3a for `allow-passthrough`).

### 4.3 Windows -- Spec Claims "Existing Direct-PTY" Fallback

The spec (Section 8.1) says Windows falls back to "the existing direct-PTY
path." This is accurate -- the codebase has extensive `#[cfg(windows)]` support
in `terminal.rs` (shell allowlist includes `cmd`, `powershell`, `pwsh` at
line 152; Windows `.exe` trimming at line 179-188) and in `mcp_sidecar.rs`.
The swarm board does appear to have been designed with Windows in mind, even if
it is primarily developed on macOS.

However, the spec should explicitly note that **persistence is a macOS/Linux-
only feature** in user-facing documentation. Operators on Windows who rely on
session persistence will need to be told it is not available, not silently
degraded.

---

## 5. Security

### 5.1 tmux Socket Permissions -- ADEQUATE

The spec (Section 8.7) correctly notes that tmux sockets are created in
`/tmp/tmux-{uid}/` with mode 0700. This is default tmux behavior and provides
per-user isolation. No issues here.

### 5.2 Metadata JSON Files -- MINOR CONCERN

Session metadata is stored at `~/.clawdstrike/terminal-sessions/{sessionId}.json`.
These files contain `cwd` paths which reveal the user's directory structure.
On a multi-user system, these files are in the user's home directory and
protected by standard POSIX permissions. However:

- The spec does not specify the file permissions. The Collaborator's
  `writeSessionMeta` uses `fs.writeFileSync` which inherits the process umask.
  The Rust equivalent should explicitly set mode 0600 on these files.
- The metadata directory itself should be mode 0700.

### 5.3 tmux Sessions Persist with Full Shell Access -- ACKNOWLEDGED RISK

This is inherent to the design and is the same trade-off the Collaborator makes.
A tmux session is a full interactive shell. If the workbench process crashes,
anyone with access to the user account can `tmux -L clawdstrike attach` to
connect to any surviving session. This is not worse than leaving a terminal
open, but it is worth noting in operator documentation.

### 5.4 `repo_roots::ensure_path_within_approved_repo` -- PRESERVED

The existing `normalize_cwd` function in `terminal.rs:210-222` calls
`repo_roots::ensure_path_within_approved_repo(&canonical)` to restrict terminal
sessions to approved directories. The tmux `new-session -c {cwd}` command
must go through the same validation. The spec does not explicitly mention this,
but the proposed flow routes through the existing `terminal_create` code path,
so the check is preserved. Worth calling out explicitly in implementation
notes.

---

## 6. Alternative Approaches

### 6.1 Script/Session Replay

Instead of tmux, record all input to the terminal and replay on restart.

**Pros**: No external binary dependency. Pure Rust implementation.
**Cons**: Cannot restore interactive state (cursor position, running processes,
shell variables). Claude Code sessions are stateful processes that cannot be
replayed from input history. This is a non-starter for the stated goal of
"agent sessions survive restarts."

**Verdict**: Not viable for the use case.

### 6.2 Persist Scrollback to Disk (Read-Only Recovery)

Write the ring buffer to disk periodically. On restart, display the saved
scrollback as a read-only history. Do not attempt to reattach the running
process.

**Pros**: Simple. No tmux dependency. Gives operators visibility into what
agents were doing.
**Cons**: The running process is still lost. This only recovers scrollback,
not session continuity. It addresses the "review what happened" use case but
not the "session survives restart" use case.

**Verdict**: Useful as a complementary feature (and cheaper to implement), but
does not replace tmux for the primary goal. The spec should consider this as
a "Phase 0" that delivers partial value immediately.

### 6.3 Zellij as a tmux Alternative

Zellij is a Rust-native terminal multiplexer with a plugin system and
client-server architecture similar to tmux.

**Pros**: Written in Rust, could theoretically be embedded as a library rather
than shelled out to. Better structured API than tmux's ad-hoc command syntax.
Actively developed.
**Cons**:
- Zellij's session management API is less mature than tmux's. There is no
  equivalent of `capture-pane -p -e` for scrollback extraction (Zellij uses
  a different scrollback model).
- The Collaborator's tmux integration is battle-tested. Porting it to Zellij
  would mean inventing a new integration from scratch with no reference
  implementation.
- Zellij cannot be statically linked as easily as tmux (it has more Rust
  dependencies and its binary is larger).
- The Zellij API for headless/embedded usage is not stable.

**Verdict**: Interesting for future exploration but premature for this use case.
The Collaborator's tmux patterns de-risk the implementation significantly.
Recommend noting Zellij as a long-term option if tmux bundling proves
burdensome.

### 6.4 `abduco` + `dvtm` (Missed Alternative)

`abduco` is a minimal session manager (like `screen -d -r` without terminal
multiplexing). It is simpler than tmux, has fewer dependencies (no libevent,
no ncurses), and provides exactly the attach/detach semantics needed.

**Pros**: Tiny binary (~20KB). Easy to statically compile. Single-purpose
(session persistence without multiplexer features).
**Cons**: No scrollback capture equivalent. No `capture-pane`. No session
environment management. Much less battle-tested.

**Verdict**: Not suitable because scrollback capture is a hard requirement.

---

## 7. Additional Issues

### 7.1 The `term.write("\x1b[2J\x1b[H")` Clear on First Data Is Fragile

The spec proposes (Section 3.4) clearing the viewport on the first real data
chunk after scrollback injection. This requires the renderer to distinguish
"scrollback was written" from "first real data arrived." The spec does not
detail the mechanism. The Collaborator does this by tracking a boolean flag in
the terminal tile component, but that code is not shown in the spec.

The ghostty-web `Terminal` class (unlike xterm.js) may handle the clear
sequence differently with respect to scrollback preservation. The implementer
should verify that `\x1b[2J` (erase display) in ghostty-web does not also
clear the scrollback buffer. If it does, the captured scrollback will be lost.

**Recommendation**: Test this specific sequence with ghostty-web before relying
on it. An alternative is to skip the viewport clear entirely and let tmux's
own screen redraw overwrite the static scrollback naturally (tmux sends a full
screen redraw when a client attaches).

### 7.2 `tmuxExec` Timeout and Error Handling

The Collaborator uses a 5-second timeout on all `tmuxExec` calls
(`tmux.ts:76`). The spec does not specify timeouts for the Rust equivalent.
`std::process::Command` has no built-in timeout. The implementation should
use `tokio::process::Command` with `tokio::time::timeout` for async tmux
calls, or set a reasonable deadline via `wait_with_output` + thread timeout
for sync calls.

A hung tmux server (e.g., due to a broken socket or zombie process) will block
the Tauri command handler indefinitely without timeouts.

### 7.3 The `portable-pty` 0.8 Crate Has Known Issues

The `Cargo.toml` comment (`SEC-PTY-001: upgrade/remove once transitive serial
is eliminated`) indicates an existing concern. `portable-pty` 0.8 has known
issues with signal handling and child process reaping on macOS. When the
PTY child is `tmux attach-session` (which itself manages child processes), any
bugs in child process tracking will manifest differently than with a simple
shell. The implementer should test:

- What happens when `tmux attach` is killed via `child.kill()` -- does it
  send SIGHUP to the tmux client cleanly?
- Does `child.try_wait()` correctly report exit status for the tmux attach
  client (not the tmux server)?

### 7.4 Resize Race Between PTY and tmux

The spec (Section 4.5, step 4) proposes: resize the PTY, then `tmux resize-window`.
The Collaborator does this in the opposite order in `reconnectSession`
(`pty.ts:211-218`) -- it attaches first, then resizes tmux. And in
`resizeSession` (`pty.ts:245-262`) it resizes the local PTY first, then tmux.

There is a subtle race: if the PTY resize happens before tmux processes the
attach, the tmux window may snap to the PTY size on attach. If tmux resize
happens after, it overrides the PTY-negotiated size. The Collaborator's order
(PTY first, tmux second) is correct because tmux's `resize-window` is the
authoritative source of truth. The spec's `terminal_reconnect` steps should
explicitly state the order as: attach client -> then `tmux resize-window`.

---

## 8. Verdict: APPROVE WITH CHANGES

The spec demonstrates a thorough understanding of the Collaborator's tmux
integration and proposes a sound adaptation for the Tauri/Rust architecture.
The core design is correct and the phased rollout with feature flags is
responsible engineering.

### Required Changes Before Implementation

1. **Fix the Tauri 2 API error** (Section 3.3): Replace
   `tauri::api::path::resource_dir(...)` with `app.path().resource_dir()`.
   The `tmux_bin()` function must accept an `AppHandle` parameter.

2. **Add orchestrator recovery section** (Section 6): Document how discovered
   tmux sessions are re-registered with the `SwarmOrchestrator`, or explicitly
   scope this spec to manual-mode-only recovery and defer orchestrator recovery.

3. **Add `set_environment` to `tmux.rs` API** (Section 7.3): The public API
   is missing environment variable injection. This is needed for session
   identifiers and potentially for agent-specific configuration.

4. **Add command timeouts for `tmux` calls**: Specify a timeout (5s, matching
   the Collaborator) for all `std::process::Command` invocations of tmux.

5. **Fix `detach_all_sessions` to await reader tasks**: The proposed function
   drops sessions without aborting/awaiting reader tasks. Port the cleanup
   discipline from `kill_all_sessions`.

### Recommended Changes

6. **Address Linux tmux version requirements**: Either bundle tmux on Linux
   or make `allow-passthrough on` conditional. Document minimum version 3.3a.

7. **Specify metadata file permissions**: 0600 for session JSON files, 0700 for
   the `~/.clawdstrike/terminal-sessions/` directory.

8. **Note the ghostty-web scrollback limit discrepancy**: 1000 lines in the
   renderer vs. 200,000 in tmux. Propose a mitigation (increase renderer limit,
   or add a "copy full history" escape hatch).

9. **Test `\x1b[2J` behavior in ghostty-web**: Verify viewport clear does not
   destroy scrollback buffer before relying on the Collaborator's clear pattern.

10. **Consider "Phase 0" read-only scrollback persistence**: Persisting the ring
    buffer to disk on shutdown delivers partial value (review capability) with
    zero external dependencies. This could ship immediately behind the same
    feature flag while tmux integration is developed.
