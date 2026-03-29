# 02 -- tmux-Backed Persistent Terminal Sessions

| Field       | Value                                          |
|-------------|------------------------------------------------|
| Status      | Draft                                          |
| Authors     | (engineer TBD)                                 |
| Created     | 2026-03-25                                     |
| Target      | `apps/workbench` (ClawdStrike Swarm Board)     |
| Reference   | `standalone/collab-public` (Collaborator)      |

---

## 1. Problem Statement

Swarm Board agent sessions run inside Tauri-managed PTY processes
(`portable-pty` crate). When the workbench app exits -- whether from a
restart, crash, macOS memory pressure kill, or manual quit -- every
running PTY dies with it. The child shell, any Claude Code instance
inside it, and all scrollback history are lost.

This is unacceptable for the Swarm Board's primary use case: long-running
agent "hunts" that coordinate multiple Claude Code sessions across
isolated git worktrees. A hunt investigating a CVE or refactoring an
auth subsystem can run for hours or days. Losing terminal state mid-hunt
means:

- Agent context and in-flight tool calls are destroyed.
- The operator cannot review what an agent was doing before the restart.
- The 8-session `MAX_ACTIVE_TERMINALS` hard cap (enforced at the
  frontend in `swarm-board-store.tsx:45`) means operators restart
  conservatively, limiting swarm parallelism.

**Goal**: Terminal sessions survive app restarts. On relaunch, the board
re-discovers surviving sessions, reattaches terminals, and restores
scrollback -- exactly as the Collaborator project does today.

---

## 2. Reference Architecture (Collaborator)

The Collaborator project (`standalone/collab-public/collab-electron`)
ships a production tmux integration. Every terminal session is a tmux
session; the Electron `node-pty` process is merely an *attached client*.
When the Electron app quits, it kills the client connections but leaves
the tmux sessions alive on the host.

### 2.1 Key Files

| File | Role |
|------|------|
| `collab-electron/src/main/tmux.ts` | tmux binary resolution, socket management, session metadata CRUD, `tmuxExec()` helper |
| `collab-electron/src/main/pty.ts` | Session lifecycle: create, reconnect, discover, kill, foreground process tracking |
| `collab-electron/src/main/paths.ts` | Defines `COLLAB_DIR` (`~/.collaborator[/dev]`) used as the metadata root |
| `collab-electron/resources/tmux.conf` | Minimal tmux config: no status bar, no prefix key, 200k scrollback, passthrough mode |
| `collab-electron/src/main/tmux.test.ts` | Integration tests exercising the full lifecycle including orphan cleanup |
| `collab-electron/packages/components/src/Terminal/TerminalTab.tsx` | xterm.js renderer that handles `restored` + `scrollbackData` props |
| `collab-electron/src/windows/terminal-tile/src/App.tsx` | Tile component that calls `ptyReconnect` for restored sessions |
| `collab-electron/packages/shared/src/window-api.d.ts` | TypeScript API surface including `ptyReconnect`, `ptyDiscover`, `ptyCleanDetached` |

### 2.2 tmux Session Management (`tmux.ts`)

```
collab-electron/src/main/tmux.ts
```

**Socket naming**: A dedicated tmux socket isolates Collaborator sessions
from any user tmux sessions. The socket name is `collab` in production,
`collab-dev` in development (line 18-19). All tmux commands go through
`baseArgs()` which injects `-L <socketName> -u -f <tmux.conf>`.

**Session naming convention**: Every session is named `collab-{sessionId}`
where `sessionId` is a 16-hex-char random string (`crypto.randomBytes(8)`).
The `tmuxSessionName()` function (line 95-97) applies this prefix.

**Metadata persistence**: Each session writes a JSON sidecar file at
`~/.collaborator/terminal-sessions/{sessionId}.json` containing:

```typescript
interface SessionMeta {
  shell: string;   // e.g. "/bin/zsh"
  cwd: string;     // working directory at creation
  createdAt: string; // ISO timestamp
}
```

This metadata survives independently of tmux. The `discoverSessions()`
function cross-references tmux's live session list with these JSON files
to reconcile state after a restart.

**Binary resolution**: In packaged builds, tmux is bundled at
`process.resourcesPath/tmux`. In development, it uses the system `tmux`.
A bundled `tmux.conf` is similarly resolved. A custom `terminfo` directory
is set via the `TERMINFO` environment variable for the bundled build.

### 2.3 Session Lifecycle (`pty.ts`)

```
collab-electron/src/main/pty.ts
```

**Create** (`createSession`, line 125-167):

1. Generate a random `sessionId`.
2. `tmuxExec("new-session", "-d", "-s", "collab-{sessionId}", "-c", cwd, "-x", cols, "-y", rows)` --
   creates a *detached* tmux session. The shell process runs inside tmux.
3. Set environment variables inside the tmux session:
   `COLLAB_PTY_SESSION_ID` and `SHELL`.
4. Write `SessionMeta` JSON to disk.
5. Call `attachClient()` to spawn a `node-pty` process that runs
   `tmux attach-session -t collab-{sessionId}`.
6. Wire `ptyProcess.onData` to forward output to the renderer via
   Electron's `webContents.send("pty:data", ...)`.

**Reconnect** (`reconnectSession`, line 178-226):

1. Verify the tmux session exists (`tmux has-session`).
2. Capture scrollback: `tmux capture-pane -t collab-{id} -p -e -S -200000`.
   The `-e` flag preserves ANSI escape sequences so colors render correctly.
3. Strip trailing blank lines from the captured scrollback.
4. Call `attachClient()` to spawn a new `node-pty` client.
5. Resize the tmux window to match the new terminal dimensions.
6. Return `{ sessionId, shell, meta, scrollback }` to the renderer.

**Discover** (`discoverSessions`, line 339-388):

1. List all tmux sessions: `tmux list-sessions -F "#{session_name}"`.
2. Read all `.json` files from the metadata directory.
3. Cross-reference: sessions with both a live tmux session AND a metadata
   file are returned as `DiscoveredSession[]`.
4. Stale metadata without a matching tmux session is deleted.
5. Orphan tmux sessions (prefixed `collab-` but no metadata) are killed.

**Shutdown** (`killAll` / `killAllAndWait`, lines 288-323):

1. Set `shuttingDown = true`.
2. Kill all `node-pty` client processes (the `tmux attach` wrappers).
3. Do NOT kill the tmux sessions themselves. They survive.

**Explicit kill** (`killSession`, line 265-282):

1. Kill the `node-pty` client.
2. Kill the tmux session: `tmux kill-session -t collab-{id}`.
3. Delete the metadata JSON file.

**Clean detached** (`cleanDetachedSessions`, line 469-481):

Called periodically to garbage-collect sessions that are no longer
tracked by the frontend. Checks both the active session ID list and the
tmux `session_attached` count -- sessions with at least one attached
client are preserved even if not in the active list (prevents killing
sessions during brief reattach windows).

### 2.4 tmux Configuration

```
collab-electron/resources/tmux.conf
```

```conf
set -g status off          # No tmux status bar (the app provides its own UI)
set -g prefix None         # No prefix key (all input goes straight to the shell)
unbind-key C-b
set -g escape-time 0       # No delay on escape sequences
set -g default-terminal "xterm-256color"
set -g history-limit 200000  # 200k lines of scrollback
set -g mouse off           # App handles mouse events
set -g focus-events on
set -g allow-passthrough on  # Allows OSC sequences to pass through to the outer terminal
set -ga terminal-overrides ",xterm-256color:Tc:smcup@:rmcup@"
```

Key design choices:
- `prefix None` + `unbind-key C-b` ensures tmux is invisible. Users
  interact with the shell, not tmux.
- `history-limit 200000` provides deep scrollback for `capture-pane`.
- `allow-passthrough on` enables Kitty/iTerm2 image protocols and other
  modern terminal features.

### 2.5 Frontend Reconnection Flow

When the Collaborator app starts, the shell window's `terminal-tile/App.tsx`
reads URL parameters to determine if a tile represents a restored session:

1. If `?restored=1&sessionId=xxx` is present, call `ptyReconnect(sessionId, cols, rows)`.
2. The response includes `scrollback` (the captured pane content with ANSI escapes).
3. The `TerminalTab` component writes the scrollback into xterm.js, then
   on first real data from the reattached client, clears the viewport
   (`\x1b[2J\x1b[H`) so tmux's live screen draw takes over cleanly.
4. If `ptyReconnect` fails (session died between discovery and reattach),
   fall back to creating a fresh session.

---

## 3. Adaptation for Tauri

The workbench is a Tauri 2 app. It does not have Node.js in the backend --
the process management layer is Rust. This section evaluates the options
for adding tmux support.

### 3.1 Current Architecture

```
src-tauri/src/commands/terminal.rs   -- Rust PTY backend using portable-pty
src/lib/workbench/terminal-service.ts -- TS bridge: invoke() wrappers
src/components/workbench/swarm-board/terminal-renderer.tsx -- ghostty-web renderer
src/features/swarm/stores/swarm-board-store.tsx -- Zustand store + Provider
```

The Rust backend (`terminal.rs`) does:
- `native_pty_system().openpty()` to create a PTY pair.
- Spawns a shell via `CommandBuilder` on the slave side.
- Reads from the master in a `spawn_blocking` thread, emitting
  `terminal:output:{id}` Tauri events.
- Stores sessions in a `HashMap<String, TerminalSession>` behind
  `Arc<Mutex<...>>` (the `TerminalState`).
- On app exit (`RunEvent::Exit`), calls `kill_all_sessions()` which
  kills every child process.

The frontend (`terminal-renderer.tsx`) uses `ghostty-web` (a WASM-based
terminal renderer using Ghostty's VT100 parser). It subscribes to Tauri
events for output and calls `terminal_write` / `terminal_resize` for input.

### 3.2 Integration Strategy: Rust tmux Wrapper

**Recommended approach**: Add a Rust `tmux.rs` module in
`src-tauri/src/commands/` that mirrors the Collaborator's `tmux.ts`
semantics. Use `std::process::Command` to shell out to `tmux`, exactly
as the Collaborator uses `execFileSync`/`execFile`.

This is the simplest, most battle-tested path:

```
src-tauri/src/commands/tmux.rs    (NEW -- tmux binary interaction)
src-tauri/src/commands/terminal.rs (MODIFIED -- optional tmux mode)
```

**Why not a Rust PTY crate + tmux protocol?** Tmux communicates via its
own control-mode protocol, but the Collaborator approach of spawning
`tmux attach-session` as a PTY child is simpler and proven. The `portable-pty`
crate already handles the PTY allocation; we just change what command
runs inside it.

**Why not Tauri's shell plugin?** `tauri-plugin-shell` is designed for
sidecar management (spawn, communicate via stdin/stdout). It does not
provide PTY allocation, which is required for terminal emulation. We
need the existing `portable-pty` path, just with tmux as the command.

### 3.3 tmux Binary Resolution

| Environment | tmux Source |
|-------------|-------------|
| macOS dev   | System tmux (`/opt/homebrew/bin/tmux` or `/usr/local/bin/tmux`) |
| macOS release | Bundled in `src-tauri/resources/bin/tmux-{target_triple}` |
| Linux dev   | System tmux (`/usr/bin/tmux`) |
| Linux release | Bundled or require system install (distro packages) |
| Windows     | Not supported initially (see Section 8) |

The bundled binary goes into `src-tauri/resources/bin/` alongside the
existing `workbench-mcp` sidecar. Tauri's `bundle.resources` config
already includes `resources/**/*` (see `tauri.conf.json:44-47`).

Resolution logic in `tmux.rs`:

```rust
fn tmux_bin() -> PathBuf {
    if cfg!(debug_assertions) {
        // Dev mode: use system tmux
        PathBuf::from("tmux")
    } else {
        // Release: bundled binary
        let resource_dir = tauri::api::path::resource_dir(...)
            .expect("resource dir");
        resource_dir.join("bin").join("tmux")
    }
}
```

### 3.4 ghostty-web Renderer Changes

The `terminal-renderer.tsx` component currently connects directly to PTY
output. With tmux, the data flow is identical -- the PTY child process is
`tmux attach-session` instead of `/bin/zsh`, but from the renderer's
perspective, it is still reading terminal output from a Tauri event stream.

The only renderer change needed is **scrollback restoration**: on reconnect,
the captured pane content must be written to the ghostty-web Terminal
instance before live data starts flowing. This mirrors the Collaborator's
`TerminalTab.tsx` pattern:

```typescript
// In terminal-renderer.tsx, add a scrollbackData prop
if (scrollbackData) {
  term.write(scrollbackData);
}
// On first real data chunk from the reattached session:
term.write("\x1b[2J\x1b[H"); // clear viewport, preserve scrollback
```

---

## 4. Session Lifecycle

### 4.1 Lifecycle States

```
  spawn ──> attach ──> [app running] ──> detach (app quit)
                                              │
                                              v
                             [tmux session persists on host]
                                              │
                                              v
                                    reattach (app restart)
                                              │
                                              v
                                   kill (explicit user action)
```

### 4.2 Spawn

Maps to `SwarmBoardProvider.spawnSession()` and
`SwarmBoardProvider.spawnClaudeSession()`.

Current flow in `swarm-board-store.tsx:1254`:
```typescript
const sessionInfo = await terminalService.create(cwd, opts.shell);
```

New flow:

1. Rust `terminal_create` checks feature flag `tmux_sessions`.
2. If enabled, calls `tmux::create_session(session_id, cwd, cols, rows)`:
   - `tmux new-session -d -s swarm-{session_id} -c {cwd} -x {cols} -y {rows}`
   - Writes metadata JSON to `~/.clawdstrike/terminal-sessions/{session_id}.json`
3. Then calls `tmux::attach_client(session_id, cols, rows)`:
   - Spawns `portable-pty` with command = `tmux -L clawdstrike attach-session -t swarm-{session_id}`
   - Wires the reader thread exactly as today
4. Returns `SessionInfo` to frontend (unchanged shape).

### 4.3 Session Naming

Convention: `swarm-{session_id}` where `session_id` is the existing UUID.

tmux socket name: `clawdstrike` (production), `clawdstrike-dev` (debug).

This isolates swarm board sessions from any user tmux and from any
Collaborator tmux sessions (which use socket `collab`).

### 4.4 Attach / Detach

**Attach** happens automatically at spawn and at reconnect. The Rust
backend spawns `tmux attach-session` inside a `portable-pty` pair.

**Detach** happens when:
- The app quits gracefully (`RunEvent::Exit`): the Rust backend kills
  the `portable-pty` children but does NOT kill tmux sessions.
- The app crashes: the OS reaps the child processes. The tmux server
  (a separate process started by the first `tmux new-session`) remains
  alive.

The modified `kill_all_sessions()` becomes `detach_all_sessions()`:

```rust
pub async fn detach_all_sessions(state: &TerminalState) {
    let mut manager = state.lock().await;
    for (_, session) in manager.sessions.drain() {
        session.alive.store(false, Ordering::SeqCst);
        let _ = session.child.kill(); // kills the tmux-attach client, not the tmux session
        // DO NOT call tmux kill-session
    }
}
```

### 4.5 Reattach

New Tauri command: `terminal_reconnect`.

```rust
#[tauri::command]
pub async fn terminal_reconnect<R: Runtime>(
    app: AppHandle<R>,
    state: tauri::State<'_, TerminalState>,
    session_id: String,
    cols: u16,
    rows: u16,
) -> Result<ReconnectInfo, String> { ... }
```

Steps:
1. Verify tmux session exists: `tmux has-session -t swarm-{session_id}`.
2. Capture scrollback: `tmux capture-pane -t swarm-{id} -p -e -S -200000`.
3. Spawn new `portable-pty` attach client.
4. Resize: `tmux resize-window -t swarm-{id} -x {cols} -y {rows}`.
5. Return `ReconnectInfo { session_id, scrollback, meta }`.

### 4.6 Kill

Explicit kill (user presses "Kill Session" on a node):
1. Kill the `portable-pty` client.
2. `tmux kill-session -t swarm-{session_id}`.
3. Delete metadata JSON.
4. Remove ring buffer.

This maps to the existing `killSession` callback in `SwarmBoardProvider`
(line 1425-1470 of `swarm-board-store.tsx`).

---

## 5. Raising the Terminal Cap

### 5.1 Current Limits

| Layer    | Constant               | Value | File |
|----------|------------------------|-------|------|
| Frontend | `MAX_ACTIVE_TERMINALS` | 8     | `swarm-board-store.tsx:45` |
| Backend  | `MAX_ACTIVE_SESSIONS`  | 32    | `terminal.rs:45` |

The frontend cap at 8 was set because each active session holds an
in-process PTY with a blocking reader thread, a ring buffer, and a
ghostty-web WASM renderer in the DOM. All of these consume resources
proportional to the number of sessions.

### 5.2 tmux Decoupling

With tmux, the resource accounting changes:

| Resource | Without tmux | With tmux |
|----------|-------------|-----------|
| PTY pair (kernel) | 1 per session | 1 per *attached* session |
| Reader thread | 1 per session | 1 per *attached* session |
| Ring buffer | 1 per session | 1 per *attached* session (tmux has its own scrollback) |
| Ghostty renderer | 1 per session | 1 per *visible* session |
| tmux server memory | N/A | ~2MB base + ~1MB per session (scrollback) |

**Attached** means a `tmux attach-session` client is running. Detached
sessions (running but not displayed) consume only tmux server memory.

### 5.3 New Limits

Replace the hard cap with a tiered model:

```typescript
// swarm-board-store.tsx
export const MAX_ATTACHED_TERMINALS = 8;  // renderer resource limit (ghostty-web instances)
export const MAX_TOTAL_SESSIONS = 64;     // tmux sessions (attached + detached)
```

The frontend only mounts `<TerminalRenderer>` for nodes that are
currently visible in the viewport or selected. Nodes scrolled out of
view have their `portable-pty` client detached (the tmux session keeps
running). When the user scrolls back or selects the node, it reattaches.

The backend `MAX_ACTIVE_SESSIONS` semaphore in `terminal.rs` should be
increased to `MAX_TOTAL_SESSIONS` (or removed entirely, since tmux
manages its own process table).

### 5.4 Lazy Attach / Detach

React Flow's viewport culling already provides visibility signals. The
`TerminalRenderer` component can implement lazy attach:

```typescript
// Pseudocode for the agent-session-node
const isInViewport = useInViewport(nodeRef);
const isSelected = nodeId === selectedNodeId;
const shouldAttach = isInViewport || isSelected;

{shouldAttach ? (
  <TerminalRenderer sessionId={sessionId} active={isSelected} />
) : (
  <TerminalPreview lines={previewLines} />
)}
```

When `shouldAttach` transitions false -> true, the renderer calls
`terminal_reconnect` to reattach. When it transitions true -> false, it
can optionally call a new `terminal_detach` command that kills the
`portable-pty` client but leaves the tmux session alive.

---

## 6. State Recovery

### 6.1 On App Restart

```
App launches
  |
  v
Rust: tmux::discover_sessions()
  |-- tmux list-sessions -F "#{session_name}"
  |-- Read ~/.clawdstrike/terminal-sessions/*.json
  |-- Cross-reference: return matched sessions
  |-- Clean orphans (tmux sessions with no metadata, metadata with no tmux session)
  |
  v
Frontend: terminalService.discover() -> DiscoveredSession[]
  |
  v
SwarmBoardProvider: match discovered sessions to persisted board nodes
  |-- For each node with a saved tmuxSessionId:
  |     If session is in discovered list:
  |       -> Set status "running", store sessionId
  |       -> When node becomes visible, TerminalRenderer calls terminal_reconnect
  |     Else:
  |       -> Set status "completed" (session died while app was closed)
  |
  v
Board renders with restored state
```

### 6.2 New Tauri Command: `terminal_discover`

```rust
#[tauri::command]
pub async fn terminal_discover() -> Result<Vec<DiscoveredSession>, String> {
    tmux::discover_sessions()
}
```

### 6.3 New Terminal Service Method

```typescript
// terminal-service.ts
discover: (): Promise<DiscoveredSession[]> =>
  invoke<DiscoveredSession[]>("terminal_discover"),
```

### 6.4 Persistence Changes

Currently, `loadPersistedBoard()` in `swarm-board-store.tsx:138-149`
strips `sessionId` from all persisted nodes:

```typescript
// Strip sessionId from persisted nodes -- PTY sessions don't survive reloads
const sanitizedNodes = validNodes.map((n) => {
  if (n.data?.sessionId) {
    return {
      ...n,
      data: {
        ...n.data,
        sessionId: undefined,
        status: n.data.status === "running" ? "idle" : n.data.status,
      },
    };
  }
  return n;
});
```

With tmux, this logic changes:

```typescript
// When tmux is enabled, preserve sessionId but add a tmuxSessionName field
// so the recovery flow can match discovered sessions to nodes.
const sanitizedNodes = validNodes.map((n) => {
  if (n.data?.sessionId) {
    return {
      ...n,
      data: {
        ...n.data,
        // Keep sessionId for tmux recovery matching
        // Status will be updated after discovery reconciliation
        status: "idle", // temporary; recovery sets to "running" if tmux session alive
        tmuxPendingRecovery: true,
      },
    };
  }
  return n;
});
```

A new field `tmuxSessionName` (type `string | undefined`) is added to
`SwarmBoardNodeData` in `swarm-board-types.ts`. This stores the tmux
session name (e.g., `swarm-{uuid}`) for recovery matching.

### 6.5 Recovery Reconciliation in SwarmBoardProvider

Add a `useEffect` in `SwarmBoardProvider` that runs after mount:

```typescript
useEffect(() => {
  if (!tmuxEnabled) return;

  terminalService.discover().then((discovered) => {
    const discoveredMap = new Map(discovered.map(d => [d.sessionId, d]));
    const { actions, nodes } = useSwarmBoardStore.getState();

    for (const node of nodes) {
      const d = node.data;
      if (!d.tmuxPendingRecovery || !d.sessionId) continue;

      if (discoveredMap.has(d.sessionId)) {
        // Session survived -- mark as running, clear recovery flag
        actions.updateNode(node.id, {
          status: "running",
          tmuxPendingRecovery: undefined,
        });
      } else {
        // Session died while app was closed
        actions.updateNode(node.id, {
          sessionId: undefined,
          status: "completed",
          tmuxPendingRecovery: undefined,
        });
      }
    }
  }).catch(() => {
    // tmux not available or discover failed -- clear all pending recovery flags
    // and strip sessionIds (fall back to non-persistent behavior)
  });
}, []);
```

---

## 7. Migration Strategy

### 7.1 Feature Flag

Add a feature flag `tmux_sessions` that controls whether the tmux path
is used. This allows shipping the code behind a gate and rolling it out
incrementally.

**Rust side** (`terminal.rs`):

```rust
fn tmux_enabled() -> bool {
    std::env::var("CLAWDSTRIKE_TMUX_SESSIONS")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false)
}
```

**Frontend side** (`terminal-service.ts`):

```typescript
export const TMUX_ENABLED = import.meta.env.VITE_TMUX_SESSIONS === "true";
```

### 7.2 Parallel Code Paths

When `tmux_enabled()` is false, the existing `terminal_create` /
`terminal_kill` / `kill_all_sessions` code paths are used unchanged.
No tmux binary is required.

When `tmux_enabled()` is true:

| Command | Without tmux | With tmux |
|---------|-------------|-----------|
| `terminal_create` | Spawn shell in PTY | Create tmux session, then attach |
| `terminal_write` | Write to PTY master | Write to PTY master (unchanged -- the PTY connects to `tmux attach`) |
| `terminal_resize` | Resize PTY | Resize PTY + `tmux resize-window` |
| `terminal_kill` | Kill child + drop PTY | Kill child + `tmux kill-session` + delete metadata |
| `kill_all_sessions` | Kill all children | Detach all clients (tmux sessions survive) |
| `terminal_reconnect` | N/A (new) | Verify session, capture scrollback, attach |
| `terminal_discover` | N/A (new) | List tmux sessions, cross-reference metadata |

### 7.3 New Rust Module: `tmux.rs`

```
src-tauri/src/commands/tmux.rs
```

Public API:

```rust
pub struct SessionMeta {
    pub shell: String,
    pub cwd: String,
    pub created_at: String,
}

pub struct DiscoveredSession {
    pub session_id: String,
    pub meta: SessionMeta,
}

pub fn tmux_available() -> bool;
pub fn create_tmux_session(id: &str, cwd: &str, cols: u16, rows: u16) -> Result<(), String>;
pub fn has_session(id: &str) -> bool;
pub fn capture_scrollback(id: &str) -> Result<String, String>;
pub fn resize_window(id: &str, cols: u16, rows: u16) -> Result<(), String>;
pub fn kill_tmux_session(id: &str) -> Result<(), String>;
pub fn discover_sessions() -> Vec<DiscoveredSession>;
pub fn write_session_meta(id: &str, meta: &SessionMeta) -> Result<(), String>;
pub fn read_session_meta(id: &str) -> Option<SessionMeta>;
pub fn delete_session_meta(id: &str);
```

Socket name: `clawdstrike` / `clawdstrike-dev`.
Metadata directory: `~/.clawdstrike/terminal-sessions/`.
Session name prefix: `swarm-`.

### 7.4 tmux.conf for Swarm Board

Create `src-tauri/resources/tmux.conf`:

```conf
set -g status off
set -g prefix None
unbind-key C-b
set -g escape-time 0
set -g default-terminal "xterm-256color"
set -g history-limit 200000
set -g mouse off
set -g focus-events on
set -g allow-passthrough on
set -ga terminal-overrides ",xterm-256color:Tc:smcup@:rmcup@"
```

This is identical to the Collaborator config. The config file is
referenced via `-f` in all tmux commands (same pattern as
`tmux.ts:baseArgs()`).

### 7.5 Fallback Behavior

If `tmux_enabled()` is true but the tmux binary is not found:

1. `terminal_create` attempts to verify tmux availability.
2. If tmux is missing, log a warning and fall back to the direct PTY path.
3. Set an `app_state.tmux_fallback = true` flag so subsequent creates
   skip the tmux check.
4. Emit a Tauri event `tmux:unavailable` so the frontend can show a
   non-blocking toast: "tmux not found -- sessions will not persist
   across restarts."

### 7.6 Implementation Phases

**Phase 1 -- Rust tmux module + create/kill**
- Implement `tmux.rs` with `create_tmux_session`, `kill_tmux_session`, `tmux_available`.
- Modify `terminal_create` to optionally route through tmux.
- Modify `kill_all_sessions` to detach instead of kill when tmux is enabled.
- Add `src-tauri/resources/tmux.conf`.
- Feature-flag everything behind `CLAWDSTRIKE_TMUX_SESSIONS=1`.
- Test: sessions survive `cargo tauri dev` restart.

**Phase 2 -- Discover + reconnect**
- Implement `discover_sessions`, `capture_scrollback`, `terminal_reconnect`.
- Add `terminal_discover` Tauri command.
- Add `terminalService.discover()` and `terminalService.reconnect()` to
  the frontend bridge.
- Modify `SwarmBoardProvider` to reconcile discovered sessions on mount.
- Modify `TerminalRenderer` to accept and render scrollback data.
- Test: launch board, spawn sessions, quit, relaunch, verify sessions
  reappear with scrollback.

**Phase 3 -- Raise terminal cap + lazy attach**
- Increase `MAX_ACTIVE_TERMINALS` or replace with tiered limits.
- Implement lazy attach/detach based on viewport visibility.
- Add `terminal_detach` command for explicit client-only teardown.

**Phase 4 -- Bundle tmux binary**
- Add macOS universal tmux binary to `src-tauri/resources/bin/`.
- Build script (`build.rs` or `prepare-tauri-build.ts`) to fetch/compile
  tmux for the target platform.
- Linux: document system dependency or bundle static build.

---

## 8. Risks and Mitigations

### 8.1 tmux Availability on Windows

tmux does not run natively on Windows. Options:

| Option | Feasibility | Notes |
|--------|------------|-------|
| Require WSL | Low UX quality | Adds WSL dependency, complicates PTY path |
| Use ConPTY directly | No persistence | Windows has no tmux equivalent |
| Skip persistence on Windows | Acceptable | Document as macOS/Linux-only for now |

**Decision**: tmux sessions are macOS/Linux only. On Windows, the
feature flag is disabled and the existing direct-PTY path is used. The
`tmux_enabled()` check includes a platform guard:

```rust
fn tmux_enabled() -> bool {
    if cfg!(target_os = "windows") { return false; }
    // ... env var check
}
```

### 8.2 Bundling tmux

tmux depends on `libevent` and `ncurses`. Options for macOS bundling:

1. **Static build**: Compile tmux with static linking to libevent and
   ncurses. Produces a single binary with no runtime dependencies.
   The Collaborator project does this successfully.
2. **Homebrew formula extraction**: Not viable for distribution.
3. **Require system install**: Acceptable for Phase 1 (dev mode). For
   release builds, bundle the static binary.

Build script addition to `scripts/prepare-tauri-build.ts`:

```typescript
// Download or compile tmux for the target platform
async function prepareTmux(target: string) {
  const tmuxVersion = "3.5a";
  // ... fetch prebuilt static binary from CI artifact store
  // ... copy to src-tauri/resources/bin/tmux
}
```

A `terminfo` database directory must also be bundled (specifically the
`xterm-256color` entry) and referenced via `TERMINFO` env var, exactly
as the Collaborator does.

### 8.3 Session Cleanup on Agent Kill

When an operator kills an agent session from the board UI, the tmux
session must be killed -- not just detached. The `killSession` callback
in `SwarmBoardProvider` (line 1425) already calls `terminalService.kill()`,
which maps to `terminal_kill`. The modified `terminal_kill` will call
`tmux kill-session` as part of cleanup.

Edge case: if the Tauri app crashes and orphan tmux sessions accumulate,
the `discover_sessions` function cleans them up on next launch:
- Sessions with metadata but no matching board node get killed.
- Sessions without metadata get killed (orphan tmux sessions).

A periodic cleanup timer (e.g., every 5 minutes) can call
`cleanDetachedSessions` to garbage-collect detached sessions whose board
nodes have been removed.

### 8.4 tmux Server Lifecycle

The tmux server process starts automatically when the first
`tmux new-session` runs (on the `clawdstrike` socket). It remains alive
as long as at least one session exists. When the last session is killed,
the server exits.

Risk: if the operator kills all sessions and then expects the app to
restart with them, they are gone. This is expected behavior -- explicit
kill means permanent destruction.

Mitigation: the "Clear Board" action (`clearBoard` in the store) should
warn: "This will permanently destroy all running agent sessions."

### 8.5 Race Conditions During Reconnect

Between `discover_sessions()` and `terminal_reconnect()`, a tmux session
could exit naturally (e.g., Claude Code finishes its task). The
`terminal_reconnect` command must handle `has-session` failure gracefully
and return an error that the frontend interprets as "session ended --
mark as completed."

The Collaborator handles this in `terminal-tile/App.tsx:33-59` by
falling back to a fresh session on reconnect failure. In the swarm board
context, the fallback should be to mark the node as "completed" rather
than spawning a new session, since agent hunts are not re-entrant.

### 8.6 Multiple Workbench Instances

If two workbench windows are open (not currently supported but future
possibility), they share the same tmux socket. The `session_attached`
count tracking in `cleanDetachedSessions` (ported from the Collaborator's
approach) prevents one instance from killing sessions attached by another.

### 8.7 Security: tmux Socket Permissions

The tmux socket is created in `/tmp/tmux-{uid}/` by default. This
directory is user-owned and mode 0700. No additional security measures
are needed -- the socket is only accessible to the current user.

For environments with restrictive `/tmp` (e.g., `noexec` mount), the
`TMUX_TMPDIR` environment variable can override the socket directory.

---

## Appendix A: File Inventory

### Files to Create

| Path | Purpose |
|------|---------|
| `src-tauri/src/commands/tmux.rs` | tmux binary interaction, session metadata CRUD |
| `src-tauri/resources/tmux.conf` | Minimal tmux configuration (headless, passthrough) |

### Files to Modify

| Path | Changes |
|------|---------|
| `src-tauri/src/commands/mod.rs` | Add `pub mod tmux;` |
| `src-tauri/src/commands/terminal.rs` | Feature-gated tmux path in `terminal_create`, `terminal_kill`, `kill_all_sessions`; new `terminal_reconnect` and `terminal_discover` commands |
| `src-tauri/src/main.rs` | Register `terminal_reconnect` and `terminal_discover` in `invoke_handler`; change `RunEvent::Exit` to detach instead of kill when tmux enabled |
| `src-tauri/Cargo.toml` | Add `dirs-next` if not already present (it is -- line 40) |
| `src/lib/workbench/terminal-service.ts` | Add `discover()`, `reconnect()` methods; add `TMUX_ENABLED` flag |
| `src/features/swarm/swarm-board-types.ts` | Add `tmuxSessionName?: string` and `tmuxPendingRecovery?: boolean` to `SwarmBoardNodeData` |
| `src/features/swarm/stores/swarm-board-store.tsx` | Change `loadPersistedBoard` to preserve sessionId when tmux enabled; add recovery reconciliation effect in `SwarmBoardProvider`; change `MAX_ACTIVE_TERMINALS` to tiered model |
| `src/components/workbench/swarm-board/terminal-renderer.tsx` | Add `scrollbackData` prop; write scrollback before live data; clear viewport on first real data chunk |
| `src/lib/workbench/use-terminal-sessions.ts` | Update `canSpawnMore` to use `MAX_ATTACHED_TERMINALS` for renderer limit and `MAX_TOTAL_SESSIONS` for overall |

### Files in Reference Codebase

| Path | What to port |
|------|-------------|
| `collab-electron/src/main/tmux.ts` | Socket naming, `tmuxExec`, `baseArgs`, session meta CRUD -- rewrite in Rust |
| `collab-electron/src/main/pty.ts` | `createSession`, `reconnectSession`, `discoverSessions`, `cleanDetachedSessions`, `killAll` vs `killSession` distinction -- rewrite in Rust |
| `collab-electron/resources/tmux.conf` | Copy verbatim |
| `collab-electron/src/main/tmux.test.ts` | Port test patterns to Rust integration tests |

---

## Appendix B: Sequence Diagrams

### B.1 Spawn (tmux enabled)

```
Frontend                  Rust Backend                 tmux server
   |                          |                            |
   |-- terminal_create ------>|                            |
   |                          |-- tmux new-session -d ---->|
   |                          |<--- ok -------------------|
   |                          |-- write meta JSON          |
   |                          |-- portable-pty spawn:      |
   |                          |   tmux attach-session ---->|
   |                          |<--- PTY output stream -----|
   |<-- SessionInfo ----------|                            |
   |                          |                            |
   |<== terminal:output:{id} events =====================>|
```

### B.2 App Quit + Restart

```
Frontend                  Rust Backend                 tmux server
   |                          |                            |
   |  [app quit]              |                            |
   |                          |-- kill PTY clients ------->| (tmux sessions stay)
   |                          |                            |
   ===== app restarts =====                                |
   |                          |                            |
   |-- terminal_discover ---->|                            |
   |                          |-- tmux list-sessions ----->|
   |                          |<--- session list ----------|
   |                          |-- read meta JSONs          |
   |<-- DiscoveredSession[] --|                            |
   |                          |                            |
   | [reconcile with board]   |                            |
   |                          |                            |
   |-- terminal_reconnect --->|                            |
   |                          |-- tmux capture-pane ------>|
   |                          |<--- scrollback ------------|
   |                          |-- portable-pty spawn:      |
   |                          |   tmux attach-session ---->|
   |<-- ReconnectInfo --------|                            |
   |   (includes scrollback)  |                            |
```

### B.3 Explicit Kill

```
Frontend                  Rust Backend                 tmux server
   |                          |                            |
   |-- terminal_kill -------->|                            |
   |                          |-- kill PTY client          |
   |                          |-- tmux kill-session ------>|
   |                          |<--- ok -------------------|
   |                          |-- delete meta JSON         |
   |<-- ok -------------------|                            |
```
