# 05 — Lower-Effort Wins: JSON-RPC Socket, Disk Persistence, File Watching

**Status**: Draft
**Author**: Engineering
**Target codebase**: `apps/workbench` (Tauri + React, Zustand stores, `@xyflow/react` board)
**Reference codebase**: `standalone/collab-public/collab-electron` (Electron, Node.js main process)

---

## Overview

Three features from the Collaborator project are low-to-medium effort wins that
would materially improve the Clawdstrike Swarm Board. Each addresses a real gap:

| Feature | Gap Today | Impact |
|---------|-----------|--------|
| JSON-RPC Control Socket | No way to script or automate the board from external tools | Unlocks CLI-driven swarm launches, CI integration, agent-to-board communication |
| Disk-Based Persistence | localStorage is lossy (5-10 MB cap, cleared on cache wipe) | Enables version-controllable state, larger boards, reliable recovery |
| File Watching | Board is blind to on-disk changes in detection rules and artifacts | Live updates when rules change, session outputs appear, or artifacts land |

Each section below covers: problem, reference implementation analysis, adaptation
plan for Tauri, method/API design, migration strategy, dependencies, and effort
estimate.

---

## Section A: JSON-RPC Control Socket

### A.1 Problem

The workbench currently has no external control API. The only way to interact
with the swarm board is through the GUI. This means:

- No CLI tool can programmatically add nodes, spawn sessions, or read board state.
- No CI pipeline can push detection results into the board.
- No external agent process can register itself on the board without going
  through the MCP sidecar (which serves a different purpose).
- Debugging and testing require manual UI interaction.

### A.2 Reference Implementation

The Collaborator project implements a JSON-RPC 2.0 server over a Unix domain socket.

**Server**: `collab-electron/src/main/json-rpc-server.ts`

Key design decisions in the reference:
- Uses Node.js `net.createServer` to listen on a Unix socket.
- Socket path: `~/.collaborator/ipc.sock` (dev mode: `~/.collaborator/dev/ipc.sock`),
  derived from `COLLAB_DIR` in `collab-electron/src/main/paths.ts`.
- Writes the actual socket path to `~/.collaborator/socket-path` so CLI tools can
  discover it without knowing whether the app runs in dev or prod mode.
- Newline-delimited JSON-RPC 2.0 protocol (one JSON object per line, responses
  end with `\n`).
- Method registry: `Map<string, MethodEntry>` with handler, description, and
  parameter metadata. Methods are registered via `registerMethod()`.
- Built-in `rpc.discover` method returns all registered methods with descriptions
  and parameter schemas.
- Connection tracking via `Set<Socket>` for clean shutdown.
- Cleanup: removes stale socket file on startup and on `stopJsonRpcServer()`.

**Canvas RPC bridge**: `collab-electron/src/main/canvas-rpc.ts`

This module bridges JSON-RPC methods to the renderer process:
- `registerCanvasRpc(win)` registers methods that proxy to the shell window via
  `webContents.send("canvas:rpc-request", ...)`.
- Responses come back via `ipcMain.on("canvas:rpc-response", ...)`.
- Each request gets a UUID and a 10-second timeout.
- Registered methods:
  - `canvas.tileList` — list all tiles with positions
  - `canvas.tileAdd` — create a tile (type, filePath, position, size)
  - `canvas.tileRemove` — remove a tile by ID
  - `canvas.tileMove` — reposition a tile
  - `canvas.tileResize` — resize a tile
  - `canvas.viewportGet` — get pan/zoom state
  - `canvas.viewportSet` — set pan/zoom state

**Canvas persistence IPC**: `collab-electron/src/main/ipc-canvas.ts`

Exposes `canvas:load-state` and `canvas:save-state` IPC handlers backed by the
disk persistence module.

### A.3 Adaptation for Tauri + Swarm Board

Electron's main process is Node.js, which makes Unix sockets trivial. Tauri's
backend is Rust. Three approaches, in order of preference:

#### Option 1: Rust-side Unix socket server (Recommended)

Add a Rust module `src-tauri/src/commands/rpc_socket.rs` that:

1. Starts a `tokio::net::UnixListener` on `~/.clawdstrike/workbench/ipc.sock`.
2. Accepts connections and reads newline-delimited JSON-RPC messages.
3. Dispatches methods to a registry similar to the reference.
4. For methods that need to read/write board state, communicates with the
   frontend via Tauri events:
   - Rust emits `rpc:request` event to the webview with `{ requestId, method, params }`.
   - Frontend handler in a new `src/lib/rpc-bridge.ts` calls into the Zustand
     stores and emits `rpc:response` back via `invoke`.
5. For methods that can be resolved entirely in Rust (e.g., `session.list` from
   the terminal manager), resolves directly.

**Why this option**: Tokio is already a dependency (`Cargo.toml` shows full
tokio features). No new process to manage. The socket lifecycle is tied to the
app lifecycle, same as the reference. Tauri's event system provides the
main-to-renderer bridge that Electron's IPC provides in the reference.

#### Option 2: Sidecar process

Spawn a small Node/Bun process (like the existing MCP sidecar pattern in
`src-tauri/src/commands/mcp_sidecar.rs`) that hosts the socket server and
communicates with the Tauri app via HTTP or stdin/stdout. This reuses the
reference implementation more directly but adds process management overhead.
Not recommended since the MCP sidecar already fills the "sidecar" slot.

#### Option 3: Tauri plugin

Wrap Option 1 as a Tauri plugin for reuse across apps. Only worthwhile if other
Backbay apps need the same pattern. Defer until needed.

### A.4 Method Design

Map the Collaborator's canvas-oriented methods to the swarm board's domain model.

```
Namespace: board.*
─────────────────────────────────────────────────────────────────────
board.nodeAdd        Add a node to the board
                     Params: { nodeType, title, position?, data? }
                     Returns: { id, position }
                     Maps to: useSwarmBoardStore.actions.addNode()

board.nodeRemove     Remove a node
                     Params: { nodeId }
                     Maps to: useSwarmBoardStore.actions.removeNode()

board.nodeUpdate     Patch node data
                     Params: { nodeId, patch }
                     Maps to: useSwarmBoardStore.actions.updateNode()

board.nodeList       List all nodes with positions and data
                     Returns: { nodes: [...] }
                     Maps to: useSwarmBoardStore.getState().nodes

board.edgeAdd        Add an edge
                     Params: { source, target, type?, label? }
                     Maps to: useSwarmBoardStore.actions.addEdge()

board.edgeRemove     Remove an edge
                     Params: { edgeId }
                     Maps to: useSwarmBoardStore.actions.removeEdge()

board.edgeList       List all edges
                     Returns: { edges: [...] }
                     Maps to: useSwarmBoardStore.getState().edges

board.viewportGet    Get current React Flow viewport
                     Returns: { x, y, zoom }

board.viewportSet    Set viewport pan and zoom
                     Params: { x, y, zoom }

board.clear          Clear the entire board
                     Maps to: useSwarmBoardStore.actions.clearBoard()

board.loadState      Bulk-load board state
                     Params: { nodes, edges, repoRoot? }
                     Maps to: useSwarmBoardStore.actions.loadState()


Namespace: session.*
─────────────────────────────────────────────────────────────────────
session.spawn        Create a new agent session (PTY + worktree)
                     Params: { title, agentModel?, branch?, cwd?, prompt? }
                     Returns: { nodeId, sessionId }
                     Maps to: SwarmBoardSessionContext.spawnSession()

session.kill         Kill a running session
                     Params: { sessionId }
                     Maps to: SwarmBoardSessionContext.killSession()

session.list         List active terminal sessions
                     Returns: { sessions: SessionInfo[] }
                     Maps to: Rust terminal_list command directly

session.status       Get status of a specific session
                     Params: { sessionId }
                     Returns: SessionInfo


Namespace: coordinator.*
─────────────────────────────────────────────────────────────────────
coordinator.status   Get swarm coordinator connection state
                     Returns: { connected, peerCount, swarmId }

coordinator.publish  Publish a finding/detection to the swarm feed
                     Params: { type, payload }
                     Maps to: SwarmCoordinator.publishFinding()


Namespace: rpc.*
─────────────────────────────────────────────────────────────────────
rpc.discover         List all available methods
                     Returns: { methods: [{ name, description, params }] }
```

### A.5 CLI Client

Ship a minimal CLI tool (`csw` or `clawdstrike-board`) that connects to the
Unix socket and sends JSON-RPC:

```bash
# List nodes
csw board.nodeList

# Add a node
csw board.nodeAdd --nodeType agentSession --title "Fix CVE-2026-1234"

# Spawn a session
csw session.spawn --title "Audit auth" --agentModel opus-4.6

# Pipe raw JSON-RPC
echo '{"jsonrpc":"2.0","id":1,"method":"board.nodeList"}' | csw --raw

# Discover available methods
csw rpc.discover
```

Implementation: a small Rust binary (or shell script using `socat`/`nc`) that
reads the socket path from `~/.clawdstrike/workbench/socket-path`, connects,
sends JSON, reads the response line, and prints it.

### A.6 Implementation Plan

| Step | Description | Files |
|------|-------------|-------|
| 1 | Create `RpcSocketState` managed state struct in Rust | `src-tauri/src/commands/rpc_socket.rs` (new) |
| 2 | Implement tokio UnixListener with newline-delimited JSON-RPC parsing | Same file |
| 3 | Build method registry with `rpc.discover` | Same file |
| 4 | Register Rust-resolvable methods (session.list, session.kill) | Same file, calling into `terminal.rs` |
| 5 | Add Tauri event bridge for frontend-resolvable methods | Same file + `src/lib/rpc-bridge.ts` (new) |
| 6 | Wire up board.* methods in the frontend bridge | `src/lib/rpc-bridge.ts` |
| 7 | Register state and start listener in `main.rs` setup | `src-tauri/src/main.rs` |
| 8 | Add cleanup on app exit | `src-tauri/src/main.rs` RunEvent::Exit handler |
| 9 | Build CLI client | `tools/csw/` (new, small Rust binary or script) |
| 10 | Write integration tests | `src-tauri/tests/rpc_socket.rs` (new) |

### A.7 Dependencies

- `tokio` (already present with `net` feature)
- `serde_json` (already present)
- `dirs-next` (already present, for `~/.clawdstrike/` path)
- No new crate dependencies required for the core socket server.

### A.8 Effort Estimate

**Medium (M)** — 3-5 engineering days.

The Rust socket server is straightforward with tokio. The main complexity is the
event bridge between Rust and the frontend Zustand stores, which mirrors what
the Collaborator does between Electron main and renderer processes. The CLI
client is a half-day addition.

---

## Section B: Disk-Based Persistence

### B.1 Problem

The workbench currently persists all state to `localStorage`:

- **swarm-board-store.tsx** (line 74-98): Saves board nodes/edges under key
  `clawdstrike_workbench_swarm_board`. Has a partial file-backed path for
  `.swarm` bundles via `writeSwarmBoardJson()` in `tauri-bridge.ts`, but the
  primary persistence is still localStorage.
- **swarm-store.tsx** (line 48-73): Saves swarm CRUD data under key
  `clawdstrike_workbench_swarms`.
- **swarm-feed-store.tsx** (line 39): Saves feed data under key
  `clawdstrike_workbench_swarm_feed`.

Problems with localStorage:

1. **Size limit**: 5-10 MB depending on browser engine. A board with 50+ nodes,
   each carrying preview lines and metadata, can approach this limit. The swarm
   feed with accumulated finding envelopes will hit it faster.
2. **Data loss**: Clearing browser data / Tauri webview cache wipes everything.
   There is no warning.
3. **Not version-controllable**: State cannot be checked into git or diffed
   meaningfully.
4. **No atomicity**: `localStorage.setItem` can be interrupted by a crash,
   leaving corrupted JSON.
5. **Single-tab**: If multiple windows were ever opened, localStorage would
   create conflicts.

### B.2 Reference Implementation

The Collaborator project uses file-based persistence with atomic writes.

**Canvas persistence**: `collab-electron/src/main/canvas-persistence.ts`

- State file: `~/.collaborator/canvas-state.json` (derived from `COLLAB_DIR`)
- Data structure:
  ```typescript
  interface CanvasState {
    version: 1;
    tiles: TileState[];     // id, type, x, y, width, height, filePath, zIndex
    viewport: { panX, panY, zoom };
  }
  ```
- `loadState()`: Reads file, parses JSON, validates version field, returns null
  on any error.
- `saveState()`: Atomic write pattern:
  1. Write to a temp file in `os.tmpdir()` with a random UUID name.
  2. `rename()` (atomic on POSIX) the temp file to the final path.
  3. This guarantees the state file is never half-written.

**App config**: `collab-electron/src/main/config.ts`

- Config file: `~/.collaborator/config.json`
- Uses `atomicWriteFileSync()` from `collab-electron/src/main/files.ts`
  (synchronous rename-based atomic write).
- Stores: workspace list, active workspace index, window state, UI preferences.

**Workspace config**: `collab-electron/src/main/workspace-config.ts`

- Per-workspace config: `<workspace>/.collaborator/config.json`
- Uses the same `atomicWriteFileSync` pattern.

**Key patterns to carry forward**:
- Versioned state format (enables future migrations)
- Atomic write (temp file + rename)
- Separate files for separate concerns (board state, config, sessions)
- Directory creation on first write (`mkdirSync(dir, { recursive: true })`)

### B.3 Adaptation for Tauri

Use Tauri's `@tauri-apps/plugin-fs` (already enabled in `capabilities/default.json`
with `fs:allow-read-text-file`, `fs:allow-write-text-file`, `fs:allow-rename`,
`fs:allow-mkdir`) to read/write to `~/.clawdstrike/workbench/`.

Alternatively, persistence can be done on the Rust side via Tauri commands,
which avoids the fs plugin permission surface. Given that the stores live in
the frontend (Zustand), the pragmatic approach is:

**Hybrid**: Frontend reads/writes files via Tauri's fs plugin for the hot path
(debounced saves). A Rust-side helper handles atomic writes (write to `.tmp`,
then rename) since the fs plugin's `writeTextFile` is not atomic.

#### File Layout

```
~/.clawdstrike/workbench/
  board-state.json      Nodes, edges, viewport, boardId, repoRoot
  sessions.json         Agent session metadata (survives app restart)
  swarms.json           Swarm CRUD data (members, policies, intel refs)
  swarm-feed.json       Swarm feed finding envelopes
  config.json           App preferences, UI state, window state
```

#### State File Schemas

**board-state.json** (replaces localStorage key `clawdstrike_workbench_swarm_board`):
```json
{
  "version": 1,
  "boardId": "board-m3x9k2",
  "repoRoot": "/Users/user/project",
  "nodes": [
    {
      "id": "agentSession-m3x9k2-1",
      "type": "agentSession",
      "position": { "x": 80, "y": 60 },
      "data": { "title": "Fix auth", "status": "running", "nodeType": "agentSession" }
    }
  ],
  "edges": [
    { "id": "edge-1", "source": "node-1", "target": "node-2", "type": "handoff" }
  ],
  "viewport": { "x": 0, "y": 0, "zoom": 1 }
}
```

**sessions.json** (new, currently not persisted across restarts):
```json
{
  "version": 1,
  "sessions": [
    {
      "id": "uuid",
      "nodeId": "agentSession-m3x9k2-1",
      "cwd": "/Users/user/project",
      "branch": "feat/fix-auth",
      "worktreePath": "/Users/user/project/.worktrees/fix-auth",
      "createdAt": "2026-03-25T10:00:00Z",
      "agentModel": "opus-4.6",
      "lastStatus": "running"
    }
  ]
}
```

**swarms.json** (replaces localStorage key `clawdstrike_workbench_swarms`):
```json
{
  "version": 1,
  "swarms": [...],
  "activeSwarmId": "swm-abc123",
  "invitationTracking": {}
}
```

**config.json** (replaces scattered localStorage keys):
```json
{
  "version": 1,
  "ui": {
    "sidebarWidth": 260,
    "inspectorOpen": false,
    "theme": "obsidian"
  },
  "recentProjects": ["/Users/user/project"],
  "generalSettings": {}
}
```

### B.4 Atomic Write Implementation

Add a Tauri command for atomic file writes:

```rust
// src-tauri/src/commands/persistence.rs (new)

#[tauri::command]
pub async fn atomic_write_file(
    path: String,
    content: String,
) -> Result<(), String> {
    let target = std::path::Path::new(&path);
    let dir = target.parent().ok_or("Invalid path")?;
    tokio::fs::create_dir_all(dir).await.map_err(|e| e.to_string())?;

    let tmp_path = dir.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    tokio::fs::write(&tmp_path, &content).await.map_err(|e| e.to_string())?;
    tokio::fs::rename(&tmp_path, &target).await.map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn read_state_file(path: String) -> Result<Option<String>, String> {
    match tokio::fs::read_to_string(&path).await {
        Ok(content) => Ok(Some(content)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}
```

### B.5 Persistence Layer (Frontend)

Create a new module `src/lib/disk-persistence.ts` that replaces the localStorage
calls in each store:

```typescript
// src/lib/disk-persistence.ts

import { invoke } from "@tauri-apps/api/core";
import { isDesktop } from "./tauri-bridge";

const BASE_DIR = "~/.clawdstrike/workbench"; // Resolved by Rust side

export async function loadStateFile<T>(filename: string): Promise<T | null> {
  if (!isDesktop()) return loadFromLocalStorage(filename); // fallback
  const content = await invoke<string | null>("read_state_file", {
    path: `${BASE_DIR}/${filename}`,
  });
  if (!content) return null;
  return JSON.parse(content) as T;
}

export async function saveStateFile(filename: string, data: unknown): Promise<void> {
  if (!isDesktop()) { saveToLocalStorage(filename, data); return; }
  await invoke("atomic_write_file", {
    path: `${BASE_DIR}/${filename}`,
    content: JSON.stringify(data, null, 2),
  });
}
```

### B.6 Debouncing & Atomicity

The reference implementation in `collab-electron/src/main/canvas-persistence.ts`
writes atomically on every call. The stores in the target already debounce at
500ms (see `swarm-board-store.tsx` line 519-527 and `swarm-store.tsx` line
224-232). Keep this pattern:

```
Store mutation
  -> schedulePersist() [500ms debounce, matches reference]
     -> persistBoard() or persistSwarms()
        -> saveStateFile("board-state.json", data)
           -> invoke("atomic_write_file", { path, content })
              -> Rust: write .tmp then rename
```

The 500ms debounce already matches the Collaborator's practice. The atomic write
(temp + rename) matches `collab-electron/src/main/canvas-persistence.ts` lines
51-57.

### B.7 Migration Strategy

The migration must be non-destructive. Users who upgrade should not lose their
existing board state.

| Step | Action |
|------|--------|
| 1 | On app startup, check if `~/.clawdstrike/workbench/board-state.json` exists |
| 2 | If it does NOT exist, check localStorage for `clawdstrike_workbench_swarm_board` |
| 3 | If localStorage has data, write it to disk, then remove the localStorage key |
| 4 | Repeat for `swarms.json` (from `clawdstrike_workbench_swarms`) and `swarm-feed.json` |
| 5 | Going forward, all reads/writes go to disk |
| 6 | Keep localStorage as a read-only fallback for one release cycle, then remove |

Implementation: a `migrateLocalStorageToDisk()` async function called once during
app initialization (in `App.tsx` or a boot sequence hook), gated by a
`migration_completed` flag in `config.json`.

### B.8 Implementation Plan

| Step | Description | Files |
|------|-------------|-------|
| 1 | Add `persistence.rs` with `atomic_write_file` and `read_state_file` commands | `src-tauri/src/commands/persistence.rs` (new) |
| 2 | Register commands in `main.rs` | `src-tauri/src/main.rs` |
| 3 | Create `src/lib/disk-persistence.ts` with load/save helpers | `src/lib/disk-persistence.ts` (new) |
| 4 | Refactor `swarm-board-store.tsx`: replace `localStorage.setItem`/`getItem` with `disk-persistence` calls | `src/features/swarm/stores/swarm-board-store.tsx` |
| 5 | Refactor `swarm-store.tsx`: same replacement | `src/features/swarm/stores/swarm-store.tsx` |
| 6 | Refactor `swarm-feed-store.tsx`: same replacement | `src/features/swarm/stores/swarm-feed-store.tsx` |
| 7 | Add migration logic | `src/lib/disk-persistence.ts` |
| 8 | Update `capabilities/default.json` fs scope if needed (already allows `$HOME/**`) | `src-tauri/capabilities/default.json` |
| 9 | Add version field to all state schemas | All store files |
| 10 | Write tests for atomic write, migration, and round-trip persistence | `src-tauri/tests/persistence.rs`, `src/lib/__tests__/disk-persistence.test.ts` |

### B.9 Dependencies

- No new crate dependencies (uses `tokio::fs`, `uuid`, both already present).
- No new npm dependencies.
- The existing `fs:allow-rename` capability is required for the atomic write
  pattern from the frontend side. It is already present in `default.json`.

### B.10 Effort Estimate

**Small-Medium (S-M)** — 2-3 engineering days.

The Rust commands are trivial. The main work is refactoring the three Zustand
stores to use async persistence instead of synchronous localStorage, and
writing the migration path. The stores already have a clean `persistBoard()` /
`persistSwarms()` function that isolates the storage call, so the change surface
is small.

---

## Section C: File Watching

### C.1 Problem

The swarm board is blind to filesystem changes. Detection rules edited in an
external editor, session output logs written by agent processes, and artifacts
produced by worktree operations do not trigger any UI update. Users must
manually refresh or re-open files. Specific scenarios:

- An operator edits a Sigma rule YAML in their preferred editor. The board's
  artifact node still shows the old content.
- An agent session writes output to a log file. The session node's preview
  does not update.
- A `git worktree` operation produces new files. The board does not know.
- A `.swarm` bundle's `board.json` is edited externally (e.g., by the JSON-RPC
  CLI tool). The board does not pick up the change.

### C.2 Reference Implementation

The Collaborator project uses `@parcel/watcher` in a worker process.

**Watcher manager**: `collab-electron/src/main/watcher.ts`

- Forks an Electron utility process (`watcher-worker.js`) to isolate the
  native watcher from the main process.
- Exposes `watchWorkspace(path)`, `stopWorker()`, and `setNotifyFn(fn)`.
- The notify function receives `FsChangeEvent[]` (grouped by directory) with
  each change having a `path` and `type` (1=create, 2=update, 3=delete).
- Auto-restarts the worker up to 5 times on crash.

**Watcher worker**: `collab-electron/src/main/watcher-worker.ts`

- Uses `@parcel/watcher.subscribe()` for native OS file watching
  (FSEvents on macOS, inotify on Linux, ReadDirectoryChanges on Windows).
- Ignore list: `.git`, `node_modules`, `dist`, `build`, `.next`, `.cache`,
  `__pycache__`, minified files, source maps.
- Groups raw events by directory into `FsChangeEvent[]` and posts to parent.
- Commands received via `process.parentPort.on("message")`:
  `watch`, `unwatch`, `close`.

**Integration**: `collab-electron/src/main/ipc-workspace.ts` line 95-96

```typescript
watcher.watchWorkspace(path);
```

Called when a workspace is opened or switched. The notify function forwards
change events to the renderer, which updates the tree view and file content.

### C.3 Adaptation for Tauri

The Collaborator's approach (worker process + @parcel/watcher) does not
translate directly. Tauri options:

#### Option 1: Rust-side `notify` crate (Recommended)

The `notify` crate is the Rust ecosystem standard for filesystem watching.
It uses the same native APIs as @parcel/watcher (FSEvents, inotify,
ReadDirectoryChanges).

Add a new Rust module `src-tauri/src/commands/file_watcher.rs`:

```rust
use notify::{recommended_watcher, Event, RecursiveMode, Watcher};
use std::sync::mpsc;
use tauri::{AppHandle, Emitter};

pub struct FileWatcherState {
    watcher: Option<notify::RecommendedWatcher>,
}

pub fn start_watching(
    app: &AppHandle,
    paths: Vec<String>,
) -> Result<(), String> {
    let app_handle = app.clone();
    let (tx, rx) = mpsc::channel::<Event>();

    let watcher = recommended_watcher(tx).map_err(|e| e.to_string())?;

    // Forward events to frontend
    std::thread::spawn(move || {
        while let Ok(event) = rx.recv() {
            let _ = app_handle.emit("fs:change", &event);
        }
    });

    // Watch each path
    for path in &paths {
        watcher.watch(path.as_ref(), RecursiveMode::Recursive)
            .map_err(|e| e.to_string())?;
    }

    // Store watcher in state...
    Ok(())
}
```

**Why this option**: Native performance, same APIs as the reference, no extra
process. The `notify` crate is battle-tested (44M downloads). Tauri's event
system replaces Electron's `process.parentPort.postMessage`.

#### Option 2: Tauri fs plugin `watch`

Tauri's `@tauri-apps/plugin-fs` exposes a `watch()` function on the JavaScript
side. However, it requires the `fs:allow-watch` permission (not currently in
`capabilities/default.json`) and its debouncing/filtering options are limited
compared to the `notify` crate used directly.

If simplicity is preferred over control, this is viable for a first iteration:

```typescript
import { watch } from "@tauri-apps/plugin-fs";

const stopWatching = await watch(
  "/path/to/project",
  (event) => { /* handle */ },
  { recursive: true, delayMs: 500 },
);
```

#### Option 3: Polling fallback

For environments where native watchers fail (network drives, FUSE mounts),
implement a polling fallback that stats watched files every 2-5 seconds.
This should be a fallback, not the primary strategy.

**Recommendation**: Start with Option 1 (Rust `notify` crate) for the core
watching, with Option 3 as a documented fallback. Option 2 can be considered
if the team prefers a JS-side-only approach for the initial implementation.

### C.4 What to Watch

| Watch Target | Path Pattern | Trigger |
|-------------|-------------|---------|
| Detection rule files | `<repoRoot>/**/*.{yaml,yml,yar,yara}` | Update artifact nodes showing that file |
| Board state file | `~/.clawdstrike/workbench/board-state.json` | Reload board if changed externally (e.g., by CLI) |
| Session output logs | `<repoRoot>/.worktrees/*/agent.log` | Update session node preview lines |
| Worktree changes | `<repoRoot>/.worktrees/*/` | Update diff node file counts, detect new artifacts |
| .swarm bundle | `<bundlePath>/board.json` | Reload board from bundle |
| Project config | `<repoRoot>/.clawdstrike/config.json` | Reload project settings |

**Ignore list** (matching the reference's `IGNORE` array):
```
.git/**
.DS_Store
Thumbs.db
node_modules/**
dist/**
build/**
out/**
.next/**
.cache/**
__pycache__/**
*.min.js
*.min.css
*.map
```

### C.5 Update Flow

```
Filesystem change detected
  |
  v
notify crate event (Rust)
  |
  v
Tauri event: app.emit("fs:change", { paths, kind })
  |
  v
Frontend listener: src/lib/file-watcher-bridge.ts
  |
  v
Classify event:
  - Detection rule changed? -> Update artifact node data
  - Session log changed?    -> Refresh preview lines in session node
  - Board state changed?    -> Reload board from disk (if external edit)
  - Worktree changed?       -> Update diff node, refresh file counts
  |
  v
Zustand store update (board store, project store, etc.)
  |
  v
React re-render (node components pick up new data)
```

**Debouncing**: The reference uses @parcel/watcher's built-in coalescing.
The `notify` crate also coalesces events, but add a 300ms debounce in the
frontend bridge to avoid rapid re-renders during multi-file saves (e.g.,
`git checkout` touching many files at once).

**Conflict resolution**: If the board state file changes on disk while there
are unsaved in-memory changes, the disk version wins (last-writer-wins). Log
a warning. Future work could add a merge strategy or conflict UI.

### C.6 Implementation Plan

| Step | Description | Files |
|------|-------------|-------|
| 1 | Add `notify` crate to `Cargo.toml` | `src-tauri/Cargo.toml` |
| 2 | Create `file_watcher.rs` with managed state and Tauri commands | `src-tauri/src/commands/file_watcher.rs` (new) |
| 3 | Register module in `commands/mod.rs` | `src-tauri/src/commands/mod.rs` |
| 4 | Add `watch_paths` and `unwatch_all` Tauri commands | `src-tauri/src/commands/file_watcher.rs` |
| 5 | Start watching on app setup (repoRoot from board store) | `src-tauri/src/main.rs` |
| 6 | Create frontend bridge `src/lib/file-watcher-bridge.ts` | New file |
| 7 | Wire bridge to board store — artifact node updates | `src/features/swarm/stores/swarm-board-store.tsx` |
| 8 | Wire bridge to project store — file tree refresh | `src/features/project/stores/project-store.tsx` |
| 9 | Add ignore list configuration | `src-tauri/src/commands/file_watcher.rs` |
| 10 | Add `fs:allow-watch` to capabilities if using Option 2 | `src-tauri/capabilities/default.json` |
| 11 | Write tests | `src-tauri/tests/file_watcher.rs` |

### C.7 Dependencies

- `notify = "7"` — new crate dependency (~400KB, no transitive heavy deps).
  Well-maintained, used by `cargo-watch`, `watchexec`, rust-analyzer, etc.
- Frontend: no new npm dependencies. Uses Tauri's existing event listener
  (`@tauri-apps/api/event`'s `listen()`).

### C.8 Effort Estimate

**Small-Medium (S-M)** — 2-4 engineering days.

The `notify` crate setup and Tauri event bridge are straightforward (day 1).
The main work is the frontend classification logic — deciding what to do with
each file change event and connecting it to the right store actions (days 2-3).
Edge cases (rapid events, large batch operations, external board state edits)
add a day of testing and polish.

---

## Summary & Prioritization

| Feature | Effort | Risk | Impact | Suggested Order |
|---------|--------|------|--------|----------------|
| **B. Disk Persistence** | S-M (2-3d) | Low — clear reference, clean abstraction boundary | High — eliminates data loss risk, unblocks larger boards | **First** |
| **C. File Watching** | S-M (2-4d) | Low-Med — edge cases with rapid events | Medium — quality-of-life, enables live workflow | **Second** |
| **A. JSON-RPC Socket** | M (3-5d) | Medium — Rust-to-frontend event bridge is new pattern | High — unlocks automation, CLI tooling, agent integration | **Third** |

**Recommended sequence**: B then C then A. Disk persistence is the foundation
that file watching and the RPC socket both benefit from (the RPC socket reads
board state; file watching detects changes to persisted state). File watching
is a natural extension of disk persistence. The RPC socket is the most impactful
but has the widest surface area, so it benefits from the other two being stable.

**Total estimated effort**: 7-12 engineering days for all three features.

---

## Appendix: Reference File Index

### Collaborator (Reference)

| File | Role |
|------|------|
| `collab-electron/src/main/json-rpc-server.ts` | Unix socket JSON-RPC server, method registry, connection handling |
| `collab-electron/src/main/canvas-rpc.ts` | Bridges JSON-RPC methods to renderer via IPC, registers canvas.* methods |
| `collab-electron/src/main/canvas-persistence.ts` | Atomic file-based canvas state save/load |
| `collab-electron/src/main/config.ts` | App config load/save with atomic writes |
| `collab-electron/src/main/workspace-config.ts` | Per-workspace config persistence |
| `collab-electron/src/main/ipc-workspace.ts` | Workspace service lifecycle, watcher integration |
| `collab-electron/src/main/ipc-canvas.ts` | Canvas persistence IPC handlers |
| `collab-electron/src/main/watcher.ts` | Watcher manager — forks worker, handles restart |
| `collab-electron/src/main/watcher-worker.ts` | @parcel/watcher subscription, event grouping, ignore list |
| `collab-electron/src/main/paths.ts` | `COLLAB_DIR` path resolution (~/.collaborator or ~/.collaborator/dev) |
| `collab-electron/src/main/files.ts` | `atomicWriteFileSync`, file utilities |
| `collab-electron/src/main/index.ts` | App entry — wires up JSON-RPC server, canvas RPC, watcher |

### Clawdstrike Workbench (Target)

| File | Role |
|------|------|
| `src-tauri/src/main.rs` | Tauri app entry, plugin registration, state management, setup |
| `src-tauri/src/commands/mod.rs` | Command module registry |
| `src-tauri/src/commands/terminal.rs` | PTY session management (session.* RPC methods will call into this) |
| `src-tauri/src/commands/mcp_sidecar.rs` | MCP sidecar pattern (reference for process management) |
| `src-tauri/Cargo.toml` | Rust dependencies (tokio, serde_json, uuid, dirs-next all present) |
| `src-tauri/capabilities/default.json` | Tauri permission scope (fs read/write/rename/mkdir already allowed) |
| `src/features/swarm/stores/swarm-board-store.tsx` | Board Zustand store — persistence at lines 74-98, debounce at 519-527 |
| `src/features/swarm/stores/swarm-store.tsx` | Swarm CRUD store — localStorage at lines 48-73, debounce at 224-232 |
| `src/features/swarm/stores/swarm-feed-store.tsx` | Swarm feed store — localStorage at line 39 |
| `src/features/swarm/swarm-board-types.ts` | Node/edge/state type definitions |
| `src/features/swarm/swarm-coordinator.ts` | Swarm networking layer (coordinator.* RPC methods) |
| `src/lib/tauri-bridge.ts` | Tauri API wrappers, `writeSwarmBoardJson()` at line 391 |
| `src/lib/tauri-commands.ts` | Tauri invoke wrappers |
