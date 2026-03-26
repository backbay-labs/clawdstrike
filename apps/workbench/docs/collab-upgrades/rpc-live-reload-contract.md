# RPC + File Watch Live-Reload Contract

Engineering contract for the combined RPC socket and file watcher live-reload capability. This document describes the interaction model, latency budget, self-write suppression chain, and CI integration patterns for external automation clients.

---

## 1. Overview

The RPC socket (`rpc_socket.rs`) and file watcher (`file_watcher.rs`) form a combined live-reload capability for external automation of the swarm board. External tools can drive the board through two complementary paths:

- **Direct RPC calls** for immediate store mutations (e.g., `board.nodeAdd`, `session.spawn`). The RPC path updates the Zustand store directly via the frontend event bridge, then persistence writes the state to disk for durability.
- **External file writes** for persistence-driven updates. An external process writes directly to the persistence directory, and the file watcher detects the change and triggers a store re-read.

The RPC socket serves JSON-RPC 2.0 over a Unix domain socket (macOS/Linux) or TCP localhost (Windows). The file watcher uses `notify-debouncer-mini` for batched, debounced filesystem event delivery.

---

## 2. RPC Method Risk Tiers

Every RPC method carries a `risk_tier` and `scope` in its static descriptor, exposed via `rpc.discover`. Risk tiers classify the danger level of each method for future authorization enforcement.

| Method                | Risk Tier   | Scope                | Notes                                           |
|-----------------------|-------------|----------------------|-------------------------------------------------|
| `rpc.discover`        | None        | Rpc                  | Pure Rust, no frontend bridge                   |
| `board.snapshot`      | Read        | RepoRead             | Returns full board state                        |
| `board.nodeAdd`       | Mutate      | RepoMutate           | Creates a board node                            |
| `board.nodeRemove`    | Mutate      | RepoMutate           | Removes a board node (kills session if attached)|
| `board.nodeUpdate`    | Mutate      | RepoMutate           | Patches node layout and/or data                 |
| `board.edgeAdd`       | Mutate      | RepoMutate           | Creates a board edge                            |
| `board.edgeRemove`    | Mutate      | RepoMutate           | Removes a board edge                            |
| `board.viewportGet`   | Read        | RepoRead             | Returns current canvas viewport                 |
| `board.viewportSet`   | Mutate      | RepoMutate           | Sets canvas viewport with optional animation    |
| `session.spawn`       | Lifecycle   | TerminalLifecycle    | Spawns terminal/Claude/worktree via PTY         |
| `session.kill`        | Lifecycle   | TerminalLifecycle    | Kills a session by nodeId or sessionId          |
| `session.list`        | Read        | TerminalRead         | Lists board + backend-discovered sessions       |
| `session.readOutput`  | Read        | TerminalRead         | Returns recent terminal output lines            |
| `coordinator.status`  | Read        | RepoRead             | Returns coordinator connectivity state          |
| `coordinator.publish` | Mutate      | RepoMutate           | Publishes a message to a coordinator channel    |

`session.spawn` and `session.kill` are classified as **Lifecycle** tier (highest risk) because they execute commands via PTY and can create or destroy OS-level processes.

---

## 3. Event-Bridge Latency Budget

Most RPC methods require a round-trip through the Tauri frontend event bridge. The path and expected latencies:

```
External Client -> Socket -> rpc_socket.rs parse+auth (~1ms)
  |
  v (rpc.discover: pure Rust, no bridge)
  |
  v (all other methods)
rpc_socket.rs -> Tauri emit("swarm:rpc_request") -> (~1-5ms)
  |
  v
swarm-rpc-bridge.ts -> Zustand read/write -> (~1-10ms)
  |
  v
rpc_frontend_respond invoke -> rpc_socket.rs -> socket write (~1-5ms)
```

### Expected Latencies by Method Category

| Category                        | Expected Latency | Notes                                  |
|---------------------------------|------------------|----------------------------------------|
| `rpc.discover`                  | < 5ms            | Pure Rust, no frontend bridge          |
| Read methods (`board.snapshot`, `session.list`, `coordinator.status`) | < 100ms typical | Zustand read + serialization |
| Board mutation methods (`board.nodeAdd`, `board.edgeAdd`, etc.)       | < 100ms typical | Zustand write + React reconciliation |
| `session.spawn` (terminal)      | < 5s             | PTY spawn + shell initialization       |
| `session.spawn` (Claude/worktree) | variable, up to 30s | Worktree creation + git operations |
| **Timeout**                     | **20s**          | `FRONTEND_RPC_TIMEOUT` in `rpc_socket.rs` |

The 20-second timeout (`FRONTEND_RPC_TIMEOUT`) applies to all methods that traverse the frontend bridge. If the frontend does not respond within this window, the RPC socket returns a timeout error to the client. `rpc.discover` is exempt because it resolves entirely in Rust.

---

## 4. Self-Write Suppression Chain

When an RPC mutation modifies the board, the resulting persistence write must not trigger a file watcher re-read. The self-write suppression chain prevents this circular update:

```
1. RPC board.nodeAdd -> swarm-rpc-bridge.ts dispatches to Zustand store
2. Zustand store mutation triggers persistence write (swarm-board-store.tsx)
3. persistence.rs calls mark_self_writes() with target paths, TTL = 1500ms
4. persistence.rs writes to disk via atomic rename (tmp -> target)
5. file_watcher.rs debouncer fires after 300ms debounce
6. file_watcher.rs checks self_writes map, finds path within TTL -> suppresses event
7. No swarm:file-watch event emitted -> no store re-read -> chain terminates
```

**Why the chain terminates:** Step 6 suppresses the watcher event because the path is found in the `self_writes` map with a deadline that has not expired. Without this suppression, step 7 would re-read the file, update the store, which would trigger another persistence write (step 2), creating an infinite feedback loop.

### Key Constants

| Constant              | Value   | Location            | Purpose                                    |
|-----------------------|---------|---------------------|--------------------------------------------|
| `SELF_WRITE_TTL_MS`  | 1500ms  | `file_watcher.rs`   | Duration to suppress watcher events after a self-write |
| `FILE_WATCH_DEBOUNCE_MS` | 300ms | `file_watcher.rs` | Debounce interval for filesystem events    |
| `FRONTEND_RPC_TIMEOUT` | 20s   | `rpc_socket.rs`     | Maximum wait for frontend bridge response  |

### Suppression Implementation Details

- `mark_self_writes()` accepts `&[PathBuf]` and records each path with a deadline of `now + 1500ms`.
- The persistence layer marks the target file, temp file, and backup file as self-writes (all three paths are passed to `mark_self_writes()`).
- Expired entries are pruned on each call to `mark_self_writes()` and on each `should_suppress_path()` check.
- Path normalization converts backslashes to forward slashes and folds case on Windows.

---

## 5. External File Write Path

When an external tool writes directly to the persistence directory (not via RPC), the update flows through the file watcher:

```
1. External process writes file to persistence directory
2. file_watcher.rs debouncer fires after 300ms
3. No matching entry in self_writes map -> event emitted
4. Frontend receives swarm:file-watch event, category: Persistence
5. Frontend re-reads persistence file and updates Zustand store
6. Store update triggers persistence write -> mark_self_writes()
7. Watcher suppresses the self-write -> chain terminates after 1 cycle
```

The key difference from the RPC path (Section 4) is that step 3 allows the event through because the external write was not registered in the `self_writes` map. The chain still terminates after exactly one cycle because step 6 registers the subsequent persistence write as a self-write, which step 7 suppresses.

---

## 6. CI Startup Sequence

The expected startup sequence for CI scripts and automation clients:

```
1. Workbench app starts
2. rpc_socket.rs binds socket and writes ipc.json + ipc.token
3. Socket is listening but frontend may not be hydrated yet
4. Frontend React tree mounts, useSwarmRpcBridge registers listener
5. rpc.discover returns a successful response -> app is ready
```

### Readiness Check

**Recommended CI pattern:** Poll `rpc.discover` with the `csw` CLI using the retry flag:

```bash
csw --retry 30 rpc.discover
```

This polls up to 30 times (once per second) waiting for the socket to become available and the app to be ready. The `csw` CLI re-reads `ipc.json` on each retry attempt to handle port changes after app restarts (important on Windows TCP transport).

### Startup Ordering Guarantees

- **Step 2 happens before step 4:** The socket is listening before the frontend hydrates. Pure-Rust methods like `rpc.discover` work at step 2, but store-dependent methods (e.g., `board.snapshot`) will time out until step 4 completes.
- **Step 5 is the definitive readiness signal:** A successful `rpc.discover` response confirms both the socket and the frontend bridge are operational.

### Exit Codes for CI

| Exit Code | Meaning                                          |
|-----------|--------------------------------------------------|
| 0         | RPC call succeeded                               |
| 1         | RPC call returned an error (method-level failure)|
| 2         | Connection failure (socket not found, retries exhausted) |

CI pipelines can branch on exit code 2 to distinguish "app not started" from "RPC method failed."

---

## 7. Windows TCP Transport

On Windows, Unix domain sockets are not available. The RPC socket falls back to TCP on localhost:

- The TCP listener binds to `127.0.0.1:0` (ephemeral port).
- The actual port is written to `ipc.json` as `{ "transport": "tcp", "host": "127.0.0.1", "port": <port> }`.
- The `csw` client reads `ipc.json` fresh on each invocation.
- Connection retry re-reads `ipc.json` between attempts to handle port changes after app restart.
- Authentication via bearer token is mandatory on TCP (any local process can connect to localhost).

The transport kind is reported in `rpc.discover` as `runtime.transport: "tcp"` or `runtime.transport: "unix"`.

---

## 8. Composition Rules

- **RPC mutations are authoritative:** They update the Zustand store directly. The subsequent persistence write is for durability, not for triggering further action.
- **External file writes are the secondary path:** They trigger a store re-read via the file watcher.
- **Do NOT mix:** Writing to the persistence file AND calling an RPC mutation for the same data in the same automation step. The RPC call is sufficient; the file write would be redundant and could cause a race condition during the self-write suppression window.
- **File watcher coverage:** The file watcher covers persistence files, workspace artifacts, and session logs. See `ConfigureSwarmFileWatcherRequest` for the full list of watched categories:
  - `persistence_filenames`: JSON files in the persistence directory (non-recursive).
  - `workspace_paths`: Absolute paths to workspace artifacts (recursive if parent directories do not yet exist).

---

## 9. Known Limitations

- **No subscription/streaming:** Clients must poll. `session.list` is the polling method for session status. There is no `board.subscribe` or push notification mechanism.
- **No batch RPC:** One request per line, one response per line. The JSON-RPC 2.0 batch array syntax is explicitly rejected.
- **Event-bridge requires frontend hydration:** Pure-Rust methods (`rpc.discover`) work immediately after socket bind, but store-dependent methods require the React tree to mount and `useSwarmRpcBridge` to register its listener. Calling store-dependent methods before hydration results in a 20-second timeout.
- **Self-write suppression TTL is 1500ms:** If an external process writes to the persistence directory within 1500ms of an internal persistence write to the same path, the external write may be incorrectly suppressed. This is acceptable because the debouncer fires at 300ms, well within the 1500ms window, and the typical external automation pattern uses RPC (not direct file writes) for mutations.
- **Newline-delimited framing:** JSON-RPC messages are delimited by newlines. Message content must not contain literal newlines in string values. `JSON.stringify` escapes them by default, so this is safe for compliant JSON producers.
- **Single concurrent board:** The RPC socket serves the active workbench board. There is no multi-board routing or board selection via RPC.
