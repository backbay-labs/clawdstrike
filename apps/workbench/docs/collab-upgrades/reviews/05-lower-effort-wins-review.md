# Review: 05 — Lower-Effort Wins (JSON-RPC Socket, Disk Persistence, File Watching)

**Reviewer**: Infrastructure/Backend Engineering
**Date**: 2026-03-25
**Spec version reviewed**: Draft
**Verdict**: **APPROVE WITH CHANGES**

---

## Section A: JSON-RPC Control Socket

### A.1 Unix Socket as Transport

**Unix socket is the right default on macOS/Linux, but the spec ignores Windows entirely.**

The spec proposes `tokio::net::UnixListener` on `~/.clawdstrike/workbench/ipc.sock`. This works on macOS and Linux. However, `Cargo.toml` line 1 shows the crate targets all platforms (no target restriction), and `main.rs` lines 48-61 already have `#[cfg(target_os = "macos")]` / `#[cfg(not(target_os = "macos"))]` branches for decorations. Unix domain sockets technically work on Windows 10+ via `AF_UNIX`, but `tokio::net::UnixListener` is gated behind `#[cfg(unix)]` and will not compile on Windows.

**Recommendation**: Use TCP `127.0.0.1` on an ephemeral port as the default transport, writing the actual `host:port` to `~/.clawdstrike/workbench/socket-path` (exactly as the reference does with its breadcrumb file). This sidesteps Windows/Unix portability issues entirely. If Unix sockets are desired for the slight performance and security advantage on POSIX, add them behind a `#[cfg(unix)]` with TCP as the Windows fallback. The reference implementation at `collab-public/collab-electron/src/main/json-rpc-server.ts` line 12 hardcodes `SOCKET_PATH` without a Windows fallback -- do not repeat this limitation.

### A.2 Method Design

The method namespace design (`board.*`, `session.*`, `coordinator.*`, `rpc.*`) is well-structured. Several gaps:

**Missing methods:**

1. **`board.snapshot` / `board.export`** -- Read the full board state in a single call for backup, piping to another tool, or CI artifact capture. `board.nodeList` + `board.edgeList` requires two round-trips.
2. **Batch operations** -- No `board.batch` or JSON-RPC batch support (the JSON-RPC 2.0 spec supports sending an array of requests). The reference at `json-rpc-server.ts` lines 59-67 (`isJsonRpcRequest`) validates single objects only and also lacks batch support. Given that this is a new implementation, consider supporting it from the start.
3. **Subscriptions/streaming** -- The spec only describes request-response. There is no way for a connected client to subscribe to board changes (e.g., "notify me when a session status changes"). This matters for CI integration where a script spawns a session and waits for completion. Without subscriptions, the client must poll `session.status`. At minimum, add a `board.subscribe` method that causes the server to push newline-delimited notifications (JSON-RPC notifications, i.e., no `id` field) on state changes. Alternatively, document that polling is the expected pattern and add a `session.waitForExit` convenience method with a timeout.
4. **`session.readOutput`** -- No way to read terminal output via RPC. The `terminal_preview` command exists in Rust (`terminal.rs` line 34, `DEFAULT_PREVIEW_LINES: usize = 6`), but no RPC method exposes it.
5. **`board.undo` / `board.redo`** -- If the board ever gets undo (spec 03 or future), the RPC should expose it.

**Method parameter validation**: The spec lists parameter schemas informally (e.g., `{ nodeType, title, position?, data? }`). Consider defining these as JSON Schema or TypeScript types in the spec itself. The reference at `json-rpc-server.ts` line 26 has `params?: Record<string, string>` in `MethodEntry`, but only for documentation -- there is no runtime validation. For a security-sensitive tool, add zod or serde-based validation on the Rust side.

### A.3 Authentication / Authorization

**This is a significant gap.** The spec does not mention authentication at all.

On a Unix socket, filesystem permissions provide some protection (only the user can access their home directory). But on a multi-user system, or if the socket path is predictable, any local process running as the same user can connect and call `session.spawn` to execute arbitrary commands via PTY. The existing Tauri security model (`main.rs` lines 94-116) is careful about restricting IPC to the same-origin webview. The RPC socket bypasses all of this.

**Recommendation**: Generate a random bearer token on startup, write it to `~/.clawdstrike/workbench/rpc-token` with `0600` permissions, and require it in every RPC request (as a top-level `token` field or in a special `rpc.authenticate` handshake at connection time). The CLI client reads the token file. This matches patterns used by Jupyter, Docker, and language servers.

If TCP localhost is used (per the Windows portability recommendation above), authentication becomes mandatory -- any local process could connect without it.

### A.4 Protocol Choice

**JSON-RPC 2.0 is the right choice for this use case.** It is simple, human-readable (critical for `socat`/`nc` debugging as the spec mentions), has no schema compilation step, and the reference already implements it. gRPC would add a protobuf dependency and compilation step that is disproportionate for an IPC mechanism. HTTP REST would work but adds overhead for the socket transport. stdin/stdout would be viable for CLI-only integration but precludes multiple concurrent clients.

One concern: the newline-delimited framing means message content must not contain literal newlines in string values. `JSON.stringify` escapes them by default, so this is safe -- but document this constraint explicitly for third-party client implementors.

### A.5 Event Bridge Latency

The spec proposes Rust -> Tauri event -> Frontend Zustand store -> Tauri invoke -> Rust for board-state methods. This round-trip through the webview adds latency (10-50ms per hop, two hops). The reference at `canvas-rpc.ts` has the same pattern with a 10-second timeout. For methods like `board.nodeList` (read-only), consider having the Rust side maintain a shadow copy of the board state that the frontend pushes to on every persist cycle. This would allow pure Rust resolution for read methods without the webview round-trip.

### A.6 Effort Estimate

**3-5 days is optimistic.** The socket server itself is 1-2 days. But:
- The Rust-to-frontend event bridge (steps 5-6) is novel in this codebase and will require careful async coordination, error handling, and timeout management. Budget 2 days.
- The CLI client with proper error handling, token auth, and output formatting is 1 day, not a half-day.
- Integration tests for IPC across Tauri are notoriously slow to set up. Budget 1 day.

**Revised estimate**: 5-7 engineering days.

---

## Section B: Disk-Based Persistence

### B.1 localStorage Key Validation

The spec's claims about localStorage keys are **accurate**:

- `swarm-board-store.tsx` line 74: `STORAGE_KEY = "clawdstrike_workbench_swarm_board"` -- confirmed.
- `swarm-store.tsx` line 48: `STORAGE_KEY = "clawdstrike_workbench_swarms"` -- confirmed.
- `swarm-feed-store.tsx` line 39: `SWARM_FEED_STORAGE_KEY = "clawdstrike_workbench_swarm_feed"` -- confirmed.

The spec correctly identifies `swarm-board-store.tsx` lines 76-98 as the persistence function. The existing `bundlePath` code path at line 87-95 shows there is already a partial disk persistence path for `.swarm` bundles via `writeSwarmBoardJson`, which the spec acknowledges.

One omission: the spec does not mention `lastSwarmStorageSnapshot` / `lastSwarmFeedStorageSnapshot` -- the snapshot comparison used for cross-tab sync (`swarm-store.tsx` lines 49-50, 144-159; `swarm-feed-store.tsx` lines 40-41). When migrating to disk, this cross-tab sync mechanism becomes irrelevant (disk is the single source of truth), but the migration must explicitly remove or replace this logic.

### B.2 Atomic Write Pattern

The proposed pattern (write `.tmp`, then `rename()`) is correct and matches the reference at `canvas-persistence.ts` lines 51-57. However, the spec misses several failure modes:

**Disk full**: `tokio::fs::write(&tmp_path, &content)` will fail. The error propagates to the frontend, which is fine. But: the `.tmp` file may be left behind. Add cleanup:
```rust
if let Err(e) = tokio::fs::rename(&tmp_path, &target).await {
    let _ = tokio::fs::remove_file(&tmp_path).await; // cleanup
    return Err(e.to_string());
}
```

**Permissions**: If `~/.clawdstrike/workbench/` has restrictive permissions, `create_dir_all` might succeed but `write` might fail. The spec should specify `0700` permissions on the directory.

**Concurrent writes from multiple windows**: The spec mentions (B.1 problem 5) that multiple windows create conflicts, but the proposed solution does not address this. If two windows write `.tmp` files and rename concurrently, the last rename wins and one window's state is silently lost. For single-window operation (the current norm), this is fine. But the spec should explicitly state that multi-window is out of scope and add a pidfile or lockfile (`~/.clawdstrike/workbench/.lock`) to detect and warn about concurrent instances.

**The temp file location**: The proposed code writes the temp file to the same directory as the target (`dir.join(format!(".{}.tmp", ...))`). This is actually better than the reference's approach of using `os.tmpdir()` (`canvas-persistence.ts` line 51-53), because `rename()` across filesystem boundaries is not atomic -- it falls back to copy+delete. The spec gets this right. However, dot-prefixed temp files could accumulate if the process crashes between write and rename. Add a startup cleanup that removes `~/.clawdstrike/workbench/.*.tmp` files.

### B.3 File Format Versioning

The spec includes `"version": 1` in all schemas, which is good. **But there is no migration framework described.** What happens when `version` becomes 2?

**Recommendation**: Add a section describing the migration pattern:
1. On load, check the `version` field.
2. If `version < CURRENT_VERSION`, run migration functions sequentially (`v1_to_v2()`, `v2_to_v3()`, etc.).
3. Write the migrated state back to disk immediately.
4. If `version > CURRENT_VERSION` (downgrade scenario), refuse to load and warn the user.

This is a 10-line pattern but prevents future headaches.

### B.4 Storage Location

**`~/.clawdstrike/workbench/` is problematic.** The codebase already uses Tauri's `app_data_dir` for Stronghold storage (`stronghold.rs` line 279: `app.path().app_data_dir()`), and `main.rs` line 28-30 uses `dirs_next::data_dir().join("com.clawdstrike.workbench")` for the machine key. This means:

- On macOS: `~/Library/Application Support/com.clawdstrike.workbench/`
- On Linux: `~/.local/share/com.clawdstrike.workbench/`
- On Windows: `C:\Users\<user>\AppData\Roaming\com.clawdstrike.workbench\`

The spec proposes `~/.clawdstrike/workbench/`, which:
1. Does not follow platform conventions (XDG on Linux, `~/Library/Application Support` on macOS, `%APPDATA%` on Windows).
2. Creates a second data location diverging from where Stronghold data already lives.
3. Is invisible by default on macOS/Linux (dot-prefixed).

**Recommendation**: Use `app.path().app_data_dir()` to match the existing Stronghold storage location. This resolves to the platform-appropriate directory. On the Rust side, `tauri::Manager::path()` provides this. On the frontend side, use `@tauri-apps/api/path::appDataDir()`. This is a single-line change that avoids a future "why is data in two places?" issue.

If the team wants a human-discoverable location for git-controllable state, keep `~/.clawdstrike/workbench/` as an optional override via an environment variable (e.g., `CLAWDSTRIKE_DATA_DIR`), but default to the platform path.

### B.5 Backup / Rotation

**The spec does not mention backup or recovery.** The swarm feed store (`swarm-feed-store.tsx`) accumulates finding envelopes that represent security-critical audit data. A single corrupted write loses everything.

**Recommendation**: On each successful atomic write, keep the previous version as `board-state.json.bak` (or `board-state.1.json`, `board-state.2.json` for N-deep rotation). The reference does not do this either, but the swarm board carries higher-value state than a canvas layout. Even `cp board-state.json board-state.json.bak` before the rename gives single-failure recovery. Cost: one extra `tokio::fs::copy` call, negligible effort.

### B.6 Sync to Async Migration Complexity

The spec underestimates the sync-to-async migration. The current stores call `localStorage.getItem()` synchronously in `getInitialState()` (`swarm-board-store.tsx` line 533-534, `swarm-store.tsx` line 132-134). The proposed `loadStateFile()` is async (returns `Promise<T | null>`). This means:

1. `getInitialState()` can no longer be synchronous. Zustand's `create()` expects synchronous initial state.
2. The stores need a loading/hydrating phase: create with empty initial state, then async-load from disk, then `set()` the real state.
3. Every consumer must handle the "not yet hydrated" case. This is a UI concern that ripples through the component tree.

The `swarm-feed-store.tsx` already handles this somewhat (`INITIAL_SWARM_FEED_STATE` as a fallback), but the board store does not -- it loads persisted state synchronously at creation time.

**Recommendation**: Use Zustand's `persist` middleware with a custom storage adapter, or implement a `hydrate()` pattern explicitly. Budget an extra 0.5-1 day for this. The spec's "small change surface" claim (B.10) is only true for the write path, not the read/initialization path.

### B.7 `swarm-feed.json` Size Concern

The swarm feed store persists *all* finding envelopes, head announcements, revocation envelopes, and quarantined copies of each (`swarm-feed-store.tsx` lines 885-901). This is the store most likely to blow past localStorage limits and *also* the one most likely to produce large JSON files on disk. A feed with thousands of findings could produce multi-megabyte JSON files.

**Recommendation**: Add a retention policy or max-record-count to `swarm-feed.json`. Consider splitting old findings into an archive file, or using a lightweight embedded database (SQLite via `tauri-plugin-sql`) for feed data specifically.

### B.8 Effort Estimate

**2-3 days is slightly optimistic.** The async initialization migration and thorough testing of the migration path (localStorage -> disk, fresh install, corrupted file recovery, version mismatch) add complexity. The `beforeunload` flush pattern in `swarm-feed-store.tsx` lines 1657-1668 needs to become a Tauri `RunEvent::Exit` handler on the Rust side, since `beforeunload` is unreliable in webviews.

**Revised estimate**: 3-4 engineering days.

---

## Section C: File Watching

### C.1 `notify` Crate Availability

**The `notify` crate is NOT in the current `Cargo.toml`.** The spec correctly identifies this as a new dependency (Section C.7: `notify = "7"`). The spec's example code at C.3 uses `notify::{recommended_watcher, Event, RecursiveMode, Watcher}`, which is the correct API for `notify` v7.

Compatibility check: `tokio` is at version 1 with full features (`Cargo.toml` line 18). The `notify` crate v7 supports async via `notify-debouncer-full` or by forwarding events through an `mpsc` channel as shown in the spec. No compatibility issues expected.

However, `notify` v7 uses `crossbeam-channel` internally, not `std::sync::mpsc`. The spec's example code at C.3 uses `std::sync::mpsc`, which would work as the callback adapter but should use `crossbeam-channel` or `tokio::sync::mpsc` for consistency. More importantly, the example code has a correctness issue:

```rust
let watcher = recommended_watcher(tx).map_err(|e| e.to_string())?;
```

The `watcher` variable is created on the stack and immediately moved into... nothing. If it is not stored in managed state, it will be dropped and watching will stop. The spec mentions "Store watcher in state..." as a comment but does not show the implementation. This is where bugs hide. The `FileWatcherState` struct needs to own the watcher behind an `Arc<Mutex<>>` in Tauri managed state, and the `start_watching` function needs to take a `State<FileWatcherState>` parameter.

### C.2 Debouncing Strategy

The spec proposes 300ms debounce in the frontend bridge (C.5), on top of `notify`'s built-in event coalescing. This is reasonable for normal editing.

**Git checkout concern**: A `git checkout` touching 500 files produces 500+ events in rapid succession. The 300ms debounce handles this for UI re-renders, but the classification logic ("what changed?") could be expensive if it runs per-event before debouncing.

**Recommendation**: Debounce at the Rust layer, not just the frontend. Collect events into a batch over 300ms, then emit a single `fs:change` Tauri event with the full batch. The reference's `@parcel/watcher` does this natively (the callback receives an `events` array, not individual events -- see `watcher-worker.ts` lines 81-94). The `notify` crate's `notify-debouncer-full` or `notify-debouncer-mini` crates provide this out of the box. Add `notify-debouncer-mini = "0.5"` (or the v7-compatible version) instead of using raw `notify`.

**What debounce interval?** 300ms is fine for the default. For `git checkout` scenarios, consider detecting rapid bursts (>50 events in 1 second) and extending the debounce window to 1-2 seconds dynamically.

### C.3 Recursive Watching

The spec proposes `RecursiveMode::Recursive` for all watch targets. This is correct for detection rules in nested directories. However:

1. **Watch count limits**: On Linux, `inotify` has a per-user watch limit (default 8192, `fs.inotify.max_user_watches`). A large monorepo with deep `node_modules` (even if ignored) can exhaust this. The reference uses `@parcel/watcher` which uses a different backend on Linux (fanotify on newer kernels, which does not have this limit). The `notify` crate's recommended watcher on Linux uses `inotify` by default. **Recommendation**: Document the inotify limit and suggest `sysctl -w fs.inotify.max_user_watches=524288` for Linux users, or consider `notify` with the `PollWatcher` fallback.

2. **The ignore list at C.4 is applied where?** The reference applies ignores in the watcher-worker via `@parcel/watcher`'s `ignore` option (native-level filtering). The `notify` crate does not have built-in ignore support -- you must filter events in the callback. This means ignored directories (`.git/**`, `node_modules/**`) still consume inotify watches on Linux. On macOS (FSEvents), this is less of an issue since FSEvents watches per-directory, not per-file. **Recommendation**: Use `notify`'s `EventHandler` to filter events, but add documentation that inotify watch limits may be an issue on Linux for large repos.

### C.4 Circular Update Prevention

**This is the most critical gap in the spec.** The update flow at C.5 shows:

```
Board writes file (disk persistence) -> Watcher sees change -> Triggers update -> Writes file
```

The spec says "Board state file changed? -> Reload board from disk (if external edit)" but provides no mechanism to distinguish "I wrote this file" from "something else wrote this file."

The reference avoids this problem because the watcher watches the *workspace* directory, not the config directory. The `watcher-worker.ts` watches the workspace path passed via the `watch` command, and `canvas-persistence.ts` writes to `~/.collaborator/` which is a different path.

In the Clawdstrike spec, however, the watch targets at C.4 include `~/.clawdstrike/workbench/board-state.json` -- the same file that the disk persistence layer writes to. This creates a guaranteed circular update loop.

**Recommendation (pick one):**
1. **Write flag**: Set a "writing" flag in `FileWatcherState` before each atomic write. The event handler checks this flag and ignores events that arrive within 500ms of a write to the same path.
2. **Content hash**: On write, store the SHA-256 of the written content. On file-change event, hash the file and compare. If it matches the last-written hash, it was our own write -- ignore it.
3. **Separate watch scope**: Do not watch `~/.clawdstrike/workbench/board-state.json` at all. Only watch it if a flag like `--watch-config` is set, intended for the "external CLI edit" use case. The default should only watch the project/repo directory.

Option 1 is the simplest. Option 2 is the most robust. Option 3 avoids the problem but loses a stated use case.

### C.5 Effort Estimate

**2-4 days is reasonable** if the circular update problem is solved cleanly. If not, debugging the feedback loop will eat 1-2 days on its own.

**Revised estimate**: 3-4 engineering days.

---

## Cross-Cutting Concerns

### Effort Estimates

| Feature | Spec Estimate | Revised Estimate | Delta |
|---------|--------------|-----------------|-------|
| A. JSON-RPC | 3-5d | 5-7d | +2d (auth, Windows, event bridge complexity) |
| B. Disk Persistence | 2-3d | 3-4d | +1d (async init migration, edge cases) |
| C. File Watching | 2-4d | 3-4d | ~same, contingent on circular update solution |
| **Total** | **7-12d** | **11-15d** | **+4d** |

The per-feature estimates are not egregiously wrong, but they consistently assume "straightforward" implementations without accounting for the integration testing and edge-case hardening that a security-oriented tool requires.

### Is B -> C -> A the Right Order?

**Yes, mostly.** The reasoning is sound:

- **B (Disk Persistence) first**: C and A both benefit from reliable disk state. C watches state files; A reads/writes board state. Without B, both are less useful.
- **C (File Watching) second**: Requires B's state files to exist on disk for the "watch board state" use case. Also, the watcher module is needed to detect external changes made via the RPC socket (A).
- **A (JSON-RPC) third**: Benefits from both B (reads state from disk for pure-Rust resolution) and C (can trigger watchers to detect RPC-driven changes).

**One adjustment**: The circular update problem (C watching files that B writes) means C should be designed *in tandem* with B, not sequentially after it. At minimum, B's `atomic_write_file` command should include a "write ID" or "write timestamp" that C can use to suppress self-triggered events. Design this interface when implementing B, even if C is built later.

### Dependencies on Specs 01-04

- **01 (Multi-Webview Isolation)**: If multi-webview is implemented, the RPC event bridge (A) must handle routing to the correct webview. The spec assumes a single `"main"` webview. Not a blocker, but note the coupling.
- **02 (Tmux Persistent Sessions)**: If sessions become persistent via tmux, `session.list` and `session.status` RPC methods need to query tmux state, not just the in-memory `TerminalManager`. The spec maps `session.list` to `terminal_list` which only knows about PTY sessions. Not a blocker but worth flagging.
- **03 (Canvas Feel)**: No direct dependencies.
- **04 (Cleaner Tile Chrome)**: No direct dependencies.

### Additional Concerns

**The `disk-persistence.ts` frontend module passes `~/.clawdstrike/workbench` as a string literal (`BASE_DIR`)**. The Rust `atomic_write_file` command takes a raw `path: String` with no validation. This is an arbitrary file write primitive -- any compromised frontend code could write to any path the user has access to. Either:
1. Restrict the Rust command to only write within the app data directory (validate the path prefix).
2. Accept a filename, not a full path, and have the Rust side resolve it relative to the data directory.

Option 2 is safer and simpler. Change the API to:
```rust
pub async fn atomic_write_file(filename: String, content: String) -> Result<(), String>
```
where `filename` is validated to not contain path separators or `..`.

---

## Summary of Required Changes

**Must-fix before implementation:**
1. Solve the circular update loop between disk persistence (B) and file watching (C). Design the suppression mechanism as part of B.
2. Add authentication to the RPC socket (A). A bearer token at minimum.
3. Restrict `atomic_write_file` to the app data directory -- do not expose an arbitrary file write command.
4. Use `app_data_dir()` (or equivalent) instead of `~/.clawdstrike/workbench/` for consistency with existing Stronghold storage.

**Should-fix:**
5. Address Windows portability for the RPC socket (TCP localhost fallback).
6. Add a schema migration framework for versioned state files.
7. Add `.tmp` file cleanup on startup.
8. Document async initialization strategy for Zustand stores.
9. Add a write-flag or content-hash mechanism to prevent watcher feedback loops.
10. Use `notify-debouncer-mini` instead of raw `notify` for batched event delivery.

**Nice-to-have:**
11. Add `board.snapshot`, `session.readOutput`, and batch RPC support.
12. Add state file backup rotation.
13. Add subscription/notification support for long-running RPC clients.
14. Add a retention policy for `swarm-feed.json`.

---

## Verdict

**APPROVE WITH CHANGES.**

The spec is thorough in its analysis of the reference implementation and proposes sensible adaptations for Tauri. The three features are well-scoped and correctly ordered. The gap analysis of the current localStorage-based persistence is accurate and well-motivated.

The required changes above are not architectural -- they are hardening and correctness issues that should be resolved before implementation begins. The circular update loop (item 1) and the arbitrary file write (item 3) are the most urgent. The auth gap (item 2) should not ship without a fix in any release that exposes the socket.

Effort estimates should be revised upward by roughly 30-40% to account for integration testing, edge cases, and the Windows portability question.
