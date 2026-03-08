# Huntronomer Workspace Shell Target Architecture

> **Status:** Draft | **Date:** 2026-03-07
> **Depends on:** `docs/specs/15-adaptive-sdr-architecture.md`, `docs/specs/16-huntronomer-event-model.md`

## 1. Goal

Add a native-backed workspace surface to the Huntronomer desktop app with:

- trusted workspace roots
- tree, tabs, breadcrumbs, and editor panes
- Monaco-based file editing
- backend-owned file watchers
- `fd` and `rg` search
- xterm.js plus a Rust PTY backend
- system git integration
- optional LSP sidecars via a language-client bridge

This surface should feel like a deliberate operator workstation, not a terminal multiplexer and not
an embedded browser filesystem toy.

## 2. Product Placement Inside Huntronomer

The workspace surface is not the home screen. `Signal Wire` remains the primary landing surface.

The intended transitions are:

- `Wire -> Huntboard -> Workspace` when a hunt needs rule, query, or artifact authoring
- `Vault -> Workspace` when proof or replay review leads to local patching or report authoring
- `Cases -> Workspace` when a promoted case needs writeups, citations, or supporting files

The workspace surface is where local assets become first-class parts of the hunt loop.

## 3. Proposed Surface Routes

- `/workspace`
- `/workspace/tree`
- `/workspace/search`
- `/workspace/git`
- `/workspace/terminal`
- `/workspace/file/:fileId`

The route should preserve selected root, open tabs, and active pane identity across reloads.

## 4. Architecture Layers

### 4.1 Shared desktop shell

Owns:

- route registration
- global command palette
- session and dock chrome
- keyboard focus routing
- cross-surface deep links from Wire, Huntboard, Vault, and Cases

Primary code paths:

- `apps/desktop/src/shell/**`

### 4.2 Rust workspace core

Create a reusable Rust crate for backend-owned workspace behavior:

- `crates/libs/huntronomer-workspace-core/**`

This crate should own:

- workspace root registry
- path canonicalization
- filesystem operations
- watchers
- search jobs
- sidecar process lifecycle
- PTY lifecycle
- git integration
- settings for trusted roots and recent roots

The Tauri app should wrap this crate instead of keeping all workspace logic directly inside
`src-tauri/src/main.rs`.

### 4.3 Tauri adapter layer

Keep the Tauri app as the capability boundary:

- `apps/desktop/src-tauri/src/commands/workspace.rs`
- `apps/desktop/src-tauri/src/commands/terminal.rs`
- `apps/desktop/src-tauri/src/commands/git.rs`
- `apps/desktop/src-tauri/src/commands/search.rs`
- `apps/desktop/src-tauri/src/state.rs`

Responsibilities:

- expose typed invoke commands
- emit events and channels to the frontend
- enforce capability scoping for tools and paths
- translate frontend requests into core-service calls

### 4.4 Frontend workspace surface

Create a dedicated feature tree:

- `apps/desktop/src/features/workspace/**`

Recommended split:

- `shell/` - surface frame, panels, layout state
- `tree/` - file explorer and breadcrumbs
- `editor/` - Monaco models, tabs, dirty state, diagnostics
- `search/` - path/content search UI
- `terminal/` - xterm.js tabs and task panes
- `git/` - status, diff summary, branch, commit actions
- `state/` - selectors and surface-level stores

### 4.5 Frontend invoke and event bridge

Add typed wrappers:

- `apps/desktop/src/services/workspace.ts`
- `apps/desktop/src/services/workspaceEvents.ts`

The frontend should render backend state, not recreate backend truth.

## 5. Backend Service Split

The backend should be decomposed into these services.

### WorkspaceService

Owns:

- root registration and trust
- canonical path resolution
- root metadata
- recent and active root state

### FsService

Owns:

- list, stat, read, write
- create, rename, move, delete
- ignore-aware traversal helpers

### WatchService

Owns:

- `notify` watchers
- event coalescing and debounce
- normalized file-change events to the frontend

### SearchService

Owns:

- `fd` path search
- `rg` content search
- optional later SQLite FTS cache

### ProcService

Owns:

- sidecar process spawning
- LSP server lifecycle
- formatter/linter tasks
- tightly allowlisted command execution

### TerminalService

Owns:

- PTY creation
- shell session lifecycle
- resize, stdin, stdout, exit status streaming

### GitService

Owns:

- system `git` status and diff summaries
- branch enumeration and checkout
- later commit/stage flows

### SettingsService

Owns:

- trusted roots
- recent workspaces
- layout preferences
- terminal profiles
- optional index settings

## 6. Frontend Surface Responsibilities

### Tree and breadcrumbs

- render the canonical workspace tree
- keep expansion state and selection stable
- reflect watcher-driven invalidation

### Tabs and editor area

- open files into Monaco models
- preserve dirty state
- expose save/reload/conflict resolution
- show diagnostics, symbols, and references when LSP is enabled

### Search panel

- use `fd` for go-to-file and path search
- use `rg` for content search
- stream results incrementally
- preserve query history per workspace

### Terminal panel

- render xterm.js tabs
- support shell and task sessions separately
- bind keyboard focus cleanly against the wider shell

### Git panel

- show branch, ahead/behind, and file status
- open diffs or files from changed-file lists
- keep the first pass intentionally status-first

## 7. Trust and Capability Model

1. The frontend never directly owns arbitrary filesystem access.
2. Native folder selection only chooses a candidate path; the backend command registers the trusted
   root and returns the canonical root descriptor.
3. All workspace requests must resolve against a registered root ID and a canonical relative path.
4. `git`, `rg`, `fd`, language servers, formatters, and PTY shells must be explicitly allowlisted.
5. The app should separate one-shot subprocesses from long-lived PTY sessions.
6. Sensitive path transitions, root removals, and tool-launch denials should be observable in logs.

## 8. Tooling Decisions

- **Shell:** Tauri v2
- **Editor:** Monaco
- **Language bridge:** `monaco-languageclient`
- **Terminal UI:** `xterm.js`
- **PTY:** `portable-pty`
- **Watcher:** `notify`
- **Search:** `fd` plus `rg`
- **Git:** system `git` first
- **Optional index:** SQLite FTS before Tantivy
- **Optional power mode:** Yazi launcher later, never the canonical tree

## 9. Layout And Dependency Direction

The dependency flow should stay one-way:

```text
Frontend Workspace UI
    -> typed frontend service wrappers
        -> Tauri command/event adapter
            -> huntronomer-workspace-core services
                -> filesystem / notify / rg / fd / git / PTY / LSP processes
```

Do not let Monaco, xterm, or any frontend surface bypass the backend service layer.

## 10. Non-Negotiable Invariants

1. The explorer is a native app surface, not a terminal-first file manager.
2. Rust owns workspace truth and trust.
3. Search starts with `fd` and `rg`, not an index.
4. System `git` ships before embedded git internals.
5. PTY-backed terminals are required for interactive shell tabs.
6. The workspace surface must stay integrated with Huntronomer objects and routes rather than
   drifting into a generic standalone IDE clone.
