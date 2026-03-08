# Spec 17: Huntronomer Workspace Services

> **Status:** Draft | **Date:** 2026-03-07
> **Author:** Codex
> **Dependencies:** Spec 15, Spec 16, Huntronomer workspace-shell planning set

## 1. Overview

This specification defines the service contract for a native-backed workspace shell inside the
Huntronomer desktop app. The goal is to support IDE-like filesystem behavior without moving
filesystem trust or process control into the frontend.

This spec standardizes:

- backend service boundaries
- trust and path rules
- frontend command and event vocabulary
- tool policy for search, git, PTY, and language servers
- persistence expectations for recent roots and workspace state

## 2. Scope

This spec defines:

- the required Rust services
- the Tauri-facing command surface
- event/channel streams for long-lived workspace activity
- first-pass tool choices
- non-negotiable trust invariants

This spec does not define:

- full visual design
- ranking or indexing heuristics beyond initial tool choices
- final file icon/theme treatment
- a full embedded git implementation

## 3. Design Invariants

1. The frontend does not directly own arbitrary filesystem operations.
2. Every workspace request resolves against a registered trusted root.
3. Paths are canonicalized in Rust before any operation is executed.
4. Interactive terminals use a PTY service, not one-shot shell commands.
5. Search starts with `fd` and `rg` before any local index.
6. System `git` is the initial git backend.
7. Yazi is never the canonical workspace model.

## 4. Required Backend Services

### 4.1 WorkspaceService

Responsibilities:

- register and remove trusted roots
- canonicalize paths
- validate root-relative requests
- track active and recent roots

### 4.2 FsService

Responsibilities:

- list children
- stat path metadata
- read and write files
- create files and directories
- rename, move, and delete paths

### 4.3 WatchService

Responsibilities:

- own `notify` watchers
- debounce/coalesce events
- emit normalized change events

### 4.4 SearchService

Responsibilities:

- run `fd` for path search
- run `rg` for content search
- stream incremental results
- apply ignore-aware traversal

### 4.5 ProcService

Responsibilities:

- spawn allowlisted sidecars
- own LSP server lifecycle
- run formatter/linter tasks
- collect exit status and stderr

### 4.6 TerminalService

Responsibilities:

- create PTY-backed shell sessions
- stream stdout and stderr
- accept stdin writes
- resize and close sessions

### 4.7 GitService

Responsibilities:

- run system `git` commands behind tight allowlists
- surface status and diff summaries
- enumerate and switch branches

### 4.8 SettingsService

Responsibilities:

- persist trusted roots
- persist recent roots
- persist workspace layout and tabs
- later persist optional index settings

## 5. Frontend Surface Contract

The frontend should consume workspace state through typed wrappers, not by calling generic shell
execution directly.

Recommended frontend structure:

- `apps/desktop/src/features/workspace/tree/**`
- `apps/desktop/src/features/workspace/editor/**`
- `apps/desktop/src/features/workspace/search/**`
- `apps/desktop/src/features/workspace/terminal/**`
- `apps/desktop/src/features/workspace/git/**`
- `apps/desktop/src/services/workspace.ts`
- `apps/desktop/src/services/workspaceEvents.ts`

The frontend is responsible for:

- rendering state
- keeping panel layout and selection state coherent
- managing Monaco and xterm.js instances
- dispatching typed commands to the backend

The frontend is not responsible for:

- resolving canonical paths
- deciding whether a command is allowlisted
- owning the authoritative workspace tree

## 6. Trust And Path Model

### 6.1 Root registration

The native folder picker may return a filesystem path, but that path is not itself sufficient for
later operations. The backend must turn it into a trusted root record:

```ts
interface WorkspaceRoot {
  id: string;
  name: string;
  canonicalPath: string;
  createdAt: string;
  lastOpenedAt: string;
}
```

### 6.2 Relative-path rule

Every file operation from the frontend must use:

- `rootId`
- a normalized relative path or path token

Absolute paths should not be accepted from the frontend after root registration.

### 6.3 Denial behavior

Requests that escape the root, reference unknown roots, or target non-allowlisted tools must fail
closed and return typed errors.

## 7. Command Surface

The exact naming can still shift, but the app should standardize on a dedicated workspace command
namespace.

### 7.1 Workspace commands

```ts
workspace_register_root(path: string) -> WorkspaceRoot
workspace_list_dir(rootId: string, relativePath: string) -> WorkspaceEntry[]
workspace_stat_path(rootId: string, relativePath: string) -> WorkspaceEntry
workspace_read_file(rootId: string, relativePath: string) -> WorkspaceFile
workspace_write_file(rootId: string, relativePath: string, contents: string) -> WriteResult
workspace_create_path(...) -> WorkspaceEntry
workspace_move_path(...) -> WorkspaceEntry
workspace_delete_path(...) -> DeleteResult
workspace_list_recent_roots() -> WorkspaceRoot[]
```

### 7.2 Search commands

```ts
workspace_search_paths(rootId: string, query: string) -> SearchJobHandle
workspace_search_content(rootId: string, query: string, globs?: string[]) -> SearchJobHandle
workspace_cancel_search(jobId: string) -> void
```

### 7.3 Terminal commands

```ts
workspace_open_terminal(rootId: string, cwd?: string, profile?: string) -> TerminalSession
workspace_resize_terminal(sessionId: string, cols: number, rows: number) -> void
workspace_write_terminal(sessionId: string, data: string) -> void
workspace_close_terminal(sessionId: string) -> void
```

### 7.4 Git commands

```ts
workspace_git_status(rootId: string) -> GitStatusSummary
workspace_git_diff_summary(rootId: string, path?: string) -> GitDiffSummary
workspace_git_branches(rootId: string) -> GitBranch[]
workspace_git_checkout(rootId: string, branch: string) -> CheckoutResult
```

### 7.5 Language-service commands

Prefer backend-owned lifecycle commands over frontend-launched subprocesses:

```ts
workspace_start_language_service(rootId: string, languageId: string) -> LanguageServiceHandle
workspace_stop_language_service(serviceId: string) -> void
```

## 8. Event And Channel Surface

Long-lived operations should stream through events or channels.

### 8.1 File-watch events

```ts
interface WorkspaceFsEvent {
  rootId: string;
  kind: "created" | "modified" | "removed" | "renamed";
  relativePath: string;
  previousRelativePath?: string;
  at: string;
}
```

### 8.2 Search stream events

```ts
interface WorkspaceSearchEvent {
  jobId: string;
  kind: "match" | "progress" | "done" | "error";
  payload: Record<string, unknown>;
}
```

### 8.3 Terminal stream events

```ts
interface WorkspaceTerminalEvent {
  sessionId: string;
  kind: "stdout" | "stderr" | "exit" | "error";
  data?: string;
  exitCode?: number;
}
```

### 8.4 Diagnostics events

```ts
interface WorkspaceDiagnosticsEvent {
  rootId: string;
  path: string;
  languageId: string;
  diagnostics: Array<{
    severity: "hint" | "info" | "warning" | "error";
    message: string;
    startLine: number;
    startColumn: number;
    endLine: number;
    endColumn: number;
  }>;
}
```

## 9. Tool Policy

### 9.1 Required first-pass tools

- Monaco
- `monaco-languageclient`
- `xterm.js`
- `portable-pty`
- `notify`
- `fd`
- `rg`
- system `git`

### 9.2 Explicitly deferred

- embedded pure-Rust git as the initial backend
- Tantivy or any advanced index as the first search layer
- Yazi as the main explorer model

## 10. Persistence Model

The workspace shell should persist:

- trusted roots
- recent roots
- open tabs per root
- active pane and layout selection
- recent search queries
- optional terminal profiles

It should not persist:

- raw PTY transcripts by default
- arbitrary LSP process state
- unsafe absolute paths outside registered roots

## 11. Verification Gates

Minimum verification for any implementation phase:

- `npm --prefix apps/desktop run typecheck`
- `npm --prefix apps/desktop run build`
- `cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml`

Additional required checks:

- backend tests for root and path-safety behavior
- search and watcher integration tests
- PTY session lifecycle tests
- workspace-surface smoke coverage in the desktop app

## 12. Final Rule

The workspace shell must remain a Huntronomer surface. It should make local assets and authoring
flows operable inside the threat-hunting product loop, not turn the desktop app into a generic
standalone developer IDE.
