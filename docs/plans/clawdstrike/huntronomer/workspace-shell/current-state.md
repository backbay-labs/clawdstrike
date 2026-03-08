# Huntronomer Workspace Shell Current State

> **Status:** Draft | **Date:** 2026-03-07
> **Scope:** Inventory the current desktop app against the desired Tauri-native workspace shell

## 1. Summary

The current desktop app has a usable shell, a functioning Tauri bridge, local session persistence,
and several runtime/proof-oriented surfaces. It does not yet have a real workspace model.

The gap is structural, not cosmetic:

- there is no trusted-root or workspace service in the backend
- there is no canonical file tree or tab model in the frontend
- there is no PTY terminal backend
- there is no Monaco or LSP integration
- there is no `fd` or `rg` sidecar orchestration for workspace search
- there is no git integration in the desktop surface

This means the requested stack should be treated as a new initiative built on top of the existing
desktop shell, not as a small extension of the current policy workbench.

## 2. Reusable Substrate

### 2.1 Desktop shell and navigation

Useful existing layers:

- `apps/desktop/src/shell/ShellApp.tsx`
- `apps/desktop/src/shell/ShellLayout.tsx`
- `apps/desktop/src/shell/components/NavRail.tsx`
- `apps/desktop/src/shell/components/CommandPalette.tsx`
- `apps/desktop/src/shell/dock/**`

These already provide:

- multi-surface routing
- keyboard-first shell patterns
- a session rail and dock system
- command-palette integration points

The workspace surface can reuse this shell instead of inventing a second app container.

### 2.2 Frontend-to-backend invoke pattern

Useful existing layers:

- `apps/desktop/src/services/tauri.ts`
- `apps/desktop/src-tauri/src/main.rs`
- `apps/desktop/src-tauri/src/commands/**`

These already prove:

- Tauri command registration is in place
- the frontend is already structured around invoke wrappers
- backend-owned operations are an established pattern in the app

This is the correct seam for workspace, terminal, search, and git commands.

### 2.3 Local persistence patterns

Useful existing layer:

- `apps/desktop/src/shell/sessions/sessionStore.ts`

This already provides:

- localStorage-backed state persistence
- schema-versioned storage
- legacy ID migration patterns
- route and session recall patterns

The workspace initiative can reuse this approach for recent roots, open tabs, terminal history, and
selected panes before introducing a heavier persistence layer.

### 2.4 Existing Rust-side discovery patterns

Useful existing layer:

- `crates/libs/hunt-scan/src/discovery.rs`

This is not a workspace shell, but it does show the repo already contains:

- platform-aware path discovery
- home-directory expansion
- installed-tool detection patterns

That is relevant for later detection of `git`, `rg`, `fd`, language servers, and optional external
power tools.

## 3. Current Gaps Against The Requested Stack

### 3.1 No workspace trust model

The app does not currently manage:

- trusted roots
- canonicalized workspace registration
- path scope policy separate from ad hoc dialog selection
- workspace-specific permissions or capability lifetimes

Today, the desktop app is runtime-centric, not workspace-centric.

### 3.2 No filesystem services

There is currently no desktop command surface for:

- listing directories
- reading or writing arbitrary workspace files
- rename, move, delete, or create flows
- metadata, breadcrumbs, or tree expansion state

The existing policy editor only works through purpose-built policy endpoints and does not generalize
into a workspace file model.

### 3.3 No backend watcher layer

The Rust desktop app does not yet use `notify`, and there is no unified file-watcher service in
`apps/desktop/src-tauri`.

That means the app cannot currently:

- keep a tree in sync with on-disk changes
- invalidate tabs when files change externally
- stream workspace-change events across the shell

### 3.4 No IDE-grade editor stack

The current editor-like surface is the policy workbench:

- `apps/desktop/src/features/forensics/policy-workbench/PolicyWorkbenchPanel.tsx`

It is a task-specific editor/tester flow built with existing UI primitives. It is not:

- Monaco
- LSP-enabled
- buffer-model driven
- suitable as a general file editor

### 3.5 No integrated terminal

The desktop app enables `tauri-plugin-shell`, but it does not expose:

- PTY sessions
- terminal tabs
- resize/stdin/stdout streaming
- long-lived interactive shells

The shell plugin is useful for tightly-scoped one-shot commands and sidecars, but it is not a
complete integrated terminal by itself.

### 3.6 No workspace search layer

There is no current desktop service for:

- `fd` path search
- `rg` content search
- streaming search results
- ignored-file-aware workspace traversal

Search today is domain-event oriented, not filesystem oriented.

### 3.7 No git surface

There is no current desktop integration for:

- git status
- diff summaries
- branch selection
- commit flows
- blame or file history

This is a hard missing capability if the workspace surface is expected to feel IDE-grade.

## 4. Keep / Build / Defer

## Keep

- Tauri app shell and invoke pattern
- session/dock/command palette infrastructure
- existing local persistence approach for lightweight settings
- runtime/proof surfaces as neighboring Huntronomer destinations
- shell plugin as the launching substrate for tightly allowlisted tools

## Build

- dedicated workspace services in Rust
- frontend workspace feature tree
- Monaco editor stack
- PTY terminal backend and xterm.js UI
- `fd` and `rg` sidecar search
- system git integration
- trust-root settings and recent-root persistence

## Defer

- Tantivy or any non-trivial index engine
- pure-Rust embedded git as the first shipping path
- Yazi as a first-class navigation model
- deep refactor/rename flows across every language from day one

## 5. Main Risks

1. The shared shell is already busy. Route, dock, and session ownership must stay orchestrated to
   avoid collisions with the existing Huntronomer surface work.
2. Tauri capability scoping will become more complex once `git`, `rg`, `fd`, language servers, and
   PTYs all enter the app.
3. Monaco, language workers, xterm.js, and terminal streaming can easily bloat the desktop bundle
   unless loaded intentionally.
4. The product can drift into a generic mini-VS-Code if the workspace surface is not kept tied to
   Huntronomer objects and workflows.

## 6. Current-State Conclusion

The current desktop app is a good host for a workspace shell, but it is not already one. The right
move is to preserve the outer shell and add a native-backed workspace subsystem with clear service
boundaries, not to keep stretching the existing policy editor and runtime views beyond their design
limits.
