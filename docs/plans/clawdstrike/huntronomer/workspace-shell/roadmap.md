# Huntronomer Workspace Shell Roadmap

> **Status:** Draft | **Date:** 2026-03-07
> **Scope:** Delivery plan for the native-backed workspace shell inside `apps/desktop`

Execution topology, lane ownership, and merge sequencing are defined in `./swarm-plan.md`.

## Delivery Principle

Build the workspace shell as a thin frontend over backend-owned services. Do not start by hand-wiring
Monaco, search, terminal, and git straight into the UI without a stable Rust service core.

## MVP Definition

The fastest sane MVP is:

- open folder
- trusted root registration
- file tree
- open/edit/save tabs in Monaco
- watcher-backed file refresh
- `rg` workspace search
- keyboard-first workspace routing inside the existing shell

This is the point where the surface becomes meaningfully useful.

## Phase 0: Docs And Contract Freeze

Deliverables:

- current-state review
- target architecture
- Spec 17 workspace-service contract
- implementation roadmap
- proposed swarm graph

Exit criteria:

- agreed module split
- agreed trust model
- agreed command and event vocabulary

## Phase 1: Workspace Core And Trust Boundary

Primary code areas:

- `crates/libs/huntronomer-workspace-core/**`
- `apps/desktop/src-tauri/src/commands/workspace.rs`
- `apps/desktop/src-tauri/src/main.rs`
- `apps/desktop/src-tauri/Cargo.toml`

Deliverables:

- trusted-root registration
- canonical path resolution
- filesystem list/read/write/create/rename/delete basics
- settings for recent and active roots
- capability-scoped tool configuration for future sidecars

Exit criteria:

- the backend can open a root and perform safe file operations against it
- the frontend has typed invoke wrappers for workspace basics

## Phase 2: Workspace Surface And Editor MVP

Primary code areas:

- `apps/desktop/src/features/workspace/**`
- `apps/desktop/src/services/workspace.ts`
- `apps/desktop/package.json`

Deliverables:

- workspace route and rail entry
- file tree and breadcrumbs
- tab strip and split-aware editor shell
- Monaco editor integration
- save, reload, dirty state, and missing-file handling

Exit criteria:

- a user can open a folder, browse files, edit a file, and save it through the desktop app

## Phase 3: Watchers, Search, And Operator Flow

Primary code areas:

- `crates/libs/huntronomer-workspace-core/src/watch/**`
- `crates/libs/huntronomer-workspace-core/src/search/**`
- `apps/desktop/src/features/workspace/search/**`

Deliverables:

- `notify` watcher integration
- backend-to-frontend file-change events
- `fd` path search and quick-open
- `rg` content search with streaming results
- command-palette and deep-link handoff into workspace files

Exit criteria:

- the workspace tree and tabs react to external file changes
- search is fast enough without any indexer

## Phase 4: Terminal And Git

Primary code areas:

- `crates/libs/huntronomer-workspace-core/src/terminal/**`
- `crates/libs/huntronomer-workspace-core/src/git/**`
- `apps/desktop/src/features/workspace/terminal/**`
- `apps/desktop/src/features/workspace/git/**`

Deliverables:

- PTY-backed terminal tabs via `portable-pty`
- xterm.js panel with resize and streaming
- system `git` status, branch, and diff summary
- command-palette hooks for task and terminal actions

Exit criteria:

- terminal tabs behave like real interactive shells
- the workspace surface can show basic repo state without leaving the app

## Phase 5: Language Intelligence

Primary code areas:

- `apps/desktop/src/features/workspace/editor/**`
- `crates/libs/huntronomer-workspace-core/src/proc/**`

Deliverables:

- `monaco-languageclient`
- sidecar-managed language servers for the top one or two languages
- diagnostics, hover, go-to-definition, and symbol search

Exit criteria:

- Monaco is no longer just a text buffer and can support real authoring workflows

## Phase 6: Persistence, Release Hardening, And Optional Indexing

Primary code areas:

- `apps/desktop/src/features/workspace/state/**`
- `apps/desktop/src-tauri/tauri.conf.json`
- packaging/release wiring

Deliverables:

- recent roots and tab/session persistence
- better empty, offline, and denied-state handling
- bundle splitting for Monaco/xterm/language features
- optional SQLite FTS spike only if `fd` plus `rg` is insufficient
- optional Yazi launcher only as a power-tool accelerator

Exit criteria:

- reloads preserve useful workspace state
- packaged builds can launch the workspace surface cleanly
- the product still feels like Huntronomer, not a bolted-on devtool

## Parallel Workstreams

- Rust core and frontend shell scaffolding can begin in parallel once the command vocabulary is
  frozen.
- Search and watcher work can progress in parallel with Monaco integration after root registration
  exists.
- PTY terminal work can progress in parallel with git status work after the workspace root contract
  is stable.
- LSP work should wait until Monaco models and basic save/reload behavior exist.

## Verification Requirements

Every phase should preserve:

- `npm --prefix apps/desktop run typecheck`
- `npm --prefix apps/desktop run build`
- `cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml`

Additional verification by phase:

- Phase 1: backend unit tests for root registration and path resolution
- Phase 2: frontend tests for tree, tabs, and dirty-state behavior
- Phase 3: search and watcher integration tests
- Phase 4: terminal-session and git-status tests
- Phase 5: language-client smoke tests
- Phase 6: packaged-app smoke, startup, and offline/degraded-mode tests

## Open Questions

1. Should the workspace surface ship as a new primary rail destination in v1, or initially as a
   command-palette and deep-link surface?
2. Which file types are first-class at launch: Markdown, YAML, JSON, Sigma-like rule files,
   scripts, or a broader general-code set?
3. Which language servers are worth productizing first without over-expanding the initial scope?
4. How much Huntronomer-specific metadata should live beside local files versus in backend objects
   such as Cases, Briefs, and Hunts?
