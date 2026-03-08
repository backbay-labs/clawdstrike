# Huntronomer Workspace Shell Swarm Plan

> **Status:** Draft | **Date:** 2026-03-07
> **Purpose:** Turn the workspace-shell roadmap into executable Codex lanes, waves, and merge gates
> **Active metadata:** `.codex/swarm/lanes.tsv`, `.codex/swarm/waves.tsv`

This plan now seeds the active swarm metadata for the Huntronomer workspace-shell initiative. The
earlier Huntronomer surface-refactor swarm remains useful as historical reference, but it is no
longer the active launcher target.

## 1. Execution Goal

Ship a native-backed workspace shell inside the existing desktop app without:

- collapsing shared shell files into merge conflict zones
- letting the frontend directly own filesystem trust
- overbuilding search, git, or indexing before the workspace basics work

The graph is shaped around five rules:

1. The workspace trust and root contract lands before Monaco, PTY, git, or search-heavy UI work.
2. Shared shell routes, dependency manifests, and Tauri capability files stay orchestrator-owned.
3. Search and terminal backends remain separate from the tree/editor UI so they can advance in
   parallel.
4. LSP waits until Monaco models and save flows are stable.
5. Release hardening and optional indexing are last.

## 2. Orchestrator-Owned Shared Files

These stay under `ORCH` ownership:

- `docs/plans/clawdstrike/huntronomer/workspace-shell/**`
- `docs/specs/17-huntronomer-workspace-services.md`
- `apps/desktop/package.json`
- `apps/desktop/src-tauri/Cargo.toml`
- `apps/desktop/src-tauri/src/main.rs`
- `apps/desktop/src-tauri/tauri.conf.json`
- `apps/desktop/src/shell/ShellApp.tsx`
- `apps/desktop/src/shell/ShellLayout.tsx`
- `apps/desktop/src/shell/plugins/registry.tsx`

Worker lanes may prepare integration-ready modules for these files, but final edits belong to
`ORCH`.

## 3. Lane Map

| Lane | Purpose | Owned paths | Depends on | Verification |
| --- | --- | --- | --- | --- |
| `ORCH` | shared wiring, merge sequencing, dependency manifests, docs, and capability policy | shared files listed above | none | `git diff --stat`, desktop typecheck/build, cargo check after each merge wave |
| `WS1` | Rust workspace core and trust roots | `crates/libs/huntronomer-workspace-core/src/workspace/**`, `crates/libs/huntronomer-workspace-core/src/fs/**`, `crates/libs/huntronomer-workspace-core/src/settings/**`, `apps/desktop/src-tauri/src/commands/workspace.rs` | `ORCH` | backend unit tests plus `cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml` |
| `WS2` | watcher, search, and sidecar process services | `crates/libs/huntronomer-workspace-core/src/watch/**`, `crates/libs/huntronomer-workspace-core/src/search/**`, `crates/libs/huntronomer-workspace-core/src/proc/**`, related tests | `WS1` | backend unit tests plus cargo check |
| `WS3` | workspace shell UI skeleton | `apps/desktop/src/features/workspace/shell/**`, `apps/desktop/src/features/workspace/tree/**`, `apps/desktop/src/features/workspace/state/**`, `apps/desktop/src/services/workspace.ts` | `ORCH` | `npm --prefix apps/desktop run typecheck` |
| `WS4` | Monaco editor and tab/buffer model | `apps/desktop/src/features/workspace/editor/**`, Monaco setup, workspace editor tests | `WS1`, `WS3` | desktop typecheck and editor-focused vitest |
| `WS5` | PTY terminal and task panel | `crates/libs/huntronomer-workspace-core/src/terminal/**`, `apps/desktop/src/features/workspace/terminal/**` | `WS1`, `WS3` | cargo check plus terminal-session tests |
| `WS6` | search and git UX | `apps/desktop/src/features/workspace/search/**`, `apps/desktop/src/features/workspace/git/**`, git/search wrappers | `WS2`, `WS3` | desktop typecheck plus focused UI tests |
| `WS7` | language client and diagnostics | `apps/desktop/src/features/workspace/editor/lsp/**`, `crates/libs/huntronomer-workspace-core/src/proc/lsp/**` | `WS2`, `WS4` | desktop typecheck, cargo check, LSP smoke tests |
| `WS8` | persistence, release hardening, optional indexing, and cross-surface verification | workspace persistence, packaging, smoke tests, optional SQLite FTS spike | `WS4`, `WS5`, `WS6`, `WS7` | desktop tests, build, cargo check, packaging smoke |

## 4. Ticket Breakdown

### ORCH

- `ORCH-T1`: keep docs, routes, manifests, and capability policy aligned
- `ORCH-T2`: integrate worker lanes into shared shell and Tauri wiring
- `ORCH-T3`: enforce merge order and verification gates

### WS1

- `WS1-T1`: implement trusted-root registration and canonical path resolution
- `WS1-T2`: implement file list/read/write/create/move/delete contracts
- `WS1-T3`: implement recent-root and active-root settings persistence

### WS2

- `WS2-T1`: implement `notify` watcher service and normalized change events
- `WS2-T2`: implement `fd` path search and `rg` content search jobs
- `WS2-T3`: implement allowlisted sidecar process management for later LSP/tooling

### WS3

- `WS3-T1`: scaffold workspace route, panel layout, and tree state
- `WS3-T2`: build breadcrumbs, tab-strip frame, and empty/denied states
- `WS3-T3`: integrate workspace commands into the command palette and shell navigation

### WS4

- `WS4-T1`: add Monaco dependencies and editor bootstrapping
- `WS4-T2`: implement file buffers, dirty state, save, and reload flows
- `WS4-T3`: connect editor tabs and selection to the workspace tree

### WS5

- `WS5-T1`: implement PTY session lifecycle in Rust
- `WS5-T2`: render xterm.js terminal tabs and resize behavior
- `WS5-T3`: separate shell sessions from task sessions

### WS6

- `WS6-T1`: build quick-open and content-search UI on top of `fd` and `rg`
- `WS6-T2`: build git status and diff-summary UI
- `WS6-T3`: deep-link search and git results into open tabs and editor panes

### WS7

- `WS7-T1`: add `monaco-languageclient` bridge
- `WS7-T2`: start and supervise top-priority language servers
- `WS7-T3`: surface diagnostics, hover, definition, and symbol navigation

### WS8

- `WS8-T1`: persist roots, tabs, and pane layout across reloads
- `WS8-T2`: harden startup, offline, denied, and packaged-app behavior
- `WS8-T3`: evaluate SQLite FTS only if `fd` and `rg` do not meet product needs

## 5. Dependency Graph

```text
ORCH
├── WS1
├── WS3
├── WS1
│   ├── WS2
│   ├── WS4
│   ├── WS5
│   └── WS8
├── WS2
│   ├── WS6
│   └── WS7
├── WS3
│   ├── WS4
│   ├── WS5
│   └── WS6
├── WS4
│   ├── WS7
│   └── WS8
├── WS5
│   └── WS8
├── WS6
│   └── WS8
└── WS7
    └── WS8
```

Critical edges:

- `WS1 -> WS4`: Monaco cannot open canonical workspace files before root and file contracts exist
- `WS1 -> WS5`: terminal working-directory trust depends on registered roots
- `WS2 -> WS6`: the search UI must consume real backend search streams
- `WS4 -> WS7`: LSP waits on stable editor models and save flows
- `WS4/WS5/WS6/WS7 -> WS8`: persistence and release hardening only make sense after the core
  surface exists

## 6. Wave Plan

| Wave | Lanes | Goal | Advance gate |
| --- | --- | --- | --- |
| `wave0` | `ORCH` | freeze docs, proposed metadata, and shared ownership | docs and spec reviewed |
| `wave1` | `WS1`, `WS3` | backend trust contract plus workspace shell scaffold | roots open safely and UI shell compiles |
| `wave2` | `WS2`, `WS4` | watcher/search core plus Monaco editor MVP | search jobs run and editor can open/save files |
| `wave3` | `WS5`, `WS6` | PTY terminal plus search/git UX | terminal tabs and git/search panels both work |
| `wave4` | `WS7` | language intelligence | diagnostics and definition flows work for top languages |
| `wave5` | `WS8` | persistence and release hardening | smoke, packaging, and degraded-mode checks pass |

## 7. Why This Graph Is Valid

1. It isolates the highest-conflict files under `ORCH`.
2. It lets backend trust and frontend surface skeleton land together before heavier feature work.
3. It keeps terminal, search, and git from blocking the Monaco/editor lane.
4. It delays LSP until the base editor path is stable.
5. It treats indexing and packaging as hardening work, not foundation work.

## 8. Launch Sequence

Seed worktrees:

```bash
scripts/codex-swarm/setup-worktrees.sh orch ws1 ws2 ws3 ws4 ws5 ws6 ws7 ws8
```

Re-run bootstrap when needed:

```bash
scripts/codex-swarm/bootstrap-lane.sh orch ws1 ws2 ws3 ws4 ws5 ws6 ws7 ws8
```

Then launch deliberately:

```bash
scripts/codex-swarm/launch-wave.sh wave0 \
  --note "Keep workspace-shell docs, manifests, and shared shell wiring under ORCH ownership."

scripts/codex-swarm/launch-wave.sh wave1 \
  --note "Land workspace trust roots and shell scaffold before search, Monaco, PTY, or git UX."
```

Only advance once merge and verification gates pass.
