# Huntronomer Workspace Shell

> **Status:** Draft | **Date:** 2026-03-07
> **Audience:** Desktop, platform, product, and swarm implementers
> **Scope:** Add a native-backed workspace surface to `apps/desktop` with real IDE-like filesystem,
> editor, search, terminal, and git behavior

This initiative extends the current Huntronomer desktop app with a serious workspace shell for
authoring, inspecting, and operating on local project roots. The target is not a terminal app
disguised as a desktop product. The target is a Tauri-native shell where the frontend renders an
IDE-like workspace while the Rust backend owns trust, filesystem access, watchers, search, process
control, and git integration.

This work sits beside the existing Huntronomer flagship surfaces:

1. `Signal Wire` remains the home screen.
2. `Huntboard` remains the live execution surface.
3. `Receipt Vault / Replay` remains the proof surface.
4. `Workspace` becomes the authoring and local-operations surface for rules, briefs, artifacts,
   runbooks, and repo-backed hunt assets.

## Reading Order

1. [Current State Review](./current-state.md)
2. [Target Architecture](./target-architecture.md)
3. [Spec 17: Huntronomer Workspace Services](../../../../specs/17-huntronomer-workspace-services.md)
4. [Spec 18: Huntronomer Shell Command Model](../../../../specs/18-huntronomer-shell-command-model.md)
5. [Implementation Roadmap](./roadmap.md)
6. [Swarm Execution Plan](./swarm-plan.md)

## Source Material

- Workspace-shell product/technical spec provided in the task thread
- Existing Huntronomer planning set:
  - [Huntronomer README](../README.md)
  - [Huntronomer Target Architecture](../target-architecture.md)
  - [Huntronomer Roadmap](../roadmap.md)
- Current desktop app:
  - `apps/desktop/README.md`
  - `apps/desktop/src/shell/**`
  - `apps/desktop/src/services/tauri.ts`
  - `apps/desktop/src-tauri/src/**`
- Existing reusable Rust substrate:
  - `crates/libs/hunt-scan/src/discovery.rs`

## Initiative Thesis

- The workspace surface should be native-backed and backend-owned, not a browser-first file picker.
- Monaco plus LSP is the right editor spine; do not invent a custom editor stack.
- `rg` and `fd` are the correct first search layer; do not build an indexer first.
- `xterm.js` needs a real PTY backend in Rust; shell one-shot commands are not enough for an
  integrated terminal.
- System `git` should ship before pure-Rust git internals.
- Yazi can be an optional launcher or picker later, but it should not define the product model.

## Code Touchpoints

| Area | Current files | Direction |
| --- | --- | --- |
| Shared shell and route wiring | `apps/desktop/src/shell/**` | Reuse for a new `Workspace` surface and command-palette entries |
| Frontend Tauri bridge | `apps/desktop/src/services/tauri.ts` | Extend with workspace, search, terminal, and git commands |
| Tauri app entry and command registration | `apps/desktop/src-tauri/src/main.rs`, `apps/desktop/src-tauri/src/commands/**` | Add dedicated workspace commands and streaming events |
| Settings and session memory patterns | `apps/desktop/src/shell/sessions/**` | Reuse for recent roots, tabs, and layout persistence |
| Policy workbench | `apps/desktop/src/features/forensics/policy-workbench/**` | Replace narrow textarea/tester model with a real workspace/editor stack |
| Search/process helpers | no desktop equivalent today | Add backend services for `fd`, `rg`, PTY, LSP, and git |

## Deliverables In This Set

- A grounded review of what the current desktop app can and cannot already support
- A target architecture for a Tauri-native workspace shell
- A formal service-spec for trust, commands, channels, and module boundaries
- A phased roadmap aligned with the requested stack
- A proposed multi-lane swarm graph for future implementation
