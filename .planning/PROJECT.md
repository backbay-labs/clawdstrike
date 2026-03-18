# ClawdStrike Workbench IDE Pivot

## What This Is

ClawdStrike Workbench is a Tauri 2 + React 19 desktop application for security operations — policy authoring, threat simulation, compliance scoring, fleet management, swarm orchestration, and receipt verification. This milestone transforms its UX from a sidebar-nav dashboard into a VS Code/Cursor-like security IDE with activity bar, splittable panes, file tree, and panel system.

## Core Value

Security operators can work across multiple views simultaneously — policy editor beside simulation results, swarm board beside audit log — with a folder-first navigation model and IDE-grade keyboard workflows. The huntronomer integration adds a spirit-driven immersive layer: 3D observatory, cyber nexus, and spirit companion woven into IDE surfaces.

## Current Milestone: v2.0 Huntronomer Integration

**Goal:** Integrate 3D cyber-nexus, spirit system, and observatory features from the huntronomer branch into the VS Code-like IDE workbench across three tiers: CSS/state drop-ins, small R3F embeds, and full immersive pane tabs.

**Target features:**
- Spirit field stain on panel backgrounds + spirit accent color on hunt UI
- Observatory seam powering activity bar badges (artifact counts)
- Spirit chamber and observatory as pane tab views
- Mini spirit companion R3F canvas in right sidebar
- Animated spirit orb in ActivityBar when spirit is bound
- Cyber nexus as alternative "Hunt Deck" pane
- Forensics river mini-view in bottom pane "Tape" tab
- Route bridge: station clicks → pane-store.openApp()
- New Zustand stores: spirit-store, observatory-store
- New commands: observatory.open, observatory.probe, spirit.bind, spirit.release, nexus.open

## Requirements

### Validated

- ✓ Activity bar + sidebar shell — v1.0
- ✓ Binary tree pane system with split/close/resize — v1.0
- ✓ Bottom pane with Terminal, Problems, Output tabs — v1.0
- ✓ 11 Zustand stores with createSelectors pattern — v1.0
- ✓ Command registry with 50+ commands and Cmd+K palette — v1.0
- ✓ Explorer panel with detection project file tree — v1.0
- ✓ Speakeasy Ed25519-signed chat panel — v1.0
- ✓ 19 routable page components (all existing features) — v1.0
- ✓ Multi-policy store decomposition (3 Zustand stores + bridge) — v1.0
- ✓ In-file search (Cmd+F, Cmd+H) — v1.1
- ✓ Global search (Cmd+Shift+F) with results panel — v1.1
- ✓ File tree mutations (create, rename, delete, status indicators) — v1.1
- ✓ Tab overflow scrolling, context menu, terminal splits — v1.1

### Active

- [ ] Spirit field stain on panel/sidebar backgrounds
- [ ] Spirit accent color on hunt-related UI elements
- [ ] Observatory seam powering activity bar badges
- [ ] Route bridge: station clicks → openApp()
- [ ] Spirit chamber as pane tab view
- [ ] Mini spirit companion R3F canvas in right sidebar
- [ ] Animated spirit orb in ActivityBar (replaces static icon when bound)
- [ ] Receipt/evidence 3D preview in editor tabs
- [ ] Forensics river mini-view in bottom pane "Tape" tab
- [ ] Observatory world as full editor pane (atlas default, flow mode opt-in)
- [ ] Cyber nexus as "Hunt Deck" pane tab
- [ ] Spirit creation chamber with full atmosphere + manifestation canvas
- [ ] Character controller Easter-egg in observatory flow mode
- [ ] spirit-store.ts and observatory-store.ts Zustand stores
- [ ] Commands: observatory.open, observatory.probe, spirit.bind, spirit.release, nexus.open

### Out of Scope

- Full VS Code extension API — overkill; MCP plugin is the right model
- Tree-sitter code editor — CodeMirror + schema-aware completions is correct for YAML/Sigma/YARA
- Vim emulation — not needed for security policy editing
- Full file system abstraction — workbench has its own DetectionProject tree
- Database viewer — irrelevant to security policy IDE
- AI chat side panel — ClawdStrike is the security layer, not an agent (Speakeasy is operator chat)
- VRM avatar rendering — too heavy for IDE; spirit orb is the right abstraction
- Full Rapier physics in workbench — observatory uses simplified scene, not full simulation

## Context

### Foundation Already Built
The workbench-dev branch (feat/workbench-dev) completed Phase A and C foundation work:
- Zustand migration (11 stores, createSelectors utility)
- Command registry (50+ commands, categories, keybindings, context awareness)
- Binary tree pane system (split/close/focus/resize)
- Bottom pane (Terminal/Problems/Output with Zustand store)
- Multi-policy store decomposition (1846-line monolith → 3 focused stores + bridge)

v1.1 added: in-file search, global search, file tree mutations, tab overflow, terminal splits.

### Huntronomer Source
Source 3D code lives in `clawdstrike-worktrees/huntronomer-workspace-orch` (branch `feature/huntronomer-workspace-orchestrator`, committed @ `1586fe2a1`).

Key source directories to port:
- `apps/desktop/src/shell/workbench/spirit/` → spirit types, defaults, sceneVisuals, fieldStain, sceneMath
- `apps/desktop/src/shell/workbench/spirit-ritual/` → creation chamber, modes, atmosphere, canvas, controls
- `apps/desktop/src/features/hunt-observatory/` → character controller, world, stations, probes, missions
- `apps/desktop/src/features/cyber-nexus/` → CyberNexusView, NexusCanvas, NexusSpiritCompanion
- `apps/desktop/src/features/forensics/` → ForensicsRiverView, HuntSpiritOverlay

### Two App Architectures
- `apps/desktop/` — Old huntronomer shell (NavRail + plugins, session-based, has all 3D features)
- `apps/workbench/` — New IDE workbench (ActivityBar + SidebarPanel + PaneRoot + BottomPane + StatusBar)

### Codebase Scale
- 504 total files (380 src + 124 tests)
- 213 workbench components across 27 directories
- 146 lib/workbench utility files
- 19 primary routes, 16+ lazy-loaded pages

### Design System
- shadcn/ui primitives (16 components in components/ui/)
- Tailwind CSS
- Custom animated components (wobble-card, moving-border)
- Monospace typography throughout
- Dark theme (only theme supported)
- React Three Fiber 9 + drei 10 + Rapier 2.2 already in deps

## Constraints

- **Framework**: Tauri 2 + React 19 + TypeScript — existing stack, no changes
- **State**: Zustand + immer — already migrated, no going back to Context
- **Routing**: HashRouter required for Tauri file:// protocol
- **Terminal**: ghostty-web + PTY — existing integration
- **Graph**: @xyflow/react — existing swarm board integration
- **Editor**: CodeMirror — existing policy editor integration
- **Compatibility**: All 19 existing routes must remain reachable (no functionality loss)
- **Testing**: All existing tests must pass after each phase

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Activity bar + sidebar panels (not redesigned nav) | VS Code model proven; reuses existing sigil icons | ✓ Good |
| Current routes become "apps" (zero page component changes) | Minimizes risk; pages render in panes instead of full-page | ✓ Good |
| Sidebar panels are lightweight summaries, not full pages | Full dashboards open as editor tabs; sidebar for glance-and-navigate | ✓ Good |
| Right sidebar for Speakeasy only (Inspector is stretch) | Speakeasy already exists; Inspector needs context-resolution system | ✓ Good |
| Lab decomposed into 3 independent apps | Enables side-by-side policy editor + simulation (key use case) | ✓ Good |
| Mini R3F canvas in right sidebar | Right sidebar already has resize handle; spirit companion fits naturally | — Pending |
| Observatory as TAB/PANE not a panel | Like VS Code Markdown Preview — full pane view, not squeezed sidebar | — Pending |
| deriveObservatoryWorld survives | Powers both full tab and minimap views | — Pending |
| Character controller is opt-in Easter-egg | Only in observatory tab flow mode; not default experience | — Pending |
| 2 new Zustand stores (spirit-store, observatory-store) | Minimal new state surface; typed spirit/observatory state | — Pending |

---
*Last updated: 2026-03-18 after v2.0 Huntronomer Integration milestone start*
