# ClawdStrike Workbench: IDE Pivot Plan

> **Pivot:** From "modernize internals" to "become a real VS Code/Cursor-like security IDE"
>
> **Branch:** `feat/workbench-dev`
> **Created:** 2026-03-17
> **Status:** Planning
> **Supersedes:** Phases A-D (foundation work retained, roadmap restructured)

---

## Vision

Transform ClawdStrike Workbench from a sidebar-nav + page-content security dashboard into a
full IDE-like application where:

1. **Activity bar + sidebar** replaces the flat nav — file tree (Explorer) is the primary left panel
2. **Editor area** with splittable panes hosts all rich "apps" (Policy Editor, Swarm Board, Simulator, etc.)
3. **Bottom panel** for Terminal, Problems, Output, Audit tail
4. **Right sidebar** for Speakeasy chat and context-sensitive inspector
5. **Current routes become "apps/plugins"** — like VS Code extensions contributing views, commands, and activity bar items

---

## Current State (What We Have)

### Already Built (Phase A/C Foundation)

| Asset | Status | Location |
|-------|--------|----------|
| Zustand stores (11) | Done | `src/features/*/stores/` |
| `createSelectors` utility | Done | `src/lib/create-selectors.ts` |
| Command registry (50+ cmds) | Done | `src/lib/command-registry.ts` + `src/lib/commands/` |
| Command palette (Cmd+K) | Done | `src/components/desktop/command-palette.tsx` |
| Binary tree pane system | Done | `src/features/panes/` (6 files) |
| Bottom pane (Terminal/Problems/Output) | Done | `src/features/bottom-pane/` (5 files) |
| Multi-policy store decomposition | Done | `src/features/policy/stores/` (5 files, bridge layer) |
| Explorer panel (file tree) | Done | `src/components/workbench/explorer/` |
| Speakeasy panel (chat) | Done | `src/components/workbench/speakeasy/` |
| 14 sidebar sigil icons | Done | `src/components/desktop/sidebar-icons.tsx` |
| Project store (file tree state) | Done | `src/features/project/stores/project-store.tsx` |
| File type registry | Done | `src/lib/workbench/file-type-registry.ts` |

### Codebase Scale

| Metric | Count |
|--------|-------|
| Total source files | 504 (380 src + 124 tests) |
| Workbench components | 213 files across 27 directories |
| lib/workbench utilities | 146 files |
| Feature stores | 30 files across 11 feature domains |
| Routable pages | 19 primary routes |
| Commands registered | 50+ |
| Keyboard shortcuts | 50+ |
| Largest components | Policy Editor (1071 LOC), Hierarchy Page (2266 LOC), Origins (2656 LOC) |

### Current Layout

```
┌─────────────────────────────────────────────┐
│ Titlebar                                    │
├────────┬────────────────────────────────────┤
│Sidebar │ PaneRoot (splittable editor area)  │
│(200px/ │                                    │
│ 52px)  │                                    │
│        ├────────────────────────────────────┤
│ 3 nav  │ BottomPane (Terminal/Problems/     │
│sections│  Output)                           │
├────────┴────────────────────────────────────┤
│ StatusBar                                   │
└─────────────────────────────────────────────┘
```

---

## Target Layout

```
┌──────────────────────────────────────────────────────────┐
│ Titlebar                                                 │
├──┬──────┬──────────────────────────────┬─────────────────┤
│A │Left  │ Editor Area                  │ Right Sidebar   │
│c │Side- │ (Binary tree pane system)    │ (Speakeasy /    │
│t │bar   │                              │  Inspector)     │
│i │      │ ┌──────────┬───────────────┐ │                 │
│v │      │ │ Policy   │ Simulator     │ │                 │
│i │      │ │ Editor   │ Results       │ │                 │
│t │      │ └──────────┴───────────────┘ │                 │
│y │      ├──────────────────────────────┤                 │
│  │      │ BottomPane                   │                 │
│B │      │ (Terminal/Problems/Output/   │                 │
│a │      │  Audit)                      │                 │
│r │      │                              │                 │
├──┴──────┴──────────────────────────────┴─────────────────┤
│ StatusBar                                                │
└──────────────────────────────────────────────────────────┘
```

---

## Activity Bar (48px Left Rail)

Icons that switch sidebar content. Clicking the active icon toggles sidebar closed.

| # | Icon | ID | Label | Sidebar Panel |
|---|------|----|-------|---------------|
| 1 | Heartbeat sigil | `heartbeat` | System Status | Posture ring, sentinel/finding/approval/fleet counts, quick links |
| 2 | Eye sigil | `sentinels` | Sentinels | Filterable sentinel list with status dots, create button |
| 3 | Diamond target | `findings` | Findings & Intel | Two collapsible sections with severity badges |
| 4 | Code brackets | `explorer` | Explorer | Project file tree (policies, Sigma, YARA, OCSF) — **primary** |
| 5 | Book sigil | `library` | Library | Policy catalog, SigmaHQ browser, import/export |
| 6 | Server stack | `fleet` | Fleet & Topology | Connection status, agent summary, topology minimap |
| 7 | Shield sigil | `compliance` | Compliance | Framework selector, score summary |
| --- | --- | --- | --- | --- |
| B | Diamond gear | `settings` | Settings | Opens Settings as editor tab (VS Code model) |

### What Gets an Activity Bar Slot vs. What Becomes an Editor Tab

**Sidebar panels** = things you glance at while working (lists, status, navigation)
**Editor tabs** = things you work IN (rich interactive apps)

---

## Route → IDE Location Migration

| Current Route | Old Nav | New Location | How It Opens |
|---|---|---|---|
| `/home` | Heartbeat link | Editor tab (default) | Default tab on launch |
| `/sentinels` | Sidebar item | **Sidebar panel** | Activity bar icon |
| `/sentinels/create` | Sentinels page | **Editor tab** | Button in sidebar panel |
| `/sentinels/:id` | Sentinels page | **Editor tab** | Click sentinel in sidebar |
| `/missions` | Sidebar item | **Editor tab** | Command palette / Heartbeat link |
| `/findings` | Sidebar item | **Sidebar panel** | Activity bar icon |
| `/findings/:id` | Findings page | **Editor tab** | Click finding in sidebar |
| `/intel/:id` | Findings page | **Editor tab** | Click intel in sidebar |
| `/lab` (swarm) | Sidebar item | **Editor tab** | Command palette |
| `/lab?tab=hunt` | Lab tab | **Editor tab** (independent) | Command palette |
| `/lab?tab=simulate` | Lab tab | **Editor tab** (independent) | Command palette |
| `/swarms` | Sidebar item | **Editor tab** (list) | Command palette |
| `/swarms/:id` | Swarms page | **Editor tab** | Click swarm in list |
| `/editor` | Sidebar item | **Editor tab** | Double-click file in Explorer |
| `/library` | Sidebar item | **Sidebar panel** | Activity bar icon |
| `/compliance` | Sidebar item | **Sidebar panel** (summary) | Activity bar icon; click-through → editor tab |
| `/approvals` | Sidebar item | **Editor tab** | Heartbeat panel link / command palette |
| `/audit` | Sidebar item | **Bottom panel tab** (tail) + **Editor tab** (full) | Bottom panel or command palette |
| `/receipts` | Sidebar item | **Editor tab** | Command palette |
| `/fleet` | Sidebar item | **Sidebar panel** (summary) | Activity bar icon; click-through → editor tab |
| `/topology` | Sidebar item | **Editor tab** | Fleet sidebar link / command palette |
| `/settings` | Bottom sidebar | **Editor tab** | Activity bar bottom gear icon |

---

## Component Hierarchy (Target)

```
DesktopLayout
├── Titlebar
├── CrashRecoveryBanner (conditional)
├── InitCommands + ShortcutProvider + CommandPalette
├── MainArea (flex row)
│   ├── ActivityBar (48px, fixed)
│   │   ├── ActivityBarItem[] (top: heartbeat, sentinels, findings, explorer, library, fleet, compliance)
│   │   └── ActivityBarItem[] (bottom: settings)
│   ├── LeftSidebar (resizable, collapsible)
│   │   └── [HeartbeatPanel | SentinelPanel | FindingsPanel |
│   │        ExplorerPanel | LibraryPanel | FleetPanel | CompliancePanel]
│   ├── EditorArea (flex column, flex-1)
│   │   ├── PaneRoot (binary tree of PaneGroups)
│   │   │   └── PaneContainer
│   │   │       ├── PaneTabBar (view tabs)
│   │   │       └── PaneRouteRenderer (renders the app)
│   │   └── BottomPane (resizable, toggleable)
│   │       └── [TerminalPanel | ProblemsPanel | OutputPanel | AuditTailPanel]
│   └── RightSidebar (resizable, toggleable, optional)
│       └── [SpeakeasyPanel | InspectorPanel]
└── StatusBar
```

---

## New Zustand Stores

| Store | Purpose | Key State |
|-------|---------|-----------|
| `activity-bar-store` | Active sidebar panel, sidebar visibility/width | `activeItem`, `sidebarVisible`, `sidebarWidth` |
| `right-sidebar-store` | Right sidebar visibility and active panel | `visible`, `activePanel`, `width` |

All existing stores (pane, bottom-pane, policy, operator, fleet, sentinel, finding, mission, swarm, project, settings) remain unchanged.

---

## Pane Store Enhancement

The existing pane store needs one key addition:

```typescript
// Current: syncRoute(route) — updates active view's route
// New: openApp(route, label) — opens route as new tab (or focuses existing)
openApp(route: string, label: string): void {
  // If a tab with this route already exists in any pane, focus it
  // Otherwise, add as new view in active pane
}
```

This is the bridge between sidebar "click to open" and the editor area.

---

## New Commands

| Command ID | Title | Category | Keybinding |
|------------|-------|----------|------------|
| `sidebar.explorer` | Show Explorer | Sidebar | Cmd+Shift+E |
| `sidebar.sentinels` | Show Sentinels | Sidebar | — |
| `sidebar.findings` | Show Findings | Sidebar | — |
| `sidebar.library` | Show Library | Sidebar | — |
| `sidebar.fleet` | Show Fleet | Sidebar | — |
| `sidebar.compliance` | Show Compliance | Sidebar | — |
| `sidebar.toggle` | Toggle Sidebar | View | Cmd+B |
| `sidebar.toggleRight` | Toggle Right Sidebar | View | Cmd+Shift+B |
| `app.missions` | Open Mission Control | Navigate | — |
| `app.approvals` | Open Approvals | Navigate | — |
| `app.audit` | Open Audit Log | Navigate | — |
| `app.receipts` | Open Receipts | Navigate | — |
| `app.topology` | Open Topology | Navigate | — |
| `app.swarmBoard` | Open Swarm Board | Navigate | — |
| `app.hunt` | Open Threat Hunt | Navigate | — |
| `app.simulator` | Open Simulator | Navigate | — |

---

## What Changes vs. What Stays

### Stays As-Is
- All 11 Zustand stores and their APIs
- Command registry singleton
- Binary tree pane system (enhanced with `openApp`)
- Bottom pane (Terminal/Problems/Output)
- All 19 page components (they become "apps" without code changes)
- Explorer panel
- Speakeasy panel
- File type registry + project store
- All 146 lib/workbench utilities
- All detection-workflow subsystem (30 files)
- StatusBar
- Titlebar
- Command palette

### Changes
- `desktop-sidebar.tsx` → decompose into `ActivityBar` + `SidebarPanel`
- `desktop-layout.tsx` → insert ActivityBar, add right sidebar zone
- `workbench-routes.tsx` → routes stay but some become sidebar-panel-only (no direct nav)
- `navigate-commands.ts` → use `paneStore.openApp()` instead of `navigate()`
- `view-commands.ts` → add sidebar toggle commands

### New Components
- `ActivityBar` — 48px icon rail
- `ActivityBarItem` — individual icon button
- `SidebarPanel` — container that renders active panel
- `HeartbeatPanel` — expanded system status (extract from Heartbeat widget)
- `SentinelPanel` — sentinel list for sidebar
- `FindingsPanel` — findings + intel list for sidebar
- `LibraryPanel` — catalog browser for sidebar (adapt from library-gallery)
- `FleetPanel` — fleet summary for sidebar
- `CompliancePanel` — compliance summary for sidebar
- `RightSidebar` — container for Speakeasy/Inspector
- `AuditTailPanel` — lightweight audit log for bottom pane (4th tab)

---

## Athas Patterns to Port

| Pattern | Athas Source | ClawdStrike Target |
|---------|-------------|-------------------|
| Activity bar toggle logic | `sidebar-pane-selector.tsx` | `ActivityBar` + `activity-bar-store` |
| Resizable left/right sidebars | `resizable-pane.tsx` | Wrap existing sidebar + new right sidebar |
| Sidebar panel switching | `main-sidebar.tsx` | `SidebarPanel` conditional rendering |
| File tree actions (create/delete/rename) | `file-explorer-tree.tsx` | Enhance existing `ExplorerPanel` |
| Slice-based Zustand composition | `ui-state-store.ts` | Activity bar + right sidebar stores |
| Context-aware keybinding dispatch | `keymaps/utils/context.ts` | Enhance existing shortcut provider |
| Terminal always-mounted pattern | `bottom-pane.tsx` | Already done in bottom-pane |

---

## Phased Execution

### Phase 1: Activity Bar + Sidebar Shell
> Decompose sidebar, add activity bar, wire panel switching

- Extract `ActivityBar` from `desktop-sidebar.tsx`
- Create `activity-bar-store` (Zustand)
- Create `SidebarPanel` container with conditional rendering
- Move system heartbeat into `HeartbeatPanel`
- Move Explorer to be the default sidebar panel
- Wire activity bar toggle logic (click same icon = collapse)
- Add `sidebar.toggle` (Cmd+B) and `sidebar.explorer` (Cmd+Shift+E) commands
- **Existing nav still works** — sidebar panels just wrap the same route content initially

### Phase 2: Sidebar Panels
> Build lightweight sidebar views for each activity bar item

- `SentinelPanel` — list from `useSentinels()`, click → `paneStore.openApp('/sentinels/:id')`
- `FindingsPanel` — list from `useFindings()`, click → open detail tab
- `LibraryPanel` — adapt catalog browser for sidebar width
- `FleetPanel` — connection status + agent summary
- `CompliancePanel` — framework selector + score cards
- `HeartbeatPanel` — posture ring + counts + quick links
- Add `openApp(route, label)` to pane store

### Phase 3: Right Sidebar + Polish
> Add right sidebar zone, wire Speakeasy, refine transitions

- Create `right-sidebar-store`
- Add `RightSidebar` container to layout
- Move Speakeasy panel to right sidebar
- Add `sidebar.toggleRight` (Cmd+Shift+B) command
- Optional: context-sensitive Inspector panel
- Add `AuditTailPanel` as 4th bottom pane tab
- Polish activity bar icons, tooltips, badges

### Phase 4: Lab Decomposition + App Opening
> Break Lab into independent apps, full "open in pane" workflow

- Lab's Swarm Board, Hunt, Simulate become independent editor tabs
- Remove `LabLayout` tab container (or keep as convenience grouping)
- All sidebar panel clicks properly open editor tabs via `openApp`
- Navigate commands rewritten to use `openApp` pattern
- Remove old sidebar nav items — activity bar is the only navigation

---

## Files That Need Changes

| File | Change | Phase |
|------|--------|-------|
| `desktop-layout.tsx` | Insert ActivityBar, add right sidebar zone | 1 |
| `desktop-sidebar.tsx` | Decompose into ActivityBar + SidebarPanel | 1 |
| `pane-store.ts` | Add `openApp(route, label)` action | 2 |
| `navigate-commands.ts` | Use `openApp()` instead of `navigate()` | 4 |
| `view-commands.ts` | Add sidebar toggle commands | 1 |
| `workbench-routes.tsx` | Mark routes as sidebar-panel vs editor-tab | 4 |
| `lab-layout.tsx` | Make Swarm/Hunt/Simulate independently openable | 4 |

---

## Success Criteria

- [ ] Activity bar with 7+1 icons controls sidebar content
- [ ] Explorer (file tree) is the default/primary sidebar view
- [ ] Clicking items in sidebar panels opens editor tabs via `openApp`
- [ ] Policy editor + simulation viewable side-by-side (pane split)
- [ ] Right sidebar available for Speakeasy chat
- [ ] Terminal accessible via Cmd+J from any context
- [ ] All existing routes still reachable (no functionality loss)
- [ ] All existing tests pass after each phase
- [ ] Command palette discovers all sidebar/app commands
- [ ] Feels like VS Code / Cursor — folder-first, panels everywhere

---

## Risk Register

| Risk | Severity | Mitigation |
|------|----------|------------|
| Sidebar panels duplicating full page components | Medium | Sidebar panels are lightweight summaries; full pages remain as editor tabs |
| Activity bar icon overload (too many items) | Low | 7+1 is within VS Code's typical range (6-8 default) |
| Right sidebar rarely used | Low | Ship Speakeasy only; Inspector is stretch goal |
| Lab decomposition breaks tab state | Medium | Maintain `?tab=` query params as fallback; test tab persistence |
| Route-to-app migration confuses existing users | Low | Default layout opens Home tab; sidebar panels provide same navigation paths |

---

*Supersedes: phase-a-foundation.md, phase-b-core-stores.md, phase-c-layout.md, phase-d-restructure.md*
*Foundation work from Phases A/C is retained and built upon.*
