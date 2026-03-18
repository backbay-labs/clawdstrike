# 04 - Migration Plan: Plugin Shell to Workbench Architecture

This document specifies the phased migration from the current plugin-based page router shell to a persistent IDE-like workbench. Each phase is self-contained and shippable. Phases 1-2 can run behind the `huntronomer:workbench:v2` feature flag so the old shell remains available as a fallback.

---

## Current Architecture Summary

The app today is structured as:

- **Router**: `createHashRouter` in `src/shell/ShellApp.tsx` (line 29) renders `ShellLayout` at `/`, with 13 plugin routes as children.
- **Layout**: `src/shell/ShellLayout.tsx` -- 220px `NavRail` on the left, `<Outlet />` in the center, floating `DockSystem` overlaid.
- **Navigation**: `src/shell/components/NavRail.tsx` -- session-focused rail showing strikecell sessions; bottom status sigil for Operations.
- **Plugins**: `src/shell/plugins/registry.tsx` -- 13 `AppPlugin` entries, each with `React.lazy` components and route arrays. Plugin type defined in `src/shell/plugins/types.ts`.
- **Dock**: `src/shell/dock/DockSystem.tsx` -- floating capsules (10 kinds) + `SessionRail` bottom bar + draggable `ShelfPanel`. State in `DockContext.tsx` via `useReducer`.
- **Sessions**: `src/shell/sessions/sessionStore.ts` -- `SessionStore` singleton with localStorage persistence, `useSyncExternalStore` hooks.
- **Keyboard**: `src/shell/keyboard/useShellShortcuts.ts` -- Cmd+1-9 mapped to fixed `AppId` set, Cmd+K palette, Cmd+[/] prev/next app.
- **Workspace**: `src/features/workspace/` -- self-contained IDE subsystem with its own tree view, editor state, search, git, terminal panels, tab frames (`WorkspaceTabFrame`), and route-based section navigation (`WorkspaceShellScreen.tsx`).

---

## Phase 1: Shell + Lens Foundation

**Goal**: Replace the outer shell frame. Everything inside still routes to plugins via `<Outlet />`, but the 220px `NavRail` is replaced by a 48px `ActivitySpine` + collapsible `LensSidebar`, and the orb becomes the `OrbLensRotor`.

### Files to Create

| File | Purpose |
|------|---------|
| `src/shell/workbench/WorkbenchShell.tsx` | New root layout component. Renders `WorkbenchStateProvider` > CSS Grid shell (`ActivitySpine` \| `LensSidebar` \| content `<Outlet />` \| `StatusBar`). Replaces `ShellLayout` in the router. |
| `src/shell/workbench/WorkbenchStateProvider.tsx` | React context provider wrapping `WorkbenchState`. Exposes `useWorkbench()` hook. Initializes from localStorage (`huntronomer:workbench:state:v1`). |
| `src/shell/workbench/workbenchState.ts` | Pure state model. Types: `ShellMode` (`wire` \| `hunt` \| `lab` \| `case`), `LensId` (see below), `WorkbenchState` (current lens, sidebar collapsed, sidebar width, selected entity, active tab group, bottom panel state). Reducer actions for all mutations. |
| `src/shell/workbench/ActivitySpine.tsx` | 48px-wide vertical icon column. Top: `OrbLensRotor`. Below: shell mode icons (Wire, Hunt, Lab, Case). Bottom: settings gear, connection status dot. Click selects shell; orb handles lens cycling. |
| `src/shell/workbench/OrbLensRotor.tsx` | Replaces `CyberNexusOrb` in the spine position. Reuses the orb visuals (glow, ring, icon) extracted from `CyberNexusOrb.tsx`. Click toggles between current and previous lens (like Alt+Tab). Long-press opens the lens picker menu (280px radial layout). Right-click context menu preserved. |
| `src/shell/workbench/LensSidebar.tsx` | Collapsible sidebar (default 240px, min 180px, max 400px, resizable). Renders content based on `activeLensId`. Each lens is lazy-loaded. See Lens Definitions below for the canonical set. |
| `src/shell/workbench/StatusBar.tsx` | 24px bottom strip. Left: shell mode indicator, active lens name. Center: breadcrumb for selected entity. Right: connection status, daemon URL, active session count. |

### Lens Definitions

The canonical `LensId` set aligns with the architecture spec (01-ARCHITECTURE.md S3.3):

```typescript
type LensId =
  | "scopes"       // Workspace trusted roots + watchlists + subscribed feeds
  | "history"      // Event stream timeline, audit log, recent tabs/commands
  | "files"        // File explorer for active workspace root (reuses WorkspaceTreeView)
  | "sandboxes"    // Policy tester sandboxes, experiment runs
  | "entities"     // Agent identities, observed hosts, IOCs
  | "swarms"       // Active swarm topology, connection graph
  | "notes";       // Investigation notes, case artifacts
```

> **Note**: All 7 lenses are available in every shell. Each shell defines prominent lenses (listed first in the orb cycle and lens picker) and a default lens. See 03-COMPONENT-LAYOUT.md S8 for the full cycle order per shell.

### Files to Modify

**`src/shell/ShellApp.tsx`**
- Import `WorkbenchShell` alongside `ShellLayout`.
- Read feature flag `huntronomer:workbench:v2` from localStorage.
- If flag is set, use `WorkbenchShell` as the root layout element (line 32). Otherwise keep `ShellLayout`.
- No changes to the plugin route children -- they continue to render inside `<Outlet />`.

```typescript
// Pseudocode for the router change
const LayoutComponent = isWorkbenchV2Enabled() ? WorkbenchShell : ShellLayout;
return createHashRouter([{
  path: "/",
  element: <LayoutComponent />,
  children: [/* unchanged plugin routes */],
}]);
```

**`src/shell/ShellLayout.tsx`**
- Add `@deprecated` JSDoc comment. No functional changes.
- Kept as fallback until Phase 2 is stable.

**`src/shell/components/CyberNexusOrb.tsx`**
- Extract the `NexusIcon` SVG component and mode-ring rendering into a shared module `src/shell/components/OrbVisuals.tsx` (new file).
- `CyberNexusOrb` imports from `OrbVisuals` (no behavior change).
- `OrbLensRotor` also imports from `OrbVisuals` but adds lens-cycling behavior.

**`src/shell/keyboard/useShellShortcuts.ts`**
- Add lens shortcuts: `Cmd+1` through `Cmd+7` select the lens by index (Scopes=1, History=2, Files=3, Sandboxes=4, Entities=5, Swarms=6, Notes=7) when workbench mode is active.
- Add shell shortcuts: `Cmd+Shift+1` through `Cmd+Shift+4` for Wire/Hunt/Lab/Case.
- The current `VIEW_KEYS` mapping (lines 17-27) is kept for legacy shell mode.
- Add `Cmd+Shift+B` to toggle sidebar collapse. This avoids conflict with `Cmd+B` (bold text in editors).
- Add `Cmd+Shift+E` for Files lens, `Cmd+Shift+F` for search focus, `Cmd+Shift+G` for Git (standard IDE bindings).

### Files to Eventually Remove

| File | Timing |
|------|--------|
| `src/shell/components/NavRail.tsx` | After Phase 2 ships and feature flag is removed. NavRail functionality is fully replaced by ActivitySpine + LensSidebar. |

### Migration of NavRail Features

| NavRail Feature | New Location |
|----------------|-------------|
| CyberNexusOrb (top) | `OrbLensRotor` at top of `ActivitySpine` |
| "Strikecell Sessions" list | History lens in `LensSidebar` (session stack section), or Entities lens |
| Session create `+` button | History lens header action or command palette |
| Operations status sigil (bottom) | `ActivitySpine` bottom icon + `StatusBar` right section |
| Session kind badges (chat/experiment/red-team) | Preserved in History lens session list |

### Test Strategy

| Category | Verification |
|----------|-------------|
| Visual | App loads with 48px spine + sidebar. Orb renders at top of spine. Lens icons are clickable. Sidebar shows content for selected lens. |
| Functional | All 13 plugin routes still render in the center `<Outlet />`. Navigating to `/nexus`, `/workspace`, `/events`, etc. works identically. |
| Regression | Command palette (`Cmd+K`) opens. `Cmd+N` creates a new tab in the current pane. `Cmd+Shift+N` creates a new strikecell session. `Cmd+,` opens Operations. Session persistence in localStorage unchanged. |
| Feature flag | Setting `huntronomer:workbench:v2` to `"0"` in localStorage loads old `ShellLayout`. Removing the key defaults to old shell. |
| Keyboard | `Cmd+1`-`7` selects lenses. `Cmd+Shift+1`-`4` switches shells. `Cmd+Shift+B` toggles sidebar. `Cmd+Shift+E/F/G` opens Files/Search/Git lenses. |

---

## Phase 2: Tab Workbench

**Goal**: Replace the full-page `<Outlet />` with a tab bar + content area. Plugins become tab content providers instead of route destinations.

### Files to Create

| File | Purpose |
|------|---------|
| `src/shell/workbench/TabBar.tsx` | Horizontal tab strip rendered above the content area. Each tab shows: icon, title, dirty indicator, close button. Supports: preview tabs (italic title, replaced on next open), pinned tabs (lock icon, not closable via single click), drag-to-reorder, middle-click close, right-click context menu (Close, Close Others, Close All, Pin/Unpin). |
| `src/shell/workbench/TabContentRenderer.tsx` | Given a `TabState`, resolves the `tabKind` to a lazy React component via `tabRegistry` and renders it. Mounts/unmounts based on active tab. Keeps recently-used tabs alive in a hidden DOM pool (configurable, default 3) for fast switching. **Note**: 3D-heavy tab kinds (`threat-radar`, `attack-graph`, `network-map`, `profile`) are excluded from the keep-alive pool to avoid GPU/memory pressure. The `tabRegistry` entry for these kinds sets `keepAlive: false`. |
| `src/shell/workbench/SplitPaneContainer.tsx` | Container that manages 1-3 split panes (vertical split). Each pane has its own `TabBar` + `TabContentRenderer`. Alt+click on a tab opens it in a new pane. Panes are resizable via drag handle. When a pane's last tab closes, the pane collapses. |
| `src/shell/workbench/tabRegistry.ts` | Maps `TabKind` string to `{ component: React.LazyExoticComponent, icon: string, defaultTitle: string }`. Populated from plugin definitions at init. |

### Tab Kind Mapping

Every current plugin maps to a tab kind. The lazy component references are the same `React.lazy` imports already in `src/shell/plugins/registry.tsx`.

| Plugin (`AppId`) | Tab Kind | Content Component | Source |
|------------------|----------|-------------------|--------|
| `nexus` | `hunt` | `ForensicsRiverView` | `registry.tsx` lines 12-15 (lazy import), plugin def line 61 |
| `workspace` | `artifact` | `WorkspaceEditorPane` | `workspace/editor/` |
| `operations` | `operations` | `OperationsHubView` | `registry.tsx` lines 17-18, plugin def line 85 |
| `events` | `signal-thread` | `EventStreamView` | `registry.tsx` line 9, plugin def line 88 |
| `policies` | `policy` | `PolicyViewerView` | `registry.tsx` lines 20-21, plugin def line 96 |
| `policy-tester` | `sandbox` | `PolicyTesterView` | `registry.tsx` lines 23-24, plugin def line 103 |
| `swarm` | `profile` | `SwarmMapView` | `registry.tsx` lines 26-27, plugin def line 111 |
| `marketplace` | `marketplace` | `MarketplaceView` | `registry.tsx` lines 29-30, plugin def line 119 |
| `workflows` | `workflow` | `WorkflowsView` | `registry.tsx` lines 32-33, plugin def line 127 |
| `threat-radar` | `threat-radar` | `ThreatRadarView` | `registry.tsx` lines 35-36, plugin def line 135 |
| `attack-graph` | `attack-graph` | `AttackGraphView` | `registry.tsx` lines 38-39, plugin def line 143 |
| `network-map` | `network-map` | `NetworkMapView` | `registry.tsx` lines 41-42, plugin def line 151 |
| `security-overview` | `brief` | `SecurityOverviewView` | `registry.tsx` lines 44-47, plugin def line 159 |

> **Tab Kind alignment**: These `TabKind` values match the canonical set in 01-ARCHITECTURE.md S3.4. The `file` kind (for workspace file tabs) is an additional non-plugin kind used when opening individual files from the Files lens.

### Tab State Model

Added to `src/shell/workbench/workbenchState.ts`:

```typescript
// Canonical TabKind -- aligned with 01-ARCHITECTURE.md S3.4
// Plugin-mapped kinds:
type TabKind =
  | "signal-thread" | "hunt" | "receipt" | "case" | "sandbox"
  | "artifact" | "brief" | "profile" | "policy"
  | "threat-radar" | "attack-graph" | "network-map"
  | "workflow" | "marketplace" | "operations"
// Non-plugin (internal) kinds:
  | "file"          // Individual workspace file (opened from Files lens)
  | "welcome";      // Empty state / getting started (shown when zero tabs open)

interface TabState {
  id: string;                    // Unique tab ID (e.g., "tab_hunt-deck_0", "tab_file_src/main.rs")
  kind: TabKind;
  title: string;
  subtitle?: string;             // e.g., file path, policy name
  icon?: string;
  isPreview: boolean;            // Preview tabs are replaced when another file opens
  isPinned: boolean;
  isDirty: boolean;
  sourceUri?: string;            // For file tabs: root-relative path. For entity tabs: entity ID.
  metadata?: Record<string, unknown>;
}

interface TabGroupState {
  id: string;                    // Pane ID ("main", "split-1", "split-2")
  tabs: TabState[];
  activeTabId: string | null;
  tabHistory: string[];          // For back/forward navigation
}
```

### Files to Modify

**`src/shell/workbench/WorkbenchShell.tsx`**
- Replace `<Outlet />` with `<SplitPaneContainer />`.
- The router still exists but routes now trigger tab-open actions instead of rendering directly. A `useEffect` watches `location.pathname` and converts route changes into `openTab()` calls.
- Route-to-tab mapping: `/<appId>` opens a tab of the corresponding `tabKind`. If a tab of that kind already exists, focus it instead of creating a duplicate.

**`src/shell/workbench/workbenchState.ts`**
- Add `tabGroups: TabGroupState[]` to `WorkbenchState`.
- Add reducer actions: `OPEN_TAB`, `CLOSE_TAB`, `PIN_TAB`, `UNPIN_TAB`, `SET_TAB_PREVIEW`, `REORDER_TAB`, `MOVE_TAB_TO_GROUP`, `SET_ACTIVE_TAB`, `SET_TAB_DIRTY`, `NAVIGATE_TAB_BACK`, `NAVIGATE_TAB_FORWARD`.
- Tab open logic: if `isPreview` and a preview tab already exists in the group, replace it. If a tab with the same `sourceUri` exists, focus it.

**`src/shell/plugins/registry.tsx`**
- Add `tabKind` field to each plugin definition.
- Add `openAsTab` boolean (default `true`) to control whether the plugin opens as a tab or as a full-page route (escape hatch).
- Example change for nexus plugin:

```typescript
{
  id: "nexus",
  name: "Hunt Deck",
  icon: "nexus",
  description: "Autonomous threat hunting command surface",
  order: 1,
  tabKind: "hunt",            // NEW
  openAsTab: true,            // NEW
  routes: [/* unchanged for backward compat */],
}
```

**`src/shell/plugins/types.ts`**
- Extend `AppPlugin` interface:

```typescript
interface AppPlugin {
  // ... existing fields ...
  tabKind?: TabKind;            // NEW: tab content mapping
  openAsTab?: boolean;          // NEW: default true
  singleton?: boolean;          // NEW: only one tab of this kind allowed
}
```

### Zero-Tab Empty State

When all tabs in a pane are closed, the pane renders a `welcome` tab with shell-appropriate quick-start actions:

| Shell | Empty State Content |
|-------|-------------------|
| Wire | "Open a feed" + recent feed list |
| Hunt | "Start a hunt" + recent hunt list |
| Lab | "Open a folder" + recent workspace roots |
| Case | "Create a case" + recent case list |

The `welcome` tab kind is not closable and does not appear in the tab bar. It auto-dismisses when any real tab opens. The empty state reuses the pattern from `WorkspaceShellScreen.tsx` lines 511-543 (empty/denied state rendering).

### Tab Overflow Behavior

When tabs exceed the available tab bar width:

1. **Horizontal scroll**: The tab bar scrolls horizontally. Left/right scroll buttons appear at the edges when overflow is detected.
2. **Tab dropdown**: A chevron button at the right end of the tab bar opens a dropdown listing all open tabs (grouped by pinned first, then by open order). Clicking an entry activates that tab.
3. **Soft limit**: At 25 open tabs, a toast warning appears: "Consider closing unused tabs." At 30 tabs, new preview tabs replace the oldest unpinned preview tab instead of the current preview tab.

### Dirty Tab Close Behavior

All close actions on dirty tabs show a confirmation dialog with three options: **Save** / **Don't Save** / **Cancel**.

- `Cmd+W` on a dirty tab: shows dialog.
- Middle-click on a dirty tab: shows dialog (middle-click is not exempt).
- Close button (X) on a dirty tab: shows dialog.
- "Close All" from tab context menu: aggregates dirty tabs -- "N tabs have unsaved changes. Save all / Don't save / Cancel."
- "Close Others" from tab context menu: same aggregation for dirty tabs being closed.

This mirrors the current `shouldBlockDirtyPolicyDraftExit` behavior in `ShellLayout.tsx` (lines 101-110) but generalized to all dirty tab kinds.

### Route-to-Tab Redirect Strategy

Old hash routes (`/#/nexus`, `/#/workspace`, etc.) must continue to work for bookmarks and external links.

In `WorkbenchShell.tsx`:
1. On mount and on `location` change, check if the pathname matches `/<appId>`.
2. Look up the plugin by `appId`. If `openAsTab` is true, dispatch `OPEN_TAB` with the matching `tabKind`.
3. For workspace sub-routes (`/workspace/search`, `/workspace/git`, etc.), open a `file` tab with appropriate metadata to restore the workspace section.
4. Replace the URL to `/#/` (root) to avoid stale route state. The URL no longer drives content -- tab state does.

### Workspace Integration

The workspace plugin is special because it has its own internal tab system (`WorkspaceTabFrame` in `workspaceShellState.ts`). In Phase 2:

- Each workspace file opens as a workbench-level `file` tab (kind `"file"`, `sourceUri` = `rootId::relativePath`).
- The workspace-internal `WorkspaceSurfaceState.tabs` array is retired. The workbench `TabGroupState` becomes the single source of truth for open files.
- `WorkspaceEditorPane` receives its `rootId` and `relativePath` as props from the tab's `sourceUri` and `metadata`.
- The workspace tree view (`WorkspaceTreeView`) in the Explorer lens dispatches `OPEN_TAB` actions to the workbench state instead of calling `setState` locally.

### Test Strategy

| Category | Verification |
|----------|-------------|
| Tab open | Clicking a spine icon or palette command creates a tab. The tab bar shows the plugin name and icon. |
| Tab preview | Single-clicking a file in Explorer opens a preview tab (italic). Double-clicking or editing pins it. |
| Tab pin | Right-click > Pin locks the tab. Pinned tabs sort to the left. |
| Tab close | Middle-click or X button closes tab. Closing last tab shows welcome/empty state. Dirty tabs show confirmation dialog. |
| Tab reorder | Drag-and-drop reorders tabs within a group. |
| Split panes | Alt+click on a tab opens it in a new vertical pane. Pane resize via drag handle. |
| Route compat | Navigating to `/#/nexus` opens the Hunt Deck tab. `/#/workspace/search` opens a file tab with search section. |
| Back/forward | Browser back/forward navigates tab history within the active group. |
| Persistence | `WorkbenchState` (including all tab groups) serializes to localStorage on change and restores on reload. |

---

## Phase 3: Panel System

**Goal**: Replace the floating capsule dock with a persistent, collapsible bottom panel with tabbed content areas.

### Files to Create

| File | Purpose |
|------|---------|
| `src/shell/workbench/BottomPanel.tsx` | Collapsible bottom panel container. Renders `BottomPanelTabs` for tab selection and the active panel content. Resizable via top drag handle (min 120px, max 50% viewport, default 180px). Toggle with `Cmd+J`. Collapse state persisted in `WorkbenchState`. |
| `src/shell/workbench/BottomPanelTabs.tsx` | Horizontal tab row for bottom panel. Tabs: Tape, Terminal, Receipts, Tasks, Replay, Diff. Each tab shows icon + label + optional badge count. Active tab highlighted. |
| `src/shell/workbench/panels/TapePanel.tsx` | Live receipt/validation stream. Replaces the Events shelf (`ShelfPanel` with `mode="events"`). Reuses `ChronicleWorkbenchShelf` content as inner component. Adds filtering controls (by guard, verdict, time range). |
| `src/shell/workbench/panels/TerminalPanel.tsx` | Wraps `WorkspaceTerminalPanel` from `src/features/workspace/terminal/`. Adds multi-terminal support with sub-tabs for each PTY session. Passes active workspace `rootId` from `WorkbenchState`. |
| `src/shell/workbench/panels/ReceiptsPanel.tsx` | Receipt browser with table view. Columns: timestamp, action type, verdict, policy, guards triggered. Click row to expand detail. Replaces artifact/inspector capsule functionality for receipt data. |
| `src/shell/workbench/panels/TasksPanel.tsx` | Swarm task list. Shows active agent tasks with status, progress, assigned agent. Replaces the "Relics" shelf content and part of the sessions functionality from `SessionRail`. |
| `src/shell/workbench/panels/ReplayPanel.tsx` | Hunt session replay. Timeline scrubber for reviewing past hunt sessions. Replaces the concept of archived sessions from `SessionStore`. |
| `src/shell/workbench/panels/DiffPanel.tsx` | Side-by-side or unified diff viewer. Activated when comparing policy versions or file changes. |

### Files to Modify

**`src/shell/workbench/WorkbenchShell.tsx`**
- Add `BottomPanel` to the CSS Grid layout. Grid becomes:

```
+--------------------------------------------------+
| ActivitySpine | LensSidebar | TabBar             |
|               |             |--------------------|
|               |             | TabContent         |
|               |             |--------------------|
|               |             | BottomPanel        |
+--------------------------------------------------+
| StatusBar                                        |
+--------------------------------------------------+
```

- Grid template: `"spine sidebar main" 1fr / 48px auto 1fr` for the top area, with the main column internally split into `TabBar | TabContent | BottomPanel` using nested flex.

**`src/shell/workbench/workbenchState.ts`**
- Add bottom panel state:

```typescript
type BottomPanelTab = "tape" | "terminal" | "receipts" | "tasks" | "replay" | "diff";

interface BottomPanelState {
  isCollapsed: boolean;
  activeTab: BottomPanelTab;
  height: number;               // Persisted pixel height
  badges: Partial<Record<BottomPanelTab, number>>;
}
```

- Add reducer actions: `TOGGLE_BOTTOM_PANEL`, `SET_BOTTOM_PANEL_TAB`, `SET_BOTTOM_PANEL_HEIGHT`, `UPDATE_BOTTOM_PANEL_BADGE`.

### Files to Deprecate/Remove

| File | Action | Reason |
|------|--------|--------|
| `src/shell/dock/DockSystem.tsx` | Remove | Replaced by `BottomPanel`. The `ShelfPanel` (lines 100-394), `CapsuleStack`, and demo content are all superseded. |
| `src/shell/dock/DockContext.tsx` | Remove | `DockState` (capsules, shelf, sessions) absorbed into `WorkbenchState`. The `DockProvider`, `useDock`, `useCapsule`, `useCapsulesByKind` hooks are no longer needed. |
| `src/shell/dock/Capsule.tsx` | Remove | Floating capsules replaced by bottom panel tabs and context inspector. |
| `src/shell/dock/SessionRail.tsx` | Remove | Bottom activity bar replaced by `StatusBar` + `BottomPanel` tabs. Hot commands move to command palette. Dial menus (Commands, Whisper, Coven) move to the palette or lens sidebar. |
| `src/shell/dock/types.ts` | Remove | `CapsuleKind`, `DockCapsuleState`, `ShelfMode`, etc. replaced by `BottomPanelTab` and `TabState`. |
| `src/shell/dock/useDockDemo.ts` | Remove | Demo data no longer needed. |
| `src/shell/dock/hotCommands.ts` | Migrate | Hot command persistence logic moves to a shared utility. The `SessionRail` dial menu is replaced by a "Hot Commands" section in the command palette. |
| `src/styles/dock.css` (if exists) | Remove | Replaced by workbench panel styles. |

### Migration of Dock Features

| Dock Feature | Current Location | New Location |
|-------------|-----------------|-------------|
| Events capsule (`kind: "events"`) | `DockSystem` > `CapsuleStack` | `BottomPanel` > Tape tab |
| Events shelf (`mode: "events"`) | `DockSystem` > `ShelfPanel` | `BottomPanel` > Tape tab (full-width) |
| Output capsule (`kind: "output"`) | `DockSystem` > `CapsuleStack` | `BottomPanel` > Terminal tab |
| Output shelf (`mode: "output"`) | `DockSystem` > `ShelfPanel` | `BottomPanel` > Terminal tab |
| Artifact capsule (`kind: "artifact"`) | `DockSystem` > `CapsuleStack` | `BottomPanel` > Tasks tab (for task artifacts) or tab content (for file artifacts) |
| Artifacts shelf (`mode: "artifacts"`) | `DockSystem` > `ShelfPanel` | `BottomPanel` > Tasks tab |
| Inspector capsule (`kind: "inspector"`) | `DockSystem` > `CapsuleStack` | `ContextInspector` (Phase 4 right pane) |
| Terminal capsule (`kind: "terminal"`) | `DockSystem` > `CapsuleStack` | `BottomPanel` > Terminal tab |
| Action capsule (`kind: "action"`) | `DockSystem` > `CapsuleStack` | Tab content (opens as action-review tab) or `BottomPanel` notification toast |
| Chat capsule (`kind: "chat"`) | `DockSystem` > `CapsuleStack` | Tab content (opens as chat tab with `tabKind: "chat"`) |
| Social capsule (`kind: "social"`) | `DockSystem` > `CapsuleStack` | `LensSidebar` > Swarm lens (entities section) |
| Season pass capsule (`kind: "season_pass"`) | `DockSystem` > `CapsuleStack` | Removed. If needed, add to Operations/Settings. |
| Kernel agent capsule (`kind: "kernel_agent"`) | `DockSystem` > `CapsuleStack` | `BottomPanel` > Tasks tab (agent status rows) |
| Session rail sessions | `SessionRail` | `StatusBar` session count + Swarm lens detail |
| Session rail dial menus | `SessionRail` (Commands/Whisper/Coven) | Command palette sections |
| Session rail OpenClaw probe | `SessionRail` (lines referencing `openclawGatewayProbe`) | `StatusBar` connection indicator |

### Adapter Layer for `DockProvider` Consumers

During Phase 3, any code that calls `useDock()`, `useCapsule()`, or `useCapsulesByKind()` needs updating. Search the codebase for these imports:

```
grep -r "useDock\|useCapsule\|DockProvider\|openCapsule\|openShelf" src/
```

For each call site:
- `openCapsule({ kind: "terminal", ... })` becomes dispatching `SET_BOTTOM_PANEL_TAB("terminal")` + `TOGGLE_BOTTOM_PANEL(open)`.
- `openShelf("events")` becomes `SET_BOTTOM_PANEL_TAB("tape")` + `TOGGLE_BOTTOM_PANEL(open)`.
- `DockProvider` wrapper in `ShellLayout.tsx` (line 392) is removed. `WorkbenchStateProvider` already wraps the entire shell.

### Test Strategy

| Category | Verification |
|----------|-------------|
| Panel toggle | `Cmd+J` toggles bottom panel. Panel appears/disappears with animation. Height persists across toggles. |
| Panel tabs | Clicking each tab (Tape/Terminal/Receipts/Tasks/Replay/Diff) shows corresponding content. Badge counts update. |
| Panel resize | Dragging top handle resizes panel. Min/max constraints enforced. Height persists to localStorage. |
| Terminal | Terminal panel renders PTY sessions. Multiple sub-tabs for multiple terminals. |
| Tape | Live receipt stream shows policy decisions. Filter controls work. |
| Dock removal | No floating capsules appear. No `SessionRail` at bottom. No shelf panels. |
| Regression | `ChronicleWorkbenchShelf` content (from `src/features/forensics/policy-workbench/`) renders correctly inside Tape panel. |

---

## Phase 4: Right Context Pane

**Goal**: Add a persistent, selection-aware right pane that shows contextual information for the currently selected entity (tab, file, receipt, agent, policy).

### Files to Create

| File | Purpose |
|------|---------|
| `src/shell/workbench/ContextInspector.tsx` | Right pane container. Collapsible (default 320px, min 240px, max 480px). Shows tabbed content based on selected entity. Toggle with `Cmd+\` (matches 01-ARCHITECTURE.md S6.3 and 02-INTERACTION-DESIGN.md S10). Collapse state in `WorkbenchState`. |
| `src/shell/workbench/inspector/ContextTab.tsx` | Metadata panel. Shows entity type, name, timestamps, linked entities, tags. For files: file size, language, last modified. For policies: schema version, guard count, inheritance chain. For agents: identity, delegation tokens, active sessions. |
| `src/shell/workbench/inspector/GraphTab.tsx` | Mini entity relationship graph. Shows connections between the selected entity and related objects (e.g., policy -> guards -> receipts -> agents). Lightweight 2D force graph, not the full 3D SwarmMap. |
| `src/shell/workbench/inspector/ProofTab.tsx` | Receipt chain viewer. Shows the Ed25519-signed receipt for the selected action, with full guard results, policy snapshot, and Merkle proof if available. Validation status (verified/unverified/expired). |
| `src/shell/workbench/inspector/CompanionTab.tsx` | AI-powered contextual suggestions. Shows relevant documentation, similar receipts, policy recommendations. Marked as experimental/optional. |

### Files to Modify

**`src/shell/workbench/WorkbenchShell.tsx`**
- Add `ContextInspector` to the grid layout. Final grid:

```
+--------------------------------------------------------------+
| Spine | Sidebar | TabBar                    | InspectorTabs  |
|       |         |---------------------------|                |
|       |         | TabContent                | InspectorBody  |
|       |         |---------------------------|                |
|       |         | BottomPanel               |                |
+--------------------------------------------------------------+
| StatusBar                                                    |
+--------------------------------------------------------------+
```

- The inspector spans the full height of the content area (from tab bar to above status bar), independent of the bottom panel.

**`src/shell/workbench/workbenchState.ts`**
- Add inspector state:

```typescript
type InspectorTab = "context" | "graph" | "proof" | "companion";

interface InspectorState {
  isCollapsed: boolean;
  width: number;
  activeTab: InspectorTab;
}

interface SelectionState {
  entityType: "file" | "receipt" | "policy" | "agent" | "session" | "guard" | null;
  entityId: string | null;
  metadata?: Record<string, unknown>;
}
```

- `WorkbenchState` gains `inspector: InspectorState` and `selection: SelectionState`.
- Add reducer actions: `TOGGLE_INSPECTOR`, `SET_INSPECTOR_TAB`, `SET_INSPECTOR_WIDTH`, `SET_SELECTION`.

### Selection Flow

1. User clicks a file tab -> `SET_SELECTION({ entityType: "file", entityId: "rootId::path" })`.
2. User clicks a receipt in Tape panel -> `SET_SELECTION({ entityType: "receipt", entityId: receiptId })`.
3. User clicks an agent in Swarm lens -> `SET_SELECTION({ entityType: "agent", entityId: agentId })`.
4. `ContextInspector` reacts to selection changes and loads appropriate data for each tab.

### Integration with Existing Workspace Inspector

The current `WorkspaceShellScreen.tsx` has a right-pane inspector (lines 402-427) showing trust-root metadata. This content migrates into `ContextTab.tsx` -- when a workspace file is selected, the context tab shows the trusted root info, canonical path, and file metadata. The workspace-internal inspector section is removed.

### Test Strategy

| Category | Verification |
|----------|-------------|
| Inspector toggle | `Cmd+\` toggles right pane. Width persists. |
| Selection tracking | Clicking a tab updates the inspector. Clicking a receipt in Tape updates the inspector. |
| Context tab | File selection shows file metadata. Policy selection shows policy details. |
| Graph tab | Shows entity connections. Nodes are clickable (updates selection). |
| Proof tab | Shows receipt details with verification status. |

---

## Risk Assessment

| Risk | Severity | Likelihood | Mitigation |
|------|----------|-----------|------------|
| Breaking existing features during Phase 1 shell swap | High | Medium | Feature flag `huntronomer:workbench:v2` gates the new shell. Old `ShellLayout` remains functional. Both share the same router children, so plugin code is untouched. |
| Router removal breaks deep links and bookmarks | Medium | High | Route-to-tab redirect in `WorkbenchShell.tsx` intercepts all `/<appId>` routes and opens corresponding tabs. Old URLs continue to work. |
| Performance with 3D backgrounds + split panes + panels | Medium | Medium | Disable `SOCBackground` (ambient 3D WebGL scene) entirely when the workbench v2 shell is active. The current `ShellLayout.tsx` (lines 123-134) already disables it for 6 of 13 routes; the workbench disables it unconditionally since multiple tab kinds can be simultaneously mounted in split panes. Lazy-load panel contents. Use `React.memo` on `TabContentRenderer` children. |
| Session/state migration from old format | Medium | Medium | `WorkbenchStateProvider` reads both old (`sdr:sessions`) and new (`huntronomer:workbench:state:v1`) storage keys. On first load in workbench mode, it migrates session data from `SessionStore` format to `WorkbenchState` format. Old data is preserved (not deleted) for rollback. |
| Tab state persistence and restore across restarts | Low | Low | `WorkbenchState` serializes to localStorage on every mutation (debounced 500ms, matching `SessionStore` pattern). On load, tabs restore with lazy content -- the component mounts but data loads on demand. |
| Workspace dual-tab conflict (internal tabs vs workbench tabs) | Medium | High | Phase 2 explicitly retires `WorkspaceSurfaceState.tabs`. The workspace tree dispatches `OPEN_TAB` to workbench state. `WorkspaceEditorPane` receives props from tab metadata. No dual-tab state. |
| Dock removal breaks external consumers | Medium | Low | Search for all `useDock`/`DockProvider` imports before Phase 3. Provide a one-release deprecation window where `DockProvider` re-exports workbench state hooks with console warnings. |
| Test coverage gaps from route-to-tab transition | Medium | Medium | Existing tests that assert on route paths (`/nexus`, `/workspace/search`, etc.) need updating to assert on tab state. Add a test helper: `expectTabOpen(kind: TabKind)` that checks `WorkbenchState`. |

---

## Backward Compatibility

1. **Feature flag gating**: Phase 1-2 run behind `huntronomer:workbench:v2` flag stored in localStorage. Setting it to `"1"` enables the new shell. Default is `"0"` (old shell).

2. **Old ShellLayout preserved**: `ShellLayout.tsx` is kept (marked `@deprecated`) until the flag is removed. No code changes to it during migration.

3. **Route compatibility**: Old hash routes (`/#/nexus`, `/#/workspace/search`, etc.) are intercepted by `WorkbenchShell` and converted to tab-open actions. External links and bookmarks continue to work.

4. **Session data migration**: The `SessionStore` (`sdr:sessions` localStorage key) is read-only in workbench mode. Sessions are migrated to `WorkbenchState` on first load. The old key is not modified, allowing rollback to old shell without data loss.

5. **DockSystem deprecation window**: During Phase 3 development, `DockProvider` is temporarily kept as a thin adapter that delegates to `WorkbenchState`. Console warnings guide migration. Removed in the release after Phase 3 ships.

6. **Plugin API stability**: `AppPlugin` interface gets new optional fields (`tabKind`, `openAsTab`, `singleton`). Existing plugins work without modification -- they default to `openAsTab: true` with their `id` as the tab kind fallback.

---

## Phase Sequencing and Dependencies

```
Phase 1: Shell + Lens Foundation
  ├── No dependencies on other phases
  ├── Can ship independently behind feature flag
  └── Duration: foundation work

Phase 2: Tab Workbench
  ├── Depends on: Phase 1 (WorkbenchShell, WorkbenchState)
  ├── Can ship incrementally (tabs first, then split panes)
  └── Duration: most complex phase

Phase 3: Panel System
  ├── Depends on: Phase 2 (tab system must be active, dock removal requires tab-based content)
  ├── Can ship panel-by-panel (Terminal first, then Tape, etc.)
  └── Duration: moderate, mostly moving existing UI

Phase 4: Right Context Pane
  ├── Depends on: Phase 2 (selection model), Phase 3 (bottom panel for receipt source)
  ├── Can ship incrementally (Context tab first, others follow)
  └── Duration: greenfield work, lowest urgency
```

---

## Checklist Per Phase

### Phase 1 Checklist
- [ ] Create `src/shell/workbench/` directory
- [ ] Implement `workbenchState.ts` with `ShellMode`, `LensId`, reducer
- [ ] Implement `WorkbenchStateProvider.tsx` with localStorage persistence
- [ ] Extract orb visuals from `CyberNexusOrb.tsx` into `OrbVisuals.tsx`
- [ ] Implement `OrbLensRotor.tsx` using shared orb visuals
- [ ] Implement `ActivitySpine.tsx` with lens icons
- [ ] Implement `LensSidebar.tsx` with lazy lens content
- [ ] Implement `WorkbenchShell.tsx` with CSS Grid layout
- [ ] Implement `StatusBar.tsx`
- [ ] Add feature flag gate in `ShellApp.tsx`
- [ ] Add lens keyboard shortcuts to `useShellShortcuts.ts`
- [ ] Verify all 13 plugin routes render in `<Outlet />`
- [ ] Verify command palette, session management, and shortcuts work

### Phase 2 Checklist
- [ ] Implement `tabRegistry.ts` with all 13 plugin mappings
- [ ] Implement `TabBar.tsx` with preview/pin/dirty/reorder
- [ ] Implement `TabContentRenderer.tsx` with lazy loading and keep-alive pool
- [ ] Implement `SplitPaneContainer.tsx`
- [ ] Add tab state model to `workbenchState.ts`
- [ ] Add `tabKind`/`openAsTab` to `AppPlugin` and all plugin definitions
- [ ] Replace `<Outlet />` with `SplitPaneContainer` in `WorkbenchShell`
- [ ] Implement route-to-tab redirect logic
- [ ] Migrate workspace internal tabs to workbench tab state
- [ ] Verify old routes open correct tabs
- [ ] Verify tab persistence across page reload

### Phase 3 Checklist
- [ ] Implement `BottomPanel.tsx` with resize and collapse
- [ ] Implement `BottomPanelTabs.tsx`
- [ ] Implement `TapePanel.tsx` (migrate `ChronicleWorkbenchShelf`)
- [ ] Implement `TerminalPanel.tsx` (wrap `WorkspaceTerminalPanel`)
- [ ] Implement `ReceiptsPanel.tsx`
- [ ] Implement `TasksPanel.tsx`
- [ ] Implement `ReplayPanel.tsx`
- [ ] Implement `DiffPanel.tsx`
- [ ] Add bottom panel state to `workbenchState.ts`
- [ ] Migrate all `useDock()`/`openCapsule()` call sites
- [ ] Remove `DockSystem`, `DockContext`, `Capsule`, `SessionRail`
- [ ] Migrate hot commands to command palette
- [ ] Verify no floating capsules or shelf panels appear

### Phase 4 Checklist
- [ ] Implement `ContextInspector.tsx` with collapse and resize
- [ ] Implement `ContextTab.tsx` (entity metadata)
- [ ] Implement `GraphTab.tsx` (mini relationship graph)
- [ ] Implement `ProofTab.tsx` (receipt chain viewer)
- [ ] Implement `CompanionTab.tsx` (AI suggestions, experimental)
- [ ] Add inspector and selection state to `workbenchState.ts`
- [ ] Wire selection updates from tabs, panels, and lenses
- [ ] Remove workspace-internal inspector from `WorkspaceShellScreen.tsx`
- [ ] Verify selection tracking across all entity types
