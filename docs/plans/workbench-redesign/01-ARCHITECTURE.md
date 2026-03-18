# 01 - Workbench Architecture Spec

**Status:** Draft
**Scope:** Huntronomer desktop app (`apps/desktop`) -- transform from plugin-routed pages to persistent IDE-like workbench.

---

## 1. Overview

The current Huntronomer desktop UI is organized as a **plugin router**: 13 `AppPlugin` entries (defined in `src/shell/plugins/registry.tsx`) map to full-page routes via `react-router-dom`'s `createHashRouter` (see `src/shell/ShellApp.tsx:29-49`). Navigating between features unmounts the previous view entirely and mounts the next one. The left rail (`NavRail`) is a session-focused sidebar (220px, see `src/shell/components/NavRail.tsx:77`), and the `CyberNexusOrb` cycles through four operation modes (observe/trace/contain/execute) that affect the Nexus strikecell view only.

The workbench redesign replaces this with a **Shell -> Lens -> Tab -> Selection** hierarchy where:

- Views persist across navigation (no unmount/remount).
- Multiple objects can be open simultaneously as tabs.
- Side panels and bottom panels update contextually without full-page transitions.
- The 13 existing plugins become **tab content providers**, not router destinations.

---

## 2. Shell / Lens / Tab / Selection Hierarchy

### 2.1 Shell (Workspace Layout Preset)

A **Shell** is a named layout preset that configures which lenses are prominent, which bottom panel tabs are expanded by default, and the default split arrangement. There are four shells:

| Shell  | Purpose | Prominent Lenses | Default Bottom Tabs | Default Split |
|--------|---------|-------------------|---------------------|---------------|
| `wire` | Live monitoring, event triage | Scopes, History | Tape, Receipts | Single pane |
| `hunt` | Active threat hunting | Entities, Swarms | Terminal, Tasks | Vertical 2-up |
| `lab`  | Policy testing, sandbox experiments | Sandboxes, Files | Terminal, Diff, Replay | Horizontal 2-up |
| `case` | Investigation authoring, case packaging | Notes, History | Receipts, Tasks | Single pane |

Switching shells does **not** close tabs or destroy tab state. It reconfigures:
1. The active lens (reset to the shell's default/prominent lens unless the user has explicitly selected a different lens). All 7 lenses are available in every shell; shells only set which lenses are *prominent* (listed first in the orb cycle and lens picker).
2. The default expanded set of `BottomPanel` tabs.
3. The default split geometry for the `TabWorkbench`.

The current `NexusOperationMode` (observe/trace/contain/execute) from `src/features/cyber-nexus/mode.ts` becomes orthogonal to the shell -- it applies as a **posture overlay** within any shell, not as the shell itself.

### 2.2 Lens (Sidebar Content Controller)

A **Lens** controls what the left sidebar (`LensSidebar`) displays. The `CyberNexusOrb` transforms from a mode cycler to a **lens rotor**: clicking the orb toggles between the current and previous lens (like Alt+Tab); long-press opens the lens picker menu (same interaction pattern as the existing mode menu in `src/shell/components/CyberNexusOrb.tsx:125-143`).

Changing the lens **does not** change the active shell, open tabs, or bottom panel state. It only replaces the sidebar tree content.

| LensId | Sidebar Content | Maps From (Current) |
|--------|----------------|---------------------|
| `scopes` | Workspace trusted roots + tree browser | `workspace` plugin routes, `WorkspaceSurfaceState.tree` |
| `history` | Event stream timeline, audit log | `events` plugin |
| `files` | File explorer for active workspace root | `workspace/tree` route |
| `sandboxes` | Policy tester sandboxes, experiment runs | `policy-tester` plugin |
| `entities` | Agent identities, swarm map sidebar | `swarm` plugin sidebar |
| `swarms` | Active swarm topology, connection graph | `swarm` + `network-map` plugins |
| `notes` | Investigation notes, case artifacts | New (case management) |

### 2.3 Tab (Object Container)

Every meaningful object opens as a tab in the central `TabWorkbench`. Tabs have two modes:

- **Preview** (italic title, not pinned): Opening a new object in preview mode replaces the current preview tab. This is the default for single-click navigation from the lens sidebar.
- **Pinned** (normal title, persistent): Double-clicking a sidebar item, or explicitly pinning, promotes a preview tab to pinned. Pinned tabs persist until explicitly closed.

Tab kinds correspond to the objects they display:

| TabKind | Content Source | Maps From (Current Plugin) |
|---------|---------------|---------------------------|
| `signal-thread` | Real-time event stream for a specific signal | `events` (EventStreamView) |
| `hunt` | Hunt deck / Nexus strikecell session | `nexus` (ForensicsRiverView) |
| `receipt` | Individual receipt inspector | `events` detail view |
| `case` | Case/investigation document | New |
| `sandbox` | Policy test sandbox environment | `policy-tester` (PolicyTesterView) |
| `artifact` | Artifact viewer (file, diff, proof) | `workspace/file/:fileId` route |
| `brief` | Security overview / dashboard | `security-overview` (SecurityOverviewView) |
| `profile` | Agent or entity profile | `swarm` detail view |
| `policy` | Policy document viewer/editor | `policies` (PolicyViewerView) |
| `threat-radar` | Live threat radar view | `threat-radar` (ThreatRadarView) |
| `attack-graph` | MITRE ATT&CK chain view | `attack-graph` (AttackGraphView) |
| `network-map` | Network topology view | `network-map` (NetworkMapView) |
| `workflow` | Workflow editor | `workflows` (WorkflowsView) |
| `marketplace` | Marketplace browser | `marketplace` (MarketplaceView) |
| `operations` | Fleet/daemon management | `operations` (OperationsHubView) |

Tabs can be organized into **split groups** for side-by-side viewing within the `TabWorkbench`.

#### Zero-Tab Empty State

When all tabs are closed (or on first launch), the `TabWorkbench` renders a shell-appropriate welcome view instead of an empty void. Each shell has tailored quick-start actions:

| Shell | Welcome Content |
|-------|----------------|
| `wire` | "Open a feed" + list of recent/subscribed feeds |
| `hunt` | "Start a hunt" + list of recent hunts |
| `lab` | "Open a folder" + list of recent workspace roots |
| `case` | "Create a case" + list of recent cases |

The welcome content is rendered as a `"welcome"` pseudo-tab that does not appear in the tab bar and auto-dismisses when any real tab opens.

### 2.4 Selection (Context Driver)

Within the active tab, the **selected item** drives:
1. The **ContextInspector** (right pane) -- shows details, provenance graph, proof chain, or companion info for the selection.
2. The **BottomPanel** context -- e.g., selecting a receipt in a hunt tab shows its proof chain in the Receipts bottom tab.

Selection is a transient, per-tab concept. Each tab tracks its own `SelectionContext`. When the user switches tabs, the right pane and bottom panel update to reflect the new tab's current selection (or show a default/empty state if nothing is selected).

---

## 3. State Model

### 3.1 Top-Level State

```typescript
/** Root workbench state -- replaces the current router + DockState + SessionsState combination. */
interface WorkbenchState {
  /** Active shell layout preset. */
  shell: ShellMode;

  /** Active lens controlling the sidebar. */
  lens: LensId;

  /** All open tabs, keyed by tab ID. */
  tabs: Map<string, WorkbenchTab>;

  /** Ordered list of tab IDs for rendering the tab bar. */
  tabOrder: string[];

  /** ID of the currently focused tab (receives keyboard input). */
  activeTabId: string | null;

  /** ID of the current preview tab (italic, replaceable), or null if none. */
  previewTabId: string | null;

  /** Split pane layout configuration. */
  splits: SplitPane;

  /** Selection state for each tab. */
  selections: Map<string, SelectionContext>;

  /** Bottom panel state. */
  bottomPanel: BottomPanelState;

  /** Right context inspector state. */
  contextInspector: ContextInspectorState;

  /** NexusOperationMode posture (orthogonal to shell). */
  posture: NexusOperationMode;

  /** Persisted per-shell layout memory. */
  shellMemory: Record<ShellMode, ShellLayoutMemory>;
}
```

### 3.2 Shell Mode

```typescript
type ShellMode = "wire" | "hunt" | "lab" | "case";
```

### 3.3 Lens ID

```typescript
type LensId =
  | "scopes"
  | "history"
  | "files"
  | "sandboxes"
  | "entities"
  | "swarms"
  | "notes";
```

### 3.4 Workbench Tab

```typescript
interface WorkbenchTab {
  /** Unique stable identifier. */
  id: string;

  /** Display title (shown in tab bar). */
  title: string;

  /** Tab content kind -- determines which content provider renders it. */
  kind: TabKind;

  /** Whether this tab is pinned (persistent) or preview (replaceable). */
  pinned: boolean;

  /** True when this tab is in preview mode (italic title, replaced on next preview open). */
  preview: boolean;

  /** Props passed to the content provider component. */
  contentProps: Record<string, unknown>;

  /** Which split group this tab belongs to. Null = primary group. */
  splitGroup: string | null;

  /** Optional icon override (defaults to kind-based icon). */
  icon?: string;

  /** Dirty/unsaved indicator. */
  dirty?: boolean;
}

type TabKind =
  | "signal-thread"
  | "hunt"
  | "receipt"
  | "case"
  | "sandbox"
  | "artifact"
  | "brief"
  | "profile"
  | "policy"
  | "threat-radar"
  | "attack-graph"
  | "network-map"
  | "workflow"
  | "marketplace"
  | "operations";
```

### 3.5 Split Pane

```typescript
/** Recursive split pane tree. Leaf nodes hold tab group IDs. */
type SplitPane =
  | { type: "leaf"; groupId: string }
  | { type: "horizontal"; children: SplitPane[]; sizes: number[] }
  | { type: "vertical"; children: SplitPane[]; sizes: number[] };
```

### 3.6 Selection Context

```typescript
interface SelectionContext {
  /** ID of the tab this selection belongs to. */
  tabId: string;

  /** Type of the selected object (e.g., "receipt", "event", "agent", "file"). */
  objectType: string | null;

  /** ID of the selected object. */
  objectId: string | null;

  /** Metadata blob passed to the ContextInspector for rendering. */
  metadata: Record<string, unknown>;

  /** Which inspector tab to activate for this selection type. */
  preferredInspectorTab?: InspectorTabId;
}
```

### 3.7 Bottom Panel State

```typescript
type BottomPanelTabId =
  | "tape"       // Live event tape / audit log
  | "terminal"   // PTY terminal sessions
  | "receipts"   // Receipt chain viewer
  | "tasks"      // Background task tracker
  | "replay"     // Session replay
  | "diff";      // Diff viewer

interface BottomPanelState {
  /** Currently active tab in the bottom panel. */
  activeTab: BottomPanelTabId;

  /** Whether the panel is collapsed (hidden). */
  collapsed: boolean;

  /** Panel height in pixels when expanded. */
  height: number;

  /** Per-shell memory: remembers which tabs were active and panel height per shell. */
  perShellMemory: Record<ShellMode, {
    activeTab: BottomPanelTabId;
    height: number;
    collapsed: boolean;
  }>;
}
```

### 3.8 Context Inspector State

```typescript
type InspectorTabId =
  | "context"    // Object details / properties
  | "graph"      // Provenance / relationship graph
  | "proof"      // Receipt proof chain
  | "companion"; // AI companion / assistant pane

interface ContextInspectorState {
  /** Currently active inspector tab. */
  activeTab: InspectorTabId;

  /** Panel width in pixels. */
  width: number;

  /** Whether the inspector is visible. */
  visible: boolean;
}
```

### 3.9 Shell Layout Memory

```typescript
/** Persisted per-shell preferences so switching shells restores prior state. */
interface ShellLayoutMemory {
  lens: LensId;
  splits: SplitPane;
  bottomPanel: {
    activeTab: BottomPanelTabId;
    height: number;
    collapsed: boolean;
  };
  contextInspector: {
    activeTab: InspectorTabId;
    width: number;
    visible: boolean;
  };
}
```

---

## 4. Component Tree

```
WorkbenchShell
+-- ActivitySpine (thin icon column, ~48px)
|   +-- OrbLensRotor (CyberNexusOrb repurposed as lens cycler)
|   +-- Divider
|   +-- ShellSwitcher (Wire/Hunt/Lab/Case mode icons, active highlighted)
|   +-- Spacer
|   +-- PostureIndicator (observe/trace/contain/execute, read-only dot)
|   +-- SettingsIcon
|
+-- LensSidebar (~240px, content driven by active LensId)
|   +-- LensSidebarHeader (lens title + collapse toggle)
|   +-- LensSidebarContent (scopes tree | history list | files tree | ...)
|
+-- TabWorkbench (center, fills remaining width)
|   +-- TabBar (horizontal tab strip)
|   |   +-- TabBarItem[] (each tab: icon, title, close button, dirty dot)
|   +-- SplitPaneContainer (recursive split layout)
|       +-- TabContentProvider (renders the correct view for tab.kind)
|
+-- ContextInspector (right pane, ~320px, toggleable)
|   +-- InspectorTabBar (Context | Graph | Proof | Companion)
|   +-- InspectorContent (driven by active tab's SelectionContext)
|
+-- BottomPanel (collapsible, resizable height)
|   +-- PanelTabBar (Tape | Terminal | Receipts | Tasks | Replay | Diff)
|   +-- PanelContent (driven by active bottom tab)
|
+-- StatusBar (absolute bottom, ~24px)
|   +-- ConnectionStatus (daemon status, maps from current NavRail status sigil)
|   +-- PostureLabel (current NexusOperationMode)
|   +-- ActiveShellLabel
|   +-- SelectionBreadcrumb
|   +-- NotificationArea
|
+-- CommandPalette (overlay, existing component at src/shell/components/CommandPalette.tsx)
```

### 4.1 Component Mapping from Current Code

| Current Component | New Component | Transformation |
|-------------------|---------------|----------------|
| `ShellLayout` (`src/shell/ShellLayout.tsx`) | `WorkbenchShell` | Outlet-based routing replaced by tab-based rendering. DockProvider stays, wrapping shifts from ShellLayout to WorkbenchShell. |
| `NavRail` (`src/shell/components/NavRail.tsx`, 220px) | `ActivitySpine` (~48px) + `LensSidebar` (~240px) | NavRail splits into two columns: thin icon spine + wider content sidebar. Session list moves into LensSidebar's "history" lens or into tabs. |
| `CyberNexusOrb` (`src/shell/components/CyberNexusOrb.tsx`) | `OrbLensRotor` | Click cycles lenses (was: modes). Long-press opens lens picker (was: mode picker). Mode/posture moves to a separate PostureIndicator in the ActivitySpine footer. |
| `DockSystem` (`src/shell/dock/DockSystem.tsx`) | `BottomPanel` + capsule overlay layer | SessionRail becomes part of StatusBar. ShelfPanel becomes BottomPanel. Floating capsules persist as an overlay layer above the workbench. |
| `CommandPalette` | `CommandPalette` (unchanged) | Commands extend with tab operations (new tab, close tab, switch tab, split, toggle panels). |
| Plugin routes (`src/shell/plugins/registry.tsx`) | `TabContentProvider` registry | Each plugin's view component becomes a `TabContentProvider` keyed by `TabKind`. No more `react-router-dom` route-per-plugin. |

---

## 5. Data Flow

### 5.1 Shell Mode Change

```
User clicks ShellSwitcher icon (e.g., Wire -> Hunt)
  |
  v
WorkbenchState.shell = "hunt"
  |
  +-> Save current layout to shellMemory["wire"]
  +-> Restore shellMemory["hunt"] (lens, splits, bottom panel, inspector)
  +-> ActivitySpine highlights the new shell mode icon (gold left border)
  +-> BottomPanel restores per-shell tab + height + collapsed state
  +-> ContextInspector restores per-shell width + visibility
  |
  Tabs remain untouched. No tab is closed or created.
```

### 5.2 Lens Change

```
User clicks OrbLensRotor (or uses Cmd+1-7 / long-press lens picker)
  |
  v
WorkbenchState.lens = newLens
  |
  +-> LensSidebar re-renders with new lens content
  |
  Tabs, BottomPanel, ContextInspector, and splits are NOT affected.
```

### 5.3 Opening an Object as a Tab

```
User double-clicks item in LensSidebar (or uses Cmd+T, command palette, etc.)
  |
  v
Determine TabKind + contentProps from the item
  |
  +-> If an existing tab matches (same kind + same contentProps.id): focus it
  |     WorkbenchState.activeTabId = existingTab.id
  |
  +-> If no match and action is "preview" (single-click):
  |     If previewTabId exists: replace that tab's content in-place
  |     If no preview tab: create new preview tab, set previewTabId
  |
  +-> If no match and action is "open" (double-click, Cmd+Enter):
  |     If previewTabId matches: promote to pinned (preview=false, pinned=true)
  |     Else: create new pinned tab
  |
  +-> TabBar re-renders, SplitPaneContainer shows new active tab content
  +-> SelectionContext for the new tab initializes (may be empty)
  +-> ContextInspector updates to reflect new tab's selection
```

### 5.4 Selection Within a Tab

```
User clicks an item inside the active tab content (e.g., a receipt row in a hunt tab)
  |
  v
Tab's content provider calls setSelection({ objectType, objectId, metadata })
  |
  +-> WorkbenchState.selections[activeTabId] updates
  +-> ContextInspector re-renders with new selection metadata
  +-> BottomPanel may highlight related data (e.g., Receipts tab auto-filters)
```

### 5.5 Plugin-to-Tab Content Provider Mapping

The 13 current plugins (`src/shell/plugins/registry.tsx:59-167`) map to tab content providers. The router is removed; the `WorkbenchShell` renders `TabContentProvider` components directly based on the active tab's `kind`.

```typescript
/** Registry that maps TabKind to the React component that renders tab content. */
const TAB_CONTENT_PROVIDERS: Record<TabKind, React.LazyExoticComponent<React.ComponentType<TabContentProps>>> = {
  "hunt":          React.lazy(() => import("@/features/forensics-river/ForensicsRiverView")),
  "signal-thread": React.lazy(() => import("@/features/events/EventStreamView")),
  "policy":        React.lazy(() => import("@/features/policies/PolicyViewerView")),
  "sandbox":       React.lazy(() => import("@/features/policies/PolicyTesterView")),
  "profile":       React.lazy(() => import("@/features/swarm/SwarmMapView")),
  "marketplace":   React.lazy(() => import("@/features/marketplace/MarketplaceView")),
  "workflow":      React.lazy(() => import("@/features/workflows/WorkflowsView")),
  "threat-radar":  React.lazy(() => import("@/features/threat-radar/ThreatRadarView")),
  "attack-graph":  React.lazy(() => import("@/features/attack-graph/AttackGraphView")),
  "network-map":   React.lazy(() => import("@/features/network-map/NetworkMapView")),
  "brief":         React.lazy(() => import("@/features/security-overview/SecurityOverviewView")),
  "operations":    React.lazy(() => import("@/features/operations/OperationsHubView")),
  "artifact":      React.lazy(() => import("@/features/workspace/shell/WorkspaceShellScreen")),
  "receipt":       React.lazy(() => import("@/features/events/ReceiptDetailView")),
  "case":          React.lazy(() => import("@/features/cases/CaseEditorView")),
};

interface TabContentProps {
  tab: WorkbenchTab;
  isActive: boolean;
  selection: SelectionContext | null;
  onSetSelection: (ctx: Partial<SelectionContext>) => void;
}
```

---

## 6. Keyboard Model

The current shortcuts (`src/shell/keyboard/useShellShortcuts.ts`) map `Cmd+1-9` to `AppId` navigation via `VIEW_KEYS`. The workbench replaces this with a layered scheme:

### 6.1 Lens Shortcuts (replaces Cmd+1-9 app navigation)

| Shortcut | Action |
|----------|--------|
| `Cmd+1` | Activate lens: Scopes |
| `Cmd+2` | Activate lens: History |
| `Cmd+3` | Activate lens: Files |
| `Cmd+4` | Activate lens: Sandboxes |
| `Cmd+5` | Activate lens: Entities |
| `Cmd+6` | Activate lens: Swarms |
| `Cmd+7` | Activate lens: Notes |

### 6.2 Tab Shortcuts (new)

| Shortcut | Action |
|----------|--------|
| `Cmd+T` | New tab (opens default tab for current shell) |
| `Cmd+W` | Close active tab |
| `Ctrl+Tab` | Cycle to next tab |
| `Ctrl+Shift+Tab` | Cycle to previous tab |
| `Cmd+Shift+T` | Reopen last closed tab |
| `Cmd+1-9` (with Ctrl modifier) | Jump to tab by position (when tab bar is focused) |

### 6.3 Panel Shortcuts (new)

| Shortcut | Action |
|----------|--------|
| `Cmd+\` | Toggle ContextInspector (right pane) |
| `Cmd+J` | Toggle BottomPanel |
| `Cmd+Shift+P` | Open CommandPalette (replaces `Cmd+K`, which is kept as alias) |
| `Cmd+K` | Open CommandPalette (legacy alias, kept for muscle memory) |

### 6.4 Shell Shortcuts (new)

| Shortcut | Action |
|----------|--------|
| `Cmd+Shift+1` | Switch to Wire shell |
| `Cmd+Shift+2` | Switch to Hunt shell |
| `Cmd+Shift+3` | Switch to Lab shell |
| `Cmd+Shift+4` | Switch to Case shell |

### 6.5 Retained Shortcuts

| Shortcut | Action | Source |
|----------|--------|--------|
| `Cmd+N` | New tab in current pane (repurposed from legacy new-session) | `useShellShortcuts.ts:62` |
| `Cmd+Shift+N` | New strikecell session | -- |
| `Cmd+F` | Focus search (contextual to active lens/tab) | `useShellShortcuts.ts:76` |
| `Cmd+,` | Open Operations (settings) | `useShellShortcuts.ts:82` |
| `Escape` | Close modal/panel/palette | `useShellShortcuts.ts:54` |
| `Cmd+[` / `Cmd+]` | Previous/next (repurposed: cycles lenses instead of apps) | `useShellShortcuts.ts:96-107` |

---

## 7. Relationship to Existing Code

### 7.1 ShellLayout -> WorkbenchShell

`src/shell/ShellLayout.tsx` currently renders:
1. `NavRail` (left, 220px)
2. `<Outlet />` (center, flex-1) -- React Router outlet
3. `DockSystem` (absolute positioned bottom rail + floating capsules)
4. `CommandPalette` (overlay)

The `WorkbenchShell` replaces this with:
1. `ActivitySpine` (left, 48px) + `LensSidebar` (left, 240px)
2. `TabWorkbench` (center) -- no React Router outlet; renders `TabContentProvider` directly
3. `ContextInspector` (right, 320px, toggleable)
4. `BottomPanel` (bottom, collapsible) -- replaces ShelfPanel from DockSystem
5. `StatusBar` (absolute bottom, 24px) -- replaces SessionRail
6. `CommandPalette` (overlay, unchanged)

> **Note**: `SOCBackground` (the ambient 3D WebGL scene) is disabled entirely when the workbench v2 shell is active. The current `ShellLayout.tsx` (lines 123-134) already disables it for 6 of 13 routes; the workbench disables it unconditionally since multiple tab kinds can be simultaneously mounted in split panes, making the background both invisible and wasteful.

The `DockProvider` (`src/shell/dock/DockContext.tsx`) wrapping persists but now feeds the capsule overlay layer (floating notifications, agent actions) rather than being the primary bottom content mechanism.

### 7.2 Plugin Routes -> Tab Content Providers

The current `createHashRouter` call in `ShellApp.tsx:29-49` generates one route per plugin with nested sub-routes (e.g., `workspace/tree`, `workspace/search`). This entire routing tree is removed.

Instead, `WorkbenchShell` maintains a `TAB_CONTENT_PROVIDERS` registry (see section 5.5). Each plugin's lazy-loaded view component is registered under a `TabKind` key. The `SplitPaneContainer` renders the active tab's content provider directly:

```
Before: ShellApp -> createHashRouter -> ShellLayout -> <Outlet> -> PluginView
After:  ShellApp -> WorkbenchShell -> TabWorkbench -> SplitPaneContainer -> TabContentProvider
```

URL routing reduces to a minimal hash for deep-linking: `#/shell/{shellMode}/tab/{tabId}`. The router no longer drives view mounting.

### 7.3 DockSystem -> BottomPanel

The `DockSystem` (`src/shell/dock/DockSystem.tsx`) currently provides:
- **Floating capsules** (`CapsuleStack`): agent actions, chat, terminal popups.
- **SessionRail**: bottom bar with session tabs and shelf triggers.
- **ShelfPanel**: draggable/resizable overlay panel for events/output/artifacts.

In the workbench:

| DockSystem Feature | Workbench Equivalent |
|--------------------|---------------------|
| `ShelfPanel` (events mode) | `BottomPanel` "Tape" tab |
| `ShelfPanel` (output mode) | `BottomPanel` "Terminal" tab |
| `ShelfPanel` (artifacts mode) | `BottomPanel` "Receipts" or "Diff" tab |
| `SessionRail` | `StatusBar` (connection status + posture label + breadcrumb) |
| Floating capsules (action, chat, social) | Capsule overlay layer (persists above WorkbenchShell) |

The `DockCapsuleState` types (`src/shell/dock/types.ts:66-81`) and `DockContext` reducer remain valid for the capsule overlay. The `ShelfState` and `SessionItem` types are superseded by `BottomPanelState` and the tab system respectively.

### 7.4 NavRail -> ActivitySpine + LensSidebar

The current `NavRail` (`src/shell/components/NavRail.tsx`) is a 220px sidebar that:
1. Shows the `CyberNexusOrb` at the top.
2. Lists strikecell sessions in a scrollable panel.
3. Has an Operations status button at the bottom.

In the workbench this splits into:

- **ActivitySpine** (48px): Icon-only column. Contains the `OrbLensRotor` (repurposed orb) at top, four `ShellSwitcher` icons (Wire/Hunt/Lab/Case, active highlighted with gold left border), a spacer, `PostureIndicator` dot, and settings icon at bottom. Lens selection is handled exclusively by the orb (click/long-press/right-click) -- lens icons do not appear in the spine.
- **LensSidebar** (240px): Content panel whose body changes based on the active lens. When `lens === "scopes"`, it renders the workspace trusted roots tree (similar to the current NavRail session panel). When `lens === "history"`, it renders an event timeline. Etc.

### 7.5 CyberNexusOrb -> OrbLensRotor

The `CyberNexusOrb` (`src/shell/components/CyberNexusOrb.tsx`) currently:
- **Click**: Cycles `NexusOperationMode` (observe -> trace -> contain -> execute) via `cycleNexusOperationMode`.
- **Long-press**: Opens the mode radial menu.
- **Right-click**: Toggles the mode menu.

The `OrbLensRotor` reuses the same interaction patterns:
- **Click**: Toggles between the current and previous lens (like Alt+Tab). If no previous lens, opens the lens picker.
- **Long-press**: Opens the lens picker menu (radial layout, 280px diameter).
- **Right-click**: Toggles the lens picker.

The operation mode (posture) is accessible via:
1. A small `PostureIndicator` in the `ActivitySpine` footer (click to cycle, long-press for menu).
2. The `CommandPalette` commands (existing commands from `ShellLayout.tsx:206-234`).
3. Keyboard shortcut (to be defined in the interaction spec).

---

## 8. State Persistence

### 8.1 What Persists Across App Restarts

- Active shell mode and lens.
- Open tabs (id, kind, contentProps) -- restored via Tauri's `localStorage` or a Tauri store plugin.
- Per-shell layout memory (splits, bottom panel, inspector state).
- Pinned vs. preview status for each tab.

### 8.2 What Does Not Persist

- Transient selection context within tabs.
- Capsule overlay state (agent actions, chat messages).
- Live terminal session PTY state (terminals reconnect on restart).
- Dirty/unsaved indicators (re-evaluated on content load).

### 8.3 Storage Key

```
huntronomer:workbench:state:v1
```

Stored as a serialized JSON blob in `localStorage`. The `WorkspaceSurfaceState` from `src/features/workspace/state/workspaceShellState.ts` (which currently manages workspace tabs, tree state, and layout) folds into `WorkbenchState` -- its `WorkspaceTabFrame` type becomes a subset of `WorkbenchTab`, and its `WorkspacePaneLayout` dimensions map into `SplitPane` sizes and `BottomPanelState.height`.

---

## 9. Context Provider Structure

```
<UiThemeProvider>
  <ConnectionProvider>
    <OpenClawProvider>
      <PolicyProvider>
        <SwarmProvider>
          <WorkbenchProvider>          {/* NEW: replaces router-based state */}
            <DockProvider>             {/* Retained: capsule overlay */}
              <WorkbenchShell />
            </DockProvider>
          </WorkbenchProvider>
        </SwarmProvider>
      </PolicyProvider>
    </OpenClawProvider>
  </ConnectionProvider>
</UiThemeProvider>
```

The `WorkbenchProvider` exposes:
- `useWorkbench()` -- full state + dispatch.
- `useActiveTab()` -- convenience hook for the focused tab.
- `useSelection()` -- convenience hook for the active tab's selection.
- `useShell()` -- current shell mode.
- `useLens()` -- current lens.
- `useBottomPanel()` -- bottom panel state + toggle/resize actions.
- `useContextInspector()` -- inspector state + toggle/resize actions.

---

## 10. Open Questions

1. **Router retention**: Should we keep a minimal `react-router-dom` router for deep-link URLs (`#/tab/{tabId}`) or go fully state-driven with manual `history.pushState`?
2. **Tab limit**: Should there be a maximum number of open tabs (e.g., 20) with LRU eviction of unpinned tabs?
3. **Workspace integration depth**: The `WorkspaceSurfaceState` has its own tab system (`WorkspaceTabFrame`). Should workspace file tabs become top-level `WorkbenchTab` entries, or should the workspace view manage its own internal tabs within a single `artifact` workbench tab?
4. **Capsule-to-tab promotion**: Should floating capsules (e.g., a chat capsule) be promotable to a tab in the workbench?
5. **Persistence granularity**: Should tab content state (scroll position, form values) persist, or only tab identity?
