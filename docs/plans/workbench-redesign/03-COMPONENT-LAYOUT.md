# 03 - Component and Layout Specification

> Huntronomer Workbench Redesign -- Implementation-ready component inventory,
> CSS grid definitions, per-shell layouts, TypeScript interfaces, and design tokens.

---

## 1. Global Layout Grid

The workbench replaces the current `ShellLayout` (NavRail 220px + flex Outlet + floating DockSystem)
with a fixed CSS grid that owns every pixel of the viewport.

```
+--------+------------+----------------------------------------+-----------------+
| (no top bar -- command palette is overlay, status bar is bottom)                |
+--------+------------+----------------------------------------+-----------------+
|        |            | TabBar (36px)                           |                 |
|  Act.  |   Lens     +----------------------------------------+    Context      |
|  Spine |   Sidebar  |                                        |    Inspector    |
|  48px  |   240px    |   Split Pane Container                 |    320px        |
|        |            |   (workbench center)                   |    (collapsible)|
|        |            |                                        |                 |
|        |            +----------------------------------------+                 |
|        |            | Bottom Panel (collapsible, ~180px)     |                 |
+--------+------------+----------------------------------------+-----------------+
| Status Bar (24px)                                                              |
+--------------------------------------------------------------------------------+
```

### 1.1 CSS Grid Definition

```css
.workbench-shell {
  display: grid;
  grid-template-columns:
    var(--activity-spine-width)                       /* 48px  */
    var(--lens-sidebar-width)                         /* 240px */
    1fr                                               /* center */
    var(--context-inspector-width);                   /* 320px */
  grid-template-rows:
    1fr                                               /* main  */
    var(--status-bar-height);                         /* 24px  */
  grid-template-areas:
    "spine lens  center inspector"
    "status status status status";
  height: 100vh;
  width: 100vw;
  overflow: hidden;
  background: var(--color-bg-primary);
}
```

The **center** grid area is itself a flex column that stacks the TabBar, SplitPaneContainer, and BottomPanel:

```css
.workbench-center {
  grid-area: center;
  display: flex;
  flex-direction: column;
  min-width: 0;
  min-height: 0;
  overflow: hidden;
}
```

### 1.2 Collapsed State Variants

When the right pane is collapsed the grid loses its fourth column:

```css
.workbench-shell[data-inspector="collapsed"] {
  grid-template-columns:
    var(--activity-spine-width)
    var(--lens-sidebar-width)
    1fr
    var(--context-inspector-collapsed-width);  /* 0px */
}
```

When the lens sidebar is collapsed (below 1024px or user toggle):

```css
.workbench-shell[data-lens="collapsed"] {
  grid-template-columns:
    var(--activity-spine-width)
    var(--lens-sidebar-collapsed-width)  /* 0px */
    1fr
    var(--context-inspector-width);
}
```

Both may be collapsed simultaneously below the minimum window threshold.

### 1.3 Center Column Internal Layout

```css
.workbench-tab-bar {
  height: var(--tab-bar-height);     /* 36px */
  flex-shrink: 0;
}

.workbench-split-pane-container {
  flex: 1;
  min-height: 0;
  overflow: hidden;
}

.workbench-bottom-panel {
  height: var(--bottom-panel-height);  /* 180px default */
  flex-shrink: 0;
  overflow: hidden;
}

.workbench-bottom-panel[data-collapsed="true"] {
  height: var(--bottom-panel-collapsed-height);  /* 0px */
}
```

### 1.4 Zero-Tab Empty State

When all tabs in a pane are closed, the `SplitPaneContainer` renders a shell-appropriate welcome view. The welcome content is a centered column with quick-start action buttons:

```css
.workbench-welcome {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 16px;
  height: 100%;
  color: var(--color-sdr-text-muted);
  font-family: var(--font-mono);
  font-size: 12px;
}
```

Each shell provides different quick-start actions (see 01-ARCHITECTURE.md S2.3). The welcome view auto-dismisses when any tab opens.

### 1.5 Tab Overflow

When tabs exceed the available tab bar width, the tab bar scrolls horizontally. Fade indicators (8px gradient) appear at left/right edges when scroll is possible. A chevron dropdown button at the right end of the tab bar opens a full tab list (pinned first, then by open order).

```css
.workbench-tab-bar-scroll-fade {
  position: absolute;
  top: 0;
  bottom: 0;
  width: 8px;
  pointer-events: none;
  z-index: 1;
}
.workbench-tab-bar-scroll-fade--left {
  left: 0;
  background: linear-gradient(90deg, var(--wb-tab-bar-bg), transparent);
}
.workbench-tab-bar-scroll-fade--right {
  right: 36px; /* space for chevron button */
  background: linear-gradient(270deg, var(--wb-tab-bar-bg), transparent);
}
```

---

## 2. ASCII Layouts Per Shell Mode

Each shell mode configures the same grid but with different content in the Lens sidebar,
center split orientation, bottom panel default state, and right inspector content.

### 2.1 Wire Shell (default)

Communication-centric. Feed-driven. Bottom panel collapsed by default.

```
+------+----------+-------------------+-------------------+-----------+
| Spine| Lens:    | TabBar [#general] [#alerts] [+]       | Inspector |
|      | Scopes   +-------------------+-------------------+           |
| [W]  | ------   |                   |                   | Context   |
| [H]  | #general | Feed list         | Selected thread   | --------  |
| [L]  | #alerts  | (left split)      | (right split)     | Participants
| [C]  | #ops     |                   |                   | Metadata  |
|      | ------   |                   |                   | Actions   |
|      | DMs      +-------------------+-------------------+           |
|      | Teams    | Bottom: Tape (collapsed)              |           |
+------+----------+---------------------------------------+-----------+
| StatusBar: Wire | connected | #general | 12 unread                  |
+------+----------+---------------------------------------+-----------+
```

- **Lens**: `LensScopesList` -- channels, DMs, team scopes
- **Center**: horizontal split -- feed list (left) + selected thread (right)
- **Bottom**: collapsed Tape (expandable event log)
- **Inspector**: `ContextInspector` -- participant list, message metadata, quick actions

### 2.2 Hunt Shell

Threat hunting. Full-width hunt flow. Bottom panel expanded by default.

```
+------+----------+---------------------------------------+-----------+
| Spine| Lens:    | TabBar [Hunt-42] [Hunt-43] [+]        | Inspector |
|      | Entities +---------------------------------------+           |
| [W]  | ------   |                                       | Proof     |
| [H]  | Alerts   |   Hunt flow graph                     | --------  |
| [L]  | Hosts    |   (full width, no split)              | Evidence  |
| [C]  | Actors   |                                       | Receipt   |
|      | IOCs     |                                       | Chain     |
|      | ------   +---------------------------------------+ Timeline  |
|      | Saved    | Bottom: Replay + Receipts (expanded)  |           |
+------+----------+---------------------------------------+-----------+
| StatusBar: Hunt | daemon:live | hunt-42 active | 3 receipts         |
+------+----------+---------------------------------------+-----------+
```

- **Lens**: `LensEntityList` -- alerts, hosts, actors, IOCs, saved hunts
- **Center**: full-width hunt flow canvas (single pane, no split)
- **Bottom**: expanded -- Replay timeline tab + Receipts log tab
- **Inspector**: `ContextInspector` -- evidence viewer, receipt chain, proof timeline

### 2.3 Lab Shell

Development and authoring. Editor + terminal. Bottom panel expanded.

```
+------+----------+-------------------+-------------------+-----------+
| Spine| Lens:    | TabBar [main.rs] [mod.rs] [+]         | Inspector |
|      | Files    +-------------------+-------------------+           |
| [W]  | ------   |                   |                   | Context   |
| [H]  | src/     | Editor pane       | Terminal pane     | --------  |
| [L]  |  main.rs | (left split)      | (right split)    | File info |
| [C]  |  lib.rs  |                   |                   | Symbols   |
|      | tests/   |                   |                   | Git blame |
|      | ------   +-------------------+-------------------+           |
|      | Roots    | Bottom: Terminal + Tasks (expanded)    |           |
+------+----------+---------------------------------------+-----------+
| StatusBar: Lab  | Rust 1.93 | Ln 42, Col 8 | UTF-8 | main          |
+------+----------+---------------------------------------+-----------+
```

- **Lens**: `LensFileTree` -- workspace file tree (reuses `WorkspaceTreeView`)
- **Center**: horizontal split -- editor pane (left) + terminal/preview (right)
- **Bottom**: expanded -- Terminal tabs + Task runner output
- **Inspector**: `ContextInspector` -- file metadata, symbol outline, git blame

### 2.4 Case Shell

Investigation documentation. Full-width document. Bottom panel collapsed.

```
+------+----------+---------------------------------------+-----------+
| Spine| Lens:    | TabBar [Case-IR-7] [Case-IR-9] [+]   | Inspector |
|      | Notes    +---------------------------------------+           |
| [W]  | ------   |                                       | Citations |
| [H]  | IR-7     |   Case document                       | --------  |
| [L]  | IR-9     |   (full width, no split)              | Evidence  |
| [C]  | IR-12    |                                       | links     |
|      | ------   |                                       | Proof     |
|      | Templates+---------------------------------------+ refs      |
|      | Archive  | Bottom: Activity log (collapsed)      |           |
+------+----------+---------------------------------------+-----------+
| StatusBar: Case | IR-7 | draft | last saved 2m ago                  |
+------+----------+---------------------------------------+-----------+
```

- **Lens**: `LensNotesList` -- case files, templates, archive
- **Center**: full-width case document editor (single pane)
- **Bottom**: collapsed activity log (expandable)
- **Inspector**: `ContextInspector` -- citations, evidence links, proof references

---

## 3. Component Inventory

### 3.1 New Components to Build

| Component | Path | Purpose |
|-----------|------|---------|
| `WorkbenchShell` | `shell/WorkbenchShell.tsx` | Root grid layout; replaces `ShellLayout` |
| `ActivitySpine` | `shell/components/ActivitySpine.tsx` | 48px icon column; replaces `NavRail` (220px) |
| `OrbLensRotor` | `shell/components/OrbLensRotor.tsx` | Transforms `CyberNexusOrb` from mode cycler to lens rotor |
| `LensSidebar` | `shell/components/LensSidebar.tsx` | 240px sidebar rendering active lens content |
| `LensScopesList` | `shell/lenses/LensScopesList.tsx` | Wire shell: channels, DMs, team scopes |
| `LensEntityList` | `shell/lenses/LensEntityList.tsx` | Hunt shell: alerts, hosts, actors, IOCs |
| `LensFileTree` | `shell/lenses/LensFileTree.tsx` | Lab shell: workspace file tree (wraps `WorkspaceTreeView`) |
| `LensNotesList` | `shell/lenses/LensNotesList.tsx` | Case shell: case notes, templates, archive |
| `LensHistoryList` | `shell/lenses/LensHistoryList.tsx` | Cross-shell: recent tabs, sessions, search history |
| `LensSwarmList` | `shell/lenses/LensSwarmList.tsx` | Cross-shell: agent swarm members |
| `LensSandboxList` | `shell/lenses/LensSandboxList.tsx` | Cross-shell: sandbox environments |
| `TabBar` | `shell/components/TabBar.tsx` | Global tab bar with preview/pin/dirty states |
| `TabBarItem` | `shell/components/TabBarItem.tsx` | Individual tab with close, dirty indicator, context menu |
| `SplitPaneContainer` | `shell/components/SplitPaneContainer.tsx` | Manages horizontal/vertical split panes with drag handles |
| `TabContentRenderer` | `shell/components/TabContentRenderer.tsx` | Routes tab kind to content component |
| `ContextInspector` | `shell/components/ContextInspector.tsx` | Right pane with inspector tabs |
| `BottomPanel` | `shell/components/BottomPanel.tsx` | Collapsible bottom panel with tabs |
| `StatusBar` | `shell/components/StatusBar.tsx` | 24px status strip with shell mode, connection, cursor info |
| `WorkbenchStateProvider` | `shell/state/WorkbenchStateProvider.tsx` | React context providing workbench state + dispatch |
| `SplitResizeHandle` | `shell/components/SplitResizeHandle.tsx` | Draggable resize handle between split panes |
| `PanelResizeHandle` | `shell/components/PanelResizeHandle.tsx` | Draggable resize handle for sidebar/inspector/bottom panel |

### 3.2 Existing Components to Refactor

| Current Component | Change | Notes |
|-------------------|--------|-------|
| `CyberNexusOrb` (`shell/components/CyberNexusOrb.tsx`) | Rename/refactor to `OrbLensRotor` | Click cycles lens (not operation mode); long-press opens radial lens menu. Mode ring becomes lens ring. Reuses `.nexus-orb` CSS classes with new `data-lens-*` attributes. |
| `NavRail` (`shell/components/NavRail.tsx`) | Absorb into `ActivitySpine` | 220px collapses to 48px. Session list moves to `LensHistoryList`. Operations status dot moves to `StatusBar`. Only shell mode icons + orb remain. |
| `CommandPalette` (`shell/components/CommandPalette.tsx`) | Extend with workbench commands | Add: `Open tab`, `Switch shell`, `Switch lens`, `Toggle bottom panel`, `Toggle inspector`, `Focus pane:left/right/bottom`. |
| `WorkspaceTreeView` (`features/workspace/tree/WorkspaceTreeView.tsx`) | Wrap inside `LensFileTree` | No internal changes. `LensFileTree` provides the lens sidebar frame around it. |
| `WorkspaceBreadcrumbs` (`features/workspace/tree/WorkspaceBreadcrumbs.tsx`) | Reuse inside `TabBar` breadcrumb area | Rendered conditionally when active tab is a file in Lab shell. |
| `WorkspaceEditorPane` (`features/workspace/editor/`) | Becomes a tab content provider | Mounted by `TabContentRenderer` for `kind: "file"` tabs. |
| `WorkspaceSearchPanel` (`features/workspace/search/`) | Becomes a bottom panel tab or tab content | Mounted by `TabContentRenderer` for `kind: "search"` tabs. |
| `WorkspaceGitPanel` (`features/workspace/git/`) | Becomes a tab content provider | Mounted by `TabContentRenderer` for `kind: "git"` tabs. |
| `WorkspaceTerminalPanel` (`features/workspace/terminal/`) | Becomes a bottom panel terminal tab | Mounted inside `BottomPanel` as a tab content provider. |

### 3.3 Existing Components to Deprecate/Remove

| Component | Replaced By | Migration Notes |
|-----------|-------------|-----------------|
| `ShellLayout` (`shell/ShellLayout.tsx`) | `WorkbenchShell` | All orchestration logic (command palette, blocker, shortcuts) moves to `WorkbenchShell`. Router `<Outlet>` replaced by `TabContentRenderer`. |
| `NavRail` (`shell/components/NavRail.tsx`) | `ActivitySpine` | 220px session-focused rail replaced by 48px icon spine. Sessions move to lens sidebar history. |
| `DockSystem` (`shell/dock/DockSystem.tsx`) | `BottomPanel` | Floating capsules replaced by bottom panel tabs. Shelf functionality merged into `BottomPanel`. Portal-based rendering eliminated. |
| `SessionRail` (`shell/dock/SessionRail.tsx`) | `StatusBar` + `LensHistoryList` | Session items split: status indicators go to `StatusBar`, session list goes to `LensHistoryList`. |
| `Capsule` (`shell/dock/Capsule.tsx`) | `BottomPanel` tabs | Each capsule kind becomes a `BottomPanel` tab. No more floating/draggable windows. |
| `ShelfPanel` (inside `DockSystem.tsx`) | `BottomPanel` | The shelf's drag/resize/expand logic is replaced by a simpler vertical resize on `BottomPanel`. |
| `WorkspaceShellScreen` (`features/workspace/shell/WorkspaceShellScreen.tsx`) | Split into lens + tabs + bottom | Explorer column becomes `LensFileTree`; center 3-column grid becomes tabbed `SplitPaneContainer`; bottom placeholder becomes `BottomPanel`; right inspector becomes `ContextInspector`. |
| `DockProvider` (`shell/dock/DockContext.tsx`) | `WorkbenchStateProvider` | Capsule/shelf state merged into unified workbench state. |

---

## 4. Key Component Interfaces

### 4.1 WorkbenchShell

```typescript
/** Root component. Replaces ShellLayout. */
interface WorkbenchShellProps {
  /** Children are not used; WorkbenchShell owns its entire grid. */
}

// Internal state managed by WorkbenchStateProvider:
interface WorkbenchState {
  activeShell: ShellId;              // "wire" | "hunt" | "lab" | "case"
  activeLens: LensId;               // current lens within active shell
  tabs: TabDescriptor[];            // ordered open tabs
  activeTabId: string | null;       // currently focused tab
  splitLayout: SplitLayout;         // center pane split config
  inspectorCollapsed: boolean;
  lensCollapsed: boolean;
  bottomPanelCollapsed: boolean;
  bottomPanelActiveTab: string;     // active tab within bottom panel
  focusedZone: FocusZone;           // "spine" | "lens" | "center" | "inspector" | "bottom"
}

type ShellId = "wire" | "hunt" | "lab" | "case";

// Canonical LensId -- aligned with 01-ARCHITECTURE.md S3.3
type LensId =
  | "scopes"       // Workspace trusted roots + watchlists + subscribed feeds
  | "history"      // Event stream timeline, audit log, recent tabs/commands
  | "files"        // File explorer for active workspace root
  | "sandboxes"    // Policy tester sandboxes, experiment runs
  | "entities"     // Agent identities, observed hosts, IOCs
  | "swarms"       // Active swarm topology, connection graph
  | "notes";       // Investigation notes, case artifacts

type FocusZone = "spine" | "lens" | "center" | "inspector" | "bottom";
```

### 4.2 ActivitySpine

```typescript
interface ActivitySpineProps {
  activeShell: ShellId;
  onSelectShell: (shell: ShellId) => void;
  connectionStatus: "connected" | "connecting" | "disconnected";
}

// Internal: renders OrbLensRotor at top, then divider, then 4 shell mode
// icons (Wire/Hunt/Lab/Case), spacer, posture indicator, settings icon
// at bottom. Width is fixed at 48px. Lens icons do NOT appear in the
// spine -- lens selection is handled exclusively by the orb.
```

### 4.3 OrbLensRotor

```typescript
interface OrbLensRotorProps {
  activeLens: LensId;
  availableLenses: LensId[];       // varies by active shell
  onCycleLens: () => void;         // click: cycle to next lens
  onSelectLens: (lens: LensId) => void;  // radial menu selection
}

// Reuses .nexus-orb CSS structure. Mode ring becomes lens ring.
// data-mode-index -> data-lens-index
// data-tone -> data-lens-tone (each lens has a characteristic tone)
```

### 4.4 LensSidebar

```typescript
interface LensSidebarProps {
  activeLens: LensId;
  collapsed: boolean;
  width: number;                   // current width (resizable)
  onResize: (width: number) => void;
  onCollapse: () => void;
}

// Renders one of: LensScopesList, LensEntityList, LensFileTree,
// LensNotesList, LensHistoryList, LensSwarmList, LensSandboxList
// based on activeLens.
```

### 4.5 TabBar and TabBarItem

```typescript
interface TabBarProps {
  tabs: TabDescriptor[];
  activeTabId: string | null;
  onActivateTab: (tabId: string) => void;
  onCloseTab: (tabId: string) => void;
  onPinTab: (tabId: string) => void;
  onReorderTab: (fromIndex: number, toIndex: number) => void;
  breadcrumb?: React.ReactNode;    // optional breadcrumb (e.g. WorkspaceBreadcrumbs)
}

interface TabBarItemProps {
  tab: TabDescriptor;
  isActive: boolean;
  onActivate: () => void;
  onClose: () => void;
  onPin: () => void;
  onContextMenu: (event: React.MouseEvent) => void;
}

interface TabDescriptor {
  id: string;
  title: string;
  kind: TabKind;
  icon?: string;                   // SVG path or icon key
  dirty: boolean;                  // unsaved changes indicator
  pinned: boolean;
  preview: boolean;                // single-click preview (italic title, replaced on next preview)
  closable: boolean;
  metadata?: Record<string, unknown>;  // tab-kind-specific data
}

// Canonical TabKind -- aligned with 01-ARCHITECTURE.md S3.4
// Plugin-mapped kinds:
type TabKind =
  | "signal-thread" | "hunt" | "receipt" | "case" | "sandbox"
  | "artifact" | "brief" | "profile" | "policy"
  | "threat-radar" | "attack-graph" | "network-map"
  | "workflow" | "marketplace" | "operations"
// Non-plugin (internal) kinds:
  | "file"          // Individual workspace file
  | "welcome";      // Empty state / getting started
```

### 4.6 SplitPaneContainer

```typescript
interface SplitPaneContainerProps {
  layout: SplitLayout;
  onLayoutChange: (layout: SplitLayout) => void;
  children: React.ReactNode;       // exactly 1 or 2 children
}

interface SplitLayout {
  direction: "horizontal" | "vertical";
  ratio: number;                   // 0.0-1.0, first pane fraction
  minPanePx: number;               // minimum pane size in px (default: 200)
}
```

### 4.7 ContextInspector

```typescript
interface ContextInspectorProps {
  collapsed: boolean;
  width: number;
  onResize: (width: number) => void;
  onCollapse: () => void;
  activeShell: ShellId;
  inspectorTabs: InspectorTabDescriptor[];
  activeInspectorTab: string;
  onActivateInspectorTab: (tabId: string) => void;
}

interface InspectorTabDescriptor {
  id: string;
  title: string;
  icon?: string;
  content: React.ReactNode;
}
```

### 4.8 BottomPanel

```typescript
interface BottomPanelProps {
  collapsed: boolean;
  height: number;
  onResize: (height: number) => void;
  onCollapse: () => void;
  onExpand: () => void;
  tabs: BottomPanelTabDescriptor[];
  activeTabId: string;
  onActivateTab: (tabId: string) => void;
}

interface BottomPanelTabDescriptor {
  id: string;
  title: string;
  icon?: string;
  badgeCount?: number;
  content: React.ReactNode;
}
```

### 4.9 StatusBar

```typescript
interface StatusBarProps {
  activeShell: ShellId;
  connectionStatus: "connected" | "connecting" | "disconnected";
  items: StatusBarItem[];          // extensible status segments
}

interface StatusBarItem {
  id: string;
  position: "left" | "center" | "right";
  content: React.ReactNode;
  onClick?: () => void;
  tooltip?: string;
}

// Default items per shell:
// Wire:  shell label | connection | active channel | unread count
// Hunt:  shell label | daemon status | active hunt | receipt count
// Lab:   shell label | language | cursor pos | encoding | branch
// Case:  shell label | case ID | draft status | last saved
```

---

## 5. CSS Token Additions

All new tokens are defined on `:root` in `styles.css` alongside the existing
`--nav-rail-width`, `--space-*`, and `--radius-*` tokens.

```css
:root {
  /* Workbench layout dimensions */
  --activity-spine-width: 48px;
  --lens-sidebar-width: 240px;
  --lens-sidebar-collapsed-width: 0px;
  --lens-sidebar-min-width: 180px;
  --lens-sidebar-max-width: 400px;
  --context-inspector-width: 320px;
  --context-inspector-collapsed-width: 0px;
  --context-inspector-min-width: 240px;
  --context-inspector-max-width: 480px;
  --bottom-panel-height: 180px;
  --bottom-panel-collapsed-height: 0px;
  --bottom-panel-min-height: 120px;
  --bottom-panel-max-height: 50vh;
  --status-bar-height: 24px;
  --tab-bar-height: 36px;
  --split-handle-width: 4px;

  /* Workbench surface colors (extend existing origin-panel tokens) */
  --wb-spine-bg: linear-gradient(
    180deg,
    rgba(7, 9, 15, 0.99) 0%,
    rgba(4, 6, 10, 1) 100%
  );
  --wb-spine-border: rgba(213, 173, 87, 0.2);
  --wb-lens-bg: linear-gradient(
    180deg,
    rgba(9, 11, 18, 0.97) 0%,
    rgba(6, 8, 14, 0.98) 100%
  );
  --wb-lens-border: rgba(45, 50, 64, 0.8);
  --wb-tab-bar-bg: rgba(11, 13, 19, 0.96);
  --wb-tab-bar-border: rgba(45, 50, 64, 0.6);
  --wb-tab-active-bg: rgba(213, 173, 87, 0.08);
  --wb-tab-active-border: rgba(213, 173, 87, 0.6);
  --wb-tab-hover-bg: rgba(213, 173, 87, 0.04);
  --wb-tab-dirty-color: rgba(238, 220, 166, 0.96);
  --wb-bottom-bg: var(--origin-panel);
  --wb-bottom-border: rgba(45, 50, 64, 0.7);
  --wb-inspector-bg: var(--origin-panel);
  --wb-inspector-border: rgba(45, 50, 64, 0.7);
  --wb-status-bg: rgba(7, 9, 15, 0.98);
  --wb-status-border: rgba(45, 50, 64, 0.5);
  --wb-split-handle-color: rgba(213, 173, 87, 0.18);
  --wb-split-handle-hover: rgba(213, 173, 87, 0.42);
  --wb-split-handle-active: rgba(213, 173, 87, 0.62);

  /* Deprecate: --nav-rail-width stays for backward compat during migration */
  /* --nav-rail-width: 220px; (existing, kept until DockSystem removal) */
}
```

### 5.1 Token Mapping from Existing to New

| Old Token / Hard-coded Value | New Token | Notes |
|------------------------------|-----------|-------|
| `--nav-rail-width: 220px` | `--activity-spine-width: 48px` | NavRail shrinks dramatically |
| `grid-cols-[minmax(260px,300px)_...]` in WorkspaceShellScreen | `--lens-sidebar-width` | CSS grid replaces Tailwind arbitrary values |
| `320px` (right inspector column) in WorkspaceShellScreen | `--context-inspector-width` | Same default, now a variable |
| `180px` (bottom panel row) in WorkspaceShellScreen | `--bottom-panel-height` | Same default, now a variable |
| `.dock-system { left: var(--nav-rail-width) }` | Removed | Dock system is replaced entirely |
| `.premium-panel` class | Reused as-is | Panel glass effect is kept for lens sidebar and inspector |

---

## 6. Z-Index Layering

All z-index values for the workbench. Replaces the current scattered values
(`z-10`, `z-20`, `z-index: 1200` on DockSystem, etc.).

```
  1   -- Status bar
 10   -- Main content panels (center, bottom, inspector)
 20   -- Activity spine
 30   -- Tab bar
 40   -- Split resize handles (elevated during drag)
 50   -- Bottom panel (when expanded, above center content)
100   -- Context inspector (when overlaying on narrow viewports)
200   -- Command palette backdrop
210   -- Command palette
300   -- Quick peek overlay (hover previews)
400   -- Orb radial lens menu
```

### 6.1 Migration from Current Z-Index Values

| Current | Component | New |
|---------|-----------|-----|
| `z-20` on `NavRail` `<nav>` | `ActivitySpine` | `z-index: 20` (unchanged) |
| `z-10` on `<main>` in ShellLayout | Center content | `z-index: 10` |
| `z-index: 1200` on `.dock-system` | Removed (DockSystem deleted) | -- |
| `100 + index` on capsule wrappers | Removed (capsules deleted) | -- |
| `z-index: 12` on `.nexus-orb-mode-menu` | `OrbLensRotor` radial menu | `z-index: 400` |

---

## 7. Responsive Behavior

### 7.1 Breakpoints

| Condition | Behavior |
|-----------|----------|
| Minimum window | 1024 x 768 (enforced by Tauri `min_width`/`min_height`) |
| Below 1280px wide | Auto-collapse context inspector (`data-inspector="collapsed"`) |
| Below 1024px wide | Auto-collapse lens sidebar (`data-lens="collapsed"`) |
| User toggle | Any panel can be manually collapsed/expanded regardless of viewport |

### 7.2 Resizable Panel Constraints

| Panel | Min | Default | Max | Handle Position |
|-------|-----|---------|-----|-----------------|
| Lens sidebar | 180px | 240px | 400px | Right edge (vertical drag) |
| Context inspector | 240px | 320px | 480px | Left edge (vertical drag) |
| Bottom panel | 120px | 180px | 50vh | Top edge (horizontal drag) |
| Split pane (each side) | 200px | 50% | calc(100% - 200px) | Center handle |

### 7.3 Resize Handle Behavior

```css
.panel-resize-handle {
  position: absolute;
  background: var(--wb-split-handle-color);
  transition: background 150ms ease;
  z-index: 40;
}

.panel-resize-handle:hover {
  background: var(--wb-split-handle-hover);
}

.panel-resize-handle:active,
.panel-resize-handle[data-dragging="true"] {
  background: var(--wb-split-handle-active);
}

/* Vertical handle (for sidebar/inspector) */
.panel-resize-handle--vertical {
  width: var(--split-handle-width);  /* 4px */
  height: 100%;
  cursor: col-resize;
}

/* Horizontal handle (for bottom panel) */
.panel-resize-handle--horizontal {
  width: 100%;
  height: var(--split-handle-width);  /* 4px */
  cursor: row-resize;
}
```

### 7.4 Collapse/Expand Transitions

```css
.lens-sidebar,
.context-inspector {
  transition: width 200ms ease, opacity 150ms ease;
  overflow: hidden;
}

.lens-sidebar[data-collapsed="true"],
.context-inspector[data-collapsed="true"] {
  width: 0;
  opacity: 0;
  pointer-events: none;
}

.workbench-bottom-panel {
  transition: height 200ms ease;
}
```

### 7.5 Window Resize Listener

```typescript
// Inside WorkbenchStateProvider:
useEffect(() => {
  const onResize = () => {
    const width = window.innerWidth;
    dispatch({ type: "SET_INSPECTOR_COLLAPSED", collapsed: width < 1280 });
    dispatch({ type: "SET_LENS_COLLAPSED", collapsed: width < 1024 });
  };

  window.addEventListener("resize", onResize);
  onResize(); // initial check
  return () => window.removeEventListener("resize", onResize);
}, [dispatch]);
```

---

## 8. Shell Mode to Lens Mapping

All 7 lenses are available in every shell. Each shell defines a **default lens** and **prominent lenses** (listed first in the orb cycle order and lens picker). Non-prominent lenses are still accessible via Cmd+1-7, long-press menu, or by cycling past the prominent set.

| Shell | Default Lens | Prominent Lenses | Full Cycle Order |
|-------|-------------|------------------|------------------|
| Wire | `scopes` | `scopes`, `history`, `swarms` | scopes, history, swarms, files, sandboxes, entities, notes |
| Hunt | `entities` | `entities`, `history`, `swarms`, `sandboxes` | entities, history, swarms, sandboxes, scopes, files, notes |
| Lab | `files` | `files`, `history`, `sandboxes` | files, history, sandboxes, scopes, entities, swarms, notes |
| Case | `notes` | `notes`, `history` | notes, history, scopes, files, sandboxes, entities, swarms |

When the user switches shell mode, the lens resets to the shell's default lens
unless the user has explicitly selected a different lens during the current session.

---

## 9. Component File Tree (Post-Migration)

```
apps/desktop/src/
  shell/
    WorkbenchShell.tsx              # NEW - root grid layout
    components/
      ActivitySpine.tsx             # NEW - 48px icon column
      OrbLensRotor.tsx              # NEW - lens cycling orb (refactored from CyberNexusOrb)
      LensSidebar.tsx               # NEW - sidebar frame
      TabBar.tsx                    # NEW - global tab bar
      TabBarItem.tsx                # NEW - individual tab
      SplitPaneContainer.tsx        # NEW - split pane manager
      SplitResizeHandle.tsx         # NEW - split drag handle
      PanelResizeHandle.tsx         # NEW - panel resize handle
      TabContentRenderer.tsx        # NEW - tab kind router
      ContextInspector.tsx          # NEW - right inspector pane
      BottomPanel.tsx               # NEW - collapsible bottom panel
      StatusBar.tsx                 # NEW - 24px status strip
      CommandPalette.tsx            # EXISTING - extended with workbench commands
      CyberNexusOrb.tsx             # DEPRECATED - replaced by OrbLensRotor
      NavRail.tsx                   # DEPRECATED - replaced by ActivitySpine
    lenses/
      LensScopesList.tsx            # NEW - Wire shell lens
      LensEntityList.tsx            # NEW - Hunt shell lens
      LensFileTree.tsx              # NEW - Lab shell lens (wraps WorkspaceTreeView)
      LensNotesList.tsx             # NEW - Case shell lens
      LensHistoryList.tsx           # NEW - cross-shell history lens
      LensSwarmList.tsx             # NEW - cross-shell swarm lens
      LensSandboxList.tsx           # NEW - cross-shell sandbox lens
    state/
      WorkbenchStateProvider.tsx     # NEW - React context + reducer
      workbenchReducer.ts           # NEW - state transitions
      workbenchTypes.ts             # NEW - all workbench types
    dock/                           # DEPRECATED - entire directory removed post-migration
      DockSystem.tsx
      DockContext.tsx
      Capsule.tsx
      SessionRail.tsx
      types.ts
    plugins/
      registry.tsx                  # MODIFIED - plugins become tab content providers
      types.ts                      # MODIFIED - AppId union may shrink; TabKind added
    ShellApp.tsx                    # MODIFIED - router replaced by WorkbenchShell
    ShellLayout.tsx                 # DEPRECATED - replaced by WorkbenchShell
  features/workspace/
    shell/
      WorkspaceShellScreen.tsx      # DEPRECATED - split into lens + tabs + panels
    state/
      workspaceShellState.ts        # MODIFIED - WorkspaceSurfaceState merges into WorkbenchState
    tree/
      WorkspaceTreeView.tsx         # KEPT - reused inside LensFileTree
      WorkspaceBreadcrumbs.tsx      # KEPT - reused inside TabBar
    editor/                         # KEPT - becomes tab content provider
    search/                         # KEPT - becomes tab/panel content provider
    git/                            # KEPT - becomes tab content provider
    terminal/                       # KEPT - becomes bottom panel tab
  styles.css                        # MODIFIED - new tokens added (Section 5)
  styles/
    dock.css                        # DEPRECATED - replaced by workbench.css
    workbench.css                   # NEW - all workbench layout styles
```

---

## 10. Cross-Reference

- **Architecture spec** (01-ARCHITECTURE.md): Defines ShellId, LensId, TabDescriptor, Selection model
- **UI/UX interaction spec** (02-INTERACTION-DESIGN.md): Keyboard shortcuts, focus flow, gestures
- **Migration plan** (04-MIGRATION-PLAN.md): Phased transition from current to workbench
