# Phase 2 Handoff: Tab Workbench

**From:** Phase 1 team
**Date:** 2026-03-07
**Branch:** `feature/huntronomer-workspace-orchestrator`

---

## What Phase 1 Delivered

Phase 1 replaced the outer shell frame with the workbench foundation. The 220px NavRail is replaced by a 48px ActivitySpine + collapsible LensSidebar. The CyberNexusOrb is paralleled by an OrbLensRotor for lens cycling. All existing features are preserved behind a feature flag.

### New Files (9)

| File | Purpose |
|------|---------|
| `src/shell/workbench/workbenchState.ts` | Pure state model: `ShellMode`, `LensId`, `BottomPanelTabId`, `InspectorTabId`, `PostureMode`, `WorkbenchState`, 12-action reducer, `SHELL_DEFAULTS`, `createInitialWorkbenchState()` |
| `src/shell/workbench/WorkbenchStateProvider.tsx` | React context + `useReducer`. localStorage persistence (`huntronomer:workbench:state:v1`, 500ms debounce). 6 hooks: `useWorkbench`, `useShell`, `useLens`, `useBottomPanel`, `useContextInspector`, `useWorkbenchDispatch` |
| `src/shell/workbench/OrbLensRotor.tsx` | Lens-cycling orb. Click toggles current/previous lens. Long-press (420ms) opens radial picker (7 items, 280px diameter). Right-click toggle. Conic gradient ring with per-lens colors. |
| `src/shell/workbench/ActivitySpine.tsx` | 48px vertical column. Top: OrbLensRotor + divider. Middle: 4 shell buttons (Wire/Hunt/Lab/Case) with gold active indicator. Bottom: posture dot (cycles observe→trace→contain→execute) + settings gear. |
| `src/shell/workbench/LensSidebar.tsx` | Collapsible sidebar (240px default, 180-400 range, drag-to-resize). Files lens: real `WorkspaceTreeView` with `getWorkspaceShellSnapshot`. 6 other lenses: structured placeholders. |
| `src/shell/workbench/WorkbenchShell.tsx` | CSS Grid root: `48px auto 1fr / 1fr 24px`. Wraps in `WorkbenchStateProvider` > `DockProvider`. Preserves: CommandPalette, policy draft guard (useBlocker), HuntronomerLaunchOverlay, DockSystem, session management, all keyboard shortcuts. Renders `<Outlet />` for plugin routes. |
| `src/shell/workbench/StatusBar.tsx` | 24px bottom strip. Left: shell + lens labels. Center: connection dot + posture. Right: session count + KB mode placeholder. |
| `src/shell/workbench/index.ts` | Barrel export for all public symbols + `isWorkbenchV2Enabled()` utility. |
| `src/shell/components/OrbVisuals.tsx` | Extracted `NexusIcon` SVG shared by `CyberNexusOrb` and available for reuse. |

### Modified Files (3)

| File | Change |
|------|--------|
| `src/shell/ShellApp.tsx` | Imports `isWorkbenchV2Enabled` + `WorkbenchShell` from barrel. Conditionally uses `WorkbenchShell` or `ShellLayout` as router root based on `huntronomer:workbench:v2` localStorage flag. All 13 plugin routes unchanged. |
| `src/shell/components/CyberNexusOrb.tsx` | Imports `NexusIcon` from `OrbVisuals.tsx` instead of inline definition. No behavioral change. |
| `src/shell/keyboard/useShellShortcuts.ts` | Added optional handlers: `isWorkbench`, `onSelectLens(index)`, `onSelectShell(index)`, `onToggleSidebar`, `onToggleBottomPanel`, `onToggleInspector`. Cmd+1-7 dispatches lens selection when `isWorkbench=true` (keys 8-9 suppressed). Cmd+Shift+1-4 for shells. Cmd+Shift+B sidebar. Cmd+J bottom panel. Cmd+\ inspector. |

### Validation Results

See `PHASE1-VALIDATION.md`. Four issues found and fixed during validation:
- C1: ActivitySpine `onOpenSettings` prop not passed → fixed
- C2: Duplicate Cmd+Shift+B handler → removed from LensSidebar
- C3: Duplicate `isWorkbenchV2Enabled` → consolidated to barrel
- C4: `PostureMode` not exported → now exported

Five remaining warnings (all Phase 2 scope or cosmetic).

---

## Phase 2 Scope: Tab Workbench

Replace the full-page `<Outlet />` with a tabbed content area. Plugins become tab content providers instead of route destinations.

### Files to Create

#### 1. `src/shell/workbench/tabRegistry.ts`

Maps `TabKind` to lazy React components. Populated from plugin definitions.

```typescript
type TabKind =
  | "signal-thread" | "hunt" | "receipt" | "case" | "sandbox"
  | "artifact" | "brief" | "profile" | "policy"
  | "threat-radar" | "attack-graph" | "network-map"
  | "workflow" | "marketplace" | "operations"
  | "file" | "welcome";

interface TabRegistryEntry {
  component: React.LazyExoticComponent<React.ComponentType<TabContentProps>>;
  icon: string;
  defaultTitle: string;
  keepAlive: boolean; // false for 3D-heavy kinds: threat-radar, attack-graph, network-map
}
```

Source components are the same `React.lazy` imports already in `src/shell/plugins/registry.tsx`.

#### 2. `src/shell/workbench/TabBar.tsx`

Horizontal tab strip above content area. Features:
- Preview tabs (italic title, replaced on next open)
- Pinned tabs (lock icon, not closable via single click, sort left)
- Drag-to-reorder
- Middle-click close
- Right-click context menu: Close, Close Others, Close All, Pin/Unpin
- Overflow: horizontal scroll + chevron dropdown listing all tabs
- Dirty indicator (dot) on modified tabs
- Tab close on dirty: Save / Don't Save / Cancel dialog

#### 3. `src/shell/workbench/TabContentRenderer.tsx`

Resolves `TabState.kind` to a component via `tabRegistry`. Mounts/unmounts based on active tab. Keep-alive pool (default 3 recent tabs) for fast switching. 3D-heavy kinds (`threat-radar`, `attack-graph`, `network-map`) excluded from pool.

#### 4. `src/shell/workbench/SplitPaneContainer.tsx`

Manages 1-3 vertical split panes. Each pane has its own `TabBar` + `TabContentRenderer`. Alt+click opens tab in new pane. Pane resize via drag handle. Pane collapses when last tab closes.

### State Model Extensions

Add to `workbenchState.ts`:

```typescript
interface TabState {
  id: string;
  kind: TabKind;
  title: string;
  subtitle?: string;
  icon?: string;
  isPreview: boolean;
  isPinned: boolean;
  isDirty: boolean;
  sourceUri?: string;
  metadata?: Record<string, unknown>;
}

interface TabGroupState {
  id: string;           // "main", "split-1", "split-2"
  tabs: TabState[];
  activeTabId: string | null;
  tabHistory: string[];
}
```

Add `tabGroups: TabGroupState[]` to `WorkbenchState`.

New reducer actions: `OPEN_TAB`, `CLOSE_TAB`, `PIN_TAB`, `UNPIN_TAB`, `SET_TAB_PREVIEW`, `REORDER_TAB`, `MOVE_TAB_TO_GROUP`, `SET_ACTIVE_TAB`, `SET_TAB_DIRTY`, `NAVIGATE_TAB_BACK`, `NAVIGATE_TAB_FORWARD`.

### Files to Modify

#### `src/shell/workbench/WorkbenchShell.tsx`

- Replace `<Outlet />` with `<SplitPaneContainer />`
- Add `useEffect` watching `location.pathname` → converts route changes to `OPEN_TAB` dispatches
- Route-to-tab mapping: `/<appId>` opens tab of matching `tabKind`. If tab already exists, focus it.
- Replace URL to `/#/` after tab open (URL no longer drives content — tab state does)

#### `src/shell/plugins/registry.tsx`

Add `tabKind` field to each plugin:

| Plugin | tabKind |
|--------|---------|
| nexus | `hunt` |
| workspace | `artifact` |
| operations | `operations` |
| events | `signal-thread` |
| policies | `policy` |
| policy-tester | `sandbox` |
| swarm | `profile` |
| marketplace | `marketplace` |
| workflows | `workflow` |
| threat-radar | `threat-radar` |
| attack-graph | `attack-graph` |
| network-map | `network-map` |
| security-overview | `brief` |

#### `src/shell/plugins/types.ts`

Extend `AppPlugin`:
```typescript
interface AppPlugin {
  // existing fields...
  tabKind?: TabKind;
  openAsTab?: boolean;   // default true
  singleton?: boolean;   // only one tab of this kind
}
```

### Workspace Integration

The workspace plugin requires special handling:
- Each workspace file opens as a workbench-level `file` tab (`sourceUri = rootId::relativePath`)
- Retire `WorkspaceSurfaceState.tabs` — workbench `TabGroupState` becomes the single source of truth
- `WorkspaceEditorPane` receives `rootId` and `relativePath` from tab metadata
- `WorkspaceTreeView` in Files lens dispatches `OPEN_TAB` to workbench state (currently `onOpenPath` prop on `LensSidebar` is ready for this)

### Route Compatibility

Old hash routes must continue working:
1. On mount + `location` change, match `/<appId>` to plugin
2. If `openAsTab`, dispatch `OPEN_TAB`
3. For workspace sub-routes (`/workspace/search`, etc.), open with appropriate metadata
4. Replace URL to `/#/` to avoid stale route state

### Zero-Tab Empty State

When all tabs close, show a shell-appropriate welcome:
- Wire: "Open a feed" + recent feeds
- Hunt: "Start a hunt" + recent hunts
- Lab: "Open a folder" + recent roots
- Case: "Create a case" + recent cases

---

## Integration Points with Phase 1

### State: `WorkbenchState` is the nucleus

All Phase 2 state extends the existing `WorkbenchState` in `workbenchState.ts`. The reducer pattern is already established — add new action types to the `WorkbenchAction` union.

### Hooks: Consumer pattern is set

Components use `useWorkbench()` for state and `useWorkbenchDispatch()` for mutations. Phase 2 should add convenience hooks: `useActiveTab()`, `useTabGroup(groupId)`, `useTabs()`.

### Keyboard: Handler interface is extensible

`useShellShortcuts.ts` already has optional handler fields. Phase 2 adds:
- `Cmd+W` → close active tab
- `Cmd+Tab` / `Ctrl+Tab` → next tab
- `Cmd+Shift+Tab` → previous tab
- `Cmd+Shift+[` / `]` → prev/next tab in group
- `Alt+Cmd+[` / `]` → prev/next split pane

### LensSidebar: `onOpenPath` is pre-wired

`LensSidebar` already accepts `onOpenPath?: (relativePath: string) => void`. Phase 2 wires this to dispatch `OPEN_TAB` with `kind: "file"`.

### Feature flag: still active

The `huntronomer:workbench:v2` flag gates Phase 2 too. The old `ShellLayout` remains untouched.

### DockSystem: still present

`WorkbenchShell` renders `<DockSystem>` outside the grid. Phase 2 keeps it. Phase 3 removes it.

---

## Known Issues to Address

### From Phase 1 Validation (W1-W5)

1. **W1: Cmd+8/9 in workbench mode** — keys 8-9 are suppressed but could be mapped to tab-switching in Phase 2
2. **W2: `color-mix()` compatibility** — verify macOS 13 WebKit support or add fallback
3. **W3: StatusBar `useSessions` re-renders** — consider `useSessionCount` hook
4. **W4: StatusBar grid positioning** — consider `grid-template-areas` if grid structure changes
5. **W5: Resize handle accessibility** — add `role="separator"` + `aria-label`

### Architecture Considerations

1. **Tab state serialization size** — with 25+ tabs and metadata, localStorage could hit quota. Consider IndexedDB for tab state if serialized size exceeds 2MB.
2. **Keep-alive pool memory** — default pool of 3 hidden DOM trees. Monitor memory impact. May need to reduce for lower-end machines.
3. **3D kind exclusion** — `threat-radar`, `attack-graph`, `network-map` must not be pooled (WebGL context limits). Enforce via `tabRegistry.keepAlive: false`.
4. **Workspace dual-tab prevention** — the `WorkspaceSurfaceState.tabs` must be fully retired. Any coexistence creates state conflicts.
5. **Plugin `routes` backward compat** — plugin `routes` arrays stay for `<Outlet />` fallback during development. Remove once all plugins have `tabKind`.

---

## Recommended Phase 2 Team Structure

| Role | Scope |
|------|-------|
| **state-architect** | Extend `workbenchState.ts` with tab types + reducer actions. Add convenience hooks. Handle tab open/close/pin/reorder logic. |
| **tab-builder** | Implement `TabBar.tsx`, `TabContentRenderer.tsx`, `tabRegistry.ts`. Handle preview/pin semantics, dirty close dialog, overflow, drag-to-reorder. |
| **split-builder** | Implement `SplitPaneContainer.tsx`. Handle pane creation (Alt+click), resize, collapse, tab movement between panes. |
| **router-bridge** | Modify `WorkbenchShell.tsx` to replace `<Outlet />` with tabs. Implement route-to-tab redirect. Wire `LensSidebar.onOpenPath` to `OPEN_TAB`. Handle workspace integration. |
| **validator** | Cross-check all files after implementation. Verify tab persistence, route compat, plugin mapping, keyboard shortcuts, spec compliance. |

### Dependency Order

```
state-architect (tab types + reducer)
  ├── tab-builder (TabBar, TabContentRenderer, tabRegistry)
  │     └── split-builder (SplitPaneContainer)
  └── router-bridge (WorkbenchShell mods, route redirect)
            └── validator (cross-check everything)
```

`state-architect` goes first — everyone else consumes the types. `tab-builder` and `router-bridge` can parallelize once types are done. `split-builder` depends on `TabBar` being done. `validator` runs last.

---

## Phase 2 Checklist

- [ ] Implement `tabRegistry.ts` with all 13 plugin mappings + `file` + `welcome`
- [ ] Add `TabKind`, `TabState`, `TabGroupState` types to `workbenchState.ts`
- [ ] Add tab reducer actions: OPEN_TAB, CLOSE_TAB, PIN_TAB, UNPIN_TAB, SET_TAB_PREVIEW, REORDER_TAB, MOVE_TAB_TO_GROUP, SET_ACTIVE_TAB, SET_TAB_DIRTY, NAVIGATE_TAB_BACK, NAVIGATE_TAB_FORWARD
- [ ] Add convenience hooks: `useActiveTab`, `useTabGroup`, `useTabs`
- [ ] Implement `TabBar.tsx` with preview/pin/dirty/reorder/overflow/context-menu
- [ ] Implement `TabContentRenderer.tsx` with lazy loading and keep-alive pool
- [ ] Implement `SplitPaneContainer.tsx` with pane create/resize/collapse
- [ ] Implement zero-tab welcome state per shell
- [ ] Add `tabKind` + `openAsTab` to `AppPlugin` interface and all plugin definitions
- [ ] Replace `<Outlet />` with `<SplitPaneContainer />` in `WorkbenchShell.tsx`
- [ ] Implement route-to-tab redirect logic
- [ ] Wire `LensSidebar.onOpenPath` to dispatch `OPEN_TAB`
- [ ] Migrate workspace internal tabs to workbench tab state
- [ ] Add tab keyboard shortcuts: Cmd+W, Cmd+Tab, Cmd+Shift+Tab
- [ ] Verify old routes open correct tabs
- [ ] Verify tab persistence across page reload
- [ ] Verify dirty tab close confirmation works for all tab kinds
