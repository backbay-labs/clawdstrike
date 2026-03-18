# Phase 3 Handoff: Bottom Panel + DockSystem Removal

**From:** Phase 2 team
**Date:** 2026-03-07
**Branch:** `feature/huntronomer-workspace-orchestrator`

---

## What Phase 2 Delivered

Phase 2 replaced the full-page `<Outlet />` with a tabbed content area. Plugins are now tab content providers instead of route destinations. The workbench supports up to 3 vertical split panes with drag-to-resize, each with its own tab bar and content renderer.

### New Files (4)

| File | Purpose |
|------|---------|
| `src/shell/workbench/tabRegistry.ts` | Maps all 18 `TabKind` values to lazy React components. `TabRegistryEntry` includes `keepAlive` flag (false for 3D-heavy kinds). `TabContentProps` interface for tab components. |
| `src/shell/workbench/TabBar.tsx` | Horizontal tab strip: preview (italic), pinned (lock icon), dirty (gold dot), drag-to-reorder, middle-click close, right-click context menu (Close / Close Others / Close All / Pin / Unpin / Move to Split), overflow scroll + all-tabs dropdown. Dirty close confirmation via `confirm()`. Full ARIA: `role="tablist"`, `role="tab"`, `aria-selected`. |
| `src/shell/workbench/TabContentRenderer.tsx` | Resolves `TabState.kind` to component via registry. Keep-alive pool (default 3, LRU eviction). 3D-heavy kinds never pooled. Zero-tab welcome state per shell mode. `Suspense` fallback per tab. |
| `src/shell/workbench/SplitPaneContainer.tsx` | 1-3 vertical split panes. Flex-ratio resize via drag handles. 200px minimum width. Focused pane gold border. Single-pane mode has no resize chrome. |

### Extended Files (6)

| File | Change |
|------|--------|
| `workbenchState.ts` | Added `TabKind`, `TabState`, `TabGroupState` types. Added `tabGroups: TabGroupState[]` to `WorkbenchState`. Added 13 reducer actions (OPEN_TAB through REMOVE_TAB_GROUP). Tab ID generation: `tab_${kind}_${Date.now()}`. |
| `WorkbenchStateProvider.tsx` | Added 3 hooks: `useActiveTab()`, `useTabGroup(groupId)`, `useTabs()`. |
| `WorkbenchShell.tsx` | Replaced `<Outlet />` with `<SplitPaneContainer />`. Route-to-tab bridge converts `/<appId>` routes to `OPEN_TAB`/`SET_ACTIVE_TAB` dispatches, then replaces URL to "/". LensSidebar.onOpenPath wired to open file tabs. Tab keyboard shortcuts: Cmd+W close, Ctrl+Tab next, Ctrl+Shift+Tab prev. |
| `plugins/types.ts` | Added `tabKind?: TabKind`, `openAsTab?: boolean`, `singleton?: boolean` to `AppPlugin`. |
| `plugins/registry.tsx` | All 13 plugins have `tabKind` and `singleton: true`. |
| `index.ts` | Exports all new components, types, and hooks. |

### Modified Files (2, fixes during validation)

| File | Fix |
|------|-----|
| `TabBar.tsx` | C1: `handleMoveToSplit` now dispatches `MOVE_TAB_TO_GROUP` after `CREATE_TAB_GROUP`. |
| `LensSidebar.tsx` | C2: Added `role="separator"` + `aria-label` to resize handle. |

### Validation Results

See `PHASE2-VALIDATION.md`. Two critical issues found and fixed, five warnings documented for Phase 3.

---

## Phase 3 Scope: Bottom Panel System + DockSystem Removal

Phase 3 replaces the DockSystem floating capsules with an integrated bottom panel, completing the workbench layout.

### Goal

The bottom panel (tape, terminal, receipts, tasks, replay, diff) is currently managed by `BottomPanelState` in the reducer but has no rendered UI in the workbench grid. The `DockSystem` remains as a legacy bridge. Phase 3 renders the bottom panel inline and removes DockSystem.

### Files to Create

#### 1. `src/shell/workbench/BottomPanel.tsx`

Renders the bottom panel region in the workbench grid. Features:
- Tab strip for 6 panel tabs (tape, terminal, receipts, tasks, replay, diff)
- Collapse/expand toggle
- Drag-to-resize height (120-600px range, already enforced in reducer)
- Panel content resolved from a registry similar to `tabRegistry.ts`
- Keyboard: Cmd+J toggles (already wired in WorkbenchShell)

#### 2. `src/shell/workbench/bottomPanelRegistry.ts`

Maps `BottomPanelTabId` to lazy components:
- `tape`: Chronicle/event tape (reuse `ChronicleWorkbenchShelf`)
- `terminal`: Workspace terminal
- `receipts`: Receipt viewer
- `tasks`: Task queue viewer
- `replay`: Session replay
- `diff`: Diff viewer

#### 3. `src/shell/workbench/ContextInspector.tsx`

Right-side inspector panel. Features:
- Tab strip for 4 inspector tabs (context, graph, proof, companion)
- Drag-to-resize width (240-480px, already enforced)
- Toggle visibility (Cmd+\ already wired)

### Files to Modify

#### `src/shell/workbench/WorkbenchShell.tsx`

- Add `<BottomPanel />` below `<SplitPaneContainer />` in the content column
- Add `<ContextInspector />` as a 4th grid column (or nested flex)
- Remove `<DockSystem>` and its `<DockProvider>` wrapper
- Remove `renderShelfContent` callback
- Remove `ChronicleWorkbenchShelf` import (moves to bottomPanelRegistry)
- Update grid template: `48px auto 1fr auto / 1fr auto 24px` (adding inspector column and bottom panel row)

#### `src/shell/workbench/workbenchState.ts`

No structural changes needed. `BottomPanelState` and `InspectorState` already exist with full reducer support. Phase 3 only renders what Phase 1 modeled.

#### `src/shell/dock/` (remove)

After `DockSystem` is removed from `WorkbenchShell`, the entire dock module can be deleted behind the v2 flag. Keep it accessible for v1 ShellLayout.

---

## Integration Points with Phase 2

### State: Already modeled

`BottomPanelState` (activeTab, collapsed, height) and `InspectorState` (activeTab, width, visible) are Phase 1 state fields. The reducer actions (`TOGGLE_BOTTOM_PANEL`, `SET_BOTTOM_PANEL_TAB`, `SET_BOTTOM_PANEL_HEIGHT`, `TOGGLE_INSPECTOR`, `SET_INSPECTOR_TAB`, `SET_INSPECTOR_WIDTH`) are already implemented.

### Hooks: Already available

`useBottomPanel()` and `useContextInspector()` hooks exist in `WorkbenchStateProvider.tsx`.

### Keyboard: Already wired

- `Cmd+J` toggles bottom panel (WorkbenchShell.tsx:447)
- `Cmd+\` toggles inspector (WorkbenchShell.tsx:448)
- `useShellShortcuts` has `onToggleBottomPanel` and `onToggleInspector` handlers

### Grid: Needs expansion

Current grid: `48px auto 1fr / 1fr 24px` (spine, sidebar, content / content, status).
Phase 3 grid: `48px auto 1fr [inspector] / 1fr auto 24px` (add inspector column and bottom panel row).

### StatusBar: Needs repositioning

StatusBar currently spans columns 1-3, row 2. With the grid expansion, it needs to span all columns in the final row.

### Feature flag: Still active

`huntronomer:workbench:v2` gates Phase 3 too. Old `ShellLayout` with `DockSystem` remains for v1.

---

## Known Issues to Address

### From Phase 2 Validation (W1-W5)

1. **W1: TabContentRenderer pool mutation inside useMemo** -- Extract pool update to useEffect or ref-based function.
2. **W2: Tab history grows unbounded** -- Cap `tabHistory` to 50-100 entries.
3. **W3: `findTabByKind` matches first occurrence** -- Consider preferring focused pane.
4. **W4: Two-dispatch race in `handleMoveToSplit`** -- Merge into single `SPLIT_TAB` action.
5. **W5: SwarmMap keepAlive** -- Verify WebGL usage, may change to true.

### Architecture Considerations

1. **Bottom panel content isolation** -- Terminal and tape may hold WebSocket connections. Ensure they are only mounted when panel is expanded (unlike tab keep-alive which keeps hidden tabs mounted).
2. **Inspector context binding** -- The inspector's "context" tab should reflect the active tab's metadata. Phase 3 needs a `useInspectorContext()` hook that derives from the active tab.
3. **Grid complexity** -- 4-column, 3-row grid with optional columns (sidebar, inspector) and optional rows (bottom panel). Consider `grid-template-areas` for clarity.
4. **Terminal multiplexing** -- If the terminal panel supports multiple sessions, it needs its own tab-like sub-state. Consider a minimal `terminalSessions` field in `WorkbenchState`.
5. **DockSystem migration path** -- Some DockSystem features (floating capsules, shelf content) may not have bottom panel equivalents. Document what is preserved vs removed.

---

## Recommended Phase 3 Team Structure

| Role | Scope |
|------|-------|
| **panel-builder** | Implement `BottomPanel.tsx`, `bottomPanelRegistry.ts`, `ContextInspector.tsx`. Handle resize, collapse, tab switching. |
| **grid-architect** | Modify `WorkbenchShell.tsx` grid layout. Integrate BottomPanel and ContextInspector. Remove DockSystem. |
| **content-migrator** | Move DockSystem shelf content (ChronicleWorkbenchShelf) to bottom panel registry. Wire terminal, receipts, tasks, replay, diff lazy imports. |
| **validator** | Cross-check all files. Verify grid layout, keyboard shortcuts, state persistence, accessibility, Phase 1/2 feature preservation. |

### Dependency Order

```
panel-builder (BottomPanel, ContextInspector, registry)
  ├── grid-architect (WorkbenchShell grid mods, DockSystem removal)
  └── content-migrator (move shelf content, wire lazy imports)
        └── validator (cross-check everything)
```

`panel-builder` goes first (components needed by grid-architect). `grid-architect` and `content-migrator` can parallelize once components exist. `validator` runs last.

---

## Phase 3 Checklist

- [ ] Implement `bottomPanelRegistry.ts` with 6 panel tab mappings
- [ ] Implement `BottomPanel.tsx` with tab strip, collapse, drag-to-resize
- [ ] Implement `ContextInspector.tsx` with tab strip, toggle, drag-to-resize
- [ ] Expand WorkbenchShell grid to accommodate bottom panel and inspector
- [ ] Remove `<DockSystem>` and `<DockProvider>` from WorkbenchShell
- [ ] Remove `renderShelfContent` callback
- [ ] Move ChronicleWorkbenchShelf to bottom panel "tape" tab
- [ ] Wire terminal lazy import to bottom panel "terminal" tab
- [ ] Wire receipts, tasks, replay, diff lazy imports
- [ ] Verify Cmd+J toggles bottom panel visibility
- [ ] Verify Cmd+\ toggles inspector visibility
- [ ] Verify bottom panel height persistence
- [ ] Verify inspector width persistence
- [ ] Add resize handle accessibility (role="separator", aria-label) to both panels
- [ ] Verify StatusBar spans full grid width after expansion
- [ ] Fix W1: TabContentRenderer pool mutation
- [ ] Fix W2: Cap tabHistory length
- [ ] Verify all Phase 1 + Phase 2 features still work
- [ ] Run full keyboard shortcut audit
