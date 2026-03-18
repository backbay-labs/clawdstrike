# Phase 3 Validation Report

**Date:** 2026-03-07
**Validator:** validator
**Branch:** `feature/huntronomer-workspace-orchestrator`

---

## Scope

Full cross-check of all Phase 3 deliverables against the PHASE3-HANDOFF spec, plus Phase 2 warning fixes:
- Phase 2 warning fixes (W1, W2)
- Bottom panel registry
- BottomPanel component
- ContextInspector component
- WorkbenchShell grid integration
- DockSystem removal
- Keyboard shortcuts preserved
- State persistence
- Accessibility
- Barrel exports

---

## Phase 2 Warning Fixes

### W1: TabContentRenderer pool mutation inside useMemo -- FIXED

**File:** `TabContentRenderer.tsx:42-70`
**Fix:** Extracted pool mutation logic from `useMemo` into a `useEffect`. The `useMemo` now only reads `poolRef.current` without mutating it. Mutations happen during the commit phase via `useEffect`, making the component safe for React concurrent mode.
- Pool update (add/promote active tab, LRU eviction) moved to `useEffect` at line 42
- Stale entry cleanup (tabs that no longer exist) also in the same `useEffect`
- `useMemo` at line 73 is now a pure read-only derivation from `poolRef.current`

### W2: Tab history grows unbounded -- FIXED

**File:** `workbenchState.ts:91-92, 190-192`
**Fix:** Added `MAX_TAB_HISTORY = 100` constant and `capHistory()` helper function. All 5 sites where `tabHistory` is constructed now wrap the result in `capHistory()`:
1. `OPEN_TAB` - sourceUri dedup path (line 311)
2. `OPEN_TAB` - preview replacement path (line 332)
3. `OPEN_TAB` - new tab append path (line 341)
4. `MOVE_TAB_TO_GROUP` - target group (line 459)
5. `SET_ACTIVE_TAB` (line 478)

`capHistory` trims from the front (`slice(-100)`) on overflow, preserving the most recent entries.

### W3-W5: Deferred (Info/Low severity)

- **W3** (findTabByKind first occurrence): Acceptable as all plugins are `singleton: true`.
- **W4** (two-dispatch race in handleMoveToSplit): React 18 batches both dispatches. No functional impact.
- **W5** (SwarmMap keepAlive): `profile` kind uses SwarmMapView which is a 3D WebGL visualization. `keepAlive: false` is correct per D15.

---

## Files Reviewed

### New Files (Phase 3)

| File | Status |
|------|--------|
| `bottomPanelRegistry.ts` | PASS (1 fix applied: C1) |
| `BottomPanel.tsx` | PASS |
| `ContextInspector.tsx` | PASS |

### Modified Files (Phase 3)

| File | Status |
|------|--------|
| `WorkbenchShell.tsx` | PASS |
| `index.ts` | PASS |
| `StatusBar.tsx` | PASS (gridArea updated) |

### Modified Files (W1/W2 Fixes)

| File | Status |
|------|--------|
| `TabContentRenderer.tsx` | PASS (W1 fix applied) |
| `workbenchState.ts` | PASS (W2 fix applied) |

---

## Phase 3 Checklist

### bottomPanelRegistry.ts

- [x] Maps all 6 `BottomPanelTabId` values: tape, terminal, receipts, tasks, replay, diff
- [x] `tape` uses `TapePanelWrapper` that lazy-loads `ChronicleWorkbenchShelf` + `useConnection()` + `isPolicyWorkbenchEnabled()` to provide required props
- [x] `terminal` uses `WorkspaceTerminalPanel` from `@/features/workspace/terminal/WorkspaceTerminalPanel`
- [x] Remaining 4 tabs (receipts, tasks, replay, diff) use placeholder components
- [x] `BottomPanelRegistryEntry` interface exported with `component`, `icon`, `label`
- [x] `getBottomPanelEntry()` helper exported
- [x] `BOTTOM_PANEL_REGISTRY` exported
- [x] Placeholders use `makePlaceholder()` factory with `React.lazy` wrapping
- [x] Each placeholder has a `displayName` for DevTools debugging

### BottomPanel.tsx

- [x] Tab strip renders 6 tabs matching `BottomPanelTabId`
- [x] Active tab has gold underline (`2px solid var(--color-origin-gold)`)
- [x] Inactive tabs use muted text color
- [x] Collapse/expand toggle button dispatches `TOGGLE_BOTTOM_PANEL`
- [x] Toggle shows chevron direction (right when collapsed, down when expanded)
- [x] Tab click dispatches `SET_BOTTOM_PANEL_TAB` (which auto-expands via reducer)
- [x] Drag-to-resize via pointer events dispatches `SET_BOTTOM_PANEL_HEIGHT`
- [x] Reducer clamps height to 120-600px range
- [x] Content area height set to 0 when collapsed
- [x] Content hidden when collapsed (conditional render: `!collapsed && ContentComponent`)
- [x] `transition: height 200ms ease` on content area
- [x] Suspense fallback for lazy-loaded panel content
- [x] Tab strip height: 28px
- [x] Font: monospace, 10px, uppercase, letter-spacing
- [x] Background: `rgba(4,6,10,0.95)`
- [x] Top border: `1px solid var(--color-border-subtle)`
- [x] Accessibility: `role="tablist"` on tab strip
- [x] Accessibility: `role="tab"` + `aria-selected` on each tab
- [x] Accessibility: `role="tabpanel"` on content area
- [x] Accessibility: `aria-controls`/`aria-labelledby` linkage between tabs and panel
- [x] Accessibility: Resize handle has `role="separator"` + `aria-label="Resize bottom panel"`
- [x] Accessibility: `aria-orientation="horizontal"` on resize handle
- [x] Resize handle highlights gold when dragging

### ContextInspector.tsx

- [x] 4 tabs render: context, graph, proof, companion
- [x] Active tab has gold underline
- [x] Companion tab has "beta" badge (inline)
- [x] Width controlled by `InspectorState.width` from `useContextInspector()`
- [x] Returns `null` when `visible === false` (zero width, no DOM)
- [x] Drag-to-resize on LEFT edge (correct: dragging left increases width)
- [x] Dispatches `SET_INSPECTOR_WIDTH`; reducer clamps 240-480px
- [x] Tab click dispatches `SET_INSPECTOR_TAB` (which auto-shows via reducer)
- [x] `transition: width 200ms ease` (disabled during drag for responsiveness)
- [x] Content area: all 4 tabs are placeholders
  - Context: "Select an item to view details" with magnifying glass icon
  - Graph: "Entity graph -- coming soon"
  - Proof: "Receipt proof chain -- coming soon"
  - Companion: "AI companion -- experimental" with beta badge
- [x] Background: `rgba(4,6,10,0.95)`
- [x] Left border: `1px solid var(--color-border-subtle)`
- [x] Tab strip: 28px, mono 10px uppercase (matches BottomPanel)
- [x] Accessibility: `role="complementary"` + `aria-label="Context inspector"`
- [x] Accessibility: `role="tablist"` on tab strip
- [x] Accessibility: `role="tab"` + `aria-selected` on each tab
- [x] Accessibility: `role="tabpanel"` on content
- [x] Accessibility: `aria-controls`/`aria-labelledby` linkage
- [x] Accessibility: Resize handle `role="separator"` + `aria-label="Resize inspector"`
- [x] Accessibility: `aria-orientation="vertical"` on resize handle

### WorkbenchShell.tsx Grid Integration

- [x] Grid uses `grid-template-areas` for clarity
- [x] Grid areas: `spine sidebar content inspector / spine sidebar bottom inspector / status status status status`
- [x] Grid columns: `48px auto 1fr auto`
- [x] Grid rows: `1fr auto 24px`
- [x] ActivitySpine in `gridArea: "spine"`
- [x] LensSidebar in `gridArea: "sidebar"`
- [x] SplitPaneContainer in `gridArea: "content"`
- [x] BottomPanel in `gridArea: "bottom"`
- [x] ContextInspector in `gridArea: "inspector"`
- [x] StatusBar uses `gridArea: "status"` (spans all columns)
- [x] DockSystem removed: no `<DockSystem>` or `<DockProvider>` in JSX
- [x] DockSystem import removed: no `import { DockProvider, DockSystem }` line
- [x] `renderShelfContent` callback removed
- [x] `ChronicleWorkbenchShelf` import removed from WorkbenchShell (moved to registry)
- [x] `isPolicyWorkbenchEnabled` import removed (no longer needed in shell)
- [x] `daemonUrl` destructuring removed from `useConnection()` (only `status` used now)
- [x] `policyWorkbenchEnabled` state removed
- [x] Root element changed from `<DockProvider>` wrapper to `<>` fragment
- [x] All Phase 1+2 features preserved:
  - Command palette (Cmd+K)
  - Policy draft navigation guard
  - Huntronomer launch overlay
  - Route-to-tab bridge
  - Session management
  - All keyboard shortcuts

### Barrel Exports (index.ts)

- [x] `BottomPanel` exported
- [x] `ContextInspector` exported
- [x] `BOTTOM_PANEL_REGISTRY` and `getBottomPanelEntry` exported
- [x] `BottomPanelRegistryEntry` type-exported
- [x] All Phase 1+2 exports preserved
- [x] `isWorkbenchV2Enabled` utility preserved

### Keyboard Shortcuts

- [x] `Cmd+J` toggles bottom panel (WorkbenchShell.tsx:447)
- [x] `Cmd+\` toggles inspector (WorkbenchShell.tsx:448)
- [x] `Cmd+W` closes active tab (WorkbenchShell.tsx:449-461)
- [x] `Ctrl+Tab` next tab (WorkbenchShell.tsx:463-471)
- [x] `Ctrl+Shift+Tab` prev tab (WorkbenchShell.tsx:473-481)
- [x] `Cmd+Shift+B` toggles sidebar (WorkbenchShell.tsx:446)
- [x] `Cmd+K` opens command palette
- [x] `Cmd+N` new session
- [x] `Cmd+1-7` select lens by index
- [x] `Cmd+Shift+1-4` switch shell
- [x] `Cmd+,` operations/settings
- [x] `Cmd+F` focus search (Nexus)
- [x] `Cmd+[/]` prev/next app
- [x] `Escape` close modal

### State Persistence

- [x] `BottomPanelState` (activeTab, collapsed, height) is part of `WorkbenchState`
- [x] `InspectorState` (activeTab, width, visible) is part of `WorkbenchState`
- [x] Both are serialized to `huntronomer:workbench:state:v1` via `WorkbenchStateProvider` debounce
- [x] Shell memory preserves per-shell bottom panel and inspector state across shell switches
- [x] `tabGroups` with `tabHistory` persisted (now capped at 100)

---

## Issues Found and Fixed

### C1: BottomPanel tape tab missing connection props -- FIXED

**File:** `bottomPanelRegistry.ts:13-30`
**Severity:** Critical (tape panel would render with undefined props)
**Problem:** `ChronicleWorkbenchShelf` requires `daemonUrl`, `connected`, and `policyWorkbenchEnabled` props. The registry originally wrapped it as a bare lazy component, and `BottomPanel` renders registry components without props (`<ContentComponent />`). This meant the tape tab would render with `undefined` props, producing a broken or empty state. The old `DockSystem` path passed these props explicitly via `renderShelfContent`.
**Fix:** Created a `TapePanelWrapper` component inside the registry that uses `React.lazy` with `Promise.all` to co-load `ChronicleWorkbenchShelf`, `ConnectionContext`, and `featureFlags`. The wrapper calls `useConnection()` to get `daemonUrl` and `status`, and `isPolicyWorkbenchEnabled()` for the feature flag, then passes them as props to `ChronicleWorkbenchShelf`. This avoids threading props through `BottomPanel` and keeps the registry self-contained.

---

## Summary

| Category | Count |
|----------|-------|
| Phase 2 warnings fixed | 2 (W1, W2) |
| Phase 3 critical fixes applied | 1 (C1: tape panel props) |
| Phase 3 files validated | 6 (3 new + 3 modified) |
| Spec compliance items checked | 82 |
| Spec compliance items passed | 82/82 |

Phase 3 implementation is complete and spec-compliant. DockSystem successfully removed from the v2 path. Bottom panel and context inspector are integrated into the grid layout with full accessibility, state persistence, and keyboard shortcut support. Phase 2 warnings W1 (pool mutation) and W2 (history cap) are fixed. Critical issue C1 (tape panel missing connection props) fixed via a self-contained wrapper in the registry.
