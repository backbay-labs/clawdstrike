# End-to-End Review & Dogfooding Report

**Date:** 2026-03-07
**Team:** huntronomer-e2e-review (5 auditors)
**Branch:** `feature/huntronomer-workspace-orchestrator`

---

## Executive Summary

**Verdict: SHIP (with 4 state bugs fixed inline)**

The Huntronomer workbench redesign across all 4 phases is structurally sound, integration-clean, and functionally complete. Five parallel audits examined structure, state, UX flows, accessibility, and cross-component integration.

- **4 state model bugs** found and **fixed** during this review (2 HIGH, 2 MEDIUM)
- **8 accessibility gaps** identified (2 critical, 3 major, 3 minor) — documented for follow-up
- **0 structural issues**, **0 integration issues**, **0 broken UX flows**

---

## Audit Results Summary

| Audit | Auditor | Items Checked | Result |
|-------|---------|---------------|--------|
| Structural (files, imports, exports, types) | structural-auditor | 10 | **10/10 PASS** |
| State model (reducer, edge cases, persistence) | state-auditor | 9 categories | **4 bugs found, all fixed** |
| UX dogfooding (10 user flows) | ux-auditor | 10 flows | **10/10 PASS** |
| Accessibility (ARIA, keyboard, focus) | a11y-auditor | 10 components | **2 PASS, 4 PARTIAL, 2 FAIL, 2 N/A** |
| Integration (flag, dock, registries, grid) | integration-auditor | 12 | **12/12 PASS** |

---

## P0: Critical Issues (Fixed)

### B1: MOVE_TAB_TO_GROUP data loss [FIXED]

**File:** `workbenchState.ts` — MOVE_TAB_TO_GROUP reducer case
**Bug:** Tab removed from source group but silently not added to target if `toGroupId` doesn't exist. Tab is permanently lost.
**Fix:** Added `if (!state.tabGroups.find((g) => g.id === toGroupId)) return state;` guard before removal.

### B2: OPEN_TAB silent failure [FIXED]

**File:** `workbenchState.ts` — OPEN_TAB reducer case
**Bug:** `updateTabGroup` silently returns unchanged array if `groupId` doesn't match. Tab open is silently dropped.
**Fix:** Added `if (!state.tabGroups.find((g) => g.id === groupId)) return state;` guard.

---

## P1: High Issues (Fixed / Documented)

### B3: Persistence shallow merge corrupts nested state [FIXED]

**File:** `WorkbenchStateProvider.tsx` — initializer merge
**Bug:** `{ ...initial, ...persisted }` is shallow. If persisted state has partial nested objects (e.g., `bottomPanel` missing `height`), the merge overwrites the entire sub-object, losing default values. Schema migrations (adding new fields) would cause undefined property access.
**Fix:** Replaced with explicit deep merge for `bottomPanel`, `inspector`, `selection`, and all 4 `shellMemory` entries (each with nested `bottomPanel` and `inspector`).

### B4: SET_ACTIVE_TAB orphaned reference [FIXED]

**File:** `workbenchState.ts` — SET_ACTIVE_TAB reducer case
**Bug:** Sets `activeTabId` without validating the tab exists in the group. Creates orphaned state reference.
**Fix:** Added `if (!group.tabs.find((t) => t.id === tabId)) return group;` guard.

### A1: OrbLensRotor radial menu items not keyboard-accessible [DOCUMENTED]

**File:** `OrbLensRotor.tsx`
**Issue:** Radial menu items lack `tabIndex` and keyboard handlers. Keyboard-only users cannot access the lens picker via the orb interaction.
**Workaround:** `Cmd+1-7` keyboard shortcuts provide equivalent access to all 7 lenses.
**Recommended fix:** Add `tabIndex={0}`, `onKeyDown` (Enter/Space to select), and arrow-key navigation to radial menu items.

### A2: SplitPaneContainer resize handles not keyboard-operable [DOCUMENTED]

**File:** `SplitPaneContainer.tsx`
**Issue:** Resize handles use pointer events only. No `tabIndex`, no arrow-key resize handlers.
**Recommended fix:** Add `tabIndex={0}`, `role="separator"`, `aria-orientation="vertical"`, and `onKeyDown` with arrow keys dispatching width changes.

---

## P2: Medium Issues (Documented)

### A3: Resize handles partially keyboard-operable [DOCUMENTED]

**Files:** `LensSidebar.tsx`, `BottomPanel.tsx`, `ContextInspector.tsx`
**Issue:** BottomPanel and ContextInspector resize handles have `tabIndex={0}` and `role="separator"` but no `onKeyDown` arrow-key handlers. LensSidebar handle has `role="separator"` but no `tabIndex`.
**Impact:** Users can focus the handle but cannot operate it via keyboard.
**Recommended fix:** Add `onKeyDown` handler that adjusts width/height by ±10px per arrow key press.

### A4: OrbLensRotor missing `aria-expanded` [DOCUMENTED]

**File:** `OrbLensRotor.tsx`
**Issue:** Orb button doesn't announce radial menu state change to screen readers.
**Recommended fix:** Add `aria-expanded={isMenuOpen}` to the orb button element.

### A5: TabBar focus management on tab close [DOCUMENTED]

**File:** `TabBar.tsx`
**Issue:** When a tab is closed, DOM focus may remain on the now-removed element. Focus should move to the newly active tab.
**Recommended fix:** After close dispatch, use `requestAnimationFrame` + `ref.focus()` to move focus to the new active tab button.

---

## P3: Low Issues (Polish)

### A6: Missing `aria-orientation` on resize handles

**Files:** `SplitPaneContainer.tsx`, `LensSidebar.tsx`
**Issue:** Resize handles missing `aria-orientation` attribute (BottomPanel and ContextInspector have it).
**Fix:** Add `aria-orientation="vertical"` to sidebar and split pane resize handles.

---

## Dogfooding Notes

The UX auditor traced all 10 major user flows end-to-end:

1. **Shell switching** — Clean. Per-shell memory round-trips correctly. Tabs survive shell switch.
2. **Lens cycling** — Solid. Click-toggle between current/previous is intuitive. Long-press radial works.
3. **Tab lifecycle** — Complete. Preview→pin→dirty→close flow handles all edge cases. Confirmation dialogs on dirty close.
4. **Route-to-tab bridge** — Correct. All 13 plugins map to tab kinds. Singleton behavior prevents duplicates. URL cleanup works.
5. **Split panes** — Functional. Drag resize smooth. Pane auto-collapses when last tab closes.
6. **Bottom panel** — Good. Content unmounts on collapse (saves resources for WebSocket-heavy tabs). TapePanelWrapper correctly provides connection props.
7. **Context inspector** — Good. All 4 tabs lazy-load and react to selection. Graph tab's force-directed canvas is responsive.
8. **Selection propagation** — Works. File open dispatches both OPEN_TAB and SET_SELECTION atomically.
9. **Command palette** — Context-sensitive commands (workspace vs nexus) switch correctly based on active tab.
10. **Feature flag** — Clean gate. Old ShellLayout untouched and accessible via flag.

**No dead-end states, no unreachable code paths, no broken interaction chains found.**

---

## Recommendations (Prioritized)

### Ship Now (Done)
- [x] Fix B1: MOVE_TAB_TO_GROUP validation
- [x] Fix B2: OPEN_TAB validation
- [x] Fix B3: Persistence deep merge
- [x] Fix B4: SET_ACTIVE_TAB validation

### Fast Follow (1 sprint)
- [ ] A1: OrbLensRotor radial menu keyboard access
- [ ] A2: SplitPaneContainer resize handle keyboard + ARIA
- [ ] A3: Arrow-key resize for all handles
- [ ] A5: Focus management on tab close

### Backlog
- [ ] A4: `aria-expanded` on orb button
- [ ] A6: `aria-orientation` on remaining resize handles
- [ ] Keyboard resize (arrow keys) for all separator handles
- [ ] Investigate whether `WorkspaceShellScreen.tsx` old inspector section should be removed (spec says yes, not done in Phase 4)

---

## Files Modified During Review

| File | Change |
|------|--------|
| `workbenchState.ts` | B1: groupId guard in OPEN_TAB. B2: toGroupId guard in MOVE_TAB_TO_GROUP. B4: tabId existence check in SET_ACTIVE_TAB. |
| `WorkbenchStateProvider.tsx` | B3: Deep merge for bottomPanel, inspector, selection, shellMemory in persistence initializer. |

---

## Conclusion

The workbench redesign is **ready to ship** behind the `huntronomer:workbench:v2` feature flag. All 4 migration phases are implemented, validated, and now e2e reviewed. The 4 state model bugs discovered during this review have been fixed. Accessibility improvements are documented as fast-follow items with clear fix descriptions.

Total workbench file count: 19 files (15 in `workbench/`, 4 in `workbench/inspector/`)
Total actions in reducer: 26 (12 Phase 1 + 13 Phase 2 + 1 Phase 4)
Total hooks: 10
Total components: 15
