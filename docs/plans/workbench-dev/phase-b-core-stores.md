# Phase B: Core Store Decomposition

> Week 3-4 — Split `multi-policy-store.tsx`, convert remaining Context providers, flatten App.tsx

## Prerequisites

- Phase A complete (Zustand + createSelectors available, 5 thin stores migrated)
- Test coverage expanded for multi-policy-store consumers

---

## B1: Decompose `multi-policy-store.tsx`

### Current State

`multi-policy-store.tsx` (1846 lines) is a monolithic Context+useReducer that manages:

**Tab Lifecycle:**
- `tabs: PolicyTab[]` — open tabs with per-tab state
- `activeTabId: string` — which tab is focused
- `splitMode: SplitMode` — "none" | "horizontal" | "vertical"
- `splitTabId: string | null` — which tab is in the split pane
- `savedPolicies: SavedPolicy[]` — persisted policy library

**Per-Tab State (`PolicyTab` interface):**
- `id: string` — unique tab identifier
- `documentId: string` — stable document identity (survives close/reopen/save/rename)
- `name: string` — display name
- `filePath: string | null` — filesystem path (null for unsaved)
- `dirty: boolean` — modified since last save
- `fileType: FileType` — clawdstrike_policy, sigma_rule, yara_rule, ocsf_event
- `policy: WorkbenchPolicy` — the active policy object
- `yaml: string` — current YAML source
- `validation: ValidationResult` — schema validation state
- `nativeValidation: NativeValidationState` — Rust CLI validation results
- `testSuiteYaml?: string` — associated test suite
- `_undoPast / _undoFuture: PolicySnapshot[]` — undo/redo stacks
- `_cleanSnapshot: PolicySnapshot | null` — for dirty tracking

**UI State:**
- `ui.sidebarCollapsed: boolean`
- `ui.activeEditorTab: "visual" | "yaml"`
- `ui.editorSyncDirection: "visual" | "yaml" | null`

**Two Contexts** (both created in `MultiPolicyProvider`):
- `MultiPolicyContext` — tab-level state
- `WorkbenchContext` — backward-compatible single-policy view

**Exported hooks:**
- `useWorkbench()` — returns `WorkbenchContextValue` with 15 fields: `state`, `dispatch`, 11 action callbacks (`saveCurrentPolicy`, `exportYaml`, `copyYaml`, `loadPolicy`, `openFile`, `openFileByPath`, `saveFile`, `saveFileAs`, `newPolicy`, `undo`, `redo`), and 2 derived booleans (`canUndo`, `canRedo`)
- `useMultiPolicy()` — returns `MultiPolicyContextValue` with 5 fields: `multiState`, `multiDispatch`, `activeTab`, `tabs`, `canAddTab`

**Action union:** `MultiPolicyAction` has exactly 30 variants: 12 multi-tab actions (`NEW_TAB`, `CLOSE_TAB`, `SWITCH_TAB`, `SET_SPLIT_MODE`, `SET_SPLIT_TAB`, `RENAME_TAB`, `REORDER_TABS`, `DUPLICATE_TAB`, `BULK_UPDATE_GUARDS`, `OPEN_TAB_OR_SWITCH`, `SET_TAB_TEST_SUITE`, `RESTORE_AUTOSAVE_ENTRIES`), 12 tab-delegated actions (`SET_POLICY`, `SET_YAML`, `UPDATE_GUARD`, `TOGGLE_GUARD`, `UPDATE_SETTINGS`, `UPDATE_META`, `UPDATE_ORIGINS`, `SET_FILE_PATH`, `MARK_CLEAN`, `SET_NATIVE_VALIDATION`, `UNDO`, `REDO`), and 6 global actions (`SAVE_POLICY`, `DELETE_SAVED_POLICY`, `LOAD_SAVED_POLICIES`, `SET_COMPARISON`, `SET_SIDEBAR_COLLAPSED`, `SET_EDITOR_TAB`).

**Consumers:** ~45 non-test files import `useWorkbench` or `useMultiPolicy`.

### Decomposition Plan

Split into **3 Zustand stores**:

#### 1. `policy-tabs-store.ts` — Tab lifecycle

```typescript
interface TabMeta {
  id: string;
  documentId: string;
  name: string;
  filePath: string | null;
  dirty: boolean;
  fileType: FileType;
}

interface PolicyTabsState {
  tabs: TabMeta[];
  activeTabId: string;
  splitMode: SplitMode;
  splitTabId: string | null;
  savedPolicies: SavedPolicy[];
  actions: {
    newTab: (opts?: NewTabOpts) => string;
    closeTab: (tabId: string) => void;       // must also call policy-edit-store.removeTab()
    setActiveTab: (tabId: string) => void;
    renameTab: (tabId: string, name: string) => void;
    duplicateTab: (tabId: string) => string;
    setSplitMode: (mode: SplitMode) => void;
    setSplitTab: (tabId: string | null) => void;
    reorderTabs: (from: number, to: number) => void;
    setFilePath: (tabId: string, path: string | null) => void;
    setDirty: (tabId: string, dirty: boolean) => void;
    // Derived
    getActiveTab: () => TabMeta | undefined;
  };
}
```

#### 2. `policy-edit-store.ts` — Active policy editing

Per-tab editing state. Uses a Map keyed by tabId for isolation:

```typescript
interface PolicyEditState {
  // Indexed by tabId
  policies: Map<string, WorkbenchPolicy>;
  yamls: Map<string, string>;
  validations: Map<string, ValidationResult>;
  nativeValidations: Map<string, NativeValidationState>;
  undoStacks: Map<string, { past: PolicySnapshot[]; future: PolicySnapshot[] }>;
  cleanSnapshots: Map<string, PolicySnapshot>;
  testSuites: Map<string, string>;     // testSuiteYaml per tab
  actions: {
    updatePolicy: (tabId: string, policy: WorkbenchPolicy) => void;
    setYaml: (tabId: string, yaml: string) => void;
    setValidation: (tabId: string, result: ValidationResult) => void;
    setNativeValidation: (tabId: string, state: NativeValidationState) => void;
    setTestSuite: (tabId: string, yaml: string) => void;
    undo: (tabId: string) => void;
    redo: (tabId: string) => void;
    markClean: (tabId: string) => void;
    isDirty: (tabId: string) => boolean;
    // Cleanup: called by policy-tabs-store when a tab is closed
    removeTab: (tabId: string) => void;
  };
}
```

> **Note:** Tab metadata (`name`, `filePath`, `dirty`, `fileType`, `documentId`)
> stays in `policy-tabs-store` since it's needed for the tab bar and file
> operations. However, `dirty` is currently computed from `_cleanSnapshot`
> comparisons inside the editing logic, creating a dependency: when
> `policy-edit-store` marks a tab clean or applies undo/redo, it must signal
> `policy-tabs-store` to update the tab's `dirty` flag. This can use
> Zustand's `subscribe` or an explicit callback.

#### 3. `workbench-ui-store.ts` — UI chrome state

```typescript
interface WorkbenchUiState {
  sidebarCollapsed: boolean;
  activeEditorTab: "visual" | "yaml";
  editorSyncDirection: "visual" | "yaml" | null;
  actions: {
    toggleSidebar: () => void;
    setSidebarCollapsed: (collapsed: boolean) => void;
    setActiveEditorTab: (tab: "visual" | "yaml") => void;
    setEditorSyncDirection: (dir: "visual" | "yaml" | null) => void;
  };
}
```

### Cross-Cutting Concern: `editorSyncDirection`

In the current reducer, `SET_POLICY` and `SET_YAML` actions update both the
active tab's policy state **and** the global `ui.editorSyncDirection` field
(lines 1313-1318 of multi-policy-store.tsx). After the split,
`policy-edit-store` mutations need to notify `workbench-ui-store` to update
the sync direction. Options:

1. **Subscribe pattern:** `policy-edit-store` exposes an `onPolicyChange`
   subscription; `workbench-ui-store` subscribes and sets direction.
2. **Explicit caller responsibility:** Components that call `updatePolicy()`
   or `setYaml()` also call `setEditorSyncDirection()`.
3. **Middleware:** Use Zustand middleware that intercepts policy-modifying
   actions and updates the UI store.

Option 1 (Zustand `subscribe`) is the cleanest — it preserves the current
behavior without requiring caller changes.

### Backward-Compat Bridge

The ~45 non-test files that currently call `useWorkbench()` and `useMultiPolicy()` need to
keep working during migration. Export bridge hooks:

```typescript
// Deprecated — migrate callers to individual stores
export function useWorkbench() {
  const ui = useWorkbenchUiStore();
  const tabs = usePolicyTabsStore();
  const activeTab = tabs.actions.getActiveTab();
  const edit = usePolicyEditStore();
  // ... compose the same return shape as before
}

export function useMultiPolicy() {
  const { tabs, activeTabId, actions } = usePolicyTabsStore();
  const activeTab = actions.getActiveTab();
  return { tabs, activeTabId, activeTab, multiDispatch: legacyDispatchBridge };
}
```

This allows incremental migration of consumers without a big-bang rewrite.

### Migration Steps

1. Create the 3 new store files alongside the existing `multi-policy-store.tsx`
2. Move state/logic into the new stores
3. Replace `MultiPolicyProvider` internals to delegate to the 3 Zustand stores
4. Verify all tests pass with the bridged implementation
5. Gradually migrate direct consumers from `useWorkbench()` to specific stores
6. Remove `MultiPolicyProvider` from `AppProviders` once all consumers migrated

---

## B2: Convert Remaining Context Stores

After B1, these providers remain in `AppProviders`:

| Store | File | Pattern | Complexity | Notes |
|-------|------|---------|-----------|-------|
| `OperatorProvider` | `operator-store.tsx` (353 lines) | useReducer | Medium | Ed25519 key management, identity, Stronghold secure store for secret keys, async crypto ops |
| `ReputationProvider` | `reputation-store.tsx` (176 lines) | useReducer | Low | Reputation event tracking keyed by fingerprint, localStorage persistence |
| `GeneralSettingsProvider` | `use-general-settings.ts` (119 lines) | useState | Low | Theme, font size, autosave interval, line numbers; localStorage persistence |
| `HintSettingsProvider` | `use-hint-settings.ts` (261 lines) | useState | Low | Master hint toggle, per-hint text/prompt overrides; localStorage persistence |
| `ProjectProvider` | `project-store.tsx` (349 lines) | useReducer | Medium | Detection project file tree, directory expand/collapse, filters (no file watching — tree is set externally) |
| `SentinelProvider` | `sentinel-store.tsx` (350 lines) | useReducer | Medium | Sentinel CRUD, localStorage persistence |
| `FindingProvider` | `finding-store.tsx` (394 lines) | useReducer | Medium | Finding CRUD, localStorage persistence |
| `SignalProvider` | `signal-store.tsx` (398 lines) | useReducer | Medium | Signal CRUD, localStorage persistence |
| `IntelProvider` | `intel-store.tsx` (395 lines) | useReducer | Medium | Intel CRUD, localStorage persistence |
| `MissionProvider` | `mission-store.tsx` (675 lines) | useReducer | Medium-High | Mission control CRUD, complex state with objectives/phases |
| `SwarmFeedProvider` | `swarm-feed-store.tsx` (2020 lines) | useReducer | High | Live event feed, SSE connection, trust policy evaluation, Merkle chain validation, replay/sync protocol |
| `SwarmProvider` | `swarm-store.tsx` (749 lines) | useReducer | Medium | Swarm CRUD, members, trust graph, invitation tracking |
| `FleetConnectionProvider` | `use-fleet-connection.ts` (422 lines) | useState (multiple) | Medium | Fleet connection with polling, auto-reconnect, Stronghold credential management, health/agent polling timers |
| `ToastProvider` | `components/ui/toast.tsx` | — | Keep | Rendering concern, should stay as Context |

**Convert all 13 providers except ToastProvider** using the same pattern from Phase A.

### Migration Order (by risk)

1. `GeneralSettingsProvider` — thin useState, few consumers
2. `HintSettingsProvider` — thin useState, few consumers
3. `ReputationProvider` — thin useReducer, few consumers
4. `SentinelProvider` — standard useReducer, localStorage persistence
5. `FindingProvider` — standard useReducer, localStorage persistence
6. `SignalProvider` — standard useReducer, localStorage persistence
7. `IntelProvider` — standard useReducer, localStorage persistence
8. `ProjectProvider` — medium (file tree state, no side effects)
9. `MissionProvider` — medium-high (complex state shape with objectives/phases)
10. `OperatorProvider` — medium (async crypto, Stronghold secure store)
11. `SwarmProvider` — medium (CRUD + invitation tracking, depends on swarm-feed ordering in current tree)
12. `FleetConnectionProvider` — medium (polling timers, auto-reconnect, credential management)
13. `SwarmFeedProvider` — high (2020 lines, SSE lifecycle, Merkle validation, trust policy evaluation)

---

## B3: Flatten App.tsx

After B1 + B2, `AppProviders` reduces from:

```tsx
// BEFORE: 15 levels
<OperatorProvider>
  <ReputationProvider>
    <ToastProvider>
      <GeneralSettingsProvider>
        <HintSettingsProvider>
          <ProjectProvider>
            <MultiPolicyProvider>
              <SentinelProvider>
                <FindingProvider>
                  <SignalProvider>
                    <IntelProvider>
                      <MissionProvider>
                        <SwarmFeedProvider>
                          <SwarmProvider>
                            <FleetConnectionProvider>{children}</FleetConnectionProvider>
                          </SwarmProvider>
                        </SwarmFeedProvider>
                      </MissionProvider>
                    </IntelProvider>
                  </SignalProvider>
                </FindingProvider>
              </SentinelProvider>
            </MultiPolicyProvider>
          </ProjectProvider>
        </HintSettingsProvider>
      </GeneralSettingsProvider>
    </ToastProvider>
  </ReputationProvider>
</OperatorProvider>
```

To:

```tsx
// AFTER: 1 provider (only rendering concerns remain)
<ToastProvider>
  {children}
</ToastProvider>
```

> **Note:** `ErrorBoundary` (class component) and `Suspense` are not Context
> providers — they remain in the App component's render tree outside
> `AppProviders`. In the real App.tsx, `ErrorBoundary` wraps `AppProviders`
> (not the other way around), and `Suspense` wraps the route content. Both
> stay as-is since they are not state providers.

---

## Testing Strategy

### Existing Test Coverage

Tests already exist for many of the stores being migrated:

- `multi-policy-store.test.tsx` — 15 tests covering tab reopen/reload, sensitive field stripping, file type coercion, Sigma/YARA/OCSF validation, localStorage persistence
- `operator-store.test.ts` — operator identity tests
- `intel-store.test.tsx` — intel CRUD tests
- `mission-store.test.tsx` — mission state tests
- `swarm-feed-store.test.tsx` — feed ingestion/trust policy tests
- `use-hint-settings.test.ts` — hint override tests

### Before Starting Phase B

Expand test coverage for the `multi-policy-store` consumer surface:

1. **Snapshot tests** for key pages that use `useWorkbench()` — verify rendered output matches (~45 consumer files)
2. **Integration tests** for tab lifecycle (new, close, switch, dirty detection) — some already exist, expand coverage
3. **Integration tests** for undo/redo across tab switches
4. **Integration tests** for file save/load round-trips
5. **Integration tests** for `editorSyncDirection` updates on `SET_POLICY`/`SET_YAML`

### During Phase B

- Run full test suite after each store migration
- Use the backward-compat bridge to keep all existing tests green
- Add new tests for each Zustand store in isolation
- Verify that the `editorSyncDirection` subscription works correctly after the split

---

## Deliverables Checklist

- [ ] `policy-tabs-store.ts` — tab lifecycle Zustand store
- [ ] `policy-edit-store.ts` — per-tab editing Zustand store
- [ ] `workbench-ui-store.ts` — UI chrome Zustand store (with `editorSyncDirection` subscription to policy-edit-store)
- [ ] Backward-compat `useWorkbench()` and `useMultiPolicy()` bridge hooks
- [ ] 13 remaining Context stores converted to Zustand (sentinel, finding, signal, intel, mission were missing from original plan)
- [ ] `AppProviders` reduced to `<ToastProvider>` only
- [ ] All existing tests pass (including 15 tests in `multi-policy-store.test.tsx`)
- [ ] No Context providers except ToastProvider
