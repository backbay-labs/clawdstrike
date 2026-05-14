# Patterns Reference: Athas → ClawdStrike Workbench

> Exact code snippets and architectural patterns to port from Athas.
> Source: `/Users/connor/Medica/backbay/standalone/athas/`

---

## 1. `createSelectors` Utility

**Source:** `athas/src/utils/zustand-selectors.ts`
**Target:** `workbench/src/lib/create-selectors.ts`

```typescript
import type { StoreApi, UseBoundStore } from "zustand";

type WithSelectors<S> = S extends { getState: () => infer T }
  ? S & { use: { [K in keyof T]: () => T[K] } }
  : never;

export const createSelectors = <S extends UseBoundStore<StoreApi<object>>>(_store: S) => {
  const store = _store as WithSelectors<typeof _store>;
  store.use = {};
  for (const k of Object.keys(store.getState())) {
    (store.use as any)[k] = () => store((s) => s[k as keyof typeof s]);
  }

  return store;
};
```

**Usage:**
```typescript
// Define store
const useMyStore = createSelectors(
  create<MyState>()(
    immer((set) => ({
      count: 0,
      name: "default",
      actions: {
        increment: () => set((s) => { s.count++; }),
      },
    }))
  )
);

// Consume — auto-memoized per-field hooks
const count = useMyStore.use.count();       // only re-renders when count changes
const name = useMyStore.use.name();         // only re-renders when name changes
const actions = useMyStore.use.actions();   // stable reference (actions don't change)
```

---

## 2. Zustand Store Pattern (Athas Convention)

Most stores in Athas follow this shape (simplified example -- not from a single real file):

```typescript
import { create } from "zustand";
import { immer } from "zustand/middleware/immer";
import { createSelectors } from "@/utils/zustand-selectors";

interface FooState {
  // Data fields
  items: Item[];
  activeId: string | null;

  // Actions namespace (stable reference)
  actions: {
    addItem: (item: Item) => void;
    removeItem: (id: string) => void;
    setActive: (id: string | null) => void;
  };
}

export const useFooStore = createSelectors(
  create<FooState>()(
    immer((set, get) => ({
      items: [],
      activeId: null,
      actions: {
        addItem: (item) => set((state) => {
          state.items.push(item);
        }),
        removeItem: (id) => set((state) => {
          state.items = state.items.filter((i) => i.id !== id);
        }),
        setActive: (id) => set((state) => {
          state.activeId = id;
        }),
      },
    }))
  )
);
```

**Key conventions:**
- `actions` namespace groups all mutations (stable reference, never causes re-render)
- `createSelectors` wrapper for auto-hooks
- No Provider needed — module-scoped singleton
- Cross-store access via `useOtherStore.getState()` (outside React, in action handlers)

**Middleware varies by store** (not all use `immer`):
- `immer` for stores with deeply nested state (e.g., `editor-app-store.ts`, `git-store.ts`)
- `persist` for stores that save to disk (e.g., `keymaps/stores/store.ts`, `command-palette/store.ts`)
- `createWithEqualityFn` + `isEqual` for stores needing custom equality (e.g., `pane-store.ts`)
- Some stores combine middleware (e.g., `immer` + `persist`); others use none

---

## 3. Cross-Store Communication

Athas stores call `getState()` on other stores from within action handlers:

```typescript
// Simplified from editor-app-store.ts — real version has more stores and logic
actions: {
  handleContentChange: async (content: string) => {
    // Access buffer store from within editor-app store action
    const { useBufferStore } = await import("@/features/editor/stores/buffer-store");
    const { activeBufferId, buffers } = useBufferStore.getState();
    const { updateBufferContent, markBufferDirty } = useBufferStore.getState().actions;

    // Access settings from another store
    const { useSettingsStore } = await import("@/features/settings/store");
    const { settings } = useSettingsStore.getState();

    // Also imports useFileWatcherStore, useHistoryStore in the real code
    // Now do the work...
    const activeBuffer = buffers.find((b) => b.id === activeBufferId);
    if (!activeBuffer) return;
    updateBufferContent(activeBuffer.id, content, true);
  },
}
```

**Pattern:** Lazy-import other stores to avoid circular dependencies. Use `getState()`
(not hooks) since action handlers run outside React render context.

---

## 4. Binary Tree Pane System

**Source:** `athas/src/features/panes/stores/pane-store.ts`

### Core Types

**Source:** `athas/src/features/panes/types/pane.ts` (exact)

```typescript
export interface PaneGroup {
  id: string;
  type: "group";
  bufferIds: string[];             // → workbench: viewIds
  activeBufferId: string | null;   // → workbench: activeViewId
}

export interface PaneSplit {
  id: string;
  type: "split";
  direction: "horizontal" | "vertical";
  children: [PaneNode, PaneNode];  // NOT first/second — uses a tuple
  sizes: [number, number];
}

export type PaneNode = PaneGroup | PaneSplit;

export type SplitDirection = "horizontal" | "vertical";
```

### Tree Operations (conceptual — simplified from `pane-tree.ts` utility functions)

```typescript
// Split: replace a group with a split containing the original + a new empty group
function splitPane(root: PaneNode, paneId: string, direction: SplitDirection): PaneNode {
  const original = findById(root, paneId);
  const newGroup = { id: uuid(), type: "group", bufferIds: [], activeBufferId: null };
  const split = {
    id: uuid(),
    type: "split",
    direction,
    children: [original, newGroup],  // tuple, not first/second
    sizes: [50, 50],
  };
  return replacePaneInTree(root, paneId, split);
}

// Close: remove a pane, promote its sibling to take the parent split's place
function closePane(root: PaneNode, paneId: string): PaneNode {
  const parent = findParentSplit(root, paneId);
  if (!parent) return root; // can't close the last pane
  const sibling = parent.children[0].id === paneId ? parent.children[1] : parent.children[0];
  return replacePaneInTree(root, parent.id, sibling);
}

// Navigate: BFS to find adjacent pane in a direction
function findAdjacentPane(root: PaneNode, paneId: string, dir: Direction): PaneGroup | null {
  // Walk up to find the nearest split with matching direction,
  // then walk down the other branch to find the nearest group
}
```

### Store

The pane store uses `createWithEqualityFn` (not plain `create`) with `fast-deep-equal`
for structural equality, since the tree is rebuilt on every mutation:

```typescript
import { createWithEqualityFn } from "zustand/traditional";
import isEqual from "fast-deep-equal";

const usePaneStoreBase = createWithEqualityFn<PaneState>()(
  immer((set, get) => ({ ... })),
  isEqual,
);
export const usePaneStore = createSelectors(usePaneStoreBase);
```

### Rendering (simplified)

```tsx
function PaneRoot() {
  const root = usePaneStore.use.root();
  return <PaneNodeRenderer node={root} />;
}

function PaneNodeRenderer({ node }: { node: PaneNode }) {
  if (node.type === "group") return <PaneContainer group={node} />;
  return (
    <div style={{ display: "flex", flexDirection: node.direction === "horizontal" ? "column" : "row" }}>
      <div style={{ flex: node.sizes[0] }}>
        <PaneNodeRenderer node={node.children[0]} />
      </div>
      <PaneResizeHandle splitId={node.id} />
      <div style={{ flex: node.sizes[1] }}>
        <PaneNodeRenderer node={node.children[1]} />
      </div>
    </div>
  );
}
```

---

## 5. Command Palette Pattern

**Source:** `athas/src/features/command-palette/`

### Action Interface

**Source:** `athas/src/features/command-palette/models/action.types.ts` (exact)

```typescript
import type { ReactNode } from "react";

export interface Action {
  id: string;                    // "workbench.toggleSidebar"
  label: string;                 // "Toggle Sidebar"
  description: string;           // required, not optional
  icon: ReactNode;               // required ReactNode, not optional IconName
  category: string;              // "View"
  keybinding?: string[];         // array of key strings, e.g. ["Cmd", "B"]
  action: () => void;            // named "action", not "callback"
}

export type ActionCategory =
  | "View"
  | "Settings"
  | "Help"
  | "File"
  | "Window"
  | "Navigation"
  | "Markdown";
```

Note: there is no `condition` or `source` field on `Action`. Filtering is done
at the factory level — factories simply omit actions that don't apply.

### Factory Pattern

Actions are generated by factory functions in `constants/` (not `actions/`).
Each factory receives a params object with store accessors and callbacks:

```typescript
// athas/src/features/command-palette/constants/git-actions.ts (simplified)
export function createGitActions(params: {
  rootFolderPath: string | null;
  showToast: (...args: any[]) => void;
  gitStore: any;
  gitOperations: { stageAllFiles: Function; commitChanges: Function; /* ... */ };
  onClose: () => void;
}): Action[] {
  return [
    {
      id: "git.commit",
      label: "Commit Changes",
      description: "Commit staged changes",
      icon: <SomeIcon />,
      category: "Git",
      action: () => { /* open commit dialog */ params.onClose(); },
    },
    // ...
  ];
}
```

### Search and Prioritization

Athas uses simple case-insensitive substring matching (not fuzzy scoring):

```typescript
const filteredActions = allActions.filter(
  (action) =>
    action.label.toLowerCase().includes(query.toLowerCase()) ||
    action.description?.toLowerCase().includes(query.toLowerCase()) ||
    action.category.toLowerCase().includes(query.toLowerCase()),
);
```

Recently-used actions are prioritized via a persisted stack (`useActionsStore`),
which stores the last 10 action IDs and moves them to the top of results.

---

## 6. Bottom Pane Layout

**Source:** `athas/src/features/layout/components/main-layout.tsx` and
`athas/src/features/layout/components/bottom-pane/bottom-pane.tsx`

### Composition (simplified from MainLayout)

The real `MainLayout` is more complex -- it handles sidebar position (left/right),
AI chat overlay, drag-and-drop, vim mode, and workspace restoration. Key structural
elements:

```tsx
// Simplified — see main-layout.tsx for full version
<div className="relative flex h-full w-full flex-col overflow-hidden bg-secondary-bg">
  <CustomTitleBarWithSettings />
  <div className="relative z-10 flex flex-1 flex-col overflow-hidden">
    <div className="flex flex-1 flex-row overflow-hidden" style={{ minHeight: 0 }}>
      {/* Sidebar uses ResizablePane, position depends on settings */}
      <ResizablePane position="left" widthKey="sidebarWidth" collapsible>
        <MainSidebar />
      </ResizablePane>

      {/* Main content area */}
      <div className="flex min-h-0 min-w-0 flex-1 flex-col gap-2 px-2 py-2">
        <div className="relative min-h-0 flex-1 overflow-hidden rounded-2xl bg-primary-bg">
          <SplitViewRoot />
        </div>
        {/* Bottom pane is a self-contained component with its own resize handle */}
        <BottomPane diagnostics={diagnostics} onDiagnosticClick={handleDiagnosticClick} />
      </div>

      {/* AI chat pane on opposite side of sidebar */}
      <ResizablePane position="right" widthKey="aiChatWidth" collapsible>
        <AIChat mode="chat" />
      </ResizablePane>
    </div>
  </div>
  <EditorFooter />
</div>
```

### BottomPane Resize Handle (built-in, not a separate component)

The resize handle is embedded directly in `BottomPane`, not a reusable `ResizeHandle`
component. It uses `ns-resize` cursor and clamps between 200px and 80% of viewport:

```tsx
// From bottom-pane.tsx (simplified)
const [height, setHeight] = useState(320);
const [isResizing, setIsResizing] = useState(false);

const handleMouseDown = useCallback((e: React.MouseEvent) => {
  e.preventDefault();
  setIsResizing(true);
  const startY = e.clientY;
  const startHeight = height;

  const handleMouseMove = (e: MouseEvent) => {
    const deltaY = startY - e.clientY;
    const newHeight = Math.min(Math.max(startHeight + deltaY, 200), window.innerHeight * 0.8);
    setHeight(newHeight);
  };

  const handleMouseUp = () => {
    setIsResizing(false);
    document.removeEventListener("mousemove", handleMouseMove);
    document.removeEventListener("mouseup", handleMouseUp);
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
  };

  document.addEventListener("mousemove", handleMouseMove);
  document.addEventListener("mouseup", handleMouseUp);
  document.body.style.cursor = "ns-resize";
  document.body.style.userSelect = "none";
}, [height]);
```

The bottom pane has two tabs: **Terminal** and **Diagnostics** (no "Output" panel).
Terminal is always mounted to preserve sessions; diagnostics renders conditionally.

### Sidebar Resize (ResizablePane)

Sidebar and AI chat panels use `ResizablePane` (`resizable-pane.tsx`), which handles
horizontal (col-resize) dragging, collapsible behavior with configurable threshold,
width persistence via settings store, and max-width clamping to keep the editor
readable.

---

## 7. Feature Directory Structure

**Source:** `athas/src/features/git/` (example -- abbreviated, real tree has more files)

```
features/git/
├── api/
│   ├── git-blame-api.ts
│   ├── git-branches-api.ts
│   ├── git-commits-api.ts
│   ├── git-diff-api.ts
│   ├── git-remotes-api.ts
│   ├── git-repo-api.ts
│   ├── git-stash-api.ts
│   ├── git-status-api.ts
│   └── git-tags-api.ts
├── components/
│   ├── diff/                   # Subdirectory for diff components
│   │   ├── git-diff-viewer.tsx
│   │   └── ...
│   ├── stash/                  # Subdirectory for stash components
│   ├── status/                 # Subdirectory for status components
│   ├── git-view.tsx            # Main sidebar view
│   ├── git-inline-blame.tsx
│   └── ...
├── hooks/
│   ├── use-git-blame.ts
│   ├── use-git-diff-data.ts
│   ├── use-git-diff-highlight.ts
│   ├── use-git-diff-view.ts
│   └── use-git-gutter.ts
├── stores/
│   ├── git-store.ts
│   ├── git-blame-store.ts
│   └── git-repository-store.ts
├── types/
│   ├── git-types.ts
│   └── git-diff-types.ts
├── utils/
│   ├── git-diff-cache.ts
│   ├── git-diff-helpers.ts
│   ├── git-diff-parser.ts
│   └── git-actions-menu-position.ts
└── tests/
    └── git-actions-menu-position.test.ts
```

**Convention:** Each feature directory is self-contained. Components, stores, hooks,
types, and utils for that feature all live together. There is no barrel `index.ts`
export -- consumers import individual files directly (e.g.,
`import { useGitStore } from "@/features/git/stores/git-store"`).

---

## 8. Keybinding System

**Source:** `athas/src/features/keymaps/`

### Architecture

The keymaps system has three layers:

1. **Types** (`types.ts`) -- `Command`, `Keybinding`, `KeymapContext`
2. **Registry** (`utils/registry.ts`) -- singleton `keymapRegistry` (class instance)
3. **Hook** (`hooks/use-keymaps.ts`) -- single `keydown` listener on `window` (capture phase)

### Core Types (exact from `types.ts`)

```typescript
export interface Command {
  id: string;                    // "editor.save"
  title: string;                 // "Save File"
  category?: string;             // "File" (optional)
  keybinding?: string;           // "cmd+s" (lowercase, not "Meta+S")
  description?: string;
  icon?: React.ReactNode;
  execute: (args?: unknown) => void | Promise<void>;
}

export interface Keybinding {
  key: string;                   // "cmd+s", "cmd+k cmd+t" (chord)
  command: string;               // command id
  when?: string;                 // context condition, e.g. "editorFocus"
  args?: unknown;
  source: "user" | "extension" | "default";
  enabled?: boolean;
}

export interface KeymapContext {
  editorFocus: boolean;
  vimMode: boolean;
  vimNormalMode: boolean;
  vimInsertMode: boolean;
  vimVisualMode: boolean;
  terminalFocus: boolean;
  sidebarFocus: boolean;
  findWidgetVisible: boolean;
  hasSelection: boolean;
  isRecordingKeybinding: boolean;
  [key: string]: boolean;        // extensible
}
```

### Registry (singleton class, not a plain Map)

```typescript
// From utils/registry.ts (simplified)
class KeymapRegistry {
  private commands = new Map<string, Command>();
  private keybindings: Keybinding[] = [];

  registerCommand(command: Command): void;
  registerKeybinding(keybinding: Keybinding): void;
  getAllKeybindings(): Keybinding[];
  async executeCommand(commandId: string, args?: unknown): Promise<void>;
}

export const keymapRegistry = new KeymapRegistry();
```

Commands are registered at app startup via `initializeKeymaps()` which calls
`registerCommands()` (from `commands/command-registry.ts`) and
`registerDefaultKeymaps()` (from `defaults/register-defaults.ts`).

### User Override Storage

User keybinding overrides are stored in a Zustand store with `persist` middleware
(persisted to Tauri plugin-store as `"keymaps-storage"`). Only `source: "user"`
keybindings are persisted:

```typescript
// From stores/store.ts (simplified)
const useKeymapStoreBase = create<KeymapState>()(
  persist(
    (set) => ({ keybindings: [], contexts: { ... }, actions: { ... } }),
    {
      name: "keymaps-storage",
      partialize: (state) => ({
        keybindings: state.keybindings.filter((kb) => kb.source === "user"),
      }),
    },
  ),
);
```

### Resolution Order

The `useKeymaps` hook iterates all registered keybindings on each `keydown` event:

1. Skip if `isRecordingKeybinding` context is true (user is rebinding a key)
2. Skip modifier-key auto-repeats (prevents floods from held Cmd+R, etc.)
3. Evaluate `when` clause against current `KeymapContext`
4. Match key event against keybinding's `key` string (supports chords like `cmd+k cmd+t`)
5. On full match: execute command via `keymapRegistry.executeCommand()`
6. On partial chord match: wait up to 1 second for the next key

User overrides in the store are separate from the registry's `keybindings` array.
The registry holds defaults + extension bindings; the store holds user overrides.
For the workbench, this is a P2 feature -- the foundation (command registry) comes first.
