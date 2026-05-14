# Phase C: Layout Evolution

> Week 5-6 — Binary tree pane system, bottom terminal panel, keyboard shortcut infra

## Prerequisites

- Phase B complete (all stores are Zustand, no provider nesting)
- Command registry operational (Phase A3)

---

## C1: Binary Tree Pane System

### Current State

`desktop-layout.tsx` (70 lines) at `src/components/desktop/desktop-layout.tsx`:
```tsx
<div className="flex flex-col h-screen w-screen overflow-hidden bg-[#05060a]">
  <ShortcutProvider />
  <CommandPalette />
  <Titlebar />
  {/* CrashRecoveryBanner (conditional) */}
  <div className="flex flex-1 min-h-0">
    <DesktopSidebar />
    <main className="flex-1 min-w-0 overflow-hidden select-text">
      <motion.div key={location.pathname} ...>
        <Outlet />       // ← single routed view, no splits
      </motion.div>
    </main>
  </div>
  <StatusBar />
</div>
```

The component also renders `ShortcutProvider`, `CommandPalette`, and a conditional
`CrashRecoveryBanner`, and uses `useAutoSave` + `useMultiPolicy` for dirty-tab
warnings via a `beforeunload` listener. The `<Outlet>` is wrapped in a Framer Motion
`<motion.div>` that animates page transitions (fade + slide).

The only split capability is `SplitMode` in the policy editor — a simple two-pane
split between two policy tabs. No cross-page splitting (e.g., editor + simulation).

### Target Architecture

**Athas model:** A recursive binary tree of pane nodes, where each leaf is a "group"
containing one or more buffers (tabs), and each branch is a "split" with a direction
and two children.

**Adapted for workbench:** Instead of editor buffers, pane groups contain **workbench views**
(routed pages). Each pane can independently display any workbench page.

```typescript
// src/lib/workbench/pane-types.ts
//
// Adapted from Athas: athas/src/features/panes/types/pane.ts
// Key differences from Athas:
//   - Athas PaneGroup uses `bufferIds: string[]` + `activeBufferId` (editor buffers)
//   - Workbench uses `views: PaneView[]` + `activeViewId` (routed pages)
//   - Athas PaneSplit uses `children: [PaneNode, PaneNode]`
//   - Workbench uses named `first`/`second` for readability

export type PaneNode = PaneGroup | PaneSplit;

export interface PaneGroup {
  id: string;
  type: "group";
  /** Which workbench views are open in this pane */
  views: PaneView[];
  /** Which view is active (visible) */
  activeViewId: string | null;
}

export interface PaneSplit {
  id: string;
  type: "split";
  direction: "horizontal" | "vertical";
  first: PaneNode;
  second: PaneNode;
  /** Flex ratio [first, second], e.g., [50, 50] */
  sizes: [number, number];
}

export interface PaneView {
  id: string;
  /** Route path, e.g., "/editor", "/lab?tab=simulate", "/receipts" */
  route: string;
  /** Display label for the pane tab bar */
  label: string;
}
```

### Pane Store

```typescript
// src/features/panes/stores/pane-store.ts

interface PaneState {
  root: PaneNode;
  activePaneId: string;
  actions: {
    splitPane: (paneId: string, direction: "horizontal" | "vertical") => void;
    closePane: (paneId: string) => void;
    setActivePane: (paneId: string) => void;
    addView: (paneId: string, view: PaneView) => void;
    removeView: (paneId: string, viewId: string) => void;
    setActiveView: (paneId: string, viewId: string) => void;
    resizeSplit: (splitId: string, sizes: [number, number]) => void;
    navigateToPane: (direction: "left" | "right" | "up" | "down") => void;
    moveViewBetweenPanes: (viewId: string, fromPaneId: string, toPaneId: string) => void;
  };
}
```

### Tree Utilities

Port from Athas (`athas/src/features/panes/utils/pane-tree.ts`) and adapt.
The Athas module exports 16 functions; the ones needed for workbench are listed below
with names aligned to the Athas originals (renamed where the workbench adaptation
requires different semantics):

```typescript
// src/features/panes/utils/pane-tree.ts

// Direct ports from Athas (same signature, rename bufferIds→views)
export function findPaneNode(root: PaneNode, id: string): PaneNode | null;
export function findPaneGroup(root: PaneNode, paneId: string): PaneGroup | null;
export function findParentSplit(root: PaneNode, childId: string): { parent: PaneSplit; childIndex: 0 | 1 } | null;
export function getAllPaneGroups(root: PaneNode): PaneGroup[];
export function getFirstPaneGroup(root: PaneNode): PaneGroup;
export function splitPane(root: PaneNode, paneId: string, direction: SplitDirection): PaneNode;
export function closePane(root: PaneNode, paneId: string): PaneNode | null;
export function updatePaneSizes(root: PaneNode, splitId: string, sizes: [number, number]): PaneNode;
export function getAdjacentPane(root: PaneNode, paneId: string, dir: Direction): PaneGroup | null;

// Adapted from Athas addBufferToPane/removeBufferFromPane/moveBufferBetweenPanes
export function addViewToPane(root: PaneNode, paneId: string, view: PaneView, setActive?: boolean): PaneNode;
export function removeViewFromPane(root: PaneNode, paneId: string, viewId: string): PaneNode;
export function moveViewBetweenPanes(root: PaneNode, viewId: string, fromPaneId: string, toPaneId: string): PaneNode;
export function setActivePaneView(root: PaneNode, paneId: string, viewId: string | null): PaneNode;
```

Note: Athas `findParentSplit` returns `{ parent, childIndex }` not just the split node.
The Athas `getAdjacentPane` uses a simple linear flattening of groups (left/up = previous
index, right/down = next index) which does not truly respect 2D spatial layout. Consider
a proper spatial lookup for the workbench if needed.

### Layout Components

`react-resizable-panels` is already a dependency (`^2.1.7` in `apps/workbench/package.json`)
and has a shadcn wrapper at `src/components/ui/resizable.tsx` (exports `ResizablePanelGroup`,
`ResizablePanel`, `ResizableHandle`). Use this for split resize handles instead of building
a custom drag implementation.

```
src/features/panes/components/
  ├── pane-root.tsx          # Renders the recursive tree using ResizablePanelGroup
  ├── pane-container.tsx     # Renders a single PaneGroup (tab bar + routed content)
  └── pane-tab-bar.tsx       # Tab bar within a pane (view tabs)
```

### Integration with react-router-dom

**Option A (MemoryRouter per pane):** Each `PaneContainer` renders its own `<MemoryRouter>`.
The main `HashRouter` in `App.tsx` controls the "primary" pane. Secondary panes use
internal navigation state from the pane store. This is more complex because nested routers
require careful context isolation, and react-router-dom v6 does not natively support
multiple concurrent router instances sharing state.

**Option B (component registry — recommended):** Keep the single HashRouter. The active
pane's view determines the URL. Non-active panes render their views from a component
registry (lazy-loaded) without affecting the URL. The pane store tracks each pane's
view independently; only the focused pane syncs with the URL bar. This is simpler and
avoids the nested-router complexity. It also works better with the existing `ShortcutProvider`
which calls `useNavigate()` from the single router context.

### Updated DesktopLayout

Must preserve the existing `ShortcutProvider`, `CommandPalette`, `CrashRecoveryBanner`,
`beforeunload` handler, and `useAutoSave`/`useMultiPolicy` hooks from the current
component. The key structural change is replacing the `<motion.div><Outlet /></motion.div>`
with `<PaneRoot />` + `<BottomPane />`:

```tsx
export function DesktopLayout() {
  // ... existing hooks: useMultiPolicy, useAutoSave, useLocation, beforeunload ...
  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-[#05060a]">
      <ShortcutProvider />
      <CommandPalette />
      <Titlebar />
      {/* CrashRecoveryBanner (conditional) */}
      <div className="flex flex-1 min-h-0">
        <DesktopSidebar />
        <div className="flex flex-1 flex-col min-w-0">
          {/* Main content area — pane tree (replaces <Outlet />) */}
          <PaneRoot />
          {/* Bottom panel (terminal, diagnostics) */}
          <BottomPane />
        </div>
      </div>
      <StatusBar />
    </div>
  );
}
```

### Keyboard Shortcuts

Register in command registry:

| Command | Keybinding | Action |
|---------|-----------|--------|
| `view.split-vertical` | `Meta+\` | Split active pane vertically |
| `view.split-horizontal` | `Meta+Shift+\` | Split active pane horizontally |
| `view.close-pane` | `Meta+Shift+W` | Close active pane |
| `view.focus-left` | `Meta+Alt+Left` | Focus pane to the left |
| `view.focus-right` | `Meta+Alt+Right` | Focus pane to the right |
| `view.focus-up` | `Meta+Alt+Up` | Focus pane above |
| `view.focus-down` | `Meta+Alt+Down` | Focus pane below |

**Conflict warning:** `Meta+Shift+W` does NOT conflict with existing `Meta+W` (close tab)
because the current `useKeyboardShortcuts` hook checks `shiftMatches` — when `shift` is
undefined/false it requires `e.shiftKey === false`, so `Meta+W` and `Meta+Shift+W` are
distinct. However, the shift-aware variant must be registered before the non-shift variant
in the shortcut array (same pattern used for `Meta+S`/`Meta+Shift+S` today).

**Alt modifier gap:** The current `useKeyboardShortcuts` hook (in `src/lib/keyboard-shortcuts.ts`)
only matches `meta` and `shift` — it does NOT check `altKey`. The `Meta+Alt+Arrow` focus
shortcuts will require extending the `ShortcutAction` interface to add an `alt?: boolean`
field and updating the matcher to check `e.altKey`. This must happen before (or as part of)
C3.

### Single-Pane Fallback

When only one pane exists (default), the layout behaves exactly like today —
sidebar + single content area. The pane system only activates on first split.

---

## C2: Bottom Pane (Terminal + Diagnostics)

### Current State

No bottom panel exists. Terminal rendering only happens inside SwarmBoard graph nodes
(`terminal-renderer.tsx` using ghostty-web). The Tauri backend has full PTY support
(`terminal-service.ts` + Rust `terminal.rs`).

### Target

A resizable bottom panel with tabs:

```
┌──────────────────────────────────┐
│ Titlebar                         │
├────────┬─────────────────────────┤
│Sidebar │ Main Content (Panes)    │
│        │                         │
│        │                         │
│        ├─────────────────────────┤
│        │ ▼ Terminal | Problems   │ ← Bottom Pane (resizable)
│        │ $ hush check ...        │
│        │                         │
├────────┴─────────────────────────┤
│ Status Bar                       │
└──────────────────────────────────┘
```

### Implementation

```typescript
// src/features/bottom-pane/stores/bottom-pane-store.ts

interface BottomPaneState {
  isOpen: boolean;
  activeTab: "terminal" | "problems" | "output";
  height: number;       // pixels
  terminalSessions: TerminalSession[];
  activeTerminalId: string | null;
  actions: {
    toggle: () => void;
    setOpen: (open: boolean) => void;
    setActiveTab: (tab: "terminal" | "problems" | "output") => void;
    setHeight: (height: number) => void;
    newTerminal: () => void;
    closeTerminal: (id: string) => void;
    setActiveTerminal: (id: string) => void;
  };
}
```

### Components

```
src/features/bottom-pane/components/
  ├── bottom-pane.tsx           # Container with resize handle + tab bar
  ├── terminal-panel.tsx        # Terminal tab (multi-session tabs + TerminalRenderer)
  ├── problems-panel.tsx        # Aggregated validation errors across all open tabs
  └── output-panel.tsx          # CLI output log (hush check results, etc.)
```

### Terminal Integration

Reuse existing infrastructure:
- `lib/workbench/terminal-service.ts` — Tauri IPC for PTY create/write/resize
- `components/workbench/swarm-board/terminal-renderer.tsx` — ghostty-web canvas renderer

The bottom-pane terminal panel wraps `TerminalRenderer` with:
- Multi-session tab bar (each terminal is a separate PTY)
- Auto-CWD to current project directory
- Profile support (default shell, hush shell, custom)

### Keyboard Shortcuts

| Command | Keybinding | Action |
|---------|-----------|--------|
| `view.toggle-terminal` | `Meta+J` | Toggle bottom pane (terminal tab) |
| `view.toggle-problems` | `Meta+Shift+M` | Toggle bottom pane (problems tab) |
| `terminal.new` | `Meta+Shift+\`` | New terminal session |
| `terminal.close` | (none) | Close active terminal |

---

## C3: Enriched Keyboard Infrastructure

### Current State

`shortcut-provider.tsx` has a `SHORTCUT_DEFINITIONS` array with 19 display entries
and a `shortcuts` useMemo that builds 21 `ShortcutAction` entries (shift variants of
save and redo are listed before their non-shift counterparts to match first; `?` is
registered alongside `/` for help).
`useKeyboardShortcuts` hook (in `src/lib/keyboard-shortcuts.ts`) listens for `keydown`
globally via `capture: true` and matches by `key`, `meta` (metaKey or ctrlKey), and
`shift`. It does NOT currently support `alt` or `ctrl` as independent modifiers.

### Target

Keybindings derived from the command registry (built in Phase A3). The shortcut provider
becomes a thin layer that:

1. Reads all commands with keybindings from the registry
2. Parses keybinding strings into `{ key, meta, shift, alt, ctrl }` matchers
3. Registers a single `keydown` listener
4. Dispatches to `command.execute()` on match

### Context Awareness

Some keybindings should only fire in certain contexts:

```typescript
type CommandContext = "global" | "editor" | "terminal" | "pane";

// Example: Meta+S saves in editor context, but does nothing in terminal
{ id: "file.save", keybinding: "Meta+S", context: "editor", execute: ... }
```

The shortcut provider checks the active context (which pane/view is focused)
before dispatching.

---

## Deliverables Checklist

- [ ] `src/features/panes/` — types, store, tree utils, components
- [ ] `PaneRoot` replaces `<Outlet />` in `DesktopLayout`
- [ ] Split commands registered and functional
- [ ] Single-pane mode works identically to current behavior
- [ ] `src/features/bottom-pane/` — store, components (terminal, problems, output)
- [ ] Terminal panel reuses ghostty-web renderer + terminal-service
- [ ] `Meta+J` toggles terminal panel
- [ ] Shortcut provider derives keybindings from command registry
- [ ] Context-aware keybinding dispatch
- [ ] All existing tests pass
