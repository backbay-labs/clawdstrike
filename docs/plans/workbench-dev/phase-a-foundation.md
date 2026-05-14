# Phase A: Foundation

> Week 1-2 — Port `createSelectors`, convert domain stores, build command registry

## A1: Port `createSelectors` Utility

**Source:** `athas/src/utils/zustand-selectors.ts`

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

**Target:** `apps/workbench/src/lib/create-selectors.ts`

This 15-line utility auto-generates per-field hooks from a Zustand store. Instead of:
```typescript
const tabs = useMultiPolicy((s) => s.tabs);
```
You write:
```typescript
const tabs = useMultiPolicyStore.use.tabs();
```

**Dependencies:** Add `zustand` + `immer` to workbench `package.json`.

---

## A2: Convert 5 Domain Context Stores to Zustand

These stores are Context+useReducer wrappers. Each includes persistence (localStorage for
sentinel, finding, intel, mission; IndexedDB for signal) and validation/normalization logic
that inflates line counts well beyond the core state management. The state shapes and reducer
patterns are straightforward despite the size. `mission-store.tsx` is the largest at 676 lines
due to extensive persisted-data normalization helpers. Converting these gives the team practice
before tackling the monoliths (multi-policy-store, policy-store).

### Migration Order

| Store | File | Lines | State Fields | Consumers |
|-------|------|-------|-------------|-----------|
| 1. `SentinelProvider` | `sentinel-store.tsx` | 351 | sentinels[], activeSentinelId, loading | HomePage, DesktopSidebar, MissionControlPage, SentinelSwarmPages |
| 2. `FindingProvider` | `finding-store.tsx` | 395 | findings[], activeFindingId | HomePage, DesktopSidebar, MissionControlPage, SentinelSwarmPages, FindingsIntelPage |
| 3. `SignalProvider` | `signal-store.tsx` | 399 | signals[], pipelineState, stats, isStreaming | MissionControlPage, SentinelDetail |
| 4. `IntelProvider` | `intel-store.tsx` | 396 | localIntel[], swarmIntel[] (SwarmIntelRecord[]), activeIntelId | FindingsIntelPage, SentinelSwarmPages |
| 5. `MissionProvider` | `mission-store.tsx` | 676 | missions[], activeMissionId, loading | MissionControlPage |

### Migration Pattern (per store)

**Before (Context+useReducer):** (simplified; actual stores also have persistence + validation)
```typescript
const SentinelContext = createContext<SentinelContextValue | null>(null);

function sentinelReducer(state: SentinelState, action: SentinelAction): SentinelState { ... }

export function SentinelProvider({ children }) {
  const [state, dispatch] = useReducer(sentinelReducer, undefined, getInitialState);
  // useCallback wrappers around dispatch calls...
  const createSentinel = useCallback(async (config) => { ... dispatch(...); }, []);
  const value = { sentinels: state.sentinels, activeSentinel, loading: state.loading, createSentinel, ... };
  return (
    <SentinelContext.Provider value={value}>
      {children}
    </SentinelContext.Provider>
  );
}

export function useSentinels() {
  const ctx = useContext(SentinelContext);
  if (!ctx) throw new Error("useSentinels must be used within SentinelProvider");
  return ctx;
}
```

**After (Zustand + createSelectors):**
```typescript
import { create } from "zustand";
import { immer } from "zustand/middleware/immer";
import { createSelectors } from "@/lib/create-selectors";

interface SentinelState {
  sentinels: Sentinel[];
  activeSentinelId: string | null;
  actions: {
    addSentinel: (s: Sentinel) => void;
    removeSentinel: (id: string) => void;
    setActive: (id: string | null) => void;
  };
}

export const useSentinelStore = createSelectors(
  create<SentinelState>()(
    immer((set) => ({
      sentinels: [],
      activeSentinelId: null,
      actions: {
        addSentinel: (s) => set((state) => { state.sentinels.push(s); }),
        removeSentinel: (id) => set((state) => {
          state.sentinels = state.sentinels.filter((s) => s.id !== id);
        }),
        setActive: (id) => set((state) => { state.activeSentinelId = id; }),
      },
    }))
  )
);
```

### Backward-Compat Shim

During migration, export a `useSentinels()` hook that delegates to the Zustand store,
so existing consumers don't need to change immediately:

```typescript
// Deprecated — migrate callers to useSentinelStore directly
export function useSentinels() {
  const sentinels = useSentinelStore.use.sentinels();
  const activeSentinelId = useSentinelStore.use.activeSentinelId();
  const actions = useSentinelStore.use.actions();
  return { sentinels, activeSentinelId, ...actions };
}
```

### Provider Removal

After converting each store, remove its `<Provider>` from `AppProviders` in `App.tsx`.
Zustand stores are module-scoped — no Provider needed.

**App.tsx provider count after A2:** 15 → 10

---

## A3: Command Registry + Enriched Command Palette

### Current State

There are two command palettes: a **desktop-level** one and an **editor-level** one. This
section targets the desktop palette. The editor palette (`src/components/workbench/editor/command-palette.tsx`, 378 lines) is a separate, more complex component scoped to the editor and is out of scope for Phase A.

`src/components/desktop/command-palette.tsx` (153 lines):
- 17 static `CommandItem` objects in a `COMMANDS` const array
- `.includes()` string matching on label and section (not fuzzy)
- Items are navigation links only (no actions, no state mutations)
- No connection to `shortcut-provider.tsx` (shortcuts defined separately)

`src/components/desktop/shortcut-provider.tsx` (158 lines):
- 20 `ShortcutAction` objects in a `useMemo` array (12 explicit + 6 from `NAV_ROUTES.map()` + 2 help variants)
- Each has `key`, `meta`, `shift?`, `description`, `action`
- Tightly coupled to `useWorkbench()` and `useMultiPolicy()` hooks, plus `isDesktop()`, `isPolicyFileType()`, `policyToYaml()`, and `triggerNativeValidation()`
- No command IDs — shortcuts and palette are disconnected

### Target Architecture

**Single command registry** consumed by both palette and shortcuts:

```
command-registry.ts
  ├── CommandPalette reads commands, renders search UI
  ├── ShortcutProvider reads keybindings, registers keydown handlers
  └── Menus (future) read commands, render native menu items
```

### Implementation

**`src/lib/command-registry.ts`:**

```typescript
export interface Command {
  id: string;                    // e.g., "navigate.editor"
  title: string;                 // e.g., "Policy Editor"
  category: CommandCategory;     // "Navigate" | "File" | "Edit" | "Policy" | "Fleet" | ...
  keybinding?: string;           // e.g., "Meta+1"
  icon?: string;                 // tabler icon name
  when?: () => boolean;          // show only when condition is true
  execute: () => void | Promise<void>;
}

export type CommandCategory =
  | "Navigate"
  | "File"
  | "Edit"
  | "Policy"
  | "Guard"
  | "Fleet"
  | "Test"
  | "Sentinel"
  | "Receipt"
  | "View"
  | "Help";

class CommandRegistry {
  private commands = new Map<string, Command>();
  private listeners = new Set<() => void>();

  register(cmd: Command): void { ... }
  registerAll(cmds: Command[]): void { ... }
  unregister(id: string): void { ... }
  getAll(): Command[] { ... }
  getById(id: string): Command | undefined { ... }
  getByCategory(cat: CommandCategory): Command[] { ... }
  search(query: string): Command[] { ... } // fuzzy match
  execute(id: string): void { ... }
  subscribe(fn: () => void): () => void { ... }
}

export const commandRegistry = new CommandRegistry();
```

**Domain command factories:**

```typescript
// src/lib/commands/navigate-commands.ts
export function registerNavigateCommands(navigate: NavigateFunction) {
  commandRegistry.registerAll([
    { id: "navigate.home", title: "Home", category: "Navigate", keybinding: "Meta+1", execute: () => navigate("/home") },
    { id: "navigate.editor", title: "Policy Editor", category: "Navigate", keybinding: "Meta+2", execute: () => navigate("/editor") },
    { id: "navigate.lab", title: "Threat Lab", category: "Navigate", keybinding: "Meta+3", execute: () => navigate("/lab") },
    // ... 14 more pages
  ]);
}

// src/lib/commands/policy-commands.ts
export function registerPolicyCommands() {
  commandRegistry.registerAll([
    { id: "policy.new", title: "New Policy", category: "Policy", keybinding: "Meta+N", execute: ... },
    { id: "policy.save", title: "Save", category: "File", keybinding: "Meta+S", execute: ... },
    { id: "policy.validate", title: "Validate Current File", category: "Policy", keybinding: "Meta+Shift+V", execute: ... },
    { id: "policy.export", title: "Export YAML", category: "File", keybinding: "Meta+E", execute: ... },
    { id: "policy.copy-source", title: "Copy Current Source", category: "Policy", keybinding: "Meta+Shift+Y", execute: ... },
    { id: "policy.switch-to-strict", title: "Switch to Strict Ruleset", category: "Policy", execute: ... },
    { id: "policy.switch-to-permissive", title: "Switch to Permissive Ruleset", category: "Policy", execute: ... },
  ]);
}

// src/lib/commands/guard-commands.ts
export function registerGuardCommands() {
  commandRegistry.registerAll([
    { id: "guard.toggle.forbidden-path", title: "Toggle: Forbidden Path Guard", category: "Guard", execute: ... },
    { id: "guard.toggle.egress-allowlist", title: "Toggle: Egress Allowlist Guard", category: "Guard", execute: ... },
    { id: "guard.toggle.secret-leak", title: "Toggle: Secret Leak Guard", category: "Guard", execute: ... },
    // ... all 13 guards
  ]);
}

// src/lib/commands/fleet-commands.ts
// src/lib/commands/test-commands.ts
// src/lib/commands/sentinel-commands.ts
// src/lib/commands/receipt-commands.ts
// src/lib/commands/view-commands.ts
```

**Target: 50+ commands** across all categories.

### Fuzzy Search

Replace `.includes()` with a proper fuzzy matcher. Options:
- `fzf-for-js` (small, fast)
- Custom subsequence matcher with scoring (Athas approach)
- Simple: split query into words, match all words against title+category

### Updated Command Palette

The palette reads from `commandRegistry.search(query)` instead of a static array.
Add recent-command tracking (persist last 10 executed commands, show at top).

### Updated Shortcut Provider

The shortcut provider reads keybindings from `commandRegistry.getAll().filter(c => c.keybinding)`
instead of a separate hardcoded array. Single source of truth.

---

## Deliverables Checklist

- [ ] `src/lib/create-selectors.ts` — ported from Athas
- [ ] `zustand` + `immer` added to `package.json`
- [ ] 5 domain stores converted (sentinel, finding, signal, intel, mission)
- [ ] 5 providers removed from `AppProviders` in `App.tsx`
- [ ] Backward-compat hooks exported for each converted store
- [ ] `src/lib/command-registry.ts` — singleton registry
- [ ] `src/lib/commands/*.ts` — 50+ domain commands registered
- [ ] `command-palette.tsx` — reads from registry, fuzzy search
- [ ] `shortcut-provider.tsx` — reads keybindings from registry
- [ ] All existing tests pass
