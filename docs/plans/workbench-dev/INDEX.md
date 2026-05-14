# Workbench Development Roadmap

> Inspired by [Athas](../../../standalone/athas) — a Tauri 2 + React 19 desktop code editor
> with battle-tested UX infrastructure patterns we want to adopt surgically.

**Branch:** `feat/workbench-dev`
**Created:** 2026-03-17
**Status:** Planning

---

## Executive Summary

Athas is a general-purpose code editor that has solved many desktop-app-grade UX problems
(pane splitting, terminal sessions, keyboard-driven workflows, extension systems). ClawdStrike
Workbench is a domain-specific security IDE with rich security features (policy authoring,
threat simulation, compliance scoring, fleet management, swarm orchestration, receipt
verification) but uses older architectural patterns for state management and has less mature
general-editor UX.

**Strategy:** Adopt Athas's UX infrastructure patterns without importing its general-editor
concerns. The workbench is not a code editor — it's a security operations center.

---

## Current State (Workbench)

| Metric | Value |
|--------|-------|
| Provider nesting depth | **15** Context providers in `AppProviders` (18 total wrapper levels incl. HashRouter, ErrorBoundary, Suspense) |
| Largest store | `multi-policy-store.tsx` (1846 lines, Context+useReducer) |
| Files in `lib/workbench/` | **106** (flat, no feature grouping) |
| Command palette items | **17** in desktop palette (`desktop/command-palette.tsx`), **14** static + 1 conditional in editor palette (`editor/command-palette.tsx`); both use `.includes()` search |
| Keyboard shortcuts | **19** definitions / **20** runtime bindings (flat array, no registry, no customization) |
| Pane system | **None** (simple SplitMode for policy editor only) |
| Terminal panel | **None** (PTY exists in SwarmBoard nodes only) |
| State management | React Context + useReducer (all stores, zero Zustand) |
| Lazy loading | Yes (20 pages via `React.lazy`) |

## What We're Adopting from Athas

| Pattern | Athas Source | Priority |
|---------|-------------|----------|
| Zustand + `createSelectors` | `src/utils/zustand-selectors.ts` (15 lines) | P0 |
| Command registry | `src/features/command-palette/` + `src/features/keymaps/` | P0 |
| Binary tree pane system | `src/features/panes/stores/pane-store.ts` | P1 |
| Bottom pane (terminal/diagnostics) | `src/features/layout/components/main-layout.tsx` | P1 |
| Feature-based directory structure | `src/features/{name}/{stores,components,hooks,types}` | P1 |
| User-customizable keybindings | `src/features/keymaps/` | P2 |

## What We're NOT Adopting

| Skip | Reason |
|------|--------|
| Tree-sitter code editor | CodeMirror + schema-aware completions is correct for YAML/Sigma/YARA |
| Vim emulation | Not needed for security policy editing |
| Full file system abstraction | Workbench has its own DetectionProject tree |
| Database viewer | Irrelevant to security policy IDE |
| Full extension/plugin system | Overkill; MCP plugin is the right model |
| AI chat side panel | ClawdStrike is the security layer, not an agent |

---

## Phase Roadmap

### Phase A: Foundation (Week 1-2)
> Port `createSelectors`, convert thin stores, build command registry

- [Phase A Spec](./phase-a-foundation.md)

### Phase B: Core Store Decomposition (Week 3-4)
> Split `multi-policy-store.tsx`, convert remaining Context providers, flatten App.tsx

- [Phase B Spec](./phase-b-core-stores.md)

### Phase C: Layout Evolution (Week 5-6)
> Binary tree pane system, bottom terminal panel, enriched keyboard shortcuts

- [Phase C Spec](./phase-c-layout.md)

### Phase D: Directory Restructure (Week 7-8)
> Feature-based organization, move 106 files from flat lib/workbench/ to features/

- [Phase D Spec](./phase-d-restructure.md)

### Patterns Reference
> Exact code snippets and architectural patterns ported from Athas

- [Patterns Reference](./patterns-reference.md)

---

## Risk Register

| Risk | Severity | Mitigation |
|------|----------|------------|
| `multi-policy-store` decomposition breaks 30+ consumers | High | Comprehensive test coverage before Phase B; expose identical hook API from Zustand stores |
| Pane system conflicts with react-router-dom | Medium | Panes render routed views; keep routes as primary nav, panes as secondary |
| Feature-dir rename breaks imports across codebase | Medium | Barrel re-exports in Phase D; batch rename with TSC verification |
| Two separate command palettes (desktop + editor) need unification | Medium | Merge into single registry in Phase A; editor palette becomes a filtered view of the global registry |
| 20 lazy-loaded routes need pane-awareness in Phase C | Medium | Audit each route's layout assumptions; add pane-safe wrappers before enabling split views |
| Zustand migration changes re-render behavior | Low | `createSelectors` + `fast-deep-equal` match or improve existing behavior |

---

## Success Criteria

- [ ] Zero custom Context providers in App.tsx (only framework wrappers: HashRouter, ErrorBoundary, Suspense)
- [ ] Single unified command palette with 50+ searchable domain commands (replaces current desktop + editor split)
- [ ] Policy editor + simulation result viewable side-by-side (pane split)
- [ ] Terminal panel accessible via Cmd+J from any page
- [ ] `lib/workbench/` directory has < 10 files (rest moved to `features/`)
- [ ] All existing tests pass after each phase
