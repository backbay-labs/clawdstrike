# Huntronomer Workbench Redesign -- Master Index

**Status:** Complete (all 4 phases implemented and validated)
**Target:** Huntronomer Desktop (`apps/desktop`)
**Date:** 2026-03-07

---

## Executive Summary

### Current State

Huntronomer's desktop UI is a **plugin-based page router**. Thirteen `AppPlugin` entries in `src/shell/plugins/registry.tsx` map to full-page routes via `react-router-dom`'s `createHashRouter` (`src/shell/ShellApp.tsx:29-49`). Navigating between features unmounts the previous view and mounts the next. The layout (`src/shell/ShellLayout.tsx`) consists of a 220px `NavRail` sidebar, a React Router `<Outlet />` for content, and a floating `DockSystem` with capsules and shelf panels.

Key limitations:
- **No persistence across views.** Navigating away from a hunt, event stream, or workspace unmounts the component. State must be manually restored on return.
- **Single-object focus.** Only one feature is visible at a time. No split views, no side-by-side comparison.
- **Disconnected panels.** The dock system (capsules, shelf) is a floating overlay layer divorced from the content area. Terminal, events, and artifacts live in separate floating windows.
- **Rigid navigation.** The 220px NavRail is hardcoded to strikecell sessions. No sidebar customization per context.

### Vision

Transform Huntronomer into a persistent **IDE-like workbench** using a four-level hierarchy:

```
Shell -> Lens -> Tab -> Selection
```

- **Shell** (Wire/Hunt/Lab/Case): Layout presets that configure panel defaults and split arrangements without closing tabs.
- **Lens** (Scopes/History/Files/Sandboxes/Entities/Swarms/Notes): Sidebar content modes that change what the left panel shows without affecting tabs.
- **Tab**: Every meaningful object (hunt, receipt, case, artifact, policy, etc.) opens as a persistent tab that survives navigation.
- **Selection**: The selected item within a tab drives the right inspector pane and bottom panel context.

All 13 existing plugins become **tab content providers** instead of route destinations. The router is removed. Navigation becomes tab management.

---

## Document Inventory

| # | Document | Path | Content |
|---|----------|------|---------|
| 01 | Architecture Spec | [`01-ARCHITECTURE.md`](./01-ARCHITECTURE.md) | Shell/Lens/Tab/Selection hierarchy. Full TypeScript state model (`WorkbenchState`, `ShellMode`, `LensId`, `WorkbenchTab`, `SplitPane`, `SelectionContext`, `BottomPanelState`, `ContextInspectorState`). Component tree. Data flow diagrams for shell changes, lens changes, tab lifecycle, and selection propagation. Plugin-to-tab-content-provider mapping. Keyboard model. Context provider structure. |
| 02 | Interaction Design | [`02-INTERACTION-DESIGN.md`](./02-INTERACTION-DESIGN.md) | Orb lens rotor behavior (click/hold/right-click grammar). Tab interaction grammar (preview vs. pin, single/double/Cmd+click, drag-to-split). Split pane model (max 2x2, per-shell defaults). Bottom panel behavior (collapse, resize, per-shell memory). Right inspector pane (Context/Graph/Proof/Companion tabs). Activity Spine layout. Lens sidebar content definitions for all 7 lenses. Visual hierarchy guidelines (gold usage, glow rules, density model). Status bar segments. Full keyboard shortcut map. Accessibility spec (ARIA labels, focus order, reduced motion). Design token reference. |
| 03 | Component & Layout | [`03-COMPONENT-LAYOUT.md`](./03-COMPONENT-LAYOUT.md) | CSS Grid definition for the workbench shell. ASCII layouts per shell mode (Wire, Hunt, Lab, Case). Full component inventory (20 new components, 9 refactored, 8 deprecated). TypeScript interfaces for all major components (`WorkbenchShell`, `ActivitySpine`, `OrbLensRotor`, `LensSidebar`, `TabBar`, `SplitPaneContainer`, `ContextInspector`, `BottomPanel`, `StatusBar`). CSS token additions (30+ new custom properties). Z-index layering map. Responsive behavior (breakpoints, resizable panel constraints, collapse transitions). Shell-to-lens mapping table. Post-migration file tree. |
| 04 | Migration Plan | [`04-MIGRATION-PLAN.md`](./04-MIGRATION-PLAN.md) | Four-phase migration plan. Phase 1: Shell + Lens foundation (ActivitySpine, OrbLensRotor, LensSidebar, feature flag). Phase 2: Tab workbench (TabBar, TabContentRenderer, SplitPaneContainer, route-to-tab redirect, workspace tab unification, zero-tab empty state, tab overflow, dirty tab close). Phase 3: Panel system (BottomPanel, 6 panel tabs, DockSystem removal, capsule migration map). Phase 4: Right context pane (ContextInspector, selection flow, 4 inspector tabs). Risk assessment matrix. Backward compatibility guarantees. Phase dependency graph. Per-phase checklists. |
| 05 | Critic Review | [`05-CRITIC-REVIEW.md`](./05-CRITIC-REVIEW.md) | Cross-spec review: 3 P0 issues (lens naming divergence, zero-tab state, tab overflow), 11 P1 issues, 11 P2 issues. Categories: cross-spec inconsistencies, technical accuracy, UX concerns, missing edge cases, keyboard conflicts, feasibility, visual hierarchy, consistency. All P0 and most P1 issues resolved in post-review polish pass. |
| -- | This Index | [`INDEX.md`](./INDEX.md) | Master index, executive summary, design principles, glossary, decision log. |
| P1 | Phase 1 Validation | [`PHASE1-VALIDATION.md`](./PHASE1-VALIDATION.md) | Phase 1 validation report: Shell + Lens foundation (ActivitySpine, OrbLensRotor, LensSidebar, WorkbenchShell grid, WorkbenchStateProvider). |
| P2H | Phase 2 Handoff | [`PHASE2-HANDOFF.md`](./PHASE2-HANDOFF.md) | Phase 2 handoff spec: Tab workbench deliverables, file inventory, integration points, recommended team structure. |
| P2V | Phase 2 Validation | [`PHASE2-VALIDATION.md`](./PHASE2-VALIDATION.md) | Phase 2 validation report: 68/68 spec items passed, 2 critical fixes applied, 5 warnings documented (W1-W5). |
| P3H | Phase 3 Handoff | [`PHASE3-HANDOFF.md`](./PHASE3-HANDOFF.md) | Phase 3 handoff spec: Bottom panel + DockSystem removal scope, integration points, known issues, team structure. |
| P3V | Phase 3 Validation | [`PHASE3-VALIDATION.md`](./PHASE3-VALIDATION.md) | Phase 3 validation report: 82/82 spec items passed, W1+W2 fixes applied, DockSystem removed, bottom panel + inspector integrated. |
| P4V | Phase 4 Validation | [`PHASE4-VALIDATION.md`](./PHASE4-VALIDATION.md) | Phase 4 validation report: 82/82 spec items passed. Inspector content tabs (ContextTab, GraphTab, ProofTab, CompanionTab) + SelectionState model. All 4 phases complete. |
| E2E | E2E Review | [`E2E-REVIEW.md`](./E2E-REVIEW.md) | End-to-end review and dogfooding: 5 parallel audits (structural, state, UX, a11y, integration). 4 state bugs found and fixed. 8 accessibility items documented. Ship-ready. |

---

## Design Principles

These principles are extracted from the architecture and interaction specs and govern all implementation decisions.

### 1. Everything opens in place first, becomes a workspace when the user decides

Objects open as preview tabs (italic, ephemeral) on single-click. The user promotes to a pinned tab by double-clicking, editing, or explicitly pinning. Nothing forces a full-page transition or a heavyweight commitment. The workbench earns screen real estate incrementally based on user intent, not upfront.

### 2. Preview first, pin later, split when needed, preserve context always

The tab lifecycle is a deliberate escalation: preview (casual glance) -> pin (active work) -> split (side-by-side comparison). At every stage, context is preserved. Switching shells reconfigures panel defaults and split layouts but **never** closes tabs, destroys component state, or resets selections. Per-shell memory restores the exact configuration the user had last time.

### 3. One persistent shell, not a set of pages

The workbench is a single persistent surface. There are no page navigations, no route-driven unmount/remount cycles. The 13 current plugins become tab content providers rendered directly by the `SplitPaneContainer`, not router destinations. Switching between a hunt, a policy, and a terminal means switching tabs -- the underlying components stay mounted.

### 4. The orb has a real job (lens rotor)

The `CyberNexusOrb` transforms from a decorative mode cycler into the primary lens control. Click toggles between current and previous lens (like Alt+Tab); long-press opens the lens picker. This is the highest-traffic interaction point in the UI and it now controls the most frequent action: changing what the sidebar shows. Operation mode (posture) moves to a secondary indicator in the Activity Spine footer and Status Bar.

### 5. Dense operator-native feel, not card wall

The default visual density is a terminal wire -- dense rows (26-32px), compact monospace text, minimal padding. Cards are the exception, used only when an item is the primary focus of a view or needs expanded detail. The gold accent (`#d5ad57`) is reserved exclusively for active/focused/live states: active tab border, focused pane indicator, live connection, orb ring. Static elements never glow. Overuse dilutes signal value.

### 6. AI is embedded context, not chatbot takeover

The Companion tab in the Context Inspector provides grounded, contextual suggestions -- summarize, pivot, propose hunt, flag contradictions. Each suggestion is a discrete card with an "Apply" button, not a conversation turn. The AI never takes over the screen or interrupts the analyst's flow. It occupies one tab in the right pane, co-equal with Context, Graph, and Proof.

---

## Glossary

| Term | Definition | Spec Reference |
|------|-----------|----------------|
| **Shell** | A named layout preset (Wire, Hunt, Lab, Case) that configures panel defaults, lens prominence, and split arrangements. Does not affect open tabs. | 01-ARCHITECTURE.md S2.1 |
| **Lens** | A sidebar content mode (Scopes, History, Files, Sandboxes, Entities, Swarms, Notes) that controls what the left `LensSidebar` displays. Changing lens does not affect tabs or panels. | 01-ARCHITECTURE.md S2.2 |
| **Tab** | A persistent container for an open object (hunt, receipt, file, case, etc.) in the center `TabWorkbench`. Supports preview (ephemeral) and pinned (persistent) modes. | 01-ARCHITECTURE.md S2.3 |
| **Selection** | The currently focused item within the active tab. Drives the `ContextInspector` right pane and contextual bottom panel content. | 01-ARCHITECTURE.md S2.4 |
| **Activity Spine** | The thin 48px icon column on the far left. Contains the `OrbLensRotor`, shell switcher icons, and status indicators. Replaces the 220px `NavRail`. | 02-INTERACTION-DESIGN.md S6, 03-COMPONENT-LAYOUT.md S3.1 |
| **Orb Lens Rotor** | The repurposed `CyberNexusOrb`. Click toggles between current and previous lens (like Alt+Tab); long-press opens the lens picker menu (280px radial). Replaces the operation mode cycler. | 02-INTERACTION-DESIGN.md S1 |
| **Lens Sidebar** | The 240px collapsible panel between the Activity Spine and the center content area. Content is driven by the active lens. | 02-INTERACTION-DESIGN.md S7, 03-COMPONENT-LAYOUT.md S4.4 |
| **Tab Workbench** | The center area containing the tab bar and split pane container. Where content is displayed and worked on. | 01-ARCHITECTURE.md S4, 03-COMPONENT-LAYOUT.md S1 |
| **Context Inspector** | The 320px collapsible right pane with four tabs (Context, Graph, Proof, Companion). Content is driven by the active tab's selection. | 02-INTERACTION-DESIGN.md S5, 04-MIGRATION-PLAN.md Phase 4 |
| **Bottom Panel** | The collapsible panel at the bottom of the center area with six tabs (Tape, Terminal, Receipts, Tasks, Replay, Diff). Replaces the `DockSystem` shelf. | 02-INTERACTION-DESIGN.md S4, 04-MIGRATION-PLAN.md Phase 3 |
| **Status Bar** | The 24px strip at the absolute bottom of the window. Shows shell mode, connection status, posture, session count, and contextual info. | 02-INTERACTION-DESIGN.md S9, 03-COMPONENT-LAYOUT.md S4.9 |
| **Tab Content Provider** | A React component registered in `TAB_CONTENT_PROVIDERS` that renders the content for a specific `TabKind`. Replaces plugin routes. Each of the 13 current plugins becomes a tab content provider. | 01-ARCHITECTURE.md S5.5, 04-MIGRATION-PLAN.md Phase 2 |
| **Preview Tab** | A tab opened via single-click. Displayed with italic title. Replaced by the next preview action. Only one preview tab exists per split pane at a time. | 02-INTERACTION-DESIGN.md S2 |
| **Pinned Tab** | A tab promoted from preview (double-click, edit, or explicit pin action). Displays with normal title weight. Persists until explicitly closed. | 02-INTERACTION-DESIGN.md S2 |
| **Split Pane** | A division of the center content area into multiple side-by-side panes. Each pane has its own tab bar. Maximum 2x2 grid. | 02-INTERACTION-DESIGN.md S3, 03-COMPONENT-LAYOUT.md S4.6 |
| **Posture** | The NexusOperationMode (observe/trace/contain/execute). Orthogonal to shells -- it applies as an operational overlay, not a navigation mode. Shown in the Status Bar and Activity Spine footer. | 01-ARCHITECTURE.md S2.1 |
| **Capsule** | A floating overlay window from the current `DockSystem`. Capsules are eliminated in the redesign; their content moves to bottom panel tabs, the context inspector, or workbench tabs. | 04-MIGRATION-PLAN.md Phase 3 |

---

## Decision Log

Decisions made during the design process. New entries should be appended at the bottom.

| # | Date | Decision | Rationale | Spec |
|---|------|----------|-----------|------|
| D1 | 2026-03-07 | Four shells (Wire/Hunt/Lab/Case) instead of free-form layouts | Constrained presets are easier to learn and optimize. Analysts typically work in one of four modes. Free-form layouts lead to configuration paralysis. | 01 S2.1 |
| D2 | 2026-03-07 | Orb cycles lenses, not operation modes | The orb is the highest-traffic interaction target. Lens cycling (sidebar content) is more frequent than posture changes. Posture moves to a secondary indicator. | 01 S7.5, 02 S1 |
| D3 | 2026-03-07 | Capsules eliminated in favor of bottom panel tabs | Floating windows are hard to manage, overlap content, and have inconsistent z-ordering. A persistent bottom panel with named tabs is more predictable. | 04 Phase 3 |
| D4 | 2026-03-07 | Route-to-tab redirect for backward compatibility | Old hash routes (`/#/nexus`, `/#/workspace/search`) must keep working. The workbench intercepts route changes and opens corresponding tabs, then clears the URL. | 04 Phase 2 |
| D5 | 2026-03-07 | Feature-flag gated migration (`huntronomer:workbench:v2`) | The redesign is too large to ship as a single atomic change. The flag allows gradual rollout and instant rollback. Old `ShellLayout` is preserved as fallback. | 04 Backward Compatibility |
| D6 | 2026-03-07 | Workspace internal tabs (`WorkspaceTabFrame`) retired in favor of workbench tabs | Having two tab systems creates state conflicts and confusing UX. The workbench tab model subsumes workspace file tabs. | 01 S8.3, 04 Phase 2 |
| D7 | 2026-03-07 | Maximum 2x2 split (4 panes) | More than 4 panes makes each pane too small to be useful on typical displays. The constraint simplifies the split pane implementation. | 02 S3 |
| D8 | 2026-03-07 | Gold accent is reserved for active/focused/live states only | Consistent with the existing design language. Prevents the "everything is gold" problem that dilutes visual hierarchy. | 02 S8 |
| D9 | 2026-03-07 | Lens sidebar default width is 240px (not 260px) | CSS token `--lens-sidebar-width: 240px` in 03 is canonical. Min 180px, max 400px. Aligned across all specs. | 03 S5, 05 A3 |
| D10 | 2026-03-07 | Bottom panel default height is 180px (not 220px or 240px) | CSS token `--bottom-panel-height: 180px` in 03 is canonical. Matches existing `WorkspaceShellScreen` grid row. | 03 S5, 05 A4 |
| D11 | 2026-03-07 | Activity Spine shows shell mode icons, not lens icons | Orb handles lens cycling exclusively. Spine shows shell mode icons (Wire/Hunt/Lab/Case). Lens icons in spine would duplicate the orb's function. | 02 S6, 05 A5 |
| D12 | 2026-03-07 | Inspector toggle shortcut is `Cmd+\` (not `Cmd+Shift+I`) | `Cmd+\` is consistent with VS Code panel toggle patterns and avoids browser devtools conflict. | 02 S10, 05 A6 |
| D13 | 2026-03-07 | `Cmd+N` creates new tab; `Cmd+Shift+N` creates new strikecell session | Tab creation is the most common operation in the workbench and deserves the simpler shortcut. Session creation is heavyweight and less frequent, so it moves to the shifted variant. | 01 S6.5, 02 S10, 05 E2 |
| D14 | 2026-03-07 | SOCBackground disabled entirely in workbench v2 mode | Multiple tab kinds can be simultaneously mounted in split panes. The ambient 3D WebGL scene is both invisible behind content and wasteful of GPU resources. | 01 S7.1, 05 F1 |
| D15 | 2026-03-07 | 3D-heavy tab kinds excluded from keep-alive pool | `threat-radar`, `attack-graph`, `network-map`, `profile` tab kinds set `keepAlive: false` in the tab registry to avoid GPU/memory pressure when offscreen. | 04 Phase 2, 05 F2 |
| D16 | 2026-03-07 | Zero-tab state shows shell-appropriate welcome content | Each shell has a tailored empty state with quick-start actions. The `welcome` tab kind auto-dismisses when any real tab opens. | 04 Phase 2, 05 D1 |
| D17 | 2026-03-07 | Tab overflow: horizontal scroll + dropdown for all-tabs list | Scroll buttons appear at tab bar edges on overflow. Chevron dropdown at right shows full tab list. Soft limit of 30 tabs with warning at 25. | 04 Phase 2, 05 D2 |
| D18 | 2026-03-07 | Dirty tab close always shows Save/Don't Save/Cancel dialog | No close action bypasses the confirmation for dirty tabs, including middle-click and "Close All". Generalizes the existing `shouldBlockDirtyPolicyDraftExit` pattern. | 04 Phase 2, 05 D5 |
| D19 | 2026-03-07 | All 7 lenses available in every shell; shells set prominence order | Restricting lenses per shell would confuse users who switch contexts frequently. Instead, shells define which lenses are prominent (listed first in orb cycle) and which is the default. | 01 S2.1, 03 S8, 05 A1 |
| D20 | 2026-03-07 | Orb single-click toggles current/previous lens (not cycle-all-7) | Cycling through 7 lenses on click is tedious (up to 6 clicks) and error-prone. Toggle-between-two mirrors Alt+Tab muscle memory. Full set reachable via long-press, right-click, or Cmd+1-7. | 02 S1, 05 C2 |
| D21 | 2026-03-07 | Radial lens menu diameter increased to 280px for 7 items | At 200px diameter, 7 items at 51.4deg spacing overlap. 280px with 116px translate radius provides ~102px center-to-center distance for comfortable targeting. | 02 S1, 05 C1 |
| D22 | 2026-03-07 | Sidebar toggle shortcut is `Cmd+Shift+B` (not `Cmd+B`) | `Cmd+B` conflicts with bold text in any text editing context. `Cmd+Shift+B` avoids the conflict entirely, consistent with VS Code. | 02 S10, 05 E1 |
| D23 | 2026-03-07 | Status bar shows both operation mode and enforcement posture | `NexusOperationMode` (observe/trace/contain/execute) is the analyst's stance; enforcement posture (permissive/default/strict) is the daemon's security level. They are distinct and both shown. | 02 S9, 05 H3 |

---

## Open Questions

Tracked from the architecture spec (01 S10) and migration plan. These require resolution before implementation begins.

| # | Question | Context | Status |
|---|----------|---------|--------|
| Q1 | Should a minimal `react-router-dom` router be retained for deep-link URLs, or go fully state-driven with `history.pushState`? | 01 S10.1 | Open |
| Q2 | Should there be a maximum number of open tabs with LRU eviction of unpinned tabs? | 01 S10.2 -- 04 Phase 2 defines soft limit of 30 tabs with warning at 25 | Resolved: D17 |
| Q3 | Should workspace file tabs be top-level `WorkbenchTab` entries or managed internally within a single workbench tab? | 01 S10.3 -- 04 Phase 2 resolves toward top-level tabs | Resolved: D6 (top-level) |
| Q4 | Should floating capsules (e.g., chat) be promotable to workbench tabs? | 01 S10.4 -- Capsules eliminated (D3), chat opens as tab directly | Resolved: D3 |
| Q5 | Should tab content state (scroll position, form values) persist across restarts, or only tab identity? | 01 S10.5 -- 01 S8 defines: only tab identity + contentProps persist; transient state does not | Resolved: 01 S8 |
| Q6 | Which of the 7 lenses is available in each shell? | All 7 lenses available in every shell. Shells define prominent lenses (listed first in orb cycle) and a default lens. See 03 S8 for prominence order. | Resolved: D19, 03 S8 |

---

## Revision History

| Date | Revision | Changes |
|------|----------|---------|
| 2026-03-07 | Initial draft | All 5 spec documents (01-04 + INDEX) authored. |
| 2026-03-07 | Critic review | 05-CRITIC-REVIEW.md authored. 3 P0, 11 P1, 11 P2 issues identified. |
| 2026-03-07 | Post-review polish | Applied all P0 and P1 fixes across all specs. Key changes: unified lens naming to canonical 7-lens set (A1), unified TabKind across all specs (A2), standardized sidebar width to 240px (A3), bottom panel height to 180px (A4), resolved ActivitySpine content to shell-mode-icons model (A5), unified inspector toggle to `Cmd+\` (A6), added zero-tab empty state (D1), added tab overflow behavior (D2), added dirty tab close confirmation (D5), changed orb click to toggle-between-two instead of cycle-all-7 (C2), increased radial menu to 280px for 7 items (C1), changed sidebar toggle to `Cmd+Shift+B` (E1), changed `Cmd+N` to new-tab / `Cmd+Shift+N` to new-session (E2), clarified operation mode vs enforcement posture in status bar (H3), all lenses available in all shells with per-shell prominence (A1/Q6), SOCBackground disabled in workbench mode (F1), 3D-heavy tabs excluded from keep-alive pool (F2). Added decisions D9-D23 to decision log. Resolved open questions Q2-Q6. |

---

## File Map

All files in this spec directory:

```
docs/plans/workbench-redesign/
  INDEX.md                  -- This document (master index)
  01-ARCHITECTURE.md        -- Core architecture: hierarchy, state model, data flow
  02-INTERACTION-DESIGN.md  -- UX: gestures, keyboard, accessibility, visual design
  03-COMPONENT-LAYOUT.md    -- Implementation: CSS grid, components, tokens, z-index
  04-MIGRATION-PLAN.md      -- Phased migration: 4 phases, risks, checklists
  05-CRITIC-REVIEW.md       -- Cross-spec review: inconsistencies, accuracy, UX, edge cases
  PHASE1-VALIDATION.md      -- Phase 1 validation report
  PHASE2-HANDOFF.md         -- Phase 2 handoff spec
  PHASE2-VALIDATION.md      -- Phase 2 validation report
  PHASE3-HANDOFF.md         -- Phase 3 handoff spec
  PHASE3-VALIDATION.md      -- Phase 3 validation report
  PHASE4-VALIDATION.md      -- Phase 4 validation report (final)
  E2E-REVIEW.md             -- End-to-end review and dogfooding report
```
