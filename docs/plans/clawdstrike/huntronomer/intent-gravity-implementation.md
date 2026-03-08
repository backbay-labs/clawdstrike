# Intent Gravity Implementation

> **Status:** Active | **Date:** 2026-03-07
> **Audience:** Desktop, product, interaction, and swarm implementers
> **Scope:** Turn the `apps/desktop/src/shell/workbench/anticipation/**` layer from a set of
> disconnected hooks into a shared predictive interaction system for the Huntronomer workbench

## Why This Exists

The workbench already has the right ambition: a predictive operator shell that feels like it is
reading the room without taking destructive action on the operator's behalf. The failure mode was
not lack of ideas. The failure mode was fragmentation:

- several anticipation hooks computed useful state
- the provider wrapped the tree
- most consumers still ignored the provider and read ad hoc hooks directly
- the staging shelf existed visually but had no durable state owner or drop path
- semantic drop zones existed as a reusable component but were bypassed by inline UI

This document defines the implementation spine for fixing that.

## Current Code Spine

The active implementation lives in these surfaces:

- `apps/desktop/src/shell/workbench/anticipation/useAnticipation.ts`
- `apps/desktop/src/shell/workbench/anticipation/AnticipationProvider.tsx`
- `apps/desktop/src/shell/workbench/LensSidebar.tsx`
- `apps/desktop/src/shell/workbench/DragDropContext.tsx`
- `apps/desktop/src/shell/workbench/WorkbenchShell.tsx`
- `apps/desktop/src/shell/workbench/anticipation/useStagingShelf.ts`
- `apps/desktop/src/shell/workbench/anticipation/StagingShelf.tsx`
- `apps/desktop/src/shell/workbench/anticipation/SmartBucketHeader.tsx`

## Implemented In This Slice

This implementation slice now establishes the shared state and execution contract for the sidebar
and its adjacent surfaces:

1. `useAnticipation()` is the fused source for phase, confidence, predictive drop labeling,
   adaptive lens hints, open-mode prediction, compatible targets, spring-loading state, and
   staging summaries.
2. `useSidebarDirector()` now drives all seven lenses, not only `EntitiesLens`, and emits
   `adjacentSurfacePromotion` so the sidebar, bottom panel, and inspector react from the same
   intent model.
3. `LensSidebar` now spring-opens from the collapsed rail, spring-loads likely lenses, routes
   predictive file opens, and renders registry-driven directives for `Entities`, `Notes`, `Files`,
   `Scopes`, `History`, `Sandboxes`, and `Swarms`.
4. `FilesLens`, `NotesLens`, `EntitiesLens`, `ScopesLens`, `HistoryLens`, `SandboxesLens`, and
   `SwarmsLens` all now speak the same section-registry contract: stable section IDs, promoted
   reason text, hide/reorder support, and director-driven expansion.
5. `DragDropContext` now stages items, carries semantic selection during drag, and executes
   role-aware hunt/run/case attachment metadata instead of only generic add/move behavior.
6. `SmartBucketHeader` and `SemanticDropZone` now preview semantic intent while hovering the
   sidebar bucket, so the operator can steer the drop before release instead of after the fact.
7. `BottomPanel` and `ContextInspector` now respond to adjacent-surface promotion with tab
   emphasis, optional auto-open, and inline explanation text.
8. Predictive `OPEN_TAB` behavior is now exercised through `openMode` routing, including compare
   and new-tab flows, with focused reducer tests.

## Remaining Delivery Order

The next slices should be implemented in this order:

1. Cursor-proximity anticipation outside direct sidebar hover.
   Reason: the collapsed rail now wakes on hover, but true "before I thought of it" behavior still
   needs approach-based prewarm instead of only direct hit-target interaction.
2. Semantic drop affordances beyond the sidebar bucket.
   Reason: the sidebar bucket now executes semantics, but Hunt Dock pills and other compatible
   targets should expose the same preview-and-commit grammar.
3. Predictive open behavior for non-file objects.
   Reason: file opens now carry predicted modes, but hunts, receipts, and notes should all route
   through the same open-mode contract and comparison heuristics.
4. Dogfood-driven choreography polish.
   Reason: timings, retract rules, and confidence thresholds are now implemented end-to-end and
   should be tuned from real operator use, not only from static heuristics.

## Guardrails

The system should keep these rules:

- low confidence: highlight and explain only
- medium confidence: promote one likely action and one likely lens
- high confidence: permit spring-loaded lens switching and deeper semantic reveal
- never perform destructive actions automatically
- every prediction must have a visible explanation string close to the affordance it changes

## Verification Gate

For this slice, the verification gate is:

- `npm --prefix apps/desktop run typecheck`
- `npm --prefix apps/desktop test`
- `npm --prefix apps/desktop run build`
