---
phase: 31-rebuilt-panels
plan: "01"
subsystem: observatory-hud
tags: [react, glassmorphism, panels, hud, unit-tests]
dependency_graph:
  requires:
    - observatory-store (selectedStationId, stations, pressureLanes, probeState, mission, replay, likelyStationId)
    - observatory-command-actions (dispatchObservatoryProbeCommand)
    - observatory-ghost-memory (deriveObservatoryGhostMemories)
    - hud-constants (STATION_COLORS_HEX, HUD_LEFT_DRAWER_WIDTH)
  provides:
    - ExplainabilityDrawerPanel (PNL-01) — station info + pressure causes + anomalies + probe action
    - MissionDrawerPanel (PNL-02) — briefing + objectives with checkmarks + progress bar
    - ReplayDrawerPanel (PNL-03) — timeline scrubber + bookmarks + jump-to-spike + compare toggle
    - GhostMemoryDrawerPanel (PNL-04) — derived ghost traces with source badges
  affects:
    - ObservatoryLeftDrawer (will mount these panels in Phase 31-02+)
tech_stack:
  added: []
  patterns:
    - inline styles with CSS var tokens (--hud-text, --hud-text-muted, --hud-accent, --hud-radius)
    - useObservatoryStore.use.* selectors for React subscriptions
    - useObservatoryStore.getState().actions.* for imperative event handlers
    - useMemo for deriving ghost traces
    - data-testid attributes on root elements and interactive items
key_files:
  created:
    - apps/workbench/src/features/observatory/components/hud/panels/ExplainabilityDrawerPanel.tsx
    - apps/workbench/src/features/observatory/components/hud/panels/MissionDrawerPanel.tsx
    - apps/workbench/src/features/observatory/components/hud/panels/ReplayDrawerPanel.tsx
    - apps/workbench/src/features/observatory/components/hud/panels/GhostMemoryDrawerPanel.tsx
    - apps/workbench/src/features/observatory/__tests__/observatory-drawer-panels.test.tsx
  modified: []
decisions:
  - "ExplainabilityDrawerPanel shows 'Select a station to inspect' empty state (not panel-level guard) — panels are always mounted in drawer, empty state is panel responsibility"
  - "GhostMemoryDrawerPanel uses useObservatoryStore((s) => s.likelyStationId) direct selector instead of use.likelyStationId() — consistent with plan spec"
  - "ReplayDrawerPanel always renders (no null empty state) — replay state always exists in store; only bookmarks section has empty message"
  - "Score bars in ExplainabilityDrawerPanel use 48px fixed width track + absolute fill child — avoids flex width fighting with label flex:1"
metrics:
  duration: 3 minutes
  completed: "2026-03-21"
  tasks_completed: 2
  files_created: 5
  files_modified: 0
  tests_added: 18
---

# Phase 31 Plan 01: Rebuilt Analyst Drawer Panels Summary

Four production-quality glassmorphism panel components for the 360px left drawer, each backed by live observatory-store data and covered by 18 unit tests.

## What Was Built

### ExplainabilityDrawerPanel (PNL-01)
Station explainability panel with color-accented station header, pressure lanes ranked list with animated score bars, anomalies section filtered from station explanation causes, and a PROBE STATION action button (disabled when probe status is not "ready").

### MissionDrawerPanel (PNL-02)
Active mission panel with status badge (IN PROGRESS / COMPLETED), mission briefing text, objectives list with unicode checkmarks (\u2713 / \u25CB), and a progress bar reflecting completed/total ratio.

### ReplayDrawerPanel (PNL-03)
Replay control panel with HTML range input timeline scrubber (frame 0-1000), clickable bookmark list that jumps frame index, jump-to-spike button (conditionally enabled), and a compare toggle (ON/OFF) that drives `replay.enabled`.

### GhostMemoryDrawerPanel (PNL-04)
Ghost memory panel that derives `ObservatoryGhostTrace[]` via `deriveObservatoryGhostMemories()` using `useMemo`. Each trace renders a source kind badge (finding=blue / receipt=teal), headline, detail text, and formatted timestamp with optional author label.

## Test Coverage

18 tests across 4 describe blocks:
- ExplainabilityDrawerPanel: empty state, station name render, probe button, panel container
- MissionDrawerPanel: empty state, briefing text, objective count, panel container
- ReplayDrawerPanel: range input, compare toggle, empty bookmarks message, panel container, spike button, toggle state
- GhostMemoryDrawerPanel: empty state, panel container, heading text, trace count

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

All 5 files verified on disk. Both task commits found: `4fd5e054c` (Task 1), `9a36ac50d` (Task 2). 18 tests pass. Zero TypeScript errors.
