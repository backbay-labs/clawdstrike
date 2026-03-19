---
phase: 03-full-immersive-panes-observatory-forensics
plan: "04"
subsystem: forensics + bottom-pane
tags: [forensics, bottom-pane, css-only, timeline, mock-data, FRNX-01]
dependency_graph:
  requires: []
  provides: [FRNX-01]
  affects: [bottom-pane-store, bottom-pane, forensics-feature]
tech_stack:
  added: []
  patterns:
    - CSS-only horizontal scroll timeline with overscroll-x-contain (WebKit pitfall 6)
    - TDD RED→GREEN: test scaffold before implementation
    - Bottom pane tab registration pattern (mirrors Audit tab)
key_files:
  created:
    - apps/workbench/src/features/forensics/__tests__/forensics-tape-panel.test.tsx
    - apps/workbench/src/features/forensics/types.ts
    - apps/workbench/src/features/forensics/components/ForensicsTapePanel.tsx
  modified:
    - apps/workbench/src/features/bottom-pane/bottom-pane-store.ts
    - apps/workbench/src/features/bottom-pane/bottom-pane.tsx
decisions:
  - "ForensicsTapePanel CSS-only with 4 mock events — glia-three deferred pending audit"
  - "TapeEventCard uses role=article for testability"
  - "IconTimeline from @tabler/icons-react for Tape button (confirmed available)"
  - "BottomPaneTab union extended to 5 members: terminal|problems|output|audit|tape"
metrics:
  duration_seconds: 174
  completed_date: "2026-03-18"
  tasks_completed: 2
  tasks_total: 2
  files_created: 3
  files_modified: 2
---

# Phase 03 Plan 04: Forensics Tape Panel + Bottom Pane Tab Registration Summary

**One-liner:** CSS-only horizontal forensics event timeline registered as "Tape" tab in bottom pane alongside Terminal/Problems/Output/Audit, with 4 mock events (allow/deny/probe/receipt), overscroll protection, and deferred telemetry notice.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Wave 0 test scaffold + TapeEvent type + ForensicsTapePanel CSS component | 70dd924cf | forensics/types.ts, forensics/components/ForensicsTapePanel.tsx, forensics/__tests__/forensics-tape-panel.test.tsx |
| 2 | Extend BottomPaneTab union + add Tape button + render case in bottom-pane.tsx | e1efc3347 | bottom-pane-store.ts, bottom-pane.tsx |

## What Was Built

### TapeEvent Type (`forensics/types.ts`)
- `TapeEventKind = "allow" | "deny" | "probe" | "receipt"` union
- `TapeEvent` interface: `{ id, timestamp, kind, label, stationId? }`

### ForensicsTapePanel (`forensics/components/ForensicsTapePanel.tsx`)
- CSS-only horizontal scrollable event timeline — no R3F, no glia-three dependency
- `MOCK_EVENTS` array: 4 entries (allow: file_read, deny: shell_exec, receipt: Ed25519, probe: station:run)
- `KIND_COLOR` map: allow=#3dbf84, deny=#c45c5c, probe=#7b68ee, receipt=#d4a84b
- `TapeEventCard` subcomponent with `role="article"` for test accessibility
- `overscroll-x-contain` on timeline row — prevents WebKit rubber-band bounce (pitfall 6)
- Footer: "forensics tape — mock data — live telemetry deferred"

### Bottom Pane Integration
- `BottomPaneTab` extended: `"terminal" | "problems" | "output" | "audit" | "tape"`
- `IconTimeline` (tabler) used for Tape button — confirmed available in installed version
- Tape button follows identical CSS pattern to Audit button
- Render chain: `activeTab === "tape" ? <ForensicsTapePanel /> :` before `<OutputPanel />`

## Test Results

- 5/5 forensics-tape-panel tests GREEN
- Full suite: my changes introduced zero new failures (35 pre-existing failures in App.test.tsx, fleet-client, intel-detail-page, observatory, crash-recovery-banner — all pre-existing from earlier phases, out of scope per deviation scope boundary rule)

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

All files verified present. All commits verified in git log.

| Check | Result |
|-------|--------|
| forensics/types.ts | FOUND |
| forensics/components/ForensicsTapePanel.tsx | FOUND |
| forensics/__tests__/forensics-tape-panel.test.tsx | FOUND |
| Commit 70dd924cf | FOUND |
| Commit e1efc3347 | FOUND |
