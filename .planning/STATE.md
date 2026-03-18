---
gsd_state_version: 1.0
milestone: v2.0
milestone_name: Huntronomer Integration
status: in-progress
stopped_at: Defining requirements
last_updated: "2026-03-18T20:00:00Z"
last_activity: 2026-03-18 -- Milestone v2.0 started
progress:
  total_phases: 0
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-18)

**Core value:** Security operators get an immersive IDE with spirit-driven 3D layers woven into IDE surfaces
**Current focus:** Defining requirements for v2.0 Huntronomer Integration

## Current Position

Phase: Not started (defining requirements)
Plan: —
Status: Defining requirements
Last activity: 2026-03-18 — Milestone v2.0 started

## Previous Milestone (v1.1 — IDE Completeness)

Completed: 2026-03-18 (phases 1-5 of 7; phases 6-7 handled by separate agent)
Phases: 5/7 | Plans: 9/9 | Requirements: 18/29
Summary: Added in-file search, global search, quick navigation, file tree mutations, tab overflow, terminal splits

## Previous Milestone (v1.0 — IDE Pivot)

Completed: 2026-03-18
Phases: 4/4 | Plans: 9/9 | Requirements: 45/45
Summary: Delivered IDE shell — activity bar, 7 sidebar panels, pane tab system, right sidebar, bottom panels, 80+ commands, lab decomposition

## Performance Metrics

**v1.0 Velocity:**
| Phase | Plan | Duration | Tasks | Files |
|-------|------|----------|-------|-------|
| Phase 01 P01 | 5min | 2 tasks | 7 files |
| Phase 01 P02 | 14min | 3 tasks | 5 files |
| Phase 02 P01 | 5min | 2 tasks | 6 files |
| Phase 02 P02 | 10min | 2 tasks | 5 files |
| Phase 02 P03 | 7min | 2 tasks | 7 files |
| Phase 03 P01 | 4min | 2 tasks | 8 files |
| Phase 03 P02 | 3min | 2 tasks | 3 files |
| Phase 04 P01 | 2min | 2 tasks | 2 files |
| Phase 04 P02 | 2min | 2 tasks | 2 files |

**v1.1 Velocity:**
| Phase | Plan | Duration | Tasks | Files |
|-------|------|----------|-------|-------|
| Phase 01 P01 | 2min | 2 tasks | 2 files |
| Phase 03 P02 | 2min | 2 tasks | 2 files |
| Phase 05 P02 | 2min | 1 tasks | 3 files |
| Phase 03 P01 | 3min | 2 tasks | 4 files |
| Phase 05 P02 | 2min | 1 tasks | 3 files |
| Phase 02 P01 | 5min | 2 tasks | 5 files |
| Phase 05 P01 | 5min | 2 tasks | 3 files |
| Phase 04 P01 | 6min | 2 tasks | 8 files |
| Phase 02 P02 | 3min | 2 tasks | 5 files |
| Phase 04 P02 | 3min | 2 tasks | 5 files |

## Accumulated Context

### Decisions

Key v1.0 decisions carried forward:
- SpeakeasyPanel uses `inline` prop for right sidebar rendering
- openApp searches all pane groups for route dedup
- navigate-commands uses Zustand getState() (no react-router dependency)
- Gold border removed from pane container (too prominent for IDE)
- Lab sub-apps independently routable at /swarm-board, /hunt, /simulator

v1.1 decisions:
- Module-level EditorView ref for command dispatch (simpler than React context)
- searchKeymap Mod-h handler extraction for replace mode (stable public API)
- search({ top: true }) for IDE-standard top-positioned search panel
- Split terminal uses [leftId, rightId] tuple (max 2 panes, simple model)
- BreadcrumbBar self-hides via internal null return (consumer needs no conditional)
- Folder breadcrumb click expands dir AND reveals Explorer sidebar via showPanel
- regex crate added as direct dep for search; 10K match cap; results grouped by file
- createDetectionFile composes saveDetectionFile with FILE_TYPE_REGISTRY defaultContent
- mutateTree helper uses immutable shallow-copy-on-write for Zustand state correctness

v2.0 decisions:
- Mini R3F canvas lives in right sidebar (already has resize handle)
- Observatory is a TAB/PANE not a panel (like VS Code Markdown Preview)
- deriveObservatoryWorld survives — powers both full tab and minimap
- Character controller is opt-in in observatory tab flow mode

### Pending Todos

None yet.

### Blockers/Concerns

None yet.

## Session Continuity

Last session: 2026-03-18T20:00:00Z
Stopped at: Defining requirements for v2.0
Resume file: Starting new milestone
