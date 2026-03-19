---
phase: 14-world-detail-npcs-ui
plan: "02"
subsystem: observatory-npcs
tags: [r3f, instanced-mesh, drei, npc, patrol, animation, useFrame]
dependency_graph:
  requires: []
  provides: [npcCrew-module, StationNpcCrew, STATION_NPC_PATROL_DATA]
  affects: [ObservatoryWorldCanvas]
tech_stack:
  added: []
  patterns:
    - drei Instances + Instance declarative instanced mesh (one draw call per station)
    - useFrame ref mutation for patrol lerp and proximity detection (no setState)
    - distanceTo camera.position as player proximity proxy
    - lookAt with Y-lock for NPC facing
key_files:
  created:
    - apps/workbench/src/features/observatory/world/npcCrew.tsx
  modified:
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
decisions:
  - "npcCrew.tsx (not .ts): JSX content requires .tsx extension — plan listed .ts but auto-fixed"
  - "NpcInstance uses useRef<THREE.Object3D | null> for <Instance> ref (not InstancedMesh)"
  - "Patrol speed constant 0.5 units/sec via lerp alpha = PATROL_SPEED * delta per frame"
  - "Proximity threshold 5.0 units — camera.position used as player proxy"
  - "NpcCrew mounted after WatchfieldPerimeter + MissionObjectiveBeacons in scene JSX"
metrics:
  duration: "~15 minutes"
  completed_date: "2026-03-19"
  tasks_completed: 2
  tasks_total: 3
  files_created: 1
  files_modified: 1
---

# Phase 14 Plan 02: NPC Capsule Crew Summary

**One-liner:** 24 instanced capsule NPC crew (4 per station) with 4-waypoint patrol lerp and camera-proximity wave reaction via drei Instances + useFrame ref mutation.

## What Was Built

Two files implement the full NPC crew system:

**`npcCrew.tsx`** — self-contained NPC module:
- `STATION_NPC_PATROL_DATA` — 4 NPC descriptors, each with a spawn offset and 4 patrol waypoint offsets (local [x, z] from station center)
- `NpcInstance` — per-NPC component using `useFrame` for patrol lerp (0.5 units/sec), `distanceTo` proximity check (5.0 unit threshold), Y-locked `lookAt` wave reaction, and `armOffsetRef` for wave animation — no `setState` anywhere
- `StationNpcCrew` — mounts a `<Instances limit={8}>` with `capsuleGeometry args={[0.12, 0.35, 4, 8]}` and one `<Instance>` child per NPC

**`ObservatoryWorldCanvas.tsx`** — scene mount:
- `import { StationNpcCrew }` added after VFX imports
- `world.districts.map((district) => <StationNpcCrew key={"npc:" + district.id} .../>)` mounted after WatchfieldPerimeter and MissionObjectiveBeacons — always mounted, not gated by `district.active`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] File extension .ts → .tsx**
- **Found during:** Task 1
- **Issue:** Plan specified `npcCrew.ts` but the file contains JSX, which requires `.tsx` extension; TypeScript would have rejected all JSX syntax
- **Fix:** Created file as `npcCrew.tsx`; import in ObservatoryWorldCanvas uses `../world/npcCrew` (no extension) so no downstream changes needed
- **Files modified:** `npcCrew.tsx` (created with correct extension)
- **Commit:** 479758009

## Checkpoint Status

Plan execution paused at Task 3 (human-verify checkpoint). Tasks 1 and 2 committed. Awaiting visual verification in the running workbench.

## Self-Check

- [x] `apps/workbench/src/features/observatory/world/npcCrew.tsx` exists
- [x] `StationNpcCrew` exported from npcCrew.tsx
- [x] `STATION_NPC_PATROL_DATA` exported from npcCrew.tsx
- [x] `StationNpcCrew` imported and mounted in ObservatoryWorldCanvas.tsx
- [x] No `setState` in useFrame (grep returns 0)
- [x] Zero new TypeScript errors introduced (pre-existing errors in districtGeometry.tsx and sidebar-icons.tsx unchanged)
- [x] Commits 479758009 and b10b5f37f verified in git log

## Self-Check: PASSED
