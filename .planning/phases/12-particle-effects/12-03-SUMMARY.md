---
phase: 12-particle-effects
plan: "03"
subsystem: observatory-vfx
tags: [particles, instanced-mesh, drei, sparkles, probe-discharge, vfx]
dependency_graph:
  requires: []
  provides: [PFX-02, PFX-03]
  affects: [ObservatoryWorldCanvas, ObservatoryHeroProp, ObservatoryWorldScene]
tech_stack:
  added: []
  patterns:
    - InstancedMesh with fibonacci sphere distribution for expanding shell VFX
    - drei Sparkles as frustum-culled ambient motes on station hero props
    - useMemo-derived probeDischargePosition from heroPropByStation map
key_files:
  created:
    - apps/workbench/src/features/observatory/vfx/ProbeDischargeVFX.tsx
  modified:
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
decisions:
  - "ProbeDischargeVFX uses mesh.count=0 when inactive — Three.js skips all 128 draw instances at zero GPU cost"
  - "FIBONACCI_POINTS allocated at module load (not per mount) — avoids GC pressure"
  - "frustumCulled=false on InstancedMesh discharge shell — shell can briefly exceed station bounding sphere during expand; simpler than updating bounds per-frame"
  - "Sparkles gated on !dormant — dormant stations (presenceScale < 0.4) are distant/invisible; gates 5 draw calls"
  - "world.core.accentColor confirmed as accent color path in DerivedObservatoryWorld"
  - "5 pre-existing TS2783 errors in sidebar-icons.tsx are out of scope; zero errors in plan-modified files"
metrics:
  duration: "196 seconds (~3 min)"
  completed_date: "2026-03-19"
  tasks_completed: 3
  tasks_total: 3
  files_created: 1
  files_modified: 1
---

# Phase 12 Plan 03: ProbeDischargeVFX + Station Sparkles Summary

One-liner: Custom InstancedMesh 128-sphere expanding shell (PFX-02) + drei Sparkles ambient motes on station hero props (PFX-03), both wired into ObservatoryWorldScene.

## What Was Built

### Task 1 — ProbeDischargeVFX (new file)

`apps/workbench/src/features/observatory/vfx/ProbeDischargeVFX.tsx`

New component implementing PFX-02 (probe energy discharge shell):
- `PARTICLE_COUNT = 128` spheres in a single InstancedMesh draw call
- `DISCHARGE_DURATION = 1.2s`, `EXPAND_SPEED = 3.0` units/sec
- `FIBONACCI_POINTS` Float32Array computed once at module load via `buildFibonacciSpherePoints()` — no per-frame allocation
- `useEffect` detects `"ready" → "active"` status transition; `useFrame` drives the expansion with `clock.elapsedTime`
- `mesh.count = 0` when not discharging — zero GPU cost between probes
- `depthWrite={false}`, `toneMapped={false}` for proper bloom pipeline integration
- `frustumCulled={false}` since the expanding shell can temporarily exceed the station's initial bounding sphere

### Task 2 — Sparkles in ObservatoryHeroProp (PFX-03)

Edit location: Line 786 (after missionTarget/interactable ring, before closing `</group>`).

```tsx
{!dormant ? (
  <Sparkles count={30} scale={2.5} size={0.6} speed={0.3}
    opacity={0.35} color={prop.glowColor} noise={0.8} />
) : null}
```

- Gated on `!dormant` (dormant = `!active && presenceScale < 0.4`) — removes 5 draw calls for out-of-range stations
- Uses `prop.glowColor` (existing hex string on each `ObservatoryHeroPropRecipe`)
- Parent `<group>` has default `frustumCulled={true}` — off-screen stations incur zero draw calls automatically

### Task 3 — ProbeDischargeVFX in ObservatoryWorldScene

Two edits:

**probeDischargePosition useMemo** (after `heroPropByStation` at line ~4117):
```tsx
const probeDischargePosition = useMemo((): [number, number, number] => {
  if (!probeLockedTargetStationId) return [0, 0, 0];
  const prop = heroPropByStation.get(probeLockedTargetStationId);
  return prop?.position ?? [0, 0, 0];
}, [heroPropByStation, probeLockedTargetStationId]);
```

**ProbeDischargeVFX JSX** (after heroProps.map at line ~4308):
```tsx
<ProbeDischargeVFX
  position={probeDischargePosition}
  probeStatus={probeStatus}
  color={world.core.accentColor}
/>
```

## Actual accentColor Field Path

`world.core.accentColor` — confirmed valid. `DerivedObservatoryWorld.core` is type `ObservatoryCoreRecipe` which has `accentColor: string` at line 341 of `deriveObservatoryWorld.ts`.

## Edit Locations in ObservatoryWorldCanvas.tsx

| Edit | Location | What |
|------|----------|------|
| drei import | Line 1 | Added `Sparkles` to destructuring |
| ProbeDischargeVFX import | Line 80 | New import after `applyObservatoryProbeConsequences` |
| Sparkles JSX | Line 786 | Last child of ObservatoryHeroProp group |
| probeDischargePosition | Line 4117 | useMemo after heroPropByStation in ObservatoryWorldScene |
| ProbeDischargeVFX JSX | Line 4308 | Sibling after heroProps.map in ObservatoryWorldScene return |

## Commits

| Task | Hash | Description |
|------|------|-------------|
| Task 1 | c6be0b4d7 | feat(12-03): add ProbeDischargeVFX component (PFX-02) |
| Task 2+3 | 24100b18f | feat(12-03): wire Sparkles motes and ProbeDischargeVFX into ObservatoryWorldCanvas (PFX-03, PFX-02) |

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

- [x] `apps/workbench/src/features/observatory/vfx/ProbeDischargeVFX.tsx` — exists
- [x] commit c6be0b4d7 — exists
- [x] commit 24100b18f — exists
- [x] Sparkles at line 786 of ObservatoryWorldCanvas.tsx — exists
- [x] ProbeDischargeVFX at line 4308 of ObservatoryWorldCanvas.tsx — exists
- [x] Zero TypeScript errors in plan-modified files
