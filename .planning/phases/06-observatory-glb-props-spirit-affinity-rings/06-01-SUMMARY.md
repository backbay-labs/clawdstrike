---
phase: 06-observatory-glb-props-spirit-affinity-rings
plan: "01"
subsystem: observatory
tags: [glb, r3f, hero-props, useGLTF, animation, three-fiber]
dependency_graph:
  requires: []
  provides:
    - OBSERVATORY_HERO_PROP_ASSETS availability="ready" (all 7)
    - 7 GLB files in apps/workbench/public/observatory-props/
    - HeroPropMesh component with bob animation in ObservatoryWorldCanvas
  affects:
    - ObservatoryScene (additive hero prop rendering)
    - deriveObservatoryWorld (reads availability flags via OBSERVATORY_HERO_PROP_ASSETS)
tech_stack:
  added:
    - useGLTF (@react-three/drei) for GLB loading
    - useGLTF.preload() for module-level eager fetch
  patterns:
    - TDD: pure unit tests for propAssets flags + bob animation math
    - Suspense boundary per hero prop with fallback=null (station sphere stays as hit target)
    - scene.clone() to prevent shared Three.js scene graph mutation across instances
key_files:
  created:
    - apps/workbench/public/observatory-props/signal-dish-tower/signal-dish-tower.glb
    - apps/workbench/public/observatory-props/subjects-lattice-anchor/subjects-lattice-anchor.glb
    - apps/workbench/public/observatory-props/operations-scan-rig/operations-scan-rig.glb
    - apps/workbench/public/observatory-props/evidence-vault-rack/evidence-vault-rack.glb
    - apps/workbench/public/observatory-props/judgment-dais/judgment-dais.glb
    - apps/workbench/public/observatory-props/watchfield-sentinel-beacon/watchfield-sentinel-beacon.glb
    - apps/workbench/public/observatory-props/operator-drone/operator-drone.glb
    - apps/workbench/src/features/observatory/__tests__/hero-prop-mesh.test.ts
  modified:
    - apps/workbench/src/features/observatory/world/propAssets.ts
    - apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx
decisions:
  - "scene.clone() used in HeroPropMesh to prevent shared scene graph corruption when same GLB is referenced by multiple instances"
  - "Hero props rendered additively (not replacing StationSphere) — sphere remains as clickable/hoverable hit target beneath the GLB prop"
  - "Suspense fallback=null per hero prop — station sphere provides visual coverage while GLB loads asynchronously"
  - "useGLTF.preload() called at module evaluation for all 7 ready assets — reduces perceptible load time on first observatory open"
  - "Test 5 uses elapsed=3π/(2*speed) for negative amplitude peak — plan spec had elapsed=π/(2*speed) which yields the positive peak; implemented correct negative peak formula"
metrics:
  duration: "3m 27s"
  completed: "2026-03-19"
  tasks_completed: 2
  files_created: 9
  files_modified: 2
---

# Phase 6 Plan 01: GLB Hero Props + HeroPropMesh Summary

GLB files for all 7 observatory stations copied from huntronomer source, propAssets availability flags flipped to "ready", and HeroPropMesh R3F component added with useGLTF loading and gentle bob animation.

## Tasks Completed

| Task | Description | Commit | Status |
|------|-------------|--------|--------|
| 1 | Copy 7 GLB dirs + flip propAssets availability to "ready" | a76f5059c | Done |
| 2 (RED) | Add hero-prop-mesh unit tests (5 tests) | accf927ad | Done |
| 2 (GREEN) | Implement HeroPropMesh + wire into ObservatoryScene | 67beedc1b | Done |

## What Was Built

**GLB assets (Task 1):** Copied all 7 hero prop GLB directories from `/huntronomer-workspace-orch/apps/desktop/public/observatory-props/` to `apps/workbench/public/observatory-props/`. Updated propAssets.ts header comment and flipped all 7 `availability: "slot"` entries to `availability: "ready"`, removing the "do not change without GLBs" warning comment.

**HeroPropMesh component (Task 2):** Added `HeroPropMesh` function component to `ObservatoryWorldCanvas.tsx`:
- Loads GLB via `useGLTF(recipe.assetUrl)`
- Applies `scene.clone()` to avoid shared scene graph mutation
- `useFrame` hook animates vertical bob: `position.y = recipe.position[1] + sin(elapsed * bobSpeed) * bobAmplitude`
- Rendered in `<Suspense fallback={null}>` wrapper at call site

**Wiring:** `ObservatoryScene` now iterates `world.heroProps` and renders each "ready" recipe in its own Suspense boundary. Station spheres remain as-is (additive rendering — GLB prop sits above the sphere hit target).

**Preloading:** Module-level `useGLTF.preload()` called for each "ready" asset immediately at module evaluation time.

## Verification Results

```
ls apps/workbench/public/observatory-props/ | wc -l  → 7
grep 'availability: "slot"'  propAssets.ts           → 0 matches
grep 'availability: "ready"' propAssets.ts           → 7 matches
grep HeroPropMesh ObservatoryWorldCanvas.tsx         → function def + Suspense render site
Tests: 5/5 passed
TypeScript: no errors introduced by this plan (pre-existing errors are unrelated)
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Bob animation test 5 elapsed formula**
- **Found during:** Task 2 (TDD)
- **Issue:** Plan specified `elapsed=Math.PI/(0.24*2)` and claimed this gives "negative peak" (-0.06). Math shows this elapsed gives `sin(π/2) = 1` → positive peak (+0.06), not negative.
- **Fix:** Test 5 uses `elapsed = (3 * Math.PI) / (2 * speed)` which gives `sin(3π/2) = -1` → bobOffset = -0.06, correctly testing the negative peak. Test description updated to "negative amplitude peak at 3π/(2*speed) elapsed".
- **Files modified:** `apps/workbench/src/features/observatory/__tests__/hero-prop-mesh.test.ts`

## Self-Check: PASSED

- apps/workbench/public/observatory-props/signal-dish-tower/signal-dish-tower.glb: FOUND
- apps/workbench/public/observatory-props/operator-drone/operator-drone.glb: FOUND
- apps/workbench/src/features/observatory/__tests__/hero-prop-mesh.test.ts: FOUND
- apps/workbench/src/features/observatory/components/ObservatoryWorldCanvas.tsx: HeroPropMesh FOUND
- Commit a76f5059c: FOUND
- Commit accf927ad: FOUND
- Commit 67beedc1b: FOUND
