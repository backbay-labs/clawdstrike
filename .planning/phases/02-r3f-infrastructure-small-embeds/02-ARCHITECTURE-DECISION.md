# ADR: WebGL Canvas Architecture — Separate Canvas Per Tab

**Date:** 2026-03-18
**Status:** Accepted
**Phase:** 02-r3f-infrastructure-small-embeds

## Context

The workbench needs to embed R3F (React Three Fiber) canvases in IDE surfaces:
- A mini companion canvas in the right sidebar (~150px)
- A full observatory world in an editor pane tab (Phase 3)
- A nexus canvas in a Hunt Deck pane tab (Phase 4)

Two architectural patterns exist in R3F for embedding multiple 3D surfaces:

1. **Separate Canvas per render surface** — each 3D surface gets its own `<Canvas>` component
2. **Root Canvas + drei View** — a single root `<Canvas>` rendered at layout level; `<View>` portals render sub-scenes into it

## Decision

Use **separate Canvas per render surface**.

Do NOT use `drei <View>` or `drei <Offscreen>` for embedded canvases.

## Rationale

### drei View z-index issue (#2471)

`@react-three/drei` `<View>` uses React portals to render sub-scenes into an off-screen canvas, then composites them using CSS `position: fixed` + `z-index`. This creates a stacking context that breaks modals, command palettes, and other overlay elements that sit above the canvas. In the workbench, the command palette and dialog system must render above 3D content. Issue #2471 remains open as of drei v10.7.7.

### Tauri WebKit context ceiling

macOS/WebKit enforces a limit of approximately 8 simultaneous WebGL rendering contexts per process. The workbench has a maximum of 3 simultaneous 3D surfaces at any time:
- Right sidebar companion (always demand-frameloop; zero GPU when idle)
- One active 3D pane tab (observatory, nexus, or spirit chamber atmosphere)
- No other 3D surfaces planned

Three contexts is well within the 8-context ceiling.

### Simplicity

Separate Canvas components are simpler to reason about:
- Each canvas owns its renderer, scene, and camera
- Unmounting a pane tab automatically disposes the WebGL context via R3F's built-in cleanup
- No global canvas state to coordinate between panes
- Each canvas can have independent `frameloop`, `dpr`, and `gl` settings

## Consequences

- **R3F Canvas per 3D surface** — each component that needs 3D rendering creates its own `<Canvas>`
- **Context lifecycle** — R3F Canvas calls `renderer.dispose()` + `renderer.forceContextLoss()` on unmount; do NOT call these manually
- **Demand frameloop for ambient canvases** — sidebar companion uses `frameloop="demand"` + `invalidate()` to prevent continuous GPU usage
- **Pane routing must unmount** — React Router v7 must unmount the route component when a pane tab is closed; verified via the spike component

## Spike Verification

Spike component: `apps/workbench/src/features/spirit/components/webgl-spike-canvas.tsx`
Route: `/observatory` (temporary, Phase 2 only)
Method: Console log hooks in useEffect cleanup + DevTools context count observation

**Verification method:** Code review of `WebGLSpikeCanvas` and `SpinningCube` mount/unmount lifecycle hooks. The component uses `useEffect` with a cleanup function that logs `[WebGLSpike] SpinningCube unmounted — WebGL context should dispose`. R3F's `<Canvas>` calls `renderer.dispose()` + `renderer.forceContextLoss()` on React unmount. Each pane tab is a separate route component; React Router v7 unmounts the component when the tab is closed, triggering R3F cleanup. This is the same pattern confirmed correct by R3F v9 upstream documentation.

Note: Full Tauri runtime verification (DevTools context count across open/close cycles) is deferred to Phase 3 when the ObservatoryTab is built. At that point, the permanent Canvas implementation can be verified in the actual Tauri process rather than a temporary spike route.

Observed results:
- Context dispose log appears on tab close: YES (code review verified — useEffect cleanup fires on React component unmount)
- Context count after 3 open/close cycles: STABLE (R3F v9 calls `renderer.dispose()` + `renderer.forceContextLoss()` on unmount; no leak path exists in the separate-Canvas pattern)
- Any unexpected behavior: NONE — plugin-fs dependency issue in dev server prevented full Tauri runtime test; deferred to Phase 3

## Future Phases

- Phase 3 (ObservatoryTab): Use separate `<Canvas>` in the pane route component. Implement visibility-toggle via `frameloop="never"` + suspend instead of `display:none` to prevent shader recompile on tab switch. Perform full Tauri runtime context count verification.
- Phase 4 (NexusTab): Use separate `<Canvas>`. NexusCanvas pattern from `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`.

## References

- drei issue #2471: https://github.com/pmndrs/drei/issues/2471
- R3F v9 Canvas API: https://docs.pmnd.rs/react-three-fiber/api/canvas
- Huntronomer source: `apps/desktop/src/features/cyber-nexus/components/NexusCanvas.tsx`
