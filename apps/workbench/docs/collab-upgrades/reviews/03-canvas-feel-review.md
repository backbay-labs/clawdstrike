# Review: 03 — Canvas Feel

> **Reviewer**: Senior Frontend/UX Engineer
> **Date**: 2026-03-25
> **Verdict**: **APPROVE WITH CHANGES**

---

## 1. Factual Accuracy

The spec is largely accurate in its description of the current codebase. Verified against `swarm-board-page.tsx`:

**Correct claims:**
- `@xyflow/react` version is `^12.10.1` (confirmed in `package.json` line 42).
- `minZoom={0.1}`, `maxZoom={2}` are set (lines 601-602).
- `fitView` is enabled with `padding: 0.2` (lines 599-600).
- `selectionKeyCode={["Shift"]}` is set (line 608).
- `deleteKeyCode={["Backspace", "Delete"]}` is set (line 607).
- Space key is bound to toggle follow-active (line 423).
- The `F` key triggers `fitView` (line 417).
- No `<Background>` component is used -- solid `#05060a` (line 606, `RF_STYLE`).
- No `snapToGrid` or `snapGrid` props are set on `<ReactFlow>`.
- `panOnDrag` is not explicitly set (defaults to `true` for left-click, which enables left-click drag panning on the canvas background).

**Correct collab-public claims (verified against source):**
- `canvas-viewport.js`: Constants `ZOOM_MIN=0.33`, `ZOOM_MAX=1`, `ZOOM_RUBBER_BAND_K=400`, `CELL=20`, `MAJOR=80` are all accurate (lines 1-5).
- `shouldZoom` checks `e.ctrlKey || (mac && e.metaKey)` -- accurate (line 9-11).
- Exponential zoom factor `Math.exp((-deltaY * 0.6) / 100)` -- accurate (line 132).
- Pan multiplier `1.2` -- accurate (lines 169-170).
- Snap-back lerp `0.15` per frame, 150ms idle delay -- accurate (lines 102, 155).
- `canvas-state.js` `snapToGrid` rounds to `GRID_CELL=20` -- accurate (lines 72-79).
- `tile-interactions.js` group drag, zoom-compensated delta, snap-on-drop -- all accurately described.

**Inaccuracy found:**
- The spec says "React Flow centers zoom on viewport center by default" (Section 1 table, "Zoom-to-cursor" row). This is **wrong**. React Flow 12's d3-zoom integration already zooms toward the cursor position by default when using `zoomOnScroll`. The zoom-to-center behavior only happens with the imperative `zoomIn()`/`zoomOut()` API used by toolbar buttons. This is a meaningful error because it overstates the gap -- the default scroll-zoom experience already has focal-point behavior. The improvement would be in the zoom *curve* and *rubber-band*, not in focal-point centering.

---

## 2. React Flow API Validation

### Props and hooks that exist and are correctly described:
- `zoomOnScroll`, `zoomOnPinch`, `zoomOnDoubleClick` -- all real boolean props. Disabling them is a valid approach.
- `panOnScroll`, `panOnScrollMode`, `panOnScrollSpeed` -- real props.
- `snapToGrid`, `snapGrid` -- real props (array `[number, number]`).
- `panOnDrag` -- accepts `boolean | number[]`. Setting `[1]` for middle-button only is correct.
- `selectionOnDrag` -- real prop (boolean). Enables marquee on left-click drag.
- `selectionKeyCode` / `multiSelectionKeyCode` -- real props.
- `onNodeDragStop` -- real callback. The `NodeDragHandler` type signature in section 4.4 is correct.
- `onSelectionDragStop` -- real callback. The `SelectionDragHandler` type exists.
- `onMoveStart`, `onMove`, `onMoveEnd` -- real callbacks for intercepting viewport transforms.
- `useReactFlow()` with `.setViewport()`, `.getViewport()`, `.fitView()`, `.zoomIn()`, `.zoomOut()`, `.zoomTo()` -- all real.
- `<Background>` with `BackgroundVariant.Dots`, `gap`, `size`, `color` props -- real.
- `<Panel>` component -- real, supports `position` prop.

### Controlled viewport mode (`viewport` + `onViewportChange`):

This is the spec's linchpin, and it requires careful scrutiny.

**Status in @xyflow/react 12.x**: The `viewport` prop and `onViewportChange` callback ARE part of the public API as of React Flow 12. However, the spec underestimates the friction:

1. **`fitView` prop conflict**: The spec uses `fitView` on `<ReactFlow>` (line 599 of current code) AND proposes controlled viewport mode. When you pass a `viewport` prop, React Flow treats the viewport as fully controlled -- meaning the `fitView` prop on mount may not work as expected, or may fire `onViewportChange` which you need to handle. The spec mentions verifying that `fitView` and imperative APIs coexist with controlled mode (section 6, Phase 1, item 1) but treats this as a footnote rather than a known hazard.

2. **Imperative API interaction**: The toolbar uses `reactFlow.zoomIn()`, `reactFlow.zoomOut()`, `reactFlow.fitView()` with `{ duration }` for animated transitions (toolbar lines 281-291). In controlled mode, these imperative calls will fire `onViewportChange` repeatedly during the animation. The custom zoom logic must not fight these calls. The spec does not address how to distinguish "imperative animation in progress" from "user wheel event" -- both arrive through `onViewportChange`. This needs a sentinel/flag pattern.

3. **d3-zoom still processes events**: Even with `zoomOnScroll={false}`, React Flow's d3-zoom instance is still mounted on the pane element. If the custom wheel handler calls `e.preventDefault()` and `e.stopPropagation()`, d3-zoom should not see the event. But the spec's implementation attaches the wheel listener to a *wrapper div*, while d3-zoom listens on an inner `.react-flow__pane` element. Event propagation order matters here. The spec should explicitly state: attach the listener to the `react-flow__renderer` or use a capture-phase listener to guarantee the custom handler fires first.

### Verdict on API surface:
The APIs referenced are real and stable. The controlled viewport approach is viable but the spec needs to address the three interaction hazards above.

---

## 3. UX Gaps the Spec Missed

### 3.1 Trackpad pinch-to-zoom vs. Ctrl+scroll

The spec disables `zoomOnPinch={false}` (Section 4.1, step 1). On macOS, trackpad pinch-to-zoom is reported by the browser as a `wheel` event with `e.ctrlKey = true` and `e.deltaY` proportional to the pinch amount. This means after disabling `zoomOnPinch`, the custom wheel handler's `shouldZoom(e)` check for `e.ctrlKey` will correctly catch pinch gestures. **This works, but the spec should call it out explicitly** because it is a common source of confusion and regression.

However, there is a subtlety: `zoomOnPinch` in React Flow specifically handles the `gesturestart`/`gesturechange`/`gestureend` Safari events, which are a separate code path from wheel events. Disabling `zoomOnPinch` means Safari's native gesture events will no longer be handled. The custom wheel handler only handles `wheel` events. On Safari, pinch gestures may fire *both* gesture events and wheel events depending on the context. The spec should either:
- Also attach `gesturestart`/`gesturechange` listeners with `e.preventDefault()` to suppress Safari's native behavior, or
- Keep `zoomOnPinch={true}` and only disable `zoomOnScroll`, accepting that pinch-to-zoom uses the default linear curve. (This is the safer option for Phase 1.)

### 3.2 Node connection UX during Space+drag

When Space+drag is active and `.react-flow__node` gets `pointer-events: none` (per the CSS in section 4.2), connection handles also become non-interactive. Users cannot start a new edge connection while space is held. This is fine for the pan gesture, but the spec should mention that the `pointer-events: none` must be removed on `keyup` to restore handle interactivity. Collab-public does not have edges/handles so this was not a concern there.

### 3.3 Minimap interaction during custom viewport control

The `<MiniMap>` component (lines 611-618 of current code) has `pannable` and `zoomable` set to `true`. In controlled viewport mode, minimap pan/zoom interactions will fire `onViewportChange`. The spec does not discuss whether the minimap's viewport changes should go through the custom zoom curve or bypass it. They should bypass it -- minimap interactions should directly set the viewport. This is another reason to distinguish event sources in the `onViewportChange` handler.

### 3.4 Performance at scale

The spec mentions profiling with "50+ nodes" (Phase 4, item 3). The existing codebase already enriches edges on every render with `hoveredNodeId` and `selectedNodeId` (lines 498-520 of `swarm-board-page.tsx`), creating new edge data objects each time. Adding a custom wheel handler that calls `setViewport` on every wheel event tick will trigger React re-renders at 60+ fps during scroll. With 100+ nodes and enriched edges, this could cause visible jank.

**Mitigation the spec should mention:**
- Use `requestAnimationFrame` to batch viewport updates (at most one per frame).
- Consider using `useStore` from `@xyflow/react` to read viewport in a non-re-rendering way, only re-rendering the zoom indicator component.
- The `onViewportChange` handler should NOT cause node/edge re-renders -- only viewport-dependent overlays (grid, zoom indicator, edge indicators).

### 3.5 Double-click zoom

The spec disables `zoomOnDoubleClick={false}` but does not propose a replacement. Double-click to zoom-to-fit on a specific node is a common canvas UX pattern. Currently, `onNodeDoubleClick` is bound to type-specific actions (expand terminal, enter note edit mode) so this is probably fine for nodes, but double-click on empty canvas to reset zoom is a useful affordance that's being removed without replacement. Consider adding it back as a custom handler.

---

## 4. Collab-Public Patterns That Don't Translate

### 4.1 No edges in collab-public

Collab-public has **zero edges**. It renders independent tiles with no lines connecting them. SwarmBoard has 5 edge types (handoff, spawned, artifact, receipt, topology) with custom animated rendering (`swarm-edge.tsx`), edge click handlers, and edge hover-reveal behavior.

**Conflicts:**
- **Space+drag with `pointer-events: none` on nodes**: This also disables edge *source* and *target* handles. In collab-public this is irrelevant. In SwarmBoard, if a user accidentally taps Space before starting an edge connection, the handles vanish. The spec's CSS `.space-held .react-flow__node { pointer-events: none; }` is too aggressive. It should target `.react-flow__node *:not(.react-flow__handle)` or manage this differently.
- **Marquee selection and edges**: Collab-public's marquee only selects tiles. React Flow's built-in selection box can also select edges within the marquee area. The spec does not address whether edge selection during marquee is desired.
- **Snap-on-drop effect on edge routing**: When nodes snap to grid on drop, their positions jump by up to 10px. Edges anchored to those nodes will also jump. For simple straight edges this is fine, but for smooth-step or bezier edges, a 10px position change can cause a visible routing recalculation. This should look fine visually but is worth testing.

### 4.2 Collab-public's DOM-based positioning vs. React Flow's transform-based positioning

Collab-public positions tiles via `left/top` and CSS `scale()` (section 2.4 of the spec). React Flow uses a single SVG/CSS `transform` on the viewport container and positions nodes in graph-coordinate space. This architectural difference means:
- Collab-public's focal-point zoom math operates on `panX/panY` (screen-space translation). React Flow's `viewport.x/y` represents the *same concept* but the sign convention differs. The spec acknowledges this ("Note: verify sign conventions") which is good, but should be more specific: React Flow's `x` is equivalent to collab-public's `panX` (both are positive-rightward translations in screen space). The focal-point math in section 4.1 step 4 uses `(focalX + viewportRef.current.x)` which suggests they believe the sign is the same. This should be validated empirically before the implementation, not during it.

### 4.3 Content overlay drag surface

Collab-public's `contentOverlay` pattern (a transparent div over tile content that acts as a secondary drag surface) does not translate to React Flow. React Flow nodes already handle drag via the node container element. The `.nodrag` CSS class on interactive content inside nodes (terminal previews, text editors) is the React Flow equivalent and is already in use.

---

## 5. Scope vs Impact

### Phase ordering assessment:

The 4-phase plan is:
1. Core Feel (zoom curve, pan scaling, grid, zoom indicator) -- 3 days
2. Snap and Space+Drag -- 2 days
3. Polish (momentum, resize recentering, edge indicators, alignment guides) -- 3 days
4. Testing -- 1 day

**This ordering is mostly correct but I would restructure:**

**Quick wins missing from Phase 1:**
- **Middle-click pan** (`panOnDrag={[1]}`): This is a one-line change. The spec puts it in Phase 1, which is correct, but it should be the *very first* thing shipped -- it's zero risk and immediately useful.
- **Dot grid background**: Adding `<Background variant={BackgroundVariant.Dots} gap={20} size={1} color="rgba(255,255,255,0.06)" />` is a 5-line change that dramatically improves spatial orientation. Ship this independently of everything else.
- **Selection marquee styling** (CSS-only): The spec puts this in Phase 3. It should be in Phase 1. It's a CSS change with zero functional risk:
  ```css
  .react-flow__selection {
    background: rgba(212, 168, 75, 0.04);
    border: 1px solid rgba(212, 168, 75, 0.3);
    border-radius: 2px;
  }
  ```
- **Arrow key nudge**: Zero risk, high utility for precision layout. Move from Phase 2 to Phase 1.

**Items that should be deferred or cut:**
- **Pan momentum** (Phase 3): High complexity, moderate impact. Trackpad users already get inertia from their OS-level scroll behavior. This is a "nice if it works perfectly, bad if it doesn't" feature. It requires tracking velocity vectors and interacting correctly with the controlled viewport. **Move to Phase 4 or cut.**
- **Alignment guides** (Phase 3, marked optional): Agree with optional. Cut from initial scope.
- **Edge indicators** (Phase 3): High value but significant implementation effort (ray-rect intersection, animated pan, tooltip positioning, cleanup lifecycle). This is more like a 2-day feature on its own. **Consider breaking into its own mini-spec.**

**Recommended re-ordering:**

| Phase | Items | Days |
|-------|-------|------|
| 0 (Quick Wins) | Middle-click pan, dot grid background, selection marquee CSS, arrow nudge | 0.5 |
| 1 (Core Feel) | Controlled viewport, custom wheel handler with exponential zoom + cursor-focal-point, zoom indicator | 2 |
| 2 (Snap + Pan) | Snap-on-drop, Space+drag, rubber-band + snap-back | 2 |
| 3 (Polish) | Resize recentering, edge indicators, double-click-to-reset on empty canvas | 3 |
| 4 (Testing) | Manual QA matrix, constant tuning, Safari gesture testing | 1 |

Total: ~8.5 days vs. spec's ~9 days. The difference is front-loading zero-risk wins so engineers see tangible improvement on day one.

---

## 6. Risk Assessment

### 6.1 Controlled viewport mode is the high-risk pivot

The entire spec hinges on switching to controlled viewport mode. This is a one-way door: once you own the viewport, every feature that touches the viewport must flow through your state management. Specifically:

**What can break:**
- `reactFlow.fitView()` with `{ duration }` produces an animated viewport transition via `d3-zoom`. In controlled mode, this fires `onViewportChange` N times per animation frame. If the custom zoom logic has any debounce, snap-back timer, or rAF loop running concurrently, the two systems will fight.
- `reactFlow.zoomIn()` / `reactFlow.zoomOut()` (toolbar, lines 281-287) behave the same way.
- The follow-active mode uses `reactFlow.fitView({ nodes: [runningNode], duration: 400 })` every 2 seconds (lines 443-450). In controlled mode, this animated viewport change arrives through `onViewportChange`. If the user is simultaneously scrolling, the two inputs will interleave.

**Mitigation strategy the spec should require:**
- A `viewportSourceRef` that tracks whether the current viewport change is from (a) user wheel/drag, (b) imperative API call, or (c) snap-back animation. This ref is checked in the `onViewportChange` handler to decide whether to apply custom logic or pass through.
- All imperative calls (`fitView`, `zoomIn`, etc.) should set `viewportSourceRef.current = "imperative"` before calling and reset it in a microtask or after the animation completes.

### 6.2 Wheel event interception fragility

The spec proposes attaching a `wheel` listener with `{ passive: false }` to the React Flow wrapper div and calling `e.preventDefault()`. This works, but:
- If React Flow updates to use a capture-phase listener internally, the custom handler may not fire first.
- Other libraries or browser extensions that listen for wheel events (e.g., smooth scrolling extensions) can interfere.
- The `e.stopPropagation()` call (implied but not stated in the spec) must be explicit to prevent d3-zoom from also processing the event.

### 6.3 Regression testing strategy

The spec proposes only manual QA (Phase 4). For a change this foundational, this is insufficient.

**Required additions:**
- **Unit tests for zoom math**: Port collab-public's `canvas-viewport.test.ts` pattern. Test the `applyZoom` function with various deltaY values, focal points, and rubber-band edge cases. This is pure math with no DOM dependency.
- **Unit tests for snap math**: Trivial to test (`Math.round(x/20)*20`), but important to codify edge cases (negative coordinates, zero, very large values).
- **Integration test for controlled viewport**: A minimal test that renders `<ReactFlow>` in controlled mode, calls `setViewport`, and asserts the viewport state is what was set. This catches regressions if `@xyflow/react` changes its controlled mode behavior in a patch release.
- **Visual regression**: If Playwright is already set up (the project has `test:e2e` scripts in `package.json`), add a smoke test that opens the swarm board, scrolls to zoom, and takes a screenshot to catch gross rendering issues.

### 6.4 Version pinning

The spec depends on `@xyflow/react ^12.10.1` (semver range allows 12.x patches). Controlled viewport mode and the interaction between custom wheel handlers and d3-zoom internals are surface areas where minor version bumps could introduce subtle behavior changes. **Pin to `~12.10.1`** (patch-only updates) for the duration of this work, then evaluate before widening.

---

## 7. Additional Technical Concerns

### 7.1 The `useReactFlow()` hook in toolbar vs. controlled viewport

The toolbar (`swarm-board-toolbar.tsx`) calls `reactFlow.getViewport()` in `getDropPosition` (line 80-91) and `reactFlow.zoomIn/Out/fitView` for zoom controls (lines 281-291). In controlled mode, `getViewport()` should still return the current viewport (it reads from the store, not from the prop). However, `zoomIn()` and `zoomOut()` will attempt to update the viewport through React Flow's internal state. With controlled mode, these updates arrive via `onViewportChange`. This works, but there is a one-frame delay between the imperative call and the state update propagating back through the controlled `viewport` prop. This can cause a visual "stutter" where the zoom snaps forward then corrects. Test this carefully.

### 7.2 Space key rebinding is a breaking change

The spec proposes rebinding Space from "toggle follow-active" to "hold for pan" and moving follow-active to `G`. This is a behavioral change for existing users. The stats bar footer currently shows `Space follow` (line 808). The keyboard shortcuts in section 4.6 should be documented in the UI (update the stats bar hint text) and ideally announced in a changelog/tooltip on first use.

### 7.3 The zoom indicator should respect the vignette overlay

The current canvas has a radial vignette overlay (lines 623-629) and a noise texture (lines 631-640). Both are `pointer-events: none` overlays with `z-index: 0`. The zoom indicator needs to be positioned above these overlays (z-index > 0) but below the inspector and context menu (z-index 100). The spec does not specify z-index for the zoom indicator.

---

## 8. Summary of Required Changes Before Implementation

| # | Category | Change Required | Severity |
|---|----------|----------------|----------|
| 1 | Factual error | Correct the claim that React Flow zooms to viewport center by default -- it already zooms toward the cursor for scroll-zoom | Medium |
| 2 | API hazard | Add a `viewportSourceRef` pattern to distinguish user input from imperative API viewport changes | High |
| 3 | Safari | Address Safari `gesturestart`/`gesturechange` events when disabling `zoomOnPinch` | High |
| 4 | Wheel listener | Specify capture-phase or explicit `stopPropagation()` to guarantee custom handler fires before d3-zoom | High |
| 5 | Performance | Add rAF batching for viewport updates from wheel events; warn about edge data enrichment cost | Medium |
| 6 | Space+drag | Narrow `pointer-events: none` scope to exclude connection handles | Medium |
| 7 | Minimap | Specify that minimap viewport changes should bypass custom zoom logic | Low |
| 8 | Phase ordering | Move quick wins (grid, marquee CSS, arrow nudge) to a Phase 0; defer pan momentum | Low |
| 9 | Testing | Add unit tests for zoom/snap math; add at least one Playwright smoke test | High |
| 10 | Version pinning | Pin `@xyflow/react` to `~12.10.1` during implementation | Low |
| 11 | Double-click | Address the removal of double-click-to-zoom (provide alternative or keep for empty canvas) | Low |

---

## 9. Overall Verdict

**APPROVE WITH CHANGES**

The spec is thorough, well-researched, and demonstrates genuine understanding of both the reference implementation and the target codebase. The Option A (customize React Flow) vs. Option B (replace) analysis is sound and the recommendation is correct. The phased implementation plan is reasonable.

However, the controlled viewport mode is a high-risk architectural change that the spec treats with insufficient caution. The three issues -- imperative API interaction, Safari gesture events, and wheel event propagation ordering -- could each independently block the implementation if discovered during coding rather than during planning. Items 2, 3, and 4 in the table above must be addressed in the spec before starting Phase 1.

The collab-public reference analysis is excellent but the spec does not adequately account for the graph-specific features (edges, handles, minimap) that collab-public simply does not have. Every interaction pattern ported from collab-public needs to be validated against the presence of edges and connection handles.

With the changes above, this spec is ready for implementation.
