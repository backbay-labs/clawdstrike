# 03 — Canvas Feel: Bringing Collab-Public's Polish to SwarmBoard

> **Status**: Draft
> **Last updated**: 2025-03-25
> **Author**: Engineering
> **Depends on**: React Flow 12.10 (`@xyflow/react ^12.10.1`)

---

## 1. Problem Statement

The SwarmBoard canvas (`swarm-board-page.tsx`) uses React Flow 12.10 with mostly
default interaction settings. The result is functional but feels "library generic"
-- zoom is linear and steppy, pan has no momentum, nodes snap to nothing, there
is no visual grid, multi-select lacks rubber-band marquee, and Space+drag panning
is absent. By contrast, the Collaborator project (`collab-public`) ships a
custom-built infinite canvas that feels native and polished: exponential zoom
with rubber-band limits, a dot-grid that responds to pan/zoom, snap-to-grid on
drop, marquee selection, Space+drag panning with cursor feedback, and grouped
multi-tile drag.

### Specific UX gaps

| Behavior | Collab-public | SwarmBoard (current) |
|---|---|---|
| **Zoom curve** | Exponential (`Math.exp(-deltaY * 0.6 / 100)`), feels analog | Linear step via React Flow default `zoomOnScroll` |
| **Zoom limits** | Rubber-band overshoot with spring snap-back (150 ms delay, 0.15 lerp factor, ZOOM_RUBBER_BAND_K=400) | Hard clamp at `minZoom=0.1` / `maxZoom=2` |
| **Zoom-to-cursor** | Focal-point-centered: pan adjusts so the point under the cursor stays fixed | React Flow centers zoom on viewport center by default |
| **Cmd+scroll zoom (macOS)** | `shouldZoom()` checks `e.metaKey` on Mac, `e.ctrlKey` everywhere | No special handling; Ctrl+scroll only |
| **Visual grid** | Canvas-rendered dot grid (20 px minor, 80 px major) that scales with zoom, light/dark aware | No grid at all; solid `#05060a` background |
| **Zoom indicator** | Transient percentage badge that fades after 1200 ms | No indicator |
| **Pan momentum** | Trackpad `deltaX/deltaY * 1.2` scaling gives natural inertia feel | React Flow default scroll panning (1:1, no scaling) |
| **Space+drag pan** | Space held sets `cursor: grab`, mousedown pans canvas, tiles become `pointer-events: none` | Space key is bound to toggle follow-active mode |
| **Middle-click pan** | `e.button === 1` starts drag-pan | Not implemented |
| **Snap-to-grid** | `snapToGrid()` rounds x/y/width/height to 20 px grid on mouse-up | No snapping; `snapGrid` prop not set |
| **Multi-tile drag** | `getGroupDragContext()` moves all selected tiles together, snap on drop | React Flow `multiSelectionKeyCode` + built-in group drag exists but no snap |
| **Marquee selection** | Custom rubber-band rectangle, AABB hit-test against tiles in canvas coords, Shift-additive | React Flow's built-in box selection via `selectionKeyCode={["Shift"]}` works but has no visual marquee customization |
| **Resize handles** | 8-direction (N/S/E/W + corners) per tile with per-type min sizes, zoom-compensated delta | `NodeResizer` component used on `agentSession` nodes only |
| **Edge indicators** | Off-screen tile dots along viewport edges with tooltips, click-to-pan animation | No off-screen indicators |
| **Canvas resize** | `ResizeObserver` recenters viewport on window resize | React Flow handles this but does not recenter |

---

## 2. Reference Implementation Analysis

All paths relative to:
```
/Users/connor/Medica/backbay/standalone/collab-public/collab-electron/src/windows/shell/src/
```

### 2.1 canvas-viewport.js — Zoom and Grid

**Constants:**
```
ZOOM_MIN = 0.33       (33%)
ZOOM_MAX = 1          (100%)
ZOOM_RUBBER_BAND_K = 400
CELL = 20             (minor grid spacing in canvas px)
MAJOR = 80            (major grid spacing)
```

**Zoom curve** (`applyZoom`, line 124-160):
- Uses exponential factor: `Math.exp((-deltaY * 0.6) / 100)`
- This maps small scroll deltas to near-1.0 factors and large deltas to larger
  jumps, producing a natural feel where the zoom rate accelerates as you scroll
  harder. The `0.6` sensitivity constant was tuned for trackpad + mouse wheel.
- **Rubber-band**: When zoom exceeds `ZOOM_MAX` (zooming in past 100%) or drops
  below `ZOOM_MIN` (zooming out past 33%), a damping factor
  `1 / (1 + overshoot * 400)` drastically reduces the zoom step. The user feels
  increasing resistance rather than a hard wall.
- **Snap-back**: After 150 ms of no wheel events (`zoomSnapTimer`), an
  `requestAnimationFrame` loop lerps zoom back to the nearest limit at
  `0.15` per frame (`snapBackZoom`, line 95-122). The focal point is preserved
  during snap-back so the viewport does not jump.

**Focal-point zoom** (line 148-150):
```js
const ratio = state.zoom / prevScale - 1;
state.panX -= (focalX - state.panX) * ratio;
state.panY -= (focalY - state.panY) * ratio;
```
This keeps the point under the cursor stationary in screen space during zoom --
a critical detail that React Flow's default zoom-to-center misses.

**macOS Cmd+scroll** (`shouldZoom`, line 9-11):
```js
return e.ctrlKey || (mac && e.metaKey);
```

**Wheel handler** (line 162-173):
```js
canvasEl.addEventListener("wheel", (e) => {
  e.preventDefault();
  if (shouldZoom(e)) {
    applyZoom(e.deltaY, e.clientX - rect.left, e.clientY - rect.top);
  } else {
    state.panX -= e.deltaX * 1.2;
    state.panY -= e.deltaY * 1.2;
    updateCanvas();
  }
}, { passive: false });
```
The `1.2` pan multiplier makes trackpad two-finger scroll feel faster and more
responsive than a raw 1:1 mapping.

**Dot grid** (`drawGrid`, line 40-78):
- Rendered to a `<canvas>` element overlaying the viewport.
- Minor dots: 1.5 px scaled by zoom, `rgba(0,0,0,0.20)` / `rgba(255,255,255,0.22)`.
- Major dots: same size but higher opacity (`0.35` / `0.40`).
- Grid offset computed from `panX % step` so dots scroll with the canvas.

**Zoom indicator** (line 80-88): Shows `${pct}%` in a DOM element, adds
`.visible` class, auto-hides after 1200 ms.

**Resize handling** (line 175-184): `ResizeObserver` adjusts `panX/panY` by
half the size delta so content stays centered when the window resizes.

### 2.2 canvas-state.js — Grid Snap and Selection Model

**File:** `canvas-state.js`

- **Tile data model**: `{ id, type, x, y, width, height, zIndex, filePath?, ... }`
  Positions and sizes are in canvas coordinates (not screen pixels).
- **`snapToGrid(tile)`** (line 76-79): Rounds x, y, width, height to nearest
  `GRID_CELL = 20` using `Math.round(value / 20) * 20`. Applied on mouse-up
  after drag and resize.
- **Selection**: A `Set<string>` of tile IDs managed by `selectTile`,
  `deselectTile`, `toggleTileSelection`, `clearSelection`.
  `getSelectedTiles()` returns the corresponding tile objects.

### 2.3 tile-interactions.js — Drag, Resize, Marquee

**File:** `tile-interactions.js`

**`attachDrag`** (line 31-128):
- Mousedown on title bar starts drag. `e.button !== 0` and `isSpaceHeld()`
  suppress drag (space is reserved for canvas pan).
- Delta is divided by `viewport.zoom` so drags are zoom-compensated:
  `dx = (e.clientX - startMX) / viewport.zoom`.
- **Group drag**: If the tile is part of a multi-selection,
  `getGroupDragContext()` returns an array of `{ tile, container, startX, startY }`
  entries. All tiles in the group move by the same delta.
  Tiles get `tile-dragging` CSS class (opacity 0.85) during drag.
- **Shift+click**: If Shift was held and the mouse did not move past
  `CLICK_THRESHOLD = 3 px`, the event is treated as a selection toggle, not a
  drag.
- **Snap on drop**: `snapToGrid(tile)` (or each tile in a group) is called in
  `onUp`.
- **Content overlay drag**: An overlay `<div>` over unfocused tile content acts
  as a secondary drag surface so users can grab tiles by their body, not just
  the title bar.

**`attachMarquee`** (line 142-258):
- Mousedown on empty canvas (not on tiles) starts a fixed-position
  `<div class="selection-marquee">` that tracks the mouse.
- On mouse-up, the marquee rect is converted from screen coords to canvas
  coords using `(sx - viewerRect.left - viewport.panX) / viewport.zoom`.
- AABB hit-test against all tiles.
- Shift adds to current selection; plain click replaces.
- If no movement, it is a click on empty canvas and clears selection.

**`attachResize`** (line 268-337):
- Creates 8 resize handles (N, S, E, W, NW, NE, SW, SE) as DOM elements.
- Drag delta is zoom-compensated.
- Per-type minimum sizes (e.g., `term: 200x120`, `graph: 300x250`).
- `snapToGrid` on mouse-up.

### 2.4 tile-renderer.js — DOM Positioning

**File:** `tile-renderer.js`

**`positionTile`** (line 222-233):
```js
const sx = tile.x * zoom + panX;
const sy = tile.y * zoom + panY;
container.style.left = `${sx}px`;
container.style.top = `${sy}px`;
container.style.width = `${tile.width}px`;
container.style.height = `${tile.height}px`;
container.style.transform = `scale(${zoom})`;
container.style.transformOrigin = "top left";
```
Tiles are positioned in screen space with `left/top`, sized in canvas space,
and scaled via CSS transform. This avoids sub-pixel jitter that arises from
scaling width/height directly.

### 2.5 renderer.js — Space+Drag Pan, Keyboard Shortcuts

**File:** `renderer.js` (the main orchestrator, ~900 lines)

**Space+drag pan** (line 632-702):
- `keydown` on Space sets `spaceHeld = true`, adds `.space-held` class
  (cursor: grab), blurs all webviews.
- `mousedown` on canvas with `e.button === 1` (middle) OR `e.button === 0 &&
  spaceHeld` starts a drag-pan:
  ```js
  viewportState.panX = startPanX + (ev.clientX - startMX);
  viewportState.panY = startPanY + (ev.clientY - startMY);
  ```
- During pan, all webview pointer events are disabled.
- `.panning` class sets `cursor: grabbing`.

**Canvas pinch from tile webviews** (line 874-879):
```js
window.shellApi.onCanvasPinch((deltaY) => {
  viewport.applyZoom(deltaY, rect.width / 2, rect.height / 2);
});
```
Trackpad pinch gestures inside webview tiles are forwarded to the main canvas
zoom handler.

### 2.6 edge-indicators.js — Off-Screen Tile Awareness

**File:** `edge-indicators.js`

- For every tile that is fully off-screen, a colored dot is rendered at the
  intersection of a ray from viewport center to tile center with the viewport
  boundary (`rayRectIntersect`).
- Hover shows a tooltip with tile type and name.
- Click triggers an animated pan (`easeOut(t) = 1 - (1-t)^3`, 350 ms) to
  center the tile, with a highlight flash on arrival.

---

## 3. Approach: Tune React Flow vs. Replace

### Option A: Keep React Flow, customize heavily

React Flow 12.10 exposes extensive customization:

| React Flow API | What it controls |
|---|---|
| `onViewportChange` / `useViewport()` | Read current zoom/pan (can layer custom logic on top) |
| `panOnScroll`, `panOnScrollMode`, `panOnScrollSpeed` | Scroll-to-pan behavior |
| `zoomOnScroll`, `zoomOnPinch`, `zoomOnDoubleClick` | Zoom triggers (can disable and replace) |
| `minZoom`, `maxZoom` | Clamp range (set wide and implement rubber-band in wrapper) |
| `snapToGrid`, `snapGrid` | Snap position during drag (grid-aligned positioning) |
| `nodesDraggable`, `onNodeDragStart/Stop` | Custom drag lifecycle hooks |
| `selectionMode`, `selectionKeyCode`, `multiSelectionKeyCode` | Built-in marquee selection |
| `panOnDrag` | Can set to `[1]` for middle-button, or `false` to fully replace |
| `defaultViewport`, `fitView`, `fitViewOptions` | Initial positioning |
| Custom `Background` component | Dot/line/cross grids with gap, color, size props |
| Custom node types with `NodeResizer` | Per-node resize handles |
| `onMoveStart` / `onMove` / `onMoveEnd` | Intercept viewport transform changes |
| `useReactFlow()` | Imperative `setViewport`, `zoomTo`, `fitView`, `getViewport` |
| `viewport` prop + `onViewportChange` | Controlled mode for full viewport ownership |

**What you keep:**
- Edge rendering engine (paths, labels, markers, smooth-step routing)
- MiniMap and Controls components
- Built-in node selection, multi-selection, keyboard delete
- Accessibility (ARIA roles, keyboard navigation)
- Connection drawing (onConnect, connection line)
- Node/edge types system with custom renderers
- Auto-layout integration (`fitView`, animated transitions)
- All existing SwarmBoard features (inspector, context menu, stats bar, live PTY nodes)

**What is hard to customize:**
- React Flow's internal d3-zoom handles wheel events before your code. To get
  collab-public's exponential curve and rubber-band, you must either (a) disable
  `zoomOnScroll` and attach your own wheel handler, or (b) use controlled
  viewport mode and transform the zoom values before applying them.
- Pan momentum/inertia requires intercepting the wheel end and animating
  continued drift, which React Flow does not provide natively.

### Option B: Replace React Flow with custom canvas

Build a custom canvas layer similar to collab-public, rendering React components
into absolutely-positioned divs transformed by a hand-managed viewport.

**What you gain:**
- Full control over every interaction: zoom curve, momentum, rubber-band, grid,
  Space+drag, marquee, edge indicators -- exactly matching collab-public.
- No fighting the library's event handling.
- Smaller bundle (drop `@xyflow/react` + `d3-zoom` + `d3-selection`).

**What you lose:**
- Edge rendering: You must implement your own edge path routing (smooth-step,
  bezier), SVG/Canvas edge layer, edge labels, animated edges. The existing
  `SwarmEdge` component and all edge type logic must be rewritten.
- MiniMap: Must build from scratch.
- Connection drawing UI: Must implement handle rendering, draggable connection
  lines, snap-to-handle.
- Built-in node selection with keyboard support: Must reimplement.
- Auto-layout `fitView` with duration animation: Must build.
- Accessibility: React Flow provides ARIA attributes and keyboard navigation
  out of the box.
- The entire existing SwarmBoard feature set (`swarm-board-page.tsx`, 6 custom
  node types, `SwarmEdge`, inspector, toolbar, left rail, stats bar) is tightly
  coupled to React Flow APIs (`useReactFlow`, `applyNodeChanges`,
  `applyEdgeChanges`, `onConnect`, `NodeProps`, `EdgeProps`, `Handle`,
  `NodeResizer`, `MiniMap`). Replacing React Flow means rewriting or adapting
  all of these.

**Estimated cost:**
- Option A: 2-3 weeks to implement all improvements incrementally.
- Option B: 6-8 weeks minimum, with high regression risk on existing features.

### Recommendation: Option A

Keep React Flow and customize aggressively. The SwarmBoard is a graph
visualization tool with rich edge semantics (handoff, spawned, artifact,
receipt, topology), live PTY terminal nodes, an inspector drawer, and force-
directed layout algorithms. These features depend heavily on React Flow's graph
primitives. The canvas feel improvements are achievable through React Flow's
customization surface without replacing the library.

The key insight is that collab-public's polish comes from a small number of
well-tuned interaction behaviors, not from a fundamentally different rendering
architecture. All of them can be layered on top of React Flow.

---

## 4. Specific Improvements

### 4.1 Zoom: Custom Exponential Curve with Rubber-Band

**Current state:** React Flow's default d3-zoom with `minZoom=0.1`, `maxZoom=2`.
Linear zoom steps, hard clamp at limits, zoom centered on viewport center.

**Target behavior:**
- Exponential zoom factor: `Math.exp((-deltaY * 0.6) / 100)`
- Rubber-band overshoot past min/max with spring snap-back
- Zoom centered on cursor position
- Cmd+scroll triggers zoom on macOS (Ctrl+scroll on all platforms)
- Transient zoom percentage indicator

**Implementation:**

1. Disable React Flow's built-in zoom: set `zoomOnScroll={false}`,
   `zoomOnPinch={false}`, `zoomOnDoubleClick={false}`.
2. Use React Flow in **controlled viewport** mode: pass `viewport` prop and
   `onViewportChange` to own the viewport transform.
3. Attach a `wheel` event listener (with `{ passive: false }`) to the React
   Flow wrapper `<div>`.
4. In the wheel handler, port collab-public's `applyZoom` logic:
   ```ts
   function applyZoom(deltaY: number, focalX: number, focalY: number) {
     const prevScale = viewportRef.current.zoom;
     let factor = Math.exp((-deltaY * 0.6) / 100);

     // Rubber-band damping
     if (prevScale >= ZOOM_MAX && factor > 1) {
       const overshoot = prevScale / ZOOM_MAX - 1;
       factor = 1 + (factor - 1) / (1 + overshoot * RUBBER_BAND_K);
     } else if (prevScale <= ZOOM_MIN && factor < 1) {
       const overshoot = ZOOM_MIN / prevScale - 1;
       factor = 1 - (1 - factor) / (1 + overshoot * RUBBER_BAND_K);
     }

     const newZoom = prevScale * factor;
     const ratio = newZoom / prevScale - 1;
     const newX = viewportRef.current.x - (focalX + viewportRef.current.x) * ratio;
     const newY = viewportRef.current.y - (focalY + viewportRef.current.y) * ratio;

     setViewport({ x: newX, y: newY, zoom: newZoom });
     scheduleSnapBack();
   }
   ```
   Note: React Flow's viewport uses `{ x, y, zoom }` where `x`/`y` are the
   translation (equivalent to collab-public's `panX`/`panY`), but the
   focal-point math inverts because React Flow's `x` is `-(panX)` in screen
   terms. Verify sign conventions during implementation.

5. Snap-back: After 150 ms idle, `requestAnimationFrame` loop lerps zoom to
   nearest limit with factor 0.15 per frame.

6. `shouldZoom(e)`: Check `e.ctrlKey || (isMac && e.metaKey)`. When false,
   fall through to pan.

7. Zoom indicator: A small absolutely-positioned `<div>` that renders
   `${Math.round(zoom * 100)}%`, shown/hidden via state with 1200 ms timeout.

**Constants (from collab-public, adjusted for SwarmBoard's wider range):**
```ts
const ZOOM_MIN = 0.15;    // SwarmBoard needs to zoom out further (was 0.33)
const ZOOM_MAX = 1.5;     // Allow slight over-zoom for node inspection (was 1.0)
const RUBBER_BAND_K = 400;
const ZOOM_SENSITIVITY = 0.6;
```

### 4.2 Pan: Momentum and Trackpad Scaling

**Current state:** React Flow default scroll panning. No momentum, no scaling.

**Target behavior:**
- Two-finger scroll maps to pan with 1.2x multiplier (matches collab-public).
- After lifting fingers, pan continues with exponential decay (momentum).
- Space+drag panning with grab/grabbing cursor.
- Middle-click drag panning.

**Implementation:**

1. In the same controlled-viewport wheel handler:
   ```ts
   // When shouldZoom is false:
   const newX = viewportRef.current.x - e.deltaX * 1.2;
   const newY = viewportRef.current.y - e.deltaY * 1.2;
   setViewport({ x: newX, y: newY, zoom: viewportRef.current.zoom });
   ```

2. **Momentum**: Track the last N wheel events (e.g., last 100 ms) to compute
   average velocity. On wheel-end (detected via a 60 ms debounce with no new
   wheel events), start a `requestAnimationFrame` loop that applies the
   velocity with exponential decay (`velocity *= 0.95` per frame). Stop when
   velocity magnitude drops below 0.5 px/frame.

3. **Space+drag**: React Flow's `panOnDrag` prop accepts an array of mouse
   buttons. Set `panOnDrag={[1]}` for middle-button pan. For Space+drag,
   track `spaceHeld` state and conditionally set `panOnDrag={[0, 1]}` when
   space is held. Alternative: disable `panOnDrag` entirely and implement
   manual mousedown/mousemove/mouseup pan (more control, matches
   collab-public). Change the Space key binding from "toggle follow-active"
   to "hold for pan" (move follow-active to a different key, e.g., `G`).

4. **Cursor feedback**: When `spaceHeld`, add `cursor: grab` to the React
   Flow wrapper. During active pan, switch to `cursor: grabbing`. Collab-
   public does this via CSS classes on the canvas element:
   ```css
   .space-held .react-flow { cursor: grab !important; }
   .space-held.panning .react-flow { cursor: grabbing !important; }
   .space-held .react-flow__node { pointer-events: none; }
   ```

### 4.3 Grid: Visual Dot Grid Overlay

**Current state:** Solid `#05060a` background. No visual reference points.

**Target behavior:** Dot grid matching collab-public's pattern -- minor dots at
20 px intervals, major dots at 80 px intervals, scaled by zoom, offset by pan.

**Implementation:**

React Flow ships a `<Background>` component:
```tsx
import { Background, BackgroundVariant } from "@xyflow/react";

<Background
  variant={BackgroundVariant.Dots}
  gap={20}
  size={1.5}
  color="rgba(255,255,255,0.08)"
/>
```

However, React Flow's `Background` only supports a single dot layer. For the
dual minor/major grid, use two stacked `Background` components:

```tsx
<Background
  id="minor"
  variant={BackgroundVariant.Dots}
  gap={20}
  size={1}
  color="rgba(255,255,255,0.06)"
/>
<Background
  id="major"
  variant={BackgroundVariant.Dots}
  gap={80}
  size={1.5}
  color="rgba(255,255,255,0.12)"
/>
```

If React Flow's `Background` does not support two instances cleanly (test this),
fall back to a custom canvas overlay identical to collab-public's `drawGrid`.
Render a `<canvas>` element behind the React Flow pane and drive it from
`onViewportChange`:

```tsx
const canvasRef = useRef<HTMLCanvasElement>(null);

function drawGrid(viewport: { x: number; y: number; zoom: number }) {
  const ctx = canvasRef.current?.getContext("2d");
  if (!ctx) return;
  // Port collab-public's drawGrid logic here
}

<canvas
  ref={canvasRef}
  className="absolute inset-0 pointer-events-none z-0"
/>
```

### 4.4 Snap-to-Grid on Drop

**Current state:** No snapping. React Flow's `snapToGrid` and `snapGrid` props
are not set.

**Target behavior:** Nodes snap to 20 px grid on drag end (not during drag, to
preserve smooth movement feel).

**Implementation:**

React Flow supports snap during drag via:
```tsx
<ReactFlow snapToGrid snapGrid={[20, 20]} ... />
```

However, collab-public's approach (free drag, snap on drop) feels better because
the node moves fluidly under the cursor and settles neatly on release. To
replicate this:

1. Do NOT set `snapToGrid` on `<ReactFlow>`.
2. Use `onNodeDragStop` to snap positions:
   ```tsx
   const SNAP_GRID = 20;

   const onNodeDragStop: NodeDragHandler = useCallback((_event, node) => {
     const snappedX = Math.round(node.position.x / SNAP_GRID) * SNAP_GRID;
     const snappedY = Math.round(node.position.y / SNAP_GRID) * SNAP_GRID;
     if (snappedX !== node.position.x || snappedY !== node.position.y) {
       storeActions.setNodes(
         nodesRef.current.map((n) =>
           n.id === node.id
             ? { ...n, position: { x: snappedX, y: snappedY } }
             : n,
         ),
       );
     }
   }, [storeActions]);
   ```

3. For **multi-node drag stop**, use `onSelectionDragStop` to snap all selected
   nodes simultaneously:
   ```tsx
   const onSelectionDragStop: SelectionDragHandler = useCallback(
     (_event, nodes) => {
       const updated = nodesRef.current.map((n) => {
         const dragged = nodes.find((d) => d.id === n.id);
         if (!dragged) return n;
         return {
           ...n,
           position: {
             x: Math.round(dragged.position.x / SNAP_GRID) * SNAP_GRID,
             y: Math.round(dragged.position.y / SNAP_GRID) * SNAP_GRID,
           },
         };
       });
       storeActions.setNodes(updated);
     },
     [storeActions],
   );
   ```

### 4.5 Group Operations: Multi-Select Drag and Alignment

**Current state:** React Flow supports multi-select via Shift key
(`selectionKeyCode={["Shift"]}`). Selected nodes can be dragged together. No
alignment guides.

**Target behavior:**
- Marquee selection (rubber-band) on empty canvas click-drag (already present
  via React Flow's built-in selection box).
- Group drag with snap-on-drop (see 4.4).
- Alignment guides: show snap lines when a dragged node aligns with other
  nodes' edges or centers.

**Implementation:**

1. **Marquee**: React Flow's `selectionOnDrag={true}` enables marquee on left-
   click drag on empty canvas. Combined with `selectionKeyCode={["Shift"]}` for
   additive selection. The visual styling of the selection box can be customized
   via CSS:
   ```css
   .react-flow__selection {
     background: rgba(74, 158, 255, 0.06);
     border: 1.5px solid rgba(74, 158, 255, 0.5);
   }
   ```
   Decision: set `selectionOnDrag` only when Space is NOT held (to avoid
   conflict with Space+drag pan). Alternatively, use `selectionKeyCode` only
   and trigger marquee on Shift+drag.

2. **Alignment guides**: Implement as an SVG overlay rendered in a custom React
   Flow panel. During `onNodeDrag`, compute alignment candidates:
   ```ts
   const ALIGN_THRESHOLD = 5; // pixels in canvas coords

   function getAlignmentLines(draggedNode, allNodes) {
     const lines = [];
     for (const other of allNodes) {
       if (other.id === draggedNode.id || other.selected) continue;
       // Horizontal center alignment
       if (Math.abs(draggedNode.position.y - other.position.y) < ALIGN_THRESHOLD) {
         lines.push({ type: 'horizontal', y: other.position.y });
       }
       // Vertical center alignment
       if (Math.abs(draggedNode.position.x - other.position.x) < ALIGN_THRESHOLD) {
         lines.push({ type: 'vertical', x: other.position.x });
       }
     }
     return lines;
   }
   ```
   This is a Phase 3 enhancement; skip for initial implementation.

### 4.6 Keyboard Shortcuts

**Current state** (from `swarm-board-page.tsx`):
- Escape: deselect
- Cmd+A: select all
- Cmd+Shift+N: new session
- Cmd+Shift+M: new note
- 1-6: quick add node types
- F: fit view
- Space: toggle follow-active
- Backspace/Delete: delete selected

**Additions to match collab-public:**
| Shortcut | Action | Priority |
|---|---|---|
| Arrow keys | Nudge selected nodes by 20 px (1 grid cell) | High |
| Shift+Arrow | Nudge selected nodes by 80 px (1 major cell) | Medium |
| Space (hold) | Pan mode (replaces toggle follow-active) | High |
| G | Gather/fit view (replaces F, frees F for future use) | Low |
| Middle-click drag | Pan | High |
| Cmd+0 | Reset zoom to 100% | Medium |
| Cmd+= / Cmd+- | Zoom in/out by step | Medium |

**Arrow nudge implementation:**
```tsx
// In the keydown handler:
if (["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(e.key)) {
  const selected = nodesRef.current.filter((n) => n.selected);
  if (selected.length === 0) return;
  e.preventDefault();
  const step = e.shiftKey ? 80 : 20;
  const dx = e.key === "ArrowRight" ? step : e.key === "ArrowLeft" ? -step : 0;
  const dy = e.key === "ArrowDown" ? step : e.key === "ArrowUp" ? -step : 0;
  const updated = nodesRef.current.map((n) =>
    n.selected
      ? { ...n, position: { x: n.position.x + dx, y: n.position.y + dy } }
      : n,
  );
  storeActions.setNodes(updated);
}
```

### 4.7 Edge Indicators for Off-Screen Nodes

**Current state:** No indication of off-screen nodes.

**Target behavior:** Colored dots along the viewport boundary pointing toward
off-screen nodes. Hover for tooltip, click to pan.

**Implementation:**

Port collab-public's `edge-indicators.js` as a React component rendered inside
a React Flow panel:

```tsx
<ReactFlow ...>
  <Panel position="top-left" className="pointer-events-none absolute inset-0">
    <EdgeIndicators
      nodes={nodes}
      viewport={viewport}
      containerRef={flowContainerRef}
      onPanToNode={(nodeId) => {
        reactFlow.fitView({ nodes: [{ id: nodeId }], padding: 0.5, duration: 350 });
      }}
    />
  </Panel>
</ReactFlow>
```

This is a Phase 3 enhancement.

### 4.8 Canvas Resize Recentering

**Current state:** React Flow auto-adjusts on resize but does not recenter.

**Target behavior:** When the window resizes, the viewport shifts by half the
size delta to keep the center of the canvas stable (matches collab-public's
ResizeObserver logic).

**Implementation:**

```tsx
useEffect(() => {
  const el = flowContainerRef.current;
  if (!el) return;
  let prevW = el.clientWidth;
  let prevH = el.clientHeight;

  const observer = new ResizeObserver(() => {
    const w = el.clientWidth;
    const h = el.clientHeight;
    const vp = reactFlow.getViewport();
    reactFlow.setViewport({
      x: vp.x + (w - prevW) / 2,
      y: vp.y + (h - prevH) / 2,
      zoom: vp.zoom,
    });
    prevW = w;
    prevH = h;
  });
  observer.observe(el);
  return () => observer.disconnect();
}, [reactFlow]);
```

---

## 5. React Flow Customization Points — API Mapping

| Improvement | React Flow API surface | Custom code needed |
|---|---|---|
| Exponential zoom | `zoomOnScroll={false}`, `zoomOnPinch={false}`, controlled `viewport` prop, `onViewportChange` | Wheel handler with `Math.exp` factor, rubber-band, snap-back animation |
| Zoom-to-cursor | Part of custom wheel handler | Focal-point pan adjustment math |
| Cmd+scroll (macOS) | Part of custom wheel handler | `shouldZoom()` key check |
| Zoom indicator | N/A (pure UI) | Absolutely-positioned `<div>` driven by viewport zoom state |
| Pan scaling | `panOnScroll={false}`, controlled viewport | Wheel handler with 1.2x multiplier |
| Pan momentum | N/A | Velocity tracking + rAF decay loop |
| Space+drag | `panOnDrag` prop or controlled viewport | Keyboard state tracking, cursor CSS, conditional panOnDrag |
| Middle-click drag | `panOnDrag={[1]}` | Minimal (React Flow supports this natively) |
| Dot grid | `<Background>` component or custom `<canvas>` | Possibly custom canvas for dual-layer grid |
| Snap on drop | `onNodeDragStop`, `onSelectionDragStop` | Snap math (`Math.round(x/20)*20`) |
| Group drag | Built-in (multi-select + drag) | Snap-on-drop for groups via `onSelectionDragStop` |
| Arrow nudge | Keyboard handler | Position update in store |
| Alignment guides | `onNodeDrag` + custom SVG overlay | Guide line computation and rendering |
| Edge indicators | Custom React component in `<Panel>` | Ray-rect intersection, animated pan |
| Resize recentering | `useReactFlow().setViewport` + `ResizeObserver` | Observer setup |
| Selection marquee styling | CSS `.react-flow__selection` | CSS only |

---

## 6. Implementation Plan

### Phase 1: Core Feel (highest impact, lowest risk) -- ~3 days

**Goal:** Make zoom and pan feel native.

1. **Controlled viewport mode**
   - File: `swarm-board-page.tsx`
   - Add `viewport` state and `onViewportChange` to `<ReactFlow>`.
   - Set `zoomOnScroll={false}`, `zoomOnPinch={false}`, `zoomOnDoubleClick={false}`.
   - Preserve all existing functionality (fitView, toolbar zoom buttons must
     still work via `useReactFlow` -- verify that controlled mode and imperative
     API coexist).

2. **Custom wheel handler**
   - New file: `src/components/workbench/swarm-board/hooks/use-canvas-viewport.ts`
   - Port `applyZoom` from collab-public's `canvas-viewport.js` (lines 124-160).
   - Port `shouldZoom` (line 9-11).
   - Port pan with 1.2x multiplier (lines 169-170).
   - Wire to controlled viewport state.

3. **Middle-click pan**
   - Add `panOnDrag={[1]}` to `<ReactFlow>`.
   - Verify it does not conflict with custom wheel handler.

4. **Dot grid background**
   - Add React Flow `<Background>` component with dot variant.
   - Test dual-layer approach. If inadequate, build custom canvas.

5. **Zoom indicator**
   - Small absolutely-positioned element showing `${pct}%`, auto-hide after 1200 ms.

**Deliverable:** Zoom feels analog and smooth. Pan is responsive. Grid gives
spatial reference. Engineer can verify by comparing trackpad scroll behavior
side-by-side with collab-public.

### Phase 2: Snap and Space+Drag -- ~2 days

**Goal:** Grid snapping and pan mode.

1. **Snap on drop**
   - Add `onNodeDragStop` and `onSelectionDragStop` handlers.
   - Snap to 20 px grid.

2. **Space+drag pan**
   - Track `spaceHeld` state via keydown/keyup.
   - When space is held: set `panOnDrag={[0, 1]}` (or implement manual pan).
   - Add cursor CSS classes.
   - Rebind Space from "toggle follow-active" to "hold for pan".
   - Move follow-active toggle to `G` key or a toolbar button.

3. **Arrow key nudge**
   - Add to existing keyboard handler.
   - 20 px step, 80 px with Shift.

4. **Rubber-band zoom + snap-back animation**
   - Implement in `use-canvas-viewport.ts`.
   - Widen zoom range: `ZOOM_MIN=0.15`, `ZOOM_MAX=1.5` (soft limits).
   - Hard limits at 0.08 and 2.0 for the rubber-band overshoot ceiling.

**Deliverable:** Nodes settle onto grid lines. Space+drag panning works.
Keyboard navigation is precise.

### Phase 3: Polish -- ~3 days

**Goal:** Parity with collab-public's minor polish details.

1. **Pan momentum**
   - Track wheel velocity over last 100 ms.
   - On wheel-end (60 ms debounce), start rAF decay loop.
   - Decay factor: 0.95/frame, stop threshold: 0.5 px/frame.

2. **Resize recentering**
   - `ResizeObserver` adjusting viewport by half-delta.

3. **Selection marquee styling**
   - CSS customization of `.react-flow__selection`.

4. **Edge indicators** (off-screen tile awareness)
   - Port `edge-indicators.js` as `<EdgeIndicators>` React component.
   - Render in a React Flow `<Panel>`.
   - Click-to-pan with animated transition.

5. **Alignment guides** (optional, assess time)
   - SVG overlay during `onNodeDrag`.
   - Show horizontal/vertical snap lines at 5 px threshold.

**Deliverable:** The canvas feels as polished as collab-public. Off-screen nodes
are discoverable.

### Phase 4: Testing and Tuning -- ~1 day

1. **Manual QA matrix:**
   - Trackpad zoom on macOS (two-finger pinch, Cmd+scroll)
   - Mouse wheel zoom (Ctrl+scroll)
   - Trackpad two-finger pan
   - Space+drag pan (hold, drag, release)
   - Middle-click pan
   - Single node drag + snap
   - Multi-select drag + snap
   - Arrow nudge (plain and Shift)
   - Rubber-band overshoot + snap-back
   - Zoom indicator display/hide
   - Grid scaling at various zoom levels
   - Window resize recentering
   - All existing toolbar buttons (zoom in/out/reset, fit view, auto-layout)
   - `fitView` on initial load and follow-active mode

2. **Constant tuning:**
   Adjust `ZOOM_SENSITIVITY`, `RUBBER_BAND_K`, pan multiplier, momentum decay,
   and snap grid size based on QA feedback.

3. **Performance check:**
   - Profile with 50+ nodes to ensure custom wheel handler does not cause jank.
   - Verify grid canvas repaints are not excessive.

---

## Appendix A: Key File Paths

### Reference (collab-public)

| File | Role |
|---|---|
| `collab-electron/src/windows/shell/src/canvas-viewport.js` | Zoom, grid, rubber-band, resize observer |
| `collab-electron/src/windows/shell/src/canvas-state.js` | Tile data model, snap-to-grid, selection state |
| `collab-electron/src/windows/shell/src/tile-interactions.js` | Drag, resize, marquee selection |
| `collab-electron/src/windows/shell/src/tile-renderer.js` | DOM positioning, tile label rendering |
| `collab-electron/src/windows/shell/src/renderer.js` | Main orchestrator: Space+drag, keyboard, IPC |
| `collab-electron/src/windows/shell/src/edge-indicators.js` | Off-screen tile dots with click-to-pan |
| `collab-electron/src/windows/shell/src/shell.css` | Cursor states, marquee, grid canvas styles |
| `collab-electron/src/windows/shell/src/canvas-viewport.test.ts` | Zoom math unit tests |
| `collab-electron/src/windows/shell/src/canvas-state.test.ts` | Snap, selection unit tests |

All paths prefixed with:
`/Users/connor/Medica/backbay/standalone/collab-public/`

### Target (clawdstrike-swarm-engine)

| File | Role |
|---|---|
| `src/components/workbench/swarm-board/swarm-board-page.tsx` | Main canvas: ReactFlow config, event handlers, keyboard shortcuts |
| `src/components/workbench/swarm-board/swarm-board-toolbar.tsx` | Toolbar: zoom buttons, layout, session spawn |
| `src/features/swarm/stores/swarm-board-store.tsx` | Zustand store: node/edge CRUD, persistence |
| `src/features/swarm/swarm-board-types.ts` | TypeScript types for nodes, edges, state |
| `src/features/swarm/layout/topology-layout.ts` | Force-directed and hierarchical layout algorithms |
| `src/components/workbench/swarm-board/edges/swarm-edge.tsx` | Custom edge renderer (5 edge types) |
| `src/components/workbench/swarm-board/nodes/agent-session-node.tsx` | Agent session node with terminal preview |
| `src/components/workbench/swarm-board/nodes/index.ts` | Node type registry |

All paths prefixed with:
`/Users/connor/Medica/backbay/standalone/clawdstrike-swarm-engine-collab-upgrades/apps/workbench/`

### New files to create

| File | Purpose |
|---|---|
| `src/components/workbench/swarm-board/hooks/use-canvas-viewport.ts` | Custom zoom/pan logic (Phase 1) |
| `src/components/workbench/swarm-board/components/zoom-indicator.tsx` | Transient zoom percentage display (Phase 1) |
| `src/components/workbench/swarm-board/components/edge-indicators.tsx` | Off-screen node dots (Phase 3) |
| `src/components/workbench/swarm-board/components/alignment-guides.tsx` | Drag alignment lines (Phase 3, optional) |

## Appendix B: Collab-Public Constants Reference

These constants from collab-public should be tuned for SwarmBoard but serve as
tested starting points:

```ts
// canvas-viewport.js
ZOOM_MIN = 0.33          // Minimum zoom (adjust to 0.15 for SwarmBoard's larger graphs)
ZOOM_MAX = 1.0           // Maximum zoom (adjust to 1.5)
ZOOM_RUBBER_BAND_K = 400 // Rubber-band stiffness (higher = stiffer)
ZOOM_SENSITIVITY = 0.6   // Exponential factor in Math.exp(-deltaY * S / 100)
SNAP_BACK_LERP = 0.15    // Per-frame interpolation toward zoom limit
SNAP_BACK_DELAY_MS = 150  // Idle time before snap-back begins
INDICATOR_TIMEOUT_MS = 1200  // Zoom indicator auto-hide delay

// canvas-state.js
GRID_CELL = 20            // Minor grid (snap granularity)
GRID_MAJOR = 80           // Major grid (visual emphasis)

// tile-interactions.js
CLICK_THRESHOLD = 3       // px movement before drag suppresses click
PAN_MULTIPLIER = 1.2      // Trackpad scroll speed boost

// edge-indicators.js
PAN_ANIM_DURATION = 350   // ms for click-to-pan animation
PAN_ANIM_EASE = (t) => 1 - Math.pow(1 - t, 3)  // Cubic ease-out
```
