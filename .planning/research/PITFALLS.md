# Pitfalls Research

**Domain:** R3F 3D features embedded in a VS Code-like IDE workbench (Tauri 2 + React 19)
**Researched:** 2026-03-18
**Confidence:** HIGH — all critical pitfalls verified against official R3F docs, GitHub issues, and direct inspection of the codebase

---

## Critical Pitfalls

### Pitfall 1: `overflow-auto` on the Pane Content Div Collapses the Canvas to 150px

**What goes wrong:**
The R3F `Canvas` component sizes itself to 100% of its nearest `position: relative` or `position: absolute` ancestor. The current `PaneContainer` wraps content in a `motion.div` with `className="min-h-0 flex-1 overflow-auto"`. When a Canvas lives inside an `overflow-auto` div, the browser cannot compute a scrollable intrinsic height, so the canvas falls back to the browser's default inline element height — 150px. The scene renders at 150px regardless of how tall the pane actually is.

**Why it happens:**
CSS flex-shrink arithmetic with `overflow: auto` does not forward explicit heights to children the same way `overflow: hidden` does. R3F's internal ResizeObserver sees the scroll container's computed height as indeterminate and falls back to a fixed intrinsic value.

**How to avoid:**
3D pane tabs must override the `overflow-auto` wrapper by rendering a `position: absolute; inset: 0` host div, and the Canvas must live inside that absolute div. The route component for Observatory, Nexus, and ForensicsRiver should NOT be wrapped in the scrollable container — they should fill their parent via absolute positioning.

The cleanest pattern: each 3D route component starts with a `<div className="absolute inset-0">` shell — matching what `NexusCanvas.tsx` already does. The `PaneContainer` `motion.div` can keep `overflow-auto` for all text/list panes; 3D tabs opt out by being absolutely positioned children.

**Warning signs:**
- Canvas renders at exactly 150px height regardless of window size.
- Resizing the pane has no effect on the canvas height.
- The scene looks vertically squashed.

**Phase to address:**
Tier 2 (first R3F embed in a pane tab). Must be resolved before any Canvas lands in a route rendered by `PaneRouteRenderer`.

---

### Pitfall 2: Multiple `<Canvas>` Instances Exhaust WebGL Contexts (16-Context Browser Limit)

**What goes wrong:**
Browsers allow only 8-16 simultaneous WebGL contexts (Chrome/WebKit enforces a hard limit; the oldest context is silently destroyed when the limit is hit). The workbench will have up to four concurrent Canvas elements: Observatory tab, Nexus Hunt Deck tab, Forensics Tape tab (bottom pane), and the Mini Spirit Companion in the right sidebar. If the user splits panes and opens multiple 3D tabs, contexts accumulate and older views go black with `THREE.WebGLRenderer: Context Lost`.

**Why it happens:**
Each R3F `<Canvas>` creates its own `WebGLRenderer` and therefore its own WebGL context. The browser limit is per-tab (Chromium: 16, Safari: 8). This is a confirmed, known issue in R3F's GitHub issues for multi-canvas architectures.

**How to avoid:**
Establish a single root `<Canvas>` at the application shell level and use `@react-three/drei`'s `<View>` component (scissor-based sub-views) for the Mini Spirit Companion and any other small embedded canvas. The root Canvas uses `<View.Port />` and each embedded 3D element registers via `<View>`. This shares a single WebGL context across all 3D surfaces.

The ForensicsRiver uses `@backbay/glia-three/three` which may own its own Canvas — this must be audited before porting. If glia-three wraps its own Canvas, a portal adapter (using `createPortal` from R3F) or a refactored View-based render path will be needed.

The ActivityBar spirit orb is tiny enough that a CSS/SVG animation is preferable to a Canvas — avoiding an entirely new context for a 48px element.

**Warning signs:**
- Console warning: `THREE.WebGLRenderer: A WebGL context could not be created.`
- Console warning: `Too many active WebGL contexts. Oldest context will be lost.`
- A previously-open 3D tab goes black when a new one is opened.
- Visible in Chrome DevTools GPU tab as rising context count.

**Phase to address:**
Tier 1 architectural decision — must be resolved before writing any Canvas placement in the workbench. A single root Canvas approach must be established as the integration contract.

---

### Pitfall 3: Canvas Mount/Unmount on Tab Switch Causes Geometry Recompilation and Memory Spikes

**What goes wrong:**
The pane system renders only the active tab's route; inactive tabs are unmounted. When the user switches away from Observatory or Nexus and then back, R3F tears down the entire Three.js scene (disposing buffers, shader programs, geometries) and then recompiles everything from scratch on re-mount. This causes:
- Visible recompilation stutter (500ms+ freeze) on tab re-open.
- GPU shader compilation spikes.
- Potential memory fragmentation from repeated alloc/free cycles.

**Why it happens:**
`PaneContainer` keys its content `motion.div` on `activeView.route` and the underlying `PaneRouteRenderer` calls `useRoutes`. Route changes unmount the previous route component entirely. Three.js does not keep shader programs or geometries alive across WebGLRenderer context resets.

**How to avoid:**
Two strategies (pick one per component size):

1. **Visibility toggle instead of unmount** — keep the 3D tab mounted but CSS-hidden (`display: none` or `visibility: hidden`) when not active. R3F supports `frameloop="never"` to pause rendering while hidden. This preserves compiled shaders and GPU memory.

2. **Suspense + aggressive asset caching** — if unmount is unavoidable, ensure all geometries and materials are declared outside the Canvas component scope (module-level constants) so they survive the component lifecycle. Use `useLoader` for any texture assets; it caches by URL. Accept the recompile cost as a one-time expense per session.

For Observatory and Nexus (large scenes), strategy 1 is preferred. For ForensicsRiver in the bottom pane (likely always mounted as a tab), it is less critical.

**Warning signs:**
- Observable freeze when switching back to a 3D tab.
- Chrome DevTools Performance panel shows a large "Compile Shader" task on tab re-focus.
- GPU memory in chrome://gpu briefly spikes then drops and spikes again on re-open.

**Phase to address:**
Tier 2 (Observatory as pane tab). The visibility-over-unmount pattern must be established before the first full-scene pane tab.

---

### Pitfall 4: `useFrame` Writing to Zustand Triggers Full React Re-renders at 60fps

**What goes wrong:**
If animation code inside `useFrame` calls a Zustand setter (e.g., updating spirit position, orb state, or observatory camera coordinates in a store), it drives React's reconciler at 60fps. Every component subscribed to that store re-renders every frame, tanking keyboard responsiveness, CodeMirror performance, and all other IDE panels.

**Why it happens:**
`useFrame` runs outside React's scheduler but Zustand `set()` calls go through React's state update path, triggering synchronous re-renders. The official R3F pitfalls documentation explicitly calls this out: "Never setState in useFrame."

**How to avoid:**
Animation state that changes every frame must live in mutable refs, not in Zustand. Use `useRef` for per-frame values (camera position, orb pulse phase, particle positions). Zustand is the right home for stable state that changes on user action: spirit bound/unbound, observatory open/closed, selected nexus node. The boundary is: "does this value change at 60fps?" — if yes, use ref; if no, use Zustand.

For the spirit orb in the ActivityBar: drive the CSS animation via a CSS custom property updated by a `requestAnimationFrame` loop if needed, rather than a Zustand subscription.

**Warning signs:**
- React DevTools Profiler shows the entire workbench re-rendering every 16ms.
- CodeMirror editor input has visible lag while a 3D pane is open.
- `useFrame` callback contains calls to `useStore`, `set()`, or `dispatch()`.

**Phase to address:**
All tiers — this is a coding contract that must be established as a rule before any `useFrame` code is written.

---

### Pitfall 5: NexusStateContext (React Context Provider) Wrapping a Canvas Causes Context Isolation

**What goes wrong:**
R3F's custom renderer runs in a separate React reconciler context. Normal React context providers (like `NexusStateContext.Provider`) that wrap a `<Canvas>` do NOT automatically pass their values into the Three.js scene tree. Any component inside the Canvas that calls `useNexusState()` will throw "must be used within NexusStateProvider" or receive `null` even if the provider exists outside the Canvas.

**Why it happens:**
R3F is a separate React renderer instance. Context does not bridge between the host renderer and the R3F fiber renderer automatically.

**How to avoid:**
State shared between 3D components and the outside world must be managed either:
1. Via Zustand (Zustand stores are module-level singletons, not tied to React context trees) — this is already the project's primary state management approach.
2. Via R3F's `useThree` store for Three.js-specific state.
3. If React context is unavoidable, use `drei`'s `<context.bridge>` utilities or pass values as props to Canvas children.

The NexusStateContext is currently a `useReducer`-based React Context. For the workbench integration, its state should be migrated to the new `nexus-store.ts` Zustand store so it works naturally inside the Canvas.

**Warning signs:**
- Runtime error: "useNexusState must be used within NexusStateProvider" thrown from a component inside `<Canvas>`.
- Components inside Canvas receive stale or default context values.
- `useContext` returns `null` inside Three.js components.

**Phase to address:**
Tier 2 (Nexus Hunt Deck pane). The NexusStateContext-to-Zustand migration must happen before porting NexusCanvas into the workbench.

---

### Pitfall 6: OrbitControls Captures Pointer Events and Breaks Pane Mouse-Down Activation

**What goes wrong:**
The existing `NexusCanvas` uses `OrbitControls`. OrbitControls calls `element.setPointerCapture()` on pointer-down to handle drag orbiting. When the pane activation handler (`onMouseDownCapture` in `PaneContainer`) fires, the event has already been captured by OrbitControls and the pane's "set active" logic may conflict or fail. Users trying to click on a non-focused 3D pane to focus it may instead start an orbit drag.

**Why it happens:**
`PaneContainer.onMouseDownCapture` uses capture-phase handling to activate the pane. OrbitControls also uses pointer capture. The two capture handlers compete for the same initial pointer-down event on the canvas element.

**How to avoid:**
Detect when the active pane is being set via `onPointerDownCapture` before OrbitControls processes the event. One robust approach: gate OrbitControls pointer capture behind a check that the pane is already active. Alternatively, add `onPointerDown` to the Canvas wrapper that calls `usePaneStore.getState().setActivePane(pane.id)` before R3F's event system processes it — matching the pattern already used in `PaneContainer`.

**Warning signs:**
- Clicking on an inactive 3D tab starts a camera orbit on the inactive pane without activating it.
- Focused pane does not switch when clicking the 3D canvas.
- Pane border active indicator does not update when clicking the canvas area.

**Phase to address:**
Tier 2 (first full-pane 3D canvas). Must be addressed in the Canvas host wrapper component, not in OrbitControls itself.

---

### Pitfall 7: R3F `drei` `<Html>` Labels Escape Canvas Clipping and Overlay IDE Chrome

**What goes wrong:**
`NexusCanvas` uses `<Html>` from drei to render node labels (the origin-card divs). `<Html>` renders into a separate DOM portal that is positioned absolutely relative to the document, not the canvas. When the canvas is inside a pane tab, HTML labels may:
- Render outside the pane's bounding box and overlap the tab bar, sidebar, or bottom pane.
- Remain visible even when the pane is scrolled, hidden, or behind another pane.
- Intercept pointer events on IDE chrome elements that sit below them in DOM order.

**Why it happens:**
drei's `<Html>` portals to a div appended to the Canvas's parent (or `document.body`). It does not clip to the canvas bounds.

**How to avoid:**
Wrap the Canvas container in `overflow: hidden` (the `absolute inset-0` host div already does this, as long as it is a positioned container). Additionally, pass `occlude` prop to `<Html>` to hide labels when they are behind objects, and consider setting `portal={{ current: canvasHostDivRef.current }}` to constrain the portal to the pane's DOM subtree.

For the workbench integration, clip the canvas host div explicitly: `<div className="absolute inset-0 overflow-hidden">`.

**Warning signs:**
- Node labels visible outside the pane border lines.
- Clicking on empty IDE toolbar area triggers a 3D scene label interaction.
- Label elements visible in DOM outside the pane's DOM subtree.

**Phase to address:**
Tier 2 (Nexus Hunt Deck and Observatory pane tabs). Should be tested in the first 3D pane tab before the others.

---

### Pitfall 8: `@backbay/glia-three` RiverView Owns Its Own Canvas — Cannot be Trivially Embedded

**What goes wrong:**
`ForensicsRiverView` imports `RiverView as River` from `@backbay/glia-three/three`. Based on the usage pattern (it is the primary rendering element of the view), this package almost certainly renders its own internal `<Canvas>`. If so, embedding it in the bottom pane tab creates a second WebGL context (see Pitfall 2), and there is no guaranteed API to pass an external renderer or scissor-viewport into it.

**Why it happens:**
External packages that bundle their own Canvas cannot share the host application's WebGL context unless they expose a `gl` prop or a `frameloop`/`renderer` override interface. Most third-party 3D packages do not expose this.

**How to avoid:**
Before embedding ForensicsRiverView, audit the glia-three package source:
- If it exposes a `gl` prop or renders as a R3F child (using `useThree`), it can be placed inside the root Canvas as a child.
- If it renders its own Canvas, either fork/patch the component to accept an external renderer, or accept a second context and manage the total context count carefully to stay under the browser limit.

As a fallback: the Tape tab can render a simplified non-Canvas river visualization (SVG or canvas 2D) that approximates the visual without requiring WebGL.

**Warning signs:**
- `ForensicsRiverView` not rendering inside the workbench Canvas structure.
- Second `WebGLRenderer` instance visible in Three.js devtools or memory profiler.
- Context count increments when Tape tab is opened.

**Phase to address:**
Tier 2/3 boundary — must be investigated before committing to the ForensicsRiver bottom pane tab.

---

### Pitfall 9: CSS Spirit Field Stain Using `mix-blend-mode` or `backdrop-filter` Creates New Stacking Contexts That Break Z-Index

**What goes wrong:**
The spirit field stain is a CSS visual effect on panel backgrounds. If implemented using `backdrop-filter`, `mix-blend-mode`, or CSS `filter` properties, those properties create new CSS stacking contexts. This breaks any `z-index` layering within those panels: dropdown menus, tooltips, and popover command palettes that rely on high z-index values render below the effect layer, not above it.

**Why it happens:**
CSS `backdrop-filter`, `filter`, `transform`, and `will-change: transform` all create stacking contexts. Elements inside a stacking context cannot escape it with z-index — they are clipped to their stacking context's paint layer.

**How to avoid:**
Apply backdrop-filter or filter effects on a pseudo-element (`::before` or `::after`) or a dedicated sibling div positioned absolutely behind content, not on the content container itself. The content area remains a clean stacking context and dropdowns/modals layer correctly.

Alternatively, use CSS custom properties to blend color into the background without creating stacking contexts — e.g., a translucent color overlay using `background: color-mix(...)` or a radial gradient with low opacity.

**Warning signs:**
- Command palette or dropdown menus render behind panel backgrounds.
- `z-index: 9999` on a tooltip has no effect when inside a spirit-stained panel.
- Chrome DevTools Layer panel shows unexpected composite layers around spirit-stained areas.

**Phase to address:**
Tier 1 (CSS spirit stain drop-in). Must be validated before moving to Tier 2, because Tier 2 adds more complex layering.

---

### Pitfall 10: Zustand Spirit/Observatory Stores Subscribing to Keyboard Commands Cause Stale Closure Captures

**What goes wrong:**
The command registry uses `createSelectors` and binds commands like `spirit.bind`, `observatory.open` at registration time. If the command handler is a closure that captures Zustand state at registration time (not at invocation time), it will call `bind()` with the spirit state as it was when the command was registered, not the current state. This results in commands that appear to work once and then do nothing on subsequent invocations.

**Why it happens:**
Commands registered with a closure that reads store state via a captured selector will not see state updates made after registration. This is a classic stale closure problem amplified by Zustand's selector pattern.

**How to avoid:**
Command handlers must call `useStore.getState()` (the imperative accessor) at invocation time, not closure-capture state. Pattern:

```typescript
// Wrong — captures state at registration time:
const spiritState = useSpiritStore.use.spirit();
registry.register("spirit.bind", () => bindSpirit(spiritState));

// Correct — reads current state at invocation time:
registry.register("spirit.bind", () => {
  const spirit = useSpiritStore.getState().spirit;
  useSpiritStore.getState().bindSpirit(spirit);
});
```

**Warning signs:**
- A command works the first time but does nothing on subsequent invocations.
- Command behavior reflects state from when the app was loaded, not current state.
- Console logging inside the command handler shows stale values.

**Phase to address:**
Tier 1 (new command registrations: observatory.open, spirit.bind, etc.).

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| One Canvas per 3D tab instead of root Canvas + Views | Simpler initial integration | Hits browser's 8-16 context limit when 3+ tabs open simultaneously; contexts lost silently | Never — the limit is hard and Tauri uses WebKit which has an 8-context limit |
| Keep NexusStateContext as React Context instead of migrating to Zustand | Less refactor work | Context does not bridge into Canvas; 3D components cannot read nexus state | Never for state consumed inside Canvas |
| Leaving `overflow-auto` on pane content div when 3D tabs render | No CSS changes needed | Canvas locks to 150px height | Never for full-viewport 3D panes |
| CSS spirit stain using `backdrop-filter` directly on container | Easy one-liner | Creates stacking context; breaks dropdown z-index | Acceptable only if confirmed that no z-indexed overlays exist in that panel subtree |
| Skipping `dispose()` on geometry/materials in R3F components | Less cleanup code | GPU memory accumulates; eventual performance degradation or OOM on long sessions | Never for ShaderMaterial or BufferGeometry created with `new` |
| Using React `useState` for per-frame animation values (orb pulse, particle positions) | Matches React patterns | Triggers reconciler at 60fps; all store subscribers re-render every frame | Never |

---

## Integration Gotchas

| Integration Point | Common Mistake | Correct Approach |
|-------------------|----------------|------------------|
| NexusCanvas inside PaneRouteRenderer | Placing Canvas inside `overflow-auto` motion.div | Render `<div className="absolute inset-0">` as first child of the route component; Canvas fills it |
| NexusStateContext + Canvas | Using useNexusState() inside Canvas children | Migrate Nexus state to Zustand `nexus-store.ts`; read via `useNexusStore` inside and outside Canvas |
| Spirit orb in 48px ActivityBar | Creating a new `<Canvas>` for a 48px element | Use a CSS/SVG animation or a `<View>` inside the root Canvas via a portal div in the ActivityBar |
| Mini spirit companion in right sidebar | New `<Canvas frameloop="always">` in sidebar | Root Canvas + `<View frames={1}>` tracking the sidebar div; `frameloop="demand"` with `invalidate()` |
| ForensicsRiver bottom pane tab | Blindly mounting `<ForensicsRiverView>` | Audit glia-three for own Canvas; if found, either accept second context or fork to accept external renderer |
| Command registry + new stores | Closure-capturing Zustand state in handlers | All command handlers call `getState()` at invocation, not at registration |
| OrbitControls + pane activation | No special handling needed | Ensure `onPointerDownCapture` on Canvas wrapper calls `setActivePane` before OrbitControls captures |

---

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| `useFrame` calling Zustand `set()` | 60fps React reconciler churn; CodeMirror lag; entire workbench re-renders on every frame | Use mutable refs for per-frame values; Zustand only for user-action-triggered state | Immediately visible with any animation that writes to a Zustand store per frame |
| `new THREE.Vector3()` inside `useFrame` | GC pauses every few seconds; stuttering animation | Declare Vector3 in component scope; use `.set()` to reuse | Subtle; gets worse over time with longer sessions |
| `frameloop="always"` on hidden/inactive tabs | CPU/GPU spinning when Observatory tab not visible | Set `frameloop="demand"` for demand-driven scenes; use `visibility change` events to pause | Any time the user works in a non-3D pane with a 3D pane open elsewhere |
| Remounting full scene on every tab switch | 500ms+ freeze on re-open; shader recompilation | Keep 3D panes CSS-hidden when inactive; never rely on route unmount for cleanup | Every tab switch to/from 3D pane |
| Multiple `<Canvas>` components live simultaneously | Oldest context goes black when context limit hit | Root Canvas + View architecture; one context total | When 3+ 3D tabs are open at the same time (common in a split-pane IDE) |
| `<Html>` labels without `occlude` or portal override | Labels float over IDE chrome (tab bar, status bar) | `overflow: hidden` on canvas host; `portal` prop to constrain to pane subtree | Any time the pane is not full-height or the canvas has sibling elements above it in z-order |

---

## "Looks Done But Isn't" Checklist

- [ ] **Canvas height:** Verify the 3D pane fills the full pane area by resizing the pane splitter — if canvas stays 150px, the overflow-auto container was not removed.
- [ ] **Context count:** Open all 3D tabs simultaneously and check the console for "Context Lost" warnings — if any appear, the multi-Canvas architecture must be fixed before shipping.
- [ ] **Tab switch stutter:** Switch between Observatory and a text pane 5 times rapidly — if there is a freeze on re-enter, the visibility-not-unmount strategy is needed.
- [ ] **useFrame + store writes:** Search all `useFrame` callbacks for any call that ends in `set()`, `setState()`, or a Zustand action — these must be replaced with ref mutations.
- [ ] **Spirit stain z-index:** Open the command palette while a spirit-stained panel is visible — if the palette renders behind the panel, a stacking context was created.
- [ ] **Spirit orb WebGL budget:** With all 3D tabs open, confirm the spirit orb still animates — if it stopped, it exceeded the context budget.
- [ ] **Nexus context in Canvas:** After migration, open Nexus tab and verify node labels render with correct names — if they show defaults, context bridging failed.
- [ ] **ForensicsRiver context count:** Open Tape tab and check Three.js memory stats — if a second renderer appears, glia-three created its own Canvas.
- [ ] **Command stale closure:** Call `spirit.bind` twice in the same session with different spirits — if the second call applies the first spirit, the stale closure pitfall was hit.
- [ ] **OrbitControls pane activation:** Click on an inactive Nexus pane — confirm the pane activates (border highlights) before the camera starts orbiting.

---

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| overflow-auto canvas height stuck | LOW | Add `absolute inset-0` wrapper div inside the 3D route component; no changes to PaneContainer |
| Multiple Canvas context exhaustion | MEDIUM | Establish root Canvas at App shell level; convert embedded canvases to `<View>` portals; audit glia-three |
| Tab switch recompile stutter | MEDIUM | Add CSS visibility toggle to PaneContainer keyed on whether route is a 3D route; keep component mounted |
| useFrame Zustand write at 60fps | LOW | Move animation values to `useRef`; only call Zustand setters from user event handlers |
| Context isolation for NexusStateContext | MEDIUM | Migrate nexusReducer state to `nexus-store.ts` Zustand; replace `useNexusState()` calls inside Canvas with Zustand hook |
| Html labels escaping pane | LOW | Add `overflow: hidden` to canvas host div; add `portal` prop to `<Html>` components |
| Stale command closure | LOW | Replace captured state with `getState()` calls in all new command handlers |
| Spirit stain stacking context | LOW | Move `backdrop-filter` or `filter` to a `::before` pseudo-element on the panel |

---

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| overflow-auto canvas height collapse | Tier 2 — first 3D pane tab | Pane resize test; canvas fills full pane height |
| Multiple Canvas context exhaustion | Tier 1 architectural contract | All 3D tabs open simultaneously; no "Context Lost" in console |
| Tab switch scene recompile stutter | Tier 2 — Observatory as pane tab | Switch 5x rapidly; no visible freeze |
| useFrame writing Zustand at 60fps | All tiers — coding contract | React DevTools Profiler shows no 60fps render cycles |
| NexusStateContext isolation in Canvas | Tier 2 — Nexus Hunt Deck tab | Nexus node labels render correct names |
| OrbitControls vs pane activation | Tier 2 — first Canvas with OrbitControls | Click inactive Nexus pane: pane activates before orbit starts |
| Html labels escaping pane bounds | Tier 2 — Nexus tab | Labels clipped at pane border; not visible over IDE chrome |
| glia-three ForensicsRiver own Canvas | Tier 2/3 boundary investigation | Three.js devtools show only one renderer in memory |
| CSS spirit stain stacking context | Tier 1 — CSS spirit stain drop-in | Command palette renders above spirit-stained panel |
| Stale command closure in new stores | Tier 1 — new Zustand stores + commands | Call spirit.bind twice; second call reflects current state |

---

## Sources

- [R3F Performance Pitfalls (official)](https://r3f.docs.pmnd.rs/advanced/pitfalls) — authoritative, HIGH confidence
- [R3F Scaling Performance (official)](https://r3f.docs.pmnd.rs/advanced/scaling-performance) — authoritative, HIGH confidence
- [drei View component docs](https://drei.docs.pmnd.rs/portals/view) — authoritative, HIGH confidence
- [Leaking WebGLRenderer on unmount — Issue #514](https://github.com/pmndrs/react-three-fiber/issues/514) — HIGH confidence
- [Leaking WebGLRenderer — Issue #3093](https://github.com/pmndrs/react-three-fiber/issues/3093) — HIGH confidence
- [Too many active WebGL contexts on Safari — Discussion #2457](https://github.com/pmndrs/react-three-fiber/discussions/2457) — HIGH confidence
- [Multiple canvas in a component — Discussion #2716](https://github.com/pmndrs/react-three-fiber/discussions/2716) — HIGH confidence
- [Canvas resize delayed after container resize — Issue #2149](https://github.com/pmndrs/react-three-fiber/issues/2149) — HIGH confidence
- [State management without restarting render loop — Discussion #2080](https://github.com/pmndrs/react-three-fiber/discussions/2080) — HIGH confidence
- [Tauri + R3F WebGL context issues — Issue #6559](https://github.com/tauri-apps/tauri/issues/6559) — MEDIUM confidence (Tauri-specific; issue may be version-dependent)
- Direct codebase inspection: `PaneContainer`, `NexusCanvas`, `NexusStateContext`, `ActivityBar`, `ForensicsRiverView`, `GlyphSentinel`, `GroundPlatform` — HIGH confidence

---

*Pitfalls research for: R3F 3D features in VS Code-like IDE workbench (huntronomer-workbench)*
*Researched: 2026-03-18*
