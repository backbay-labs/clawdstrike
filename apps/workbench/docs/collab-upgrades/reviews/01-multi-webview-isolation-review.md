# Review: 01 -- Multi-Webview Tile Isolation

**Reviewer:** Systems Architecture Review
**Date:** 2026-03-25
**Spec version reviewed:** Draft, 2026-03-25

---

## Verdict: NEEDS REWORK

The spec demonstrates strong domain knowledge of both the target codebase and the
collab-public reference architecture. The problem statement is real, and the phased
migration approach is sensible. However, the spec contains multiple API errors that
would cause the Rust code to fail to compile, underestimates the severity of the
React Flow coordinate synchronization problem, and does not adequately address the
fundamental architectural mismatch between native overlay webviews and a React Flow
canvas. The spec also omits simpler alternatives that should be evaluated before
committing to a 5-week native webview approach.

---

## 1. Factual Accuracy

### 1.1 WRONG: Tauri Rust API -- `get_window` does not exist in Tauri v2

The proposed `create_tile_webview` command (Section 3.1, spec line ~209) uses:

```rust
let main_window = app.get_window("main")
    .ok_or("main window not found")?;
```

In Tauri v2 (the project uses v2.10.3 per `Cargo.lock`), the correct method is
`app.get_webview_window("main")`. The existing codebase already uses the correct
API at `main.rs:47`:

```rust
if let Some(window) = app.get_webview_window("main") {
```

`get_window` was the Tauri v1 API. This would fail to compile.

### 1.2 WRONG: `Window::add_child` does not exist in Tauri v2

The spec's proposed code (Section 3.1, spec line ~222) calls:

```rust
let _webview = main_window.add_child(
    tauri::webview::WebviewBuilder::new(...)
        .auto_resize(),
    tauri::LogicalPosition::new(x, y),
    tauri::LogicalSize::new(width, height),
).map_err(|e| e.to_string())?;
```

The Tauri v2 API for adding child webviews to a window is
`Window::add_child()` which does exist in the multi-webview feature, but:

- The `tauri` crate must have the `"unstable"` feature enabled. The current
  `Cargo.toml` specifies `tauri = { version = "2", features = [] }` -- no
  features at all. Multi-webview support is gated behind the `"unstable"`
  feature flag in Tauri v2.
- `WebviewBuilder::auto_resize()` does not exist. The correct approach is to
  manually manage position and size via `Webview::set_position()` /
  `Webview::set_size()`.
- The return type of `add_child` would need verification against the actual
  Tauri 2.10.3 API surface; the method signature may differ from what the
  spec assumes.

**Impact:** The entire Rust backend proposal (Phase 0 deliverable) needs to be
rewritten against the actual Tauri v2 multi-webview API. This should be
prototyped before the spec is finalized.

### 1.3 WRONG: PTY event name format

Section 5.4 states:

> The Rust backend emits `terminal_output_{sessionId}` events

The actual event name format uses colons, not underscores:
`terminal:output:{sessionId}` (see `terminal.rs:530`). The TypeScript side also
uses this format (`terminal-service.ts:140`):

```ts
listen<string>(`terminal:output:${sessionId}`, ...)
```

This is a minor doc error but matters for the IPC protocol specification.

### 1.4 CORRECT: TerminalRenderer uses ghostty-web, not xterm.js

The spec correctly identifies `TerminalRenderer` as using ghostty-web. Verified
at `terminal-renderer.tsx:12`:

```ts
import { init as initGhostty, Terminal, FitAddon } from "ghostty-web";
```

However, there is a nuance the spec misses: the spec says "ghostty-web WASM"
and "canvas rendering" throughout. The actual `TerminalRenderer` creates a
`Terminal` instance from `ghostty-web` which does use WASM internally, but the
rendering model needs to be confirmed -- ghostty-web may use WebGL or canvas2d.
This matters because WebGL contexts are limited per page (typically 8-16),
which could be a **more fundamental** scaling limitation than memory pressure.

### 1.5 CORRECT: MAX_ACTIVE_TERMINALS = 8

Confirmed at `swarm-board-store.tsx:45`:
```ts
export const MAX_ACTIVE_TERMINALS = 8;
```

The spec also correctly notes this is defined in `swarm-board-store.tsx`, not
`swarm-board-page.tsx`. The spec says "swarm-board-store.tsx" which is accurate.

### 1.6 CORRECT: Scrollback = 1000

Confirmed at `terminal-renderer.tsx:123`:
```ts
scrollback: 1000,
```

### 1.7 CORRECT: collab-public reference file paths and line numbers

Spot-checked the following claims:

| Claim | Actual |
|-------|--------|
| `tile-manager.js:26` has `tileDOMs` Map | Line 26: `const tileDOMs = new Map();` -- confirmed |
| `tile-manager.js:28` has `focusedTileId` | Line 28: `let focusedTileId = null;` -- confirmed |
| `tile-manager.js:168` has `spawnTerminalWebview` | Line 168: `function spawnTerminalWebview(tile, autoFocus = false) {` -- confirmed |
| `tile-manager.js:213` has `spawnGraphWebview` | Line 213: `function spawnGraphWebview(tile) {` -- confirmed |
| `tile-manager.js:236` has `spawnBrowserWebview` | Line 236: `function spawnBrowserWebview(tile, autoFocus = false) {` -- confirmed |
| `tile-manager.js:376` has `render-process-gone` | Line 376: `wv.addEventListener("render-process-gone", () => {` -- confirmed |
| `tile-manager.js:398` has `createCanvasTile` | Line 398: `function createCanvasTile(type, cx, cy, extra = {}) {` -- confirmed |
| `canvas-state.js:20` has tiles array | Line 20: `export const tiles = [];` -- confirmed |
| `index.ts:274` has `applyZoomToAll` | Line 274: `function applyZoomToAll(level: number): void {` -- confirmed |
| `index.ts:261` has `did-attach-webview` | Line 261: `win.webContents.on("did-attach-webview", ...)` -- confirmed |
| `index.ts:475` has `shell:get-view-config` | Line 475: `ipcMain.handle("shell:get-view-config", () => {` -- confirmed |

The reference architecture section is thorough and accurate.

### 1.8 PARTIALLY WRONG: `tile-manager.js:129-134` for sendInputEvent

The spec says "a synthetic mouse click is forwarded via `sendInputEvent`
(`tile-manager.js:129-134`)." The actual lines are 129-134 in the function body,
but the `sendInputEvent` calls span lines 129-133. This is close enough to not
be misleading.

### 1.9 WRONG: `tile-manager.js:523` for createFileTile

The spec says: "`createFileTile(type, cx, cy, filePath)` (`tile-manager.js:523`)"
-- actual line 523 is `function createFileTile(type, cx, cy, filePath)` -- confirmed.
But the spec lists this as part of "Type-specific webview spawning" in Section 2.2
bullet 2, alongside `spawnTerminalWebview`, `spawnGraphWebview`, and
`spawnBrowserWebview`. `createFileTile` is not a webview-spawning function -- it
is a tile creation function (listed under "Tile CRUD" in the source). It does
spawn webviews internally, but conflating it with the `spawn*Webview` functions
is slightly misleading.

### 1.10 MISSING: The CSP claim is incomplete

Section 3.4 says:

> The current CSP in `tauri.conf.json` restricts to `default-src 'self'`.

The actual CSP at `tauri.conf.json:31` is significantly more permissive:

```
default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: asset: https://asset.localhost; connect-src ipc: http://ipc.localhost
```

This matters because child webviews inherit the parent window's CSP by default
in Tauri. The `connect-src ipc: http://ipc.localhost` directive may need to be
verified for child webview IPC. Also, if tile webviews need to load from
`http://localhost:1421/tile/terminal.html` during dev (as Section 7.6 suggests),
the CSP's `connect-src` and `default-src` would block that.

---

## 2. Feasibility

### 2.1 Tauri Multi-Webview: It exists but is gated behind `unstable`

Tauri v2 does support multiple webviews in a single window. However, this feature
requires the `"unstable"` feature flag on the `tauri` crate. The project currently
uses `tauri = { version = "2", features = [] }`.

Adding `features = ["unstable"]` is a conscious decision that opts into APIs that
may change between Tauri minor versions. This is a real risk for a production app
and should be called out explicitly in the spec's risk section.

### 2.2 WKWebView Process Isolation: Weaker Than Implied

Section 3.5 correctly notes that WKWebView shares a process pool. But the spec
then says "Tauri's error handling will detect the failure." This is optimistic.
WKWebView's process crash handling is:

- `WKNavigationDelegate.webViewWebContentProcessDidTerminate()` fires when the
  web content process crashes.
- Tauri v2 does not currently expose this delegate method as an event to the
  frontend. You would need a custom Tauri plugin to hook into it.

This means **crash isolation on macOS -- the primary stated goal of this spec --
may not work out of the box**. The spec should have a concrete plan for detecting
child webview crashes on macOS, not just a vague reference to "Tauri's error
handling."

### 2.3 rAF Polling for Coordinate Sync: Viable But Expensive

The spec proposes calling `getBoundingClientRect()` + IPC `reposition()` on every
animation frame for every isolated tile. For 8 tiles at 60fps, that is:

- 480 `getBoundingClientRect()` calls/second (triggers layout recalc in some cases)
- 480 IPC round-trips/second (JS -> Rust -> native compositor)

This is technically feasible but will consume meaningful CPU. The batched
reposition command (Section 4.4) helps with IPC, but the `getBoundingClientRect()`
calls still force synchronous layout. The spec should recommend
`IntersectionObserver` for visibility detection and only poll position for
visible tiles.

---

## 3. Architecture Gaps

### 3.1 CRITICAL: React Flow Edges Are Rendered Below Native Overlays

Section 7.3 states:

> Edges: React Flow renders edges in an SVG layer below nodes. Edges connecting
> to isolated nodes will be visible because they are below the node chrome.

This is incorrect reasoning. React Flow renders edges in an SVG/HTML layer that
is part of the DOM. Native webview overlays are composited by the OS window
manager **on top of all DOM content**. This means:

- Edges connecting to/from isolated nodes will be **hidden behind** the overlay
  webview of the target/source node.
- Animated edges (e.g., the `spawned` edge type with `animated: true`) will be
  invisible where they pass under an overlay.
- The edge's connection point (Handle) is rendered as part of the React Flow
  node DOM, but the edge line itself extends into the SVG layer, which is
  behind the overlay.

This is a fundamental visual regression. Every edge connecting to an agent
session node will appear to "go behind" the terminal content, creating a broken
visual. The spec needs a mitigation strategy, such as:

- Rendering edge segments as part of the node chrome layer (above the overlay)
- Using transparent inset padding on the overlay so edges have a visible margin
- Re-rendering affected edge segments as native overlay decorations

### 3.2 CRITICAL: React Flow Drag Preview Will Break

When a user drags an isolated node, React Flow updates the node's CSS transform.
The overlay webview repositioning lags by at least one frame (IPC round-trip).
During drag, this means:

- The node chrome (title bar, handles, footer) moves smoothly via CSS transform
- The overlay webview stutters 1-2 frames behind

This creates a very noticeable visual glitch. The collab-public reference does
NOT have this problem because its webviews are DOM elements (`<webview>` tags)
that participate in the same layout/rendering pipeline. Native overlay webviews
do not.

The spec mentions hiding webviews during "fast zoom gestures" (Section 7.2) but
does not address the drag case, which is far more common. **Hiding the overlay
during drag would mean the terminal goes blank every time the user repositions
a node.** This is a significant UX regression.

### 3.3 React Flow Selection Rectangle

The spec mentions hiding webviews during marquee selection (Section 4.3, bullet
3) but does not specify how to detect marquee start/end. React Flow does not
expose a `onSelectionStart`/`onSelectionEnd` callback. You would need to:

- Monitor `onSelectionChange` (which fires after selection, not during drag)
- Use a `mousedown` listener on the selection key (Shift) + pane to detect
  selection start
- Track the `selectionKeyCode` state manually

This is doable but non-trivial and should be specified.

### 3.4 Accessibility Is Not Addressed

The spec does not mention accessibility at all. Separate native webviews are
opaque to screen readers -- the main webview's accessibility tree cannot
"see into" child webviews. This means:

- Terminal content in isolated webviews is invisible to VoiceOver/NVDA
- Users cannot tab-navigate from the React Flow canvas into terminal content
  smoothly
- ARIA live regions in the main canvas cannot announce terminal activity from
  child webviews

Given that this is a security tool (Clawdstrike), accessibility may be a
compliance requirement.

### 3.5 Capability Permissions for Child Webviews

The current `capabilities/default.json` grants permissions only to
`"windows": ["main"]`. Child webviews created dynamically with labels like
`"tile-abc123"` will NOT have any Tauri command permissions by default.

The spec needs to address:

- Adding a `"webviews": ["tile-*"]` glob pattern to the capabilities config
  so child webviews can invoke `terminal_write`, `terminal_resize`, etc.
- Alternatively, restricting child webview capabilities to a subset (e.g.,
  terminal commands only, no stronghold or fs access) for defense in depth.

Without this, the tile webviews will get "permission denied" errors on every
Tauri invoke call. This is a **blocking** gap for Phase 1.

### 3.6 WebGL Context Limits

If ghostty-web uses WebGL for rendering (common for high-performance terminal
emulators), there is a browser-level limit on WebGL contexts. Typical limits:

- Chrome/WebView2: 16 contexts per page
- WebKit/WKWebView: 8 contexts per process pool

With isolated webviews, each terminal gets its own context budget, which is
actually better than in-tree. But if WKWebView shares a process pool (Section
3.5), the 8-context limit may still apply across all child webviews. This
should be investigated.

---

## 4. Scope Creep Risk

### 4.1 The Phased Plan Is 5 Weeks for a Feature That May Not Be Needed

The timeline is:
- Phase 0: 1 week (infrastructure)
- Phase 1: 2 weeks (isolated terminals)
- Phase 2: 1 week (isolated viewers)
- Phase 3: 1 week (optimization)

Five weeks of engineering for process isolation. But the spec's own problem
statement cites three liabilities:

1. **Fault propagation:** The existing `SwarmBoardErrorBoundary` already catches
   render errors. The real issue is that it kills the whole canvas. A
   per-node error boundary (wrapping each `AgentSessionNode`) would solve 90%
   of this for approximately 2 days of work.

2. **Memory pressure:** Eight ghostty-web instances may hit 2GB. But the Rust
   backend already has `MAX_ACTIVE_SESSIONS = 32` (terminal.rs:45) and the
   frontend caps at `MAX_ACTIVE_TERMINALS = 8`. The real fix may be reducing
   scrollback from 1000 to 200 (matching the Rust ring buffer), recycling
   idle terminal instances, or switching to a lighter terminal renderer for
   unselected nodes.

3. **Security boundary:** The spec says "a malicious command output rendered by
   one terminal's WASM parser could theoretically exploit the shared context."
   This is a theoretical concern -- ghostty-web's WASM sandbox already provides
   memory isolation. A WASM module cannot access JS heap objects outside its
   own linear memory. The real security risk is that all webview JS has access
   to `__TAURI_INTERNALS__`, but this is true of child webviews too (they get
   the same IPC bridge).

### 4.2 Phase 2 Is Premature

The spec says Phase 2 isolates artifact and diff nodes, but then notes these
are currently "just file icon + name" and "just +/- summary." Specifying
isolation for nodes that have no heavy content is scope creep by definition.
Phase 2 should be removed from this spec and addressed if/when those nodes
gain complex content.

---

## 5. Alternative Approaches Not Considered

### 5.1 Per-Node Error Boundaries (Simplest, ~2 days)

Wrap each `AgentSessionNode` (and `TerminalRenderer`) in its own React error
boundary. When a terminal crashes, that node shows "Terminal crashed. Click to
restart." The rest of the canvas is unaffected.

This solves the fault propagation problem entirely without any native webview
complexity. The existing `SwarmBoardErrorBoundary` already demonstrates the
pattern -- it just needs to be applied at the node level instead of the canvas
level.

```tsx
// In nodes/index.ts, wrap the component:
agentSession: withNodeErrorBoundary(AgentSessionNode),
```

### 5.2 iframe Isolation (Moderate, ~1-2 weeks)

Use `<iframe sandbox="allow-scripts allow-same-origin">` elements within React
Flow nodes. Each terminal tile loads a separate HTML page in an iframe. This
provides:

- **Process isolation** (iframes get separate renderer processes in modern
  browsers/webviews, depending on origin)
- **Crash isolation** (an iframe crash does not affect the parent)
- **DOM isolation** (separate JS context)

Crucially, iframes are DOM elements, so they:
- Participate in React Flow's coordinate system natively
- Are clipped, scrolled, and transformed with the parent
- Do not have the z-index overlay problem
- Do not require IPC for repositioning

The downsides are: Tauri's single-origin model means iframes would need
`srcdoc` or blob URLs (no separate origin = weaker security isolation), and
iframe-to-parent communication uses `postMessage` instead of Tauri events.

But for the stated goals of fault isolation and memory pressure reduction,
iframes are significantly simpler than native webview overlays.

### 5.3 Terminal Instance Recycling (Simplest for memory, ~3 days)

The memory pressure problem can be addressed without any isolation by:

- Only mounting `TerminalRenderer` (ghostty-web) for the selected node and
  its immediate neighbors
- For all other nodes, rendering a static text preview from the ring buffer
  (the `previewLines` fallback path already exists in `agent-session-node.tsx`
  lines 232-274)
- Reconnecting the terminal to the PTY session when the node is selected

This reduces the number of live ghostty-web instances from 8 to 1-3 at any
given time. The PTY sessions continue running in the Rust backend; only the
rendering frontend is multiplexed.

### 5.4 Web Workers for Terminal Parsing (Does Not Apply)

The spec's problem is about rendering, not parsing. Web Workers with
OffscreenCanvas could theoretically move terminal rendering off the main
thread, but ghostty-web already handles this internally via WASM. This
alternative does not meaningfully address the stated problems.

---

## 6. Dependency Risks

### 6.1 Tauri `unstable` Feature Flag

Multi-webview requires `features = ["unstable"]`. This means:
- API may change between Tauri 2.10.x and 2.11.x
- Bugs in the multi-webview path may be less thoroughly tested
- Upgrading Tauri becomes riskier (must verify multi-webview still works)

### 6.2 Platform-Specific Behavior

The spec acknowledges platform differences but underestimates them:

- **macOS:** WKWebView shares process pool. Crash isolation is not guaranteed.
  The `WKProcessPool` configuration is not exposed by Tauri.
- **Windows:** WebView2 requires Edge runtime. Multi-webview with separate
  processes requires custom `EnvironmentOptions`. Tauri does not expose this.
- **Linux:** WebKitGTK is the weakest performer. Creating multiple WebKitWebView
  instances is slow (~200-500ms each) and memory-heavy (~50-80MB each).

### 6.3 ghostty-web Compatibility in Child Webviews

ghostty-web initializes WASM and potentially WebGL. In a child webview, the
WASM binary must be loadable (CSP must allow `wasm-unsafe-eval`, which the
current CSP does). But the child webview loads a different HTML entry point,
so the WASM binary path resolution may differ. This needs testing.

### 6.4 Vite Multi-Page Build Complexity

The spec proposes adding three additional HTML entry points to the Vite build.
This means:
- Shared dependencies (React, Tailwind, ghostty-web) are bundled into each
  entry point separately unless code-splitting is configured
- Dev server must serve multiple entry points (Vite supports this but HMR
  for child webview content requires separate WebSocket connections)
- Build time increases proportionally to the number of entry points

---

## 7. Specific Technical Issues

### 7.1 The `reposition` Command Uses f64, Should Use Physical Pixels

The proposed command uses `tauri::LogicalPosition::new(x, y)` with `f64`
values from `getBoundingClientRect()`. On high-DPI displays, logical and
physical pixel coordinates diverge. `getBoundingClientRect()` returns CSS
pixels (logical), which is correct for `LogicalPosition`. However, the spec
does not account for the possibility that the main webview's DPI scale differs
from the child webview's scale factor, which can happen on multi-monitor setups
with different DPI. Tauri converts logical to physical internally, but the
source coordinates must be in the same coordinate space.

### 7.2 The Batch Reposition Command Swallows Errors

Section 4.4's `batch_reposition_tile_webviews` uses `let _ =` to discard
individual reposition errors:

```rust
let _ = webview.set_position(...);
let _ = webview.set_size(...);
```

If a webview was destroyed between the JS call and the Rust handler (race
condition during rapid node deletion), this silently fails. The command should
collect and return errors, or at minimum log them.

### 7.3 No Lifecycle Cleanup for Orphaned Webviews

If the React component unmounts (e.g., route change away from SwarmBoard)
without explicitly destroying all tile webviews, the native webviews remain
alive and consuming resources. The spec does not address cleanup during:

- Route navigation away from SwarmBoardPage
- Window close
- Error boundary activation (the `SwarmBoardErrorBoundary` renders an error
  message, but the overlay webviews are still alive behind it)

---

## 8. What the Spec Does Well

- The reference architecture analysis (Section 2) is excellent. Line-number
  references to collab-public are verified and accurate.
- The IPC design (Section 5) correctly identifies that Tauri events are
  app-global, making PTY data routing simpler than Electron's model.
- The phased rollout with in-tree fallback is the right approach.
- The "What Stays In-Tree" table (Section 6) makes the right calls about
  which node types need isolation.
- The risk section (Section 7) identifies real issues, even if the mitigations
  are sometimes hand-wavy.

---

## 9. Recommendations

1. **Prototype the Tauri multi-webview API first.** Before committing to this
   spec, build a minimal proof-of-concept: create one child webview, position
   it over a React Flow node, drag the node, and measure the lag. If the drag
   jank is unacceptable (>2 frames), the entire approach is compromised.

2. **Implement per-node error boundaries immediately.** This is a 2-day win
   that solves the most user-visible problem (canvas crash) regardless of
   whether webview isolation is pursued. It should be split out of this spec
   and shipped independently.

3. **Implement terminal instance recycling.** Only mount ghostty-web for
   selected/active nodes. This addresses memory pressure without any
   architectural changes.

4. **If proceeding with webview isolation:**
   - Fix the Rust API calls (`get_webview_window`, not `get_window`)
   - Add the `"unstable"` feature to `Cargo.toml` and verify the
     `add_child` API signature against Tauri 2.10.3 source
   - Add `"webviews": ["tile-*"]` to `capabilities/default.json`
   - Design the edge rendering solution before Phase 1 (Section 3.1 above)
   - Design the drag-sync solution before Phase 1 (Section 3.2 above)
   - Remove Phase 2 from this spec (premature)
   - Add a "crash detection on macOS" spike to Phase 0

5. **Evaluate iframe isolation as the middle ground.** It solves fault isolation
   and DOM isolation without the coordinate sync nightmare. Write a comparison
   section in the spec.

---

## Summary of Blocking Issues

| # | Issue | Severity | Section |
|---|-------|----------|---------|
| 1 | `get_window` does not exist in Tauri v2; code will not compile | Blocking | 1.1 |
| 2 | `Window::add_child` requires `unstable` feature; not enabled | Blocking | 1.2 |
| 3 | Capability permissions not granted to child webviews (`tile-*`) | Blocking | 3.5 |
| 4 | React Flow edges hidden behind native overlays; no mitigation | High | 3.1 |
| 5 | Node drag causes visible overlay lag; no mitigation for common case | High | 3.2 |
| 6 | macOS crash detection not exposed by Tauri; core goal may not work | High | 2.2 |
| 7 | Simpler alternatives (error boundaries, instance recycling) not evaluated | Process | 5.1, 5.3 |
