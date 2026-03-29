# 01 — Multi-Webview Tile Isolation

Technical specification for bringing process-isolated webview tiles from the
Collaborator project into the Clawdstrike Swarm Board.

**Status:** Shelved (see [ADR-001](ADR-001-multi-webview-isolation-deferred.md))
**Author:** Engineering
**Date:** 2026-03-25

---

## 1. Problem Statement

The Swarm Board (`swarm-board-page.tsx`) renders every node — agent sessions,
terminals, artifacts, diffs, notes, receipts — in a single React tree inside one
Tauri `WebviewWindow` (label `"main"`). All six custom node types registered in
`nodes/index.ts` are plain React components mounted by React Flow:

```
ReactFlowProvider
  └─ SwarmBoardCanvas
       └─ <ReactFlow nodeTypes={swarmBoardNodeTypes} />
            ├─ AgentSessionNode  ← embeds <TerminalRenderer /> (ghostty-web WASM)
            ├─ AgentSessionNode
            ├─ TerminalTaskNode
            ├─ NoteNode
            ├─ ReceiptNode
            └─ ...
```

This single-tree architecture creates three concrete liabilities:

### 1.1 Fault Propagation

A crash inside any node component — particularly `TerminalRenderer` (which loads
ghostty-web WASM, does canvas rendering, and subscribes to Tauri event streams)
— propagates through React's error boundary to the entire board. The
`SwarmBoardErrorBoundary` in `swarm-board-page.tsx` catches render errors, but
when it fires the *entire canvas* is replaced with an error message. Every
running session, every note, every receipt is gone from view until the user
refreshes.

The reference collab-public architecture handles this differently: when a
terminal tile's webview process crashes (`render-process-gone` event in
`tile-manager.js:376`), only that tile shows a crash notice. The canvas and all
other tiles remain fully operational.

### 1.2 Memory Pressure

The `MAX_ACTIVE_TERMINALS` constant in `swarm-board-store.tsx` is set to 8, but
all eight ghostty-web `Terminal` instances share the main webview's memory space.
Each terminal allocates a scrollback buffer (1000 lines per
`terminal-renderer.tsx:123`), a canvas rendering context, and a WASM module.
Under load — eight agents running concurrent coding sessions — this single
process can exceed 2 GB heap, triggering browser GC pauses that freeze the
*entire* React Flow canvas (including panning, zooming, and node selection).

### 1.3 Security Boundary

All terminal sessions share the same JavaScript context. A malicious command
output rendered by one terminal's WASM parser could theoretically exploit the
shared context to read data from other sessions or invoke Tauri IPC commands
(the `__TAURI_INTERNALS__` bridge is available to all code in the main
webview).

---

## 2. Reference Architecture (collab-public)

The Collaborator Electron app implements per-tile process isolation using
Electron's `<webview>` tag. Each tile on the infinite canvas is a separate
renderer process with its own V8 isolate, DOM, and memory space.

### 2.1 Key Files

| File | Role |
|------|------|
| `collab-electron/src/main/index.ts` | Main process: creates the shell `BrowserWindow` with `webviewTag: true`, registers IPC handlers, manages PTY sessions |
| `collab-electron/src/windows/shell/src/tile-manager.js` | Shell renderer: tile lifecycle — create, delete, spawn webviews, manage focus, persist canvas state |
| `collab-electron/src/windows/shell/src/webview-factory.js` | Shell renderer: generic webview creation with preload injection, ready-queue, IPC message routing |
| `collab-electron/src/windows/shell/src/canvas-state.js` | Tile data model: array of `Tile` objects with `{id, type, x, y, width, height, filePath, ptySessionId, zIndex}` |
| `collab-electron/src/windows/shell/src/canvas-viewport.js` | Viewport math: pan, zoom, grid drawing (the shell renderer manages viewport; webview tiles are positioned within it) |
| `collab-electron/src/preload/shell.ts` | Preload for the shell window: exposes `shellApi` to the renderer (canvas save/load, PTY kill, view config, shortcuts) |
| `collab-electron/src/preload/universal.ts` | Preload for tile webviews: exposes `api` to each tile (PTY create/write/resize, file ops, theme, sendToHost) |
| `collab-electron/src/main/ipc-canvas.ts` | Main process: canvas persistence, cross-webview drag, pinch-zoom forwarding |
| `collab-electron/src/main/canvas-rpc.ts` | Main process: JSON-RPC bridge for external tools to manipulate canvas tiles |

### 2.2 How Webviews Are Spawned Per Tile

The shell renderer is a vanilla JS application (not React). It manages a flat
`tiles` array (`canvas-state.js:20`) and a parallel `tileDOMs` Map
(`tile-manager.js:26`). When a tile is created, the flow is:

1. **`createCanvasTile(type, cx, cy, extra)`** (`tile-manager.js:398`)
   - Calls `addTile()` to push a tile object onto the `tiles` array
   - Calls `createTileDOM(tile, callbacks)` to build the container DOM
     (title bar, content area, close button, resize handles)
   - Attaches drag and resize handlers via `tile-interactions.js`
   - Appends the container to `tileLayer` and stores it in `tileDOMs`

2. **Type-specific webview spawning** — separate functions per tile type:
   - **`spawnTerminalWebview(tile)`** (`tile-manager.js:168`): Creates a
     `<webview>` element with `src` pointing to the terminal-tile renderer
     (`configs.terminalTile.src`), sets the `preload` attribute to the
     universal preload script, and enables `contextIsolation=yes, sandbox=yes`.
     The PTY session ID is passed via URL query parameters.
   - **`spawnGraphWebview(tile)`** (`tile-manager.js:213`): Same pattern,
     different renderer URL, passes `folder` and `workspace` as query params.
   - **`spawnBrowserWebview(tile)`** (`tile-manager.js:236`): Uses
     `partition: "persist:browser"` for isolated storage, enables
     `allowpopups`, and wires up navigation/error/crash event handlers.
   - **`createFileTile(type, cx, cy, filePath)`** (`tile-manager.js:523`):
     For code/note tiles, creates a webview pointing to the viewer renderer
     with `tilePath` and `tileMode` query params. For images, embeds an
     `<img>` directly (no webview needed).

3. **Each webview runs its own renderer process** — a complete React app
   (terminal-tile has `App.tsx` + xterm.js; viewer has BlockNote or CodeMirror).
   These apps communicate with the main process through the universal preload
   bridge (`api.*` methods).

### 2.3 View Config Pattern

The main process provides renderer URLs and preload paths via an IPC handler
(`shell:get-view-config` in `index.ts:475`):

```ts
ipcMain.handle("shell:get-view-config", () => ({
  nav:          { src: getRendererURL("nav"),           preload },
  viewer:       { src: getRendererURL("viewer"),        preload },
  terminal:     { src: getRendererURL("terminal"),      preload },
  terminalTile: { src: getRendererURL("terminal-tile"), preload },
  graphTile:    { src: getRendererURL("graph-tile"),    preload },
  settings:     { src: getRendererURL("settings"),      preload },
  terminalList: { src: getRendererURL("terminal-list"), preload },
}));
```

The shell renderer fetches this config at startup and passes it to
`createTileManager({ configs })`. Each spawned webview gets the correct
`src` and `preload` for its tile type.

### 2.4 Focus and Interaction Model

The shell manages a `focusedTileId` (`tile-manager.js:28`). When a tile is
clicked:
- `bringToFront(tile)` bumps the tile's `zIndex`
- The previous focused tile's webview receives a `"shell-blur"` IPC message
- The new tile's webview gets `.focus()` and a synthetic mouse click is
  forwarded via `sendInputEvent` (`tile-manager.js:129-134`)
- Pointer events on all webviews are toggled off during drag operations
  (`disablePointerEvents`/`enablePointerEvents` callbacks)

### 2.5 Crash Isolation in Practice

In `spawnBrowserWebview` (`tile-manager.js:376`):
```js
wv.addEventListener("render-process-gone", () => {
  const crashDiv = document.createElement("div");
  crashDiv.textContent = "Page crashed. Edit the URL and press Enter to reload.";
  if (dom.webview) {
    dom.contentArea.removeChild(dom.webview);
    dom.webview = null;
  }
  dom.contentArea.appendChild(crashDiv);
});
```

The crashed webview is replaced inline. The shell renderer, canvas, and all
other tiles continue operating.

---

## 3. Adaptation for Tauri

Tauri v2 supports multiple webviews within a single window via the
`WebviewWindow` and `Webview` APIs. The key difference from Electron:

| Aspect | Electron | Tauri v2 |
|--------|----------|----------|
| Isolation unit | `<webview>` tag (renderer process) | `Webview` (WKWebView/WebView2 instance) |
| Creation | DOM element in renderer | Rust API or `@tauri-apps/api/webviewWindow` |
| Positioning | CSS on the `<webview>` element | `Webview::set_position()` / `set_size()` on the Rust side |
| IPC | `preload` script + `ipcRenderer.sendToHost()` | `@tauri-apps/api/event` (emit/listen) or Tauri commands |
| Content | Separate HTML entry point | Separate HTML entry point (or URL) |
| Process model | Each webview = separate Chromium renderer | Platform-dependent (WKWebView shares process pool; WebView2 can be per-process) |

### 3.1 Creating Tile Webviews in Tauri

The Tauri Rust backend needs a new command to create child webviews attached to
the main window:

```rust
// src-tauri/src/commands/tile_webview.rs (new file)

use tauri::{AppHandle, Manager, Runtime, WebviewUrl, WebviewWindowBuilder};

#[tauri::command]
pub async fn create_tile_webview<R: Runtime>(
    app: AppHandle<R>,
    tile_id: String,
    tile_type: String,       // "terminal" | "graph" | "artifact" | ...
    x: f64,
    y: f64,
    width: f64,
    height: f64,
    query_params: String,    // URL-encoded params (sessionId, filePath, etc.)
) -> Result<(), String> {
    let main_window = app.get_window("main")
        .ok_or("main window not found")?;

    let url = match tile_type.as_str() {
        "terminal" => format!("/tile/terminal.html?{}", query_params),
        "graph"    => format!("/tile/graph.html?{}", query_params),
        "viewer"   => format!("/tile/viewer.html?{}", query_params),
        _          => return Err(format!("unknown tile type: {}", tile_type)),
    };

    let label = format!("tile-{}", tile_id);

    // Create a child webview inside the main window
    let _webview = main_window.add_child(
        tauri::webview::WebviewBuilder::new(
            &label,
            WebviewUrl::App(url.into()),
        )
        .auto_resize(),
        tauri::LogicalPosition::new(x, y),
        tauri::LogicalSize::new(width, height),
    ).map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub async fn reposition_tile_webview<R: Runtime>(
    app: AppHandle<R>,
    tile_id: String,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
) -> Result<(), String> {
    let label = format!("tile-{}", tile_id);
    let webview = app.get_webview(&label)
        .ok_or_else(|| format!("webview not found: {}", label))?;

    webview.set_position(tauri::LogicalPosition::new(x, y))
        .map_err(|e| e.to_string())?;
    webview.set_size(tauri::LogicalSize::new(width, height))
        .map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
pub async fn destroy_tile_webview<R: Runtime>(
    app: AppHandle<R>,
    tile_id: String,
) -> Result<(), String> {
    let label = format!("tile-{}", tile_id);
    if let Some(webview) = app.get_webview(&label) {
        webview.close().map_err(|e| e.to_string())?;
    }
    Ok(())
}
```

Register these in `main.rs` alongside existing terminal/worktree commands.

### 3.2 TypeScript Service Layer

Create a new service to manage tile webviews from the React side:

```
src/lib/workbench/tile-webview-service.ts (new file)
```

```ts
import { invoke } from "@tauri-apps/api/core";
import { emit, listen, type UnlistenFn } from "@tauri-apps/api/event";

export const tileWebviewService = {
  async create(params: {
    tileId: string;
    tileType: string;
    x: number;
    y: number;
    width: number;
    height: number;
    queryParams?: Record<string, string>;
  }): Promise<void> {
    const qs = new URLSearchParams(params.queryParams ?? {}).toString();
    await invoke("create_tile_webview", {
      tileId: params.tileId,
      tileType: params.tileType,
      x: params.x,
      y: params.y,
      width: params.width,
      height: params.height,
      queryParams: qs,
    });
  },

  async reposition(tileId: string, x: number, y: number, w: number, h: number): Promise<void> {
    await invoke("reposition_tile_webview", {
      tileId,
      x, y,
      width: w,
      height: h,
    });
  },

  async destroy(tileId: string): Promise<void> {
    await invoke("destroy_tile_webview", { tileId });
  },

  async sendToTile(tileId: string, channel: string, payload: unknown): Promise<void> {
    await emit(`tile:${tileId}:${channel}`, payload);
  },

  onTileMessage(tileId: string, channel: string, cb: (payload: unknown) => void): Promise<UnlistenFn> {
    return listen(`tile:${tileId}:${channel}`, (event) => cb(event.payload));
  },
};
```

### 3.3 Tile HTML Entry Points

Each isolated tile type needs its own HTML entry point, bundled by Vite as
separate entries:

```
src/tile-renderers/
  terminal/
    index.html          ← <script src="main.tsx">
    main.tsx            ← mounts <TileTerminal /> (ghostty-web)
    TileTerminal.tsx    ← standalone terminal, no React Flow dependency
  viewer/
    index.html
    main.tsx
    TileViewer.tsx
  graph/
    index.html
    main.tsx
    TileGraph.tsx
```

These are analogous to collab-public's `src/windows/terminal-tile/`,
`src/windows/viewer/`, etc. Each is a self-contained mini-app that communicates
with the Tauri backend via `@tauri-apps/api` and with the main canvas via the
Tauri event bus.

Vite multi-page config in `vite.config.ts`:

```ts
build: {
  rollupOptions: {
    input: {
      main: resolve(__dirname, "index.html"),
      tileTerminal: resolve(__dirname, "src/tile-renderers/terminal/index.html"),
      tileViewer: resolve(__dirname, "src/tile-renderers/viewer/index.html"),
      tileGraph: resolve(__dirname, "src/tile-renderers/graph/index.html"),
    },
  },
},
```

### 3.4 CSP Update

The current CSP in `tauri.conf.json` restricts to `default-src 'self'`. Child
webviews loading tile renderer HTML from the app bundle will satisfy this. No
CSP change is needed for same-origin tile content. If tiles ever load remote
URLs (browser tile), a partition-specific CSP policy would be needed.

### 3.5 Platform Differences

- **macOS (WKWebView):** All webviews share a process pool by default.
  WKWebView does not guarantee process isolation per webview, but each webview
  has its own DOM and JavaScript context. A crash in one WKWebView process may
  affect others in the same pool, but Tauri's error handling will detect the
  failure. For stronger isolation, use `WKWebViewConfiguration.processPool` via
  a Tauri plugin.

- **Windows (WebView2):** By default, WebView2 instances in the same user data
  folder share a browser process. Per-webview process isolation is available
  via `CreateCoreWebView2ControllerOptions::put_IsUserInitiatedNavigationPolicyEnabled`.
  Tauri does not expose this directly, but a custom plugin can configure it.

- **Linux (WebKitGTK):** Each `WebKitWebView` runs in a separate web process
  by default. This gives the strongest isolation guarantee out of the box.

---

## 4. Integration with React Flow

React Flow renders nodes as React components within its own SVG/HTML coordinate
system. It applies CSS transforms (translate + scale) to position nodes. A
Tauri child webview, however, is positioned in screen/window coordinates by the
native compositor — it cannot be a child of a React Flow node's DOM tree.

### 4.1 The Overlay Shell Pattern

The solution is to split each isolatable node into two layers:

1. **React Flow node component (positioning shell):** A lightweight React
   component registered in `swarmBoardNodeTypes`. It renders the node's chrome
   (title bar, status indicators, resize handles, React Flow Handles) but
   **not** the heavy content (terminal, code viewer). The content area is a
   transparent placeholder div.

2. **Native webview overlay:** A Tauri child webview positioned to exactly
   overlap the placeholder div. The webview renders the actual terminal/viewer
   content.

The positioning shell observes its own screen coordinates (via
`getBoundingClientRect()` on the placeholder, polled or observed via
`ResizeObserver` + `MutationObserver`) and calls
`tileWebviewService.reposition()` to keep the overlay in sync.

### 4.2 Coordinate Synchronization

React Flow applies a viewport transform to all nodes:
```
transform: translate(${viewport.x}px, ${viewport.y}px) scale(${viewport.zoom})
```

During pan/zoom, every node's screen position changes. The overlay webview must
track this. The approach:

```ts
// Inside the React Flow node component for an isolated tile

function IsolatedAgentSessionNode({ id, data, selected }: NodeProps) {
  const placeholderRef = useRef<HTMLDivElement>(null);
  const tileId = id;
  const isIsolated = !!data.sessionId; // Only isolate live terminal sessions

  // Sync overlay position on every animation frame while visible
  useEffect(() => {
    if (!isIsolated || !placeholderRef.current) return;

    let rafId: number;
    function sync() {
      const rect = placeholderRef.current!.getBoundingClientRect();
      tileWebviewService.reposition(
        tileId,
        rect.left,
        rect.top,
        rect.width,
        rect.height,
      );
      rafId = requestAnimationFrame(sync);
    }
    rafId = requestAnimationFrame(sync);

    return () => cancelAnimationFrame(rafId);
  }, [isIsolated, tileId]);

  // ...render chrome + transparent placeholder...
}
```

> **Performance note:** `requestAnimationFrame` polling at 60fps for N
> webviews means N `reposition` IPC calls per frame. For 8 tiles this is
> manageable. For 20+, batch the calls into a single Tauri command that
> repositions all tile webviews at once (see Section 4.4).

### 4.3 Visibility and Z-Index

React Flow nodes have z-index managed by selection state and render order.
Overlay webviews are native compositor layers — they always render on top of
the React DOM. This means:

- **Context menus and inspector drawers** (rendered as React portals) will
  appear *behind* overlay webviews unless we explicitly hide overlapping
  webviews.
- **The minimap** is unaffected (it reads node data, not DOM).
- **Drag previews and selection rectangles** need careful layering.

Solutions:
1. When the inspector drawer opens (`state.inspectorOpen === true`), hide
   all tile webviews (`webview.setVisibility(false)`) or move them off-screen.
2. When a context menu opens, temporarily hide the webview for the targeted
   node.
3. During marquee selection, hide all webviews.
4. Use `webview.setZIndex()` (if supported by the platform) or manage
   visibility explicitly.

### 4.4 Batched Repositioning

To avoid per-tile IPC overhead during pan/zoom, introduce a batch command:

```rust
#[tauri::command]
pub async fn batch_reposition_tile_webviews<R: Runtime>(
    app: AppHandle<R>,
    updates: Vec<TilePosition>,
) -> Result<(), String> {
    for update in updates {
        let label = format!("tile-{}", update.tile_id);
        if let Some(webview) = app.get_webview(&label) {
            let _ = webview.set_position(
                tauri::LogicalPosition::new(update.x, update.y),
            );
            let _ = webview.set_size(
                tauri::LogicalSize::new(update.width, update.height),
            );
        }
    }
    Ok(())
}
```

The React side collects all position updates in a single rAF tick and sends
them as one batch.

### 4.5 Zoom Scaling

When React Flow zooms out (e.g., `viewport.zoom = 0.5`), nodes appear at half
size. The overlay webview must match. Tauri's `Webview` does not have a
`setZoomLevel()` on all platforms, but the physical size returned by
`getBoundingClientRect()` already accounts for the CSS transform scale. So
`reposition()` with the rect dimensions naturally scales the webview.

The content inside the webview, however, renders at its native resolution.
At low zoom levels this means the terminal text is too large relative to the
node chrome. Options:
- Send the effective zoom level to the tile webview via an event; the tile
  adjusts its internal font size (collab-public does this with
  `applyZoomToAll` in `index.ts:274`).
- Accept the visual mismatch at extreme zoom levels (below 0.5x users are
  likely in overview mode, not reading terminal output).

---

## 5. IPC Design

### 5.1 Collab-Public's IPC Pattern

Collab-public uses a three-layer IPC model:

1. **Main <-> Shell renderer:** `ipcMain.handle()` / `ipcRenderer.invoke()`
   via the shell preload (`preload/shell.ts`). The shell preload exposes
   `window.shellApi` with methods like `canvasLoadState`, `ptyKillSession`,
   `getViewConfig`, etc.

2. **Main <-> Tile webview:** `ipcMain.handle()` / `ipcRenderer.invoke()` via
   the universal preload (`preload/universal.ts`). Each tile webview gets
   `window.api` with methods like `ptyCreate`, `ptyWrite`, `readFile`,
   `writeFile`, etc.

3. **Shell renderer <-> Tile webview:** The shell uses `webview.send(channel, ...args)`
   to push messages into tile webviews. Tile webviews use
   `ipcRenderer.sendToHost(channel, ...args)` (exposed as `api.sendToHost`)
   to send messages back to the shell. The shell listens via
   `wv.addEventListener("ipc-message", handler)`.

The forwarding pattern (`shell:forward`) in `ipc.ts:36-47` lets the main
process route messages to specific webview panels by name:

```ts
function forwardToWebview(target, channel, ...args) {
  mainWindow?.webContents.send("shell:forward", target, channel, ...args);
}
```

The shell renderer's `onForwardToWebview` callback dispatches to the correct
webview based on the `target` string.

### 5.2 Tauri IPC Mapping

In Tauri, we replace the three-layer model with Tauri's event bus:

| Collab-public pattern | Tauri equivalent |
|---|---|
| `ipcRenderer.invoke("pty:create")` | `invoke("terminal_create", {...})` (already exists) |
| `ipcRenderer.sendToHost("pty-session-id", id)` | `emit("tile-to-canvas", { tileId, channel: "pty-session-id", payload: id })` |
| `webview.send("shell-blur")` | `emit_to("tile-{id}", "canvas-to-tile", { channel: "shell-blur" })` |
| `shell:forward` routing | `emit_to()` targeting specific webview labels |

### 5.3 Message Protocol

Define a typed message protocol for canvas-tile communication:

```ts
// src/lib/workbench/tile-ipc-protocol.ts (new file)

/** Messages from the main canvas to an isolated tile webview. */
export type CanvasToTileMessage =
  | { channel: "focus" }
  | { channel: "blur" }
  | { channel: "zoom-changed"; zoom: number }
  | { channel: "theme-changed"; theme: "dark" | "light" }
  | { channel: "session-config"; sessionId: string; cwd: string }
  | { channel: "dispose" };

/** Messages from an isolated tile webview back to the main canvas. */
export type TileToCanvasMessage =
  | { channel: "ready"; tileId: string }
  | { channel: "pty-session-id"; tileId: string; sessionId: string }
  | { channel: "title-changed"; tileId: string; title: string }
  | { channel: "crashed"; tileId: string; error: string }
  | { channel: "resize-request"; tileId: string; width: number; height: number };
```

### 5.4 PTY Data Flow

Today, `TerminalRenderer` subscribes to PTY output via
`terminalService.onOutput(sessionId, cb)`, which calls
`listen(`terminal_output_${sessionId}`, ...)` on the Tauri event bus. This
already works across webview boundaries because Tauri events are app-global.

The isolated terminal tile webview can use the exact same
`terminalService.onOutput()` call. The Rust backend emits
`terminal_output_{sessionId}` events to all listeners; the tile webview
just needs to register. No changes to `terminal.rs` are required for output
streaming.

For input (user keystrokes), the tile webview calls
`terminalService.write(sessionId, data)` which invokes the Tauri command
`terminal_write`. Again, this works unchanged — the command is available to
any webview in the app.

**This is a significant advantage over collab-public's model**, where PTY
data routing requires explicit `event.sender.id` tracking in the main process
(`pty.ts`) and per-webview IPC forwarding. In Tauri, the event bus handles
fan-out natively.

---

## 6. Migration Strategy

### Phase 0: Foundation (1 week)

**Goal:** Build the infrastructure without changing any existing behavior.

- [ ] Create `src-tauri/src/commands/tile_webview.rs` with `create_tile_webview`,
      `reposition_tile_webview`, `batch_reposition_tile_webviews`, and
      `destroy_tile_webview` commands.
- [ ] Register the new commands in `main.rs`.
- [ ] Create `src/lib/workbench/tile-webview-service.ts`.
- [ ] Create `src/lib/workbench/tile-ipc-protocol.ts`.
- [ ] Create the `src/tile-renderers/terminal/` entry point with a minimal
      standalone terminal component (ghostty-web init, theme, PTY subscription).
- [ ] Update `vite.config.ts` for multi-page build.
- [ ] Update CSP in `tauri.conf.json` if needed for child webview URLs.
- [ ] Add unit tests for `tile-webview-service.ts`.

### Phase 1: Isolated Terminal Tiles (2 weeks)

**Goal:** Agent session nodes with live PTY sessions use isolated webviews.
Non-terminal nodes remain in-tree.

- [ ] Create `IsolatedAgentSessionNode` — a new React Flow node component that
      renders the title bar, status indicators, footer metrics, and resize
      handles in-tree, but delegates the terminal content area to an overlay
      webview.
- [ ] Implement the coordinate sync loop (Section 4.2).
- [ ] Implement visibility management (Section 4.3): hide overlays when
      inspector opens, during context menu, during marquee select.
- [ ] Update `nodes/index.ts` to register `IsolatedAgentSessionNode` under a
      new type key (e.g., `agentSessionIsolated`).
- [ ] Update `swarm-board-store.tsx` to assign the isolated type when a node
      has a live `sessionId`, and the in-tree type when it doesn't (offline/
      mock sessions).
- [ ] Wire up `TileToCanvasMessage` handling: when the tile webview reports
      `"pty-session-id"`, update the board store; when it reports `"crashed"`,
      show an inline error in the positioning shell and offer a "Restart"
      button.
- [ ] Migrate the `killSession` flow to also call
      `tileWebviewService.destroy()`.
- [ ] Verify that `MAX_ACTIVE_TERMINALS = 8` still makes sense when each
      terminal is in its own webview (memory per webview is lower but webview
      creation cost is higher; may need to adjust).
- [ ] Write integration tests: spawn a session, verify webview creation,
      verify coordinate sync on pan/zoom, verify crash recovery.

### Phase 2: Isolated Viewer Tiles (1 week)

**Goal:** If/when artifact and diff nodes grow to embed code editors or file
viewers, isolate those as well.

- [ ] Create `src/tile-renderers/viewer/` entry point.
- [ ] Create `IsolatedArtifactNode` and `IsolatedDiffNode` (or a generic
      `IsolatedViewerNode` parameterized by content type).
- [ ] Re-use the same overlay positioning infrastructure from Phase 1.

### What Stays In-Tree

These node types do NOT need isolation and should remain as plain React Flow
components:

| Node Type | Reason |
|-----------|--------|
| `NoteNode` | Lightweight textarea; no external process or WASM. Crash risk is near zero. |
| `ReceiptNode` | Static data display. No interactive content. |
| `TerminalTaskNode` | Badge/label only. No embedded terminal. |
| `ArtifactNode` (Phase 1) | Currently just file icon + name. No heavy content. |
| `DiffNode` (Phase 1) | Currently just +/- summary. No syntax-highlighted diff viewer yet. |

### Phase 3: Performance Optimization (1 week)

- [ ] Implement the batched repositioning command (Section 4.4).
- [ ] Add a viewport-culling optimization: when a tile is scrolled off-screen
      (its React Flow node is outside the visible viewport), hide or destroy
      the overlay webview and recreate it when the node scrolls back into view.
      Collab-public does not need this because Electron webviews handle
      off-screen rendering natively, but Tauri child webviews consume resources
      even when not visible.
- [ ] Profile memory usage: compare 8 isolated webview terminals vs. 8
      in-tree ghostty-web terminals. Document the delta.
- [ ] Consider a webview pool: pre-create 2-3 webviews and reassign them to
      tiles on demand, avoiding the creation latency.

---

## 7. Risks and Mitigations

### 7.1 Webview Creation Latency

**Risk:** Creating a Tauri child webview involves native platform calls
(WKWebView allocation on macOS, WebView2 creation on Windows). This can take
50-200ms, causing a visible delay when the user spawns a new agent session.

**Mitigation:**
- Show the positioning shell immediately with a "loading" skeleton in the
  content area. Spawn the webview asynchronously. When the tile webview
  emits `"ready"`, fade it in.
- Pre-warm a pool of 2 idle webviews at app startup. When a tile is created,
  reassign a pooled webview instead of creating a new one.
- The collab-public reference handles this naturally because the `<webview>`
  element is appended to the DOM and loads asynchronously — the shell shows
  the tile chrome immediately and the webview content appears when `dom-ready`
  fires (`tile-manager.js:197`).

### 7.2 Coordinate Sync Jank During Pan/Zoom

**Risk:** During a smooth pan/zoom gesture, the React Flow transform updates
at 60fps via CSS. The overlay webview repositioning goes through IPC (JS ->
Rust -> native compositor), introducing 1-2 frames of lag. This causes a
visible "swimming" effect where the webview slightly trails the node chrome.

**Mitigation:**
- Use the batched reposition command to minimize IPC round-trips.
- On macOS, WKWebView repositioning is composited and typically completes
  within the same frame as the request.
- Accept minor lag at extreme zoom speeds. The collab-public reference also
  has this issue (webview repositioning via DOM layout is not perfectly
  synchronous with CSS transforms), but it is perceptually acceptable because
  the tile chrome moves with the transform and the webview content catches up
  within 1 frame.
- During fast zoom gestures (pinch-to-zoom), temporarily hide overlay
  webviews and show a static screenshot/placeholder, then reposition and
  unhide when the gesture ends. This is the approach used by VS Code's
  webview editor tabs.

### 7.3 Z-Index Conflicts

**Risk:** Native webview overlays always render on top of the HTML DOM. React
Flow's selection box, edge rendering, context menus, and the inspector drawer
will appear behind webview overlays.

**Mitigation:**
- Selection box: Hide all tile webviews during selection drag (set
  `visibility: hidden` on the native webview). Re-show on mouse up.
- Context menu: When `contextMenu` state is set, hide the webview for the
  targeted node.
- Inspector drawer: When `state.inspectorOpen === true`, hide all webviews
  or set their z-order below the inspector's portal.
- Edges: React Flow renders edges in an SVG layer below nodes. Edges
  connecting to isolated nodes will be visible because they are below the
  node chrome (which is in the React DOM). The webview overlay covers the
  node's content area but not its Handle connection points, so edge anchor
  rendering is unaffected.

### 7.4 Memory Overhead of Multiple Webviews

**Risk:** Each child webview has baseline memory overhead (WebView2: ~30-50MB,
WKWebView: ~20-40MB, WebKitGTK: ~30-60MB). Eight isolated terminal webviews
could consume 200-500MB of memory just for the webview runtime, vs. the
current ~50-100MB for eight in-tree ghostty-web instances.

**Mitigation:**
- The max concurrent isolated webviews should be capped
  (`MAX_ISOLATED_TILES`). Tiles beyond the cap fall back to in-tree rendering
  (the existing `TerminalRenderer` component remains as a fallback).
- Viewport culling (Phase 3): destroy webviews for off-screen tiles and
  recreate them on demand. The PTY session continues running in the Rust
  backend; only the rendering frontend is torn down and rebuilt.
- On memory-constrained machines, detect available RAM at startup and set a
  lower cap (e.g., 4 isolated tiles instead of 8).

### 7.5 Focus Management Complexity

**Risk:** With multiple native webviews, keyboard focus routing becomes
complex. A key press might go to the wrong webview, or the React Flow canvas
might not receive keyboard shortcuts when a webview has focus.

**Mitigation:**
- Follow collab-public's model: the shell tracks `focusedTileId` and
  explicitly sends `focus`/`blur` messages to tile webviews.
- Global keyboard shortcuts (Cmd+Shift+N, Escape, F, etc.) are registered on
  the main window via Tauri's `register_shortcut` or by intercepting events
  at the window level before they reach any webview.
- When the user clicks the canvas background (React Flow's `onPaneClick`),
  send `blur` to the currently focused tile webview and reclaim focus to the
  main webview.
- Each tile webview's global shortcut handler checks for canvas-level
  shortcuts and forwards them via event emission (collab-public does this with
  `attachShortcutListener` in `index.ts:205` and the `before-input-event`
  handler on each webview in `index.ts:261`).

### 7.6 Development Complexity

**Risk:** Multi-page Vite builds, separate tile renderer apps, and native
webview management significantly increase build/debug complexity.

**Mitigation:**
- Keep the in-tree `TerminalRenderer` and all current node components
  working as-is. Isolation is an *additive* feature that can be toggled
  with a feature flag (`ENABLE_WEBVIEW_ISOLATION` in settings or env var).
- The tile renderer apps share the same `@tauri-apps/api` and Tailwind
  config as the main app, minimizing divergence.
- Dev mode: Vite's dev server serves all entry points at different paths.
  Child webviews point to `http://localhost:1421/tile/terminal.html`
  (the dev URL from `tauri.conf.json`).
- Add a debug overlay (toggled with a dev-only shortcut) that draws red
  borders around overlay webview positions, making coordinate sync issues
  visible.

---

## Appendix A: File Map

### Files to Create

| Path | Description |
|------|-------------|
| `src-tauri/src/commands/tile_webview.rs` | Rust commands for child webview CRUD + batch reposition |
| `src/lib/workbench/tile-webview-service.ts` | TypeScript bridge for tile webview commands |
| `src/lib/workbench/tile-ipc-protocol.ts` | Typed message protocol for canvas <-> tile IPC |
| `src/tile-renderers/terminal/index.html` | Entry point for isolated terminal tile |
| `src/tile-renderers/terminal/main.tsx` | Bootstrap for isolated terminal tile |
| `src/tile-renderers/terminal/TileTerminal.tsx` | Standalone terminal component (ghostty-web + PTY) |
| `src/components/workbench/swarm-board/nodes/isolated-agent-session-node.tsx` | Overlay-shell node for isolated agent sessions |

### Files to Modify

| Path | Change |
|------|--------|
| `src-tauri/src/main.rs` | Register `tile_webview::*` commands |
| `src-tauri/src/commands/mod.rs` | Add `pub mod tile_webview;` |
| `src-tauri/tauri.conf.json` | Add child webview permissions if needed |
| `vite.config.ts` | Add multi-page rollup inputs for tile renderers |
| `src/components/workbench/swarm-board/nodes/index.ts` | Register `agentSessionIsolated` node type |
| `src/features/swarm/swarm-board-types.ts` | Add `"agentSessionIsolated"` to `SwarmNodeType` union |
| `src/features/swarm/stores/swarm-board-store.tsx` | Assign isolated type for live sessions; handle tile webview lifecycle |
| `src/components/workbench/swarm-board/swarm-board-page.tsx` | Add visibility management for overlay webviews during inspector/context menu |

### Reference Files (collab-public, read-only)

| Path | What to Study |
|------|---------------|
| `collab-electron/src/windows/shell/src/tile-manager.js` | Webview spawn patterns per tile type, focus model, crash recovery |
| `collab-electron/src/windows/shell/src/webview-factory.js` | Generic webview creation with preload, ready-queue, IPC routing |
| `collab-electron/src/windows/shell/src/canvas-state.js` | Tile data model, z-index management |
| `collab-electron/src/preload/universal.ts` | Per-tile preload API surface (what each tile can do) |
| `collab-electron/src/main/index.ts` | View config, shortcut forwarding, `did-attach-webview` pattern |
| `collab-electron/src/main/ipc-canvas.ts` | Cross-webview drag, pinch forwarding |
| `collab-electron/src/main/canvas-rpc.ts` | External RPC to manipulate canvas tiles |
