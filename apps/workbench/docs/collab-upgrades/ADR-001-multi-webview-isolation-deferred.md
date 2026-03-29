# ADR-001: Defer Native Multi-Webview Tile Isolation

**Status:** Accepted
**Date:** 2026-03-26
**Deciders:** Engineering
**Supersedes:** 01-multi-webview-isolation.md (Draft, shelved)
**Satisfies:** ADR-01 (from REQUIREMENTS.md)

---

## Context

The Swarm Board renders every node -- agent sessions, terminals, artifacts, diffs,
notes, receipts -- in a single React tree inside one Tauri `WebviewWindow`. All
terminal surfaces use ghostty-web (WASM), sharing the main webview's JS heap and
WebGL context budget.

Spec 01 ("Multi-Webview Tile Isolation") proposed running each agent-session tile
in its own native webview, overlaid on top of the React Flow canvas. The spec was
a 5-week implementation plan covering Rust webview lifecycle management, overlay
positioning via `requestAnimationFrame` polling, IPC bridging for PTY data, and
cross-platform crash detection. The goal was per-node fault isolation and memory
containment.

The spec was reviewed and received a **NEEDS REWORK** verdict with 3 blocking and
4 high-severity issues. This ADR records the decision to defer the approach and
pursue simpler, already partially implemented alternatives.

---

## Decision

We will **NOT** pursue native multi-webview tile isolation in this cycle.

We **WILL** pursue per-node error boundaries and terminal instance recycling as
the approved containment path. These are incremental extensions of code that
already exists in the codebase.

This is a deferral, not a permanent rejection. See Revisit Criteria below.

---

## Rationale

The review of Spec 01 identified 7 blocking or high-severity issues. Each is
cited by review section number:

| # | Issue | Severity | Review Section |
|---|-------|----------|----------------|
| 1 | `get_window` does not exist in Tauri v2 -- the spec's Rust code uses the v1 API and will not compile. The project uses `get_webview_window` (see `main.rs:47`). | Blocking | 1.1 |
| 2 | `Window::add_child` requires the `unstable` feature flag on the `tauri` crate. The project's `Cargo.toml` specifies `tauri = { version = "2", features = [] }` -- no features enabled. Opting into `unstable` accepts API breakage between Tauri minor versions. | Blocking | 1.2, 2.1 |
| 3 | Capability permissions in `capabilities/default.json` are granted only to `"windows": ["main"]`. Child webviews labeled `"tile-*"` receive no permissions and every Tauri invoke call returns "permission denied." | Blocking | 3.5 |
| 4 | React Flow renders edges in a DOM-layer SVG. Native overlay webviews are composited by the OS window manager on top of all DOM content. Edges connecting to agent-session nodes become invisible behind the overlay. No mitigation was proposed. | High | 3.1 |
| 5 | Node drag updates the React Flow node's CSS transform instantly, but the overlay webview repositioning lags by at least one IPC round-trip (1-2 frames). The most common user interaction -- dragging a node -- visibly glitches. | High | 3.2 |
| 6 | macOS WKWebView crash detection (`webViewWebContentProcessDidTerminate`) is not exposed by Tauri as a frontend event. The core goal of crash isolation may not work on the primary development platform without a custom Tauri plugin. | High | 2.2 |
| 7 | Simpler alternatives -- per-node error boundaries (~2 days) and terminal instance recycling (~3 days) -- were not evaluated before committing to a 5-week native webview approach. | Process | 5.1, 5.3 |

**Security boundary weakness:** The review (Section 4.1, point 3) noted that
ghostty-web's WASM sandbox already provides memory isolation (WASM modules cannot
access JS heap outside their linear memory). Child webviews would still share
`__TAURI_INTERNALS__` (the same IPC bridge), so the security gain from native
webview isolation is marginal. The real security model is the Clawdstrike policy
engine, not process isolation at the UI layer.

---

## Approved Alternatives

### Per-node error boundaries (~2 days)

`TerminalTileErrorBoundary` already exists in `agent-session-node.tsx` (lines
49-121). It wraps each `TerminalRenderer`, catches render crashes via
`getDerivedStateFromError`, displays an error message with a "Reload terminal
surface" button, and leaves the rest of the canvas unaffected. Recovery uses
key-based remount via an `attempt` counter.

Extending this pattern to other node types that may gain heavy content is
approximately 2 days of work.

### Terminal instance recycling (~3 days)

The `previewLines` fallback path in `agent-session-node.tsx` already renders
static text from the ring buffer when `TerminalRenderer` is not mounted.
Recycling means only mounting ghostty-web for selected or active nodes and
showing `previewLines` for the rest. This reduces live terminal instances from
8 (the current `MAX_ACTIVE_TERMINALS` cap) to 1-3 at any given time.

`TerminalRenderer` (terminal-renderer.tsx) already has a fatal-error state with
a retry button (lines 301-322), so reconnection after recycling is handled.
Estimated effort is approximately 3 days.

### Cost comparison

| Approach | Effort | Fault isolation | Memory reduction | Security boundary |
|----------|--------|----------------|-----------------|-------------------|
| Native multi-webview (Spec 01) | ~5 weeks | Maybe (platform-dependent) | Yes (separate processes) | Marginal (same IPC bridge) |
| Per-node error boundaries | ~2 days | Yes (React-level) | No | No |
| Terminal instance recycling | ~3 days | No | Yes (8 to 1-3 instances) | No |
| Error boundaries + recycling | ~1 week | Yes | Yes | No |

The combined alternative delivers fault isolation and memory reduction at
approximately one-fifth the cost, without the platform-dependent uncertainties
of the native overlay approach.

---

## Consequences

1. Spec 01 is shelved. Its status is updated to "Shelved (see ADR-001)." The
   spec document is preserved as a historical record.

2. Future roadmap phases that need fault isolation should extend the error
   boundary pattern, not reopen native multi-webview.

3. Native multi-webview remains a valid architectural option for a future cycle
   if and only if the revisit criteria below are all met.

4. No partial overlay infrastructure (child webview lifecycle, rAF positioning
   loop, tile HTML entry points) should be built speculatively. The cost of
   that infrastructure is only justified when all blocking issues are resolved.

---

## Revisit Criteria

This decision should be reopened when **ALL** of the following are true:

1. Tauri removes the `unstable` gate from `Window::add_child` or provides a
   stable multi-webview API that does not require opting into unstable features.

2. A working prototype demonstrates less than 2-frame drag-lag with native
   overlay webviews on macOS, Windows, and Linux.

3. The prototype resolves the React Flow SVG edge z-index conflict -- edges
   must be visible above or through native overlays, not hidden behind them.

4. Tauri exposes a cross-platform webview crash detection API, or the project
   ships its own health-check mechanism that is verified to work on macOS
   WKWebView (not just Windows WebView2).

5. The per-node error boundary approach has been shown insufficient for a
   specific, documented class of failure that React error boundaries cannot
   contain (e.g., a crash that corrupts the JS runtime itself).

Each criterion must be independently verifiable. Meeting 4 of 5 is not
sufficient to reopen.

---

## References

- Spec: [01-multi-webview-isolation.md](01-multi-webview-isolation.md)
- Review: [01-multi-webview-isolation-review.md](reviews/01-multi-webview-isolation-review.md)
- Error boundary: `../../src/components/workbench/swarm-board/nodes/agent-session-node.tsx` (lines 49-121)
- Terminal error state: `../../src/components/workbench/swarm-board/terminal-renderer.tsx` (lines 301-322)
- Requirement: ADR-01 in REQUIREMENTS.md
