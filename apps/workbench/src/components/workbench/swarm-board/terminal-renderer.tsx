/**
 * TerminalRenderer — ghostty-web terminal connected to a Tauri PTY session.
 *
 * Mounts a ghostty-web Terminal (canvas-based, Ghostty VT100 parser via WASM)
 * in the DOM and connects it to the PTY backend via Tauri events for output
 * and the terminal-service for input/resize.
 * Supports an `active` prop to switch between full interactivity (selected
 * nodes) and a passive live-output view (unselected nodes with smaller font).
 */

import { useEffect, useRef, useCallback } from "react";
import { init as initGhostty, Terminal, FitAddon } from "ghostty-web";
import { terminalService } from "@/lib/workbench/terminal-service";

// ---------------------------------------------------------------------------
// WASM initialisation — call once, cache the promise
// ---------------------------------------------------------------------------

let ghosttyReady: Promise<void> | null = null;
let ghosttyFailed = false;
function ensureGhosttyInit(): Promise<void> {
  if (ghosttyFailed) return Promise.reject(new Error("ghostty-web init failed"));
  if (!ghosttyReady) {
    ghosttyReady = initGhostty().catch((err) => {
      ghosttyFailed = true;
      ghosttyReady = null;
      throw err;
    });
  }
  return ghosttyReady;
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface TerminalRendererProps {
  /** PTY session ID from the Rust backend */
  sessionId: string;
  /** When true, full font size and cursor blink; when false, smaller passive view */
  active: boolean;
  /** Width hint from the node container (pixels) */
  width?: number;
  /** Height hint from the node container (pixels) */
  height?: number;
  /** Called when the terminal is ready (opened and fit) */
  onReady?: () => void;
  /** Font size override (defaults to 11 when active, 8 when passive) */
  fontSize?: number;
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

const TERMINAL_THEME = {
  background: "#0a0c12",
  foreground: "#ece7dc",
  cursor: "#d4a84b",
  cursorAccent: "#0a0c12",
  selectionBackground: "#d4a84b33",
  black: "#0b0d13",
  red: "#c45c5c",
  green: "#3dbf84",
  yellow: "#d4a84b",
  blue: "#5b8def",
  magenta: "#8b5cf6",
  cyan: "#55788b",
  white: "#ece7dc",
  brightBlack: "#6f7f9a",
  brightRed: "#e06c6c",
  brightGreen: "#4dd498",
  brightYellow: "#e8c06a",
  brightBlue: "#7ba3f5",
  brightMagenta: "#a67df8",
  brightCyan: "#6a9bab",
  brightWhite: "#f5f0e6",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function TerminalRenderer({
  sessionId,
  active,
  width,
  height,
  onReady,
  fontSize,
}: TerminalRendererProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const unlistenRef = useRef<(() => void) | null>(null);
  const onDataDisposeRef = useRef<{ dispose: () => void } | null>(null);
  const isDisposedRef = useRef(false);
  const mountedSessionRef = useRef<string | null>(null);

  // Resolved font size
  const resolvedFontSize = fontSize ?? (active ? 11 : 8);

  // --- Mount terminal ---
  useEffect(() => {
    const container = containerRef.current;
    if (!container || !sessionId) return;

    isDisposedRef.current = false;
    mountedSessionRef.current = sessionId;

    // ghostty-web requires WASM init before Terminal creation
    let cancelled = false;
    ensureGhosttyInit()
      .then(() => {
        if (cancelled || isDisposedRef.current) return;

        const term = new Terminal({
          theme: TERMINAL_THEME,
          fontSize: resolvedFontSize,
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          cursorBlink: active,
          cursorStyle: "bar",
          scrollback: 1000,
          allowTransparency: true,
          convertEol: true,
        });

        const fitAddon = new FitAddon();
        term.loadAddon(fitAddon);

        term.open(container);
        termRef.current = term;
        fitAddonRef.current = fitAddon;

        // Initial fit
        requestAnimationFrame(() => {
          if (isDisposedRef.current) return;
          try {
            fitAddon.fit();
            // Notify PTY backend of initial dimensions
            const dims = fitAddon.proposeDimensions();
            if (dims) {
              terminalService.resize(sessionId, dims.cols, dims.rows).catch(() => {});
            }
          } catch {
            // Container may not be ready yet
          }
          onReady?.();
        });

        // Subscribe to PTY output.
        //
        // Note: there is a small window between terminal creation (above) and
        // when `listen()` resolves (below) during which PTY output events
        // could be emitted and missed.  In practice this is negligible because
        // the Tauri event bridge queues on the Rust side and `listen()` is
        // typically resolved within a single microtask.  If exact
        // byte-fidelity is needed, use `terminal_preview` to back-fill.
        terminalService
          .onOutput(sessionId, (data: string) => {
            if (
              !isDisposedRef.current
              && mountedSessionRef.current === sessionId
              && termRef.current
            ) {
              termRef.current.write(data);
            }
          })
          .then((unlisten) => {
            if (isDisposedRef.current || mountedSessionRef.current !== sessionId) {
              // Terminal was disposed or re-mounted with a different session
              // while the listener was being registered.
              unlisten();
            } else {
              unlistenRef.current = unlisten;
            }
          })
          .catch((err) => {
            console.error("[TerminalRenderer] Failed to subscribe to output:", err);
          });

        // Forward user input to PTY stdin
        const onDataDispose = term.onData((data: string) => {
          if (isDisposedRef.current || mountedSessionRef.current !== sessionId) {
            return;
          }
          terminalService.write(sessionId, data).catch(() => {});
        });
        onDataDisposeRef.current = onDataDispose;
      })
      .catch((err) => {
        console.error("[TerminalRenderer] Failed to initialize ghostty-web:", err);
      });

    // Cleanup
    return () => {
      cancelled = true;
      isDisposedRef.current = true;
      if (mountedSessionRef.current === sessionId) {
        mountedSessionRef.current = null;
      }

      if (unlistenRef.current) {
        unlistenRef.current();
        unlistenRef.current = null;
      }
      if (onDataDisposeRef.current) {
        onDataDisposeRef.current.dispose();
        onDataDisposeRef.current = null;
      }

      termRef.current?.dispose();
      termRef.current = null;
      fitAddonRef.current = null;
    };
    // We intentionally only run this effect once per sessionId mount.
    // active/fontSize changes are handled by separate effects below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId]);

  // --- Update font size and cursor when active changes ---
  useEffect(() => {
    const term = termRef.current;
    if (!term) return;
    term.options.fontSize = resolvedFontSize;
    term.options.cursorBlink = active;
    // Re-fit after font size change
    requestAnimationFrame(() => {
      try {
        fitAddonRef.current?.fit();
        const dims = fitAddonRef.current?.proposeDimensions();
        if (dims && sessionId) {
          terminalService.resize(sessionId, dims.cols, dims.rows).catch(() => {});
        }
      } catch {
        // ignore
      }
    });
  }, [active, resolvedFontSize, sessionId]);

  // --- Refit when container size changes ---
  const handleResize = useCallback(() => {
    if (isDisposedRef.current) return;
    try {
      fitAddonRef.current?.fit();
      const dims = fitAddonRef.current?.proposeDimensions();
      if (dims && sessionId) {
        terminalService.resize(sessionId, dims.cols, dims.rows).catch(() => {});
      }
    } catch {
      // ignore
    }
  }, [sessionId]);

  // Watch for container resize via ResizeObserver
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const observer = new ResizeObserver(() => {
      handleResize();
    });
    observer.observe(container);
    return () => observer.disconnect();
  }, [handleResize]);

  // Also refit when width/height props change
  useEffect(() => {
    handleResize();
  }, [width, height, handleResize]);

  return (
    <div
      ref={containerRef}
      className="nodrag nowheel"
      style={{
        width: "100%",
        height: "100%",
        overflow: "hidden",
        backgroundColor: "#0a0c12",
      }}
      // Prevent React Flow from capturing keyboard events inside the terminal
      onKeyDown={(e) => e.stopPropagation()}
      onKeyUp={(e) => e.stopPropagation()}
      // Prevent React Flow from treating mouse events inside as drag/pan
      onMouseDown={(e) => e.stopPropagation()}
      onWheel={(e) => e.stopPropagation()}
    />
  );
}
