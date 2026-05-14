/**
 * CodeMirror 6 remote cursor & selection extension for multi-analyst presence.
 *
 * Renders colored vertical carets at remote analysts' cursor positions and
 * translucent highlights over their selections.  Hovering a caret shows a
 * floating label with the analyst's display name.
 *
 * Data flow:
 *   Inbound  — Zustand usePresenceStore.subscribe() (raw, outside React)
 *              dispatches StateEffect into the editor.
 *   Outbound — ViewPlugin.update() detects local selection changes, throttles
 *              to 50 ms, and sends via getPresenceSocket().
 *
 * Architecture follows the same Facet+StateEffect+StateField pattern as
 * guard-gutter.ts — the extension is added statically to the extensions
 * array and never rebuilt when cursor data changes.
 */

import {
  type DecorationSet,
  Decoration,
  EditorView,
  ViewPlugin,
  type ViewUpdate,
  WidgetType,
} from "@codemirror/view";
import {
  Facet,
  Prec,
  StateEffect,
  StateField,
  type Extension,
  type Range,
} from "@codemirror/state";
import {
  usePresenceStore,
  type PresenceStoreState,
} from "@/features/presence/stores/presence-store";
import { getPresenceSocket } from "@/features/presence/use-presence-connection";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Hard cap on rendered remote cursors per editor instance. */
const MAX_REMOTE_CURSORS = 20;

/** Outbound cursor update throttle in milliseconds. */
const THROTTLE_MS = 50;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

interface RemoteCursorData {
  fingerprint: string;
  displayName: string;
  color: string;
  cursor: { line: number; ch: number } | null;
  selection: {
    anchorLine: number;
    anchorCh: number;
    headLine: number;
    headCh: number;
  } | null;
}

function collectRemoteCursors(
  filePath: string,
  state: Pick<PresenceStoreState, "analysts" | "localAnalystId">,
): RemoteCursorData[] {
  if (!filePath) {
    return [];
  }

  const cursors: RemoteCursorData[] = [];

  for (const [fp, analyst] of state.analysts) {
    if (fp === state.localAnalystId) continue;
    if (analyst.activeFile !== filePath) continue;
    if (!analyst.cursor && !analyst.selection) continue;
    cursors.push({
      fingerprint: fp,
      displayName: analyst.displayName,
      color: analyst.color,
      cursor: analyst.cursor,
      selection: analyst.selection,
    });
  }

  return cursors;
}

// ---------------------------------------------------------------------------
// Facet — file path injection (set once per editor instance)
// ---------------------------------------------------------------------------

/**
 * Facet that tells the presence plugin which file this editor is showing.
 * Provided via `presenceFilePath.of(path)` in the extensions array.
 */
export const presenceFilePath = Facet.define<string, string>({
  combine: (values) => values[values.length - 1] ?? "",
});

// Alias kept for acceptance criteria (remotePresenceFacet)
export { presenceFilePath as remotePresenceFacet };

// ---------------------------------------------------------------------------
// StateEffect + StateField — remote cursor data injection
// ---------------------------------------------------------------------------

/** Effect to push remote cursor data into the editor. */
export const updateRemoteCursors = StateEffect.define<RemoteCursorData[]>();

/** State field storing the latest set of remote cursors for this editor. */
const remoteCursorsField = StateField.define<RemoteCursorData[]>({
  create(state) {
    return collectRemoteCursors(
      state.facet(presenceFilePath),
      usePresenceStore.getState(),
    );
  },
  update(value, tr) {
    for (const effect of tr.effects) {
      if (effect.is(updateRemoteCursors)) {
        return effect.value;
      }
    }
    return value;
  },
});

// ---------------------------------------------------------------------------
// CursorCaretWidget — renders the colored vertical bar + hover label
// ---------------------------------------------------------------------------

class CursorCaretWidget extends WidgetType {
  constructor(
    readonly displayName: string,
    readonly color: string,
  ) {
    super();
  }

  override eq(other: WidgetType): boolean {
    return (
      other instanceof CursorCaretWidget &&
      other.displayName === this.displayName &&
      other.color === this.color
    );
  }

  override ignoreEvent(): boolean {
    return true; // Don't capture clicks or other events
  }

  override toDOM(): HTMLElement {
    const caret = document.createElement("span");
    caret.className = "cm-remote-caret";
    caret.style.borderLeftColor = this.color;

    const label = document.createElement("span");
    label.className = "cm-remote-caret-label";
    label.textContent = this.displayName;
    label.style.backgroundColor = this.color;

    caret.appendChild(label);
    return caret;
  }
}

// ---------------------------------------------------------------------------
// ViewPlugin — orchestrates inbound subscription + outbound sends
// ---------------------------------------------------------------------------

const presenceCursorsPlugin = ViewPlugin.fromClass(
  class {
    decorations: DecorationSet = Decoration.none;
    private unsubscribe: (() => void) | null = null;
    private throttleTimer: ReturnType<typeof setTimeout> | null = null;
    private lastSentMessage = "";

    constructor(private view: EditorView) {
      this.decorations = this.buildDecorations(
        view,
        view.state.field(remoteCursorsField),
      );

      // Subscribe to presence store outside React.
      // On every store update we extract remote cursors for this file and
      // dispatch a StateEffect so the StateField + decorations update.
      this.unsubscribe = usePresenceStore.subscribe((state) => {
        const cursors = collectRemoteCursors(
          this.view.state.facet(presenceFilePath),
          state,
        );

        // Dispatch into the editor — safe from outside React
        this.view.dispatch({ effects: updateRemoteCursors.of(cursors) });
      });
    }

    update(update: ViewUpdate): void {
      // Rebuild decorations whenever the cursor data field changes
      const cursors = update.state.field(remoteCursorsField);
      this.decorations = this.buildDecorations(update.view, cursors);

      // Outbound: send local cursor/selection changes throttled
      if (update.selectionSet) {
        this.scheduleOutboundCursor(update.view);
      }
    }

    destroy(): void {
      this.unsubscribe?.();
      this.unsubscribe = null;

      if (this.throttleTimer != null) {
        clearTimeout(this.throttleTimer);
        this.throttleTimer = null;
      }

      this.decorations = Decoration.none;
    }

    // ---- Decoration builder ----

    private buildDecorations(
      view: EditorView,
      cursors: RemoteCursorData[],
    ): DecorationSet {
      if (cursors.length === 0) return Decoration.none;

      const doc = view.state.doc;
      const maxLine = doc.lines;
      const limited = cursors.slice(0, MAX_REMOTE_CURSORS);

      const decorations: Range<Decoration>[] = [];

      for (const c of limited) {
        // Cursor caret widget
        if (c.cursor) {
          const line = Math.max(1, Math.min(c.cursor.line, maxLine));
          const lineObj = doc.line(line);
          const ch = Math.max(0, Math.min(c.cursor.ch, lineObj.length));
          const pos = lineObj.from + ch;

          decorations.push(
            Decoration.widget({
              widget: new CursorCaretWidget(c.displayName, c.color),
              side: 1,
            }).range(pos),
          );
        }

        // Selection highlight mark
        if (c.selection) {
          const anchorLine = Math.max(
            1,
            Math.min(c.selection.anchorLine, maxLine),
          );
          const headLine = Math.max(
            1,
            Math.min(c.selection.headLine, maxLine),
          );

          const anchorLineObj = doc.line(anchorLine);
          const headLineObj = doc.line(headLine);

          const anchorCh = Math.max(
            0,
            Math.min(c.selection.anchorCh, anchorLineObj.length),
          );
          const headCh = Math.max(
            0,
            Math.min(c.selection.headCh, headLineObj.length),
          );

          const from = anchorLineObj.from + anchorCh;
          const to = headLineObj.from + headCh;

          // Ensure from <= to for the mark range
          const markFrom = Math.min(from, to);
          const markTo = Math.max(from, to);

          if (markFrom !== markTo) {
            decorations.push(
              Decoration.mark({
                class: "cm-remote-selection",
                attributes: {
                  style: `background-color: ${c.color}33`,
                },
              }).range(markFrom, markTo),
            );
          }
        }
      }

      // RangeSet.of requires sorted ranges
      decorations.sort((a, b) => a.from - b.from);
      return Decoration.set(decorations, true);
    }

    // ---- Outbound cursor throttle ----

    private scheduleOutboundCursor(view: EditorView): void {
      if (this.throttleTimer != null) return; // Throttle active
      this.throttleTimer = setTimeout(() => {
        this.throttleTimer = null;
        this.sendCursorUpdate(view);
      }, THROTTLE_MS);
    }

    private sendCursorUpdate(view: EditorView): void {
      const filePath = view.state.facet(presenceFilePath);
      if (!filePath) return;

      const socket = getPresenceSocket();
      if (!socket) return;

      const sel = view.state.selection.main;
      const headLineObj = view.state.doc.lineAt(sel.head);
      const headLine = headLineObj.number;
      const headCh = sel.head - headLineObj.from;

      if (sel.head === sel.anchor) {
        // No selection — just a cursor position
        const msg = JSON.stringify({
          type: "cursor",
          file_path: filePath,
          line: headLine,
          ch: headCh,
        });
        if (msg === this.lastSentMessage) return; // Dedup
        this.lastSentMessage = msg;
        socket.send({
          type: "cursor",
          file_path: filePath,
          line: headLine,
          ch: headCh,
        });
      } else {
        // Selection range
        const anchorLineObj = view.state.doc.lineAt(sel.anchor);
        const anchorLine = anchorLineObj.number;
        const anchorCh = sel.anchor - anchorLineObj.from;

        const msg = JSON.stringify({
          type: "selection",
          file_path: filePath,
          anchor_line: anchorLine,
          anchor_ch: anchorCh,
          head_line: headLine,
          head_ch: headCh,
        });
        if (msg === this.lastSentMessage) return; // Dedup
        this.lastSentMessage = msg;
        socket.send({
          type: "selection",
          file_path: filePath,
          anchor_line: anchorLine,
          anchor_ch: anchorCh,
          head_line: headLine,
          head_ch: headCh,
        });
      }
    }
  },
  {
    decorations: (v) => v.decorations,
  },
);

// ---------------------------------------------------------------------------
// Theme — caret, label, and selection highlight styles
// ---------------------------------------------------------------------------

const presenceCursorsTheme = EditorView.theme({
  ".cm-remote-caret": {
    position: "relative",
    borderLeft: "2px solid",
    marginLeft: "-1px",
    marginRight: "-1px",
    pointerEvents: "auto",
  },
  ".cm-remote-caret-label": {
    position: "absolute",
    bottom: "100%",
    left: "-1px",
    padding: "1px 6px",
    borderRadius: "4px 4px 4px 0",
    fontSize: "11px",
    fontFamily: "'JetBrains Mono', monospace",
    lineHeight: "1.4",
    color: "#fff",
    whiteSpace: "nowrap",
    opacity: "0",
    transition: "opacity 150ms ease",
    pointerEvents: "none",
    zIndex: "10",
  },
  ".cm-remote-caret:hover .cm-remote-caret-label": {
    opacity: "1",
  },
  ".cm-remote-selection": {
    // Background color set inline via attributes.style
  },
});

// ---------------------------------------------------------------------------
// Extension factory
// ---------------------------------------------------------------------------

/**
 * Create the presence cursor extension for multi-analyst awareness.
 *
 * Returns an Extension[] containing:
 * 1. The remote cursors StateField (data store)
 * 2. The ViewPlugin (subscription, decoration building, outbound sends)
 * 3. Theme styles for carets, labels, and selection highlights
 *
 * Wrapped in Prec.low to avoid conflicting with guard-gutter and
 * coverage-gutter extensions.
 */
export function presenceCursors(): Extension[] {
  return [
    Prec.low(remoteCursorsField),
    Prec.low(presenceCursorsPlugin),
    Prec.low(presenceCursorsTheme),
  ];
}
