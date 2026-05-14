/**
 * CodeMirror 6 gutter extension for "Run Test" buttons on guard config sections.
 *
 * Places a play-button icon in the gutter on the first line of each guard
 * config block. The button is hidden by default and appears on hover.
 * Clicking dispatches the onRunTest callback with the guard ID.
 */

import {
  gutter,
  GutterMarker,
  EditorView,
} from "@codemirror/view";
import {
  StateField,
  StateEffect,
  RangeSet,
  type Extension,
} from "@codemirror/state";
import { getGuardMeta } from "@/lib/workbench/guard-registry";
import type { GuardLineRange } from "./gutter-types";

// ---- State management ----

/** Effect to push parsed guard ranges into editor state. */
export const updateGuardRanges = StateEffect.define<GuardLineRange[]>();

/** State field storing current guard ranges. */
export const guardRangesField = StateField.define<GuardLineRange[]>({
  create() {
    return [];
  },
  update(value, tr) {
    for (const effect of tr.effects) {
      if (effect.is(updateGuardRanges)) {
        return effect.value;
      }
    }
    return value;
  },
});

/**
 * Derived state field that builds a RangeSet of RunTestMarkers from guard ranges.
 * The gutter reads this field directly via the `markers` option.
 */
const guardMarkerSet = StateField.define<RangeSet<GutterMarker>>({
  create() {
    return RangeSet.empty;
  },
  update(value, tr) {
    // Keep marker positions in sync with document edits
    if (tr.docChanged) value = value.map(tr.changes);
    // Rebuild when guard ranges change
    for (const effect of tr.effects) {
      if (effect.is(updateGuardRanges)) {
        const ranges = effect.value;
        const markers: ReturnType<GutterMarker["range"]>[] = [];
        for (const range of ranges) {
          if (range.fromLine >= 1 && range.fromLine <= tr.state.doc.lines) {
            const line = tr.state.doc.line(range.fromLine);
            markers.push(new RunTestMarker(range.guardId).range(line.from));
          }
        }
        // RangeSet.of requires sorted ranges
        markers.sort((a, b) => a.from - b.from);
        return RangeSet.of(markers);
      }
    }
    return value;
  },
});

// ---- Gutter marker ----

class RunTestMarker extends GutterMarker {
  constructor(readonly guardId: string) {
    super();
  }

  override eq(other: GutterMarker): boolean {
    return other instanceof RunTestMarker && other.guardId === this.guardId;
  }

  override toDOM(): HTMLElement {
    const span = document.createElement("span");
    span.className = "cm-guard-test-btn";
    span.textContent = "\u25B6"; // Black right-pointing triangle
    const meta = getGuardMeta(this.guardId);
    span.title = `Run test: ${meta?.name ?? this.guardId}`;
    span.dataset.guardId = this.guardId;
    return span;
  }
}

// ---- Extension factory ----

/**
 * Create the guard test gutter extension.
 *
 * Returns an Extension[] containing:
 * 1. The guard ranges StateField
 * 2. A derived marker RangeSet field
 * 3. A gutter that displays RunTestMarker on the first line of each guard range
 * 4. Theme styling for the play button (hidden by default, visible on hover)
 * 5. A DOM event handler that intercepts clicks on play buttons
 *
 * @param onRunTest - Callback invoked with the guard ID when a play button is clicked.
 */
export function guardTestGutter(
  onRunTest: (guardId: string) => void,
): Extension[] {
  return [
    guardRangesField,
    guardMarkerSet,

    gutter({
      class: "cm-guard-test-gutter",
      markers: (view) => view.state.field(guardMarkerSet),
    }),

    EditorView.theme({
      ".cm-guard-test-gutter": {
        width: "20px",
      },
      ".cm-guard-test-gutter .cm-gutterElement": {
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "0",
      },
      ".cm-guard-test-btn": {
        opacity: "0",
        transition: "opacity 150ms ease",
        cursor: "pointer",
        color: "#d4a84b",
        fontSize: "10px",
        lineHeight: "1",
        userSelect: "none",
      },
      ".cm-guard-test-gutter .cm-gutterElement:hover .cm-guard-test-btn": {
        opacity: "1",
      },
      ".cm-guard-test-btn:hover": {
        color: "#3dbf84",
      },
    }),

    EditorView.domEventHandlers({
      click(event) {
        const target = event.target as HTMLElement;
        const btn = target.closest(".cm-guard-test-btn") as HTMLElement | null;
        if (btn?.dataset.guardId) {
          event.preventDefault();
          event.stopPropagation();
          onRunTest(btn.dataset.guardId);
          return true;
        }
        return false;
      },
    }),
  ];
}
