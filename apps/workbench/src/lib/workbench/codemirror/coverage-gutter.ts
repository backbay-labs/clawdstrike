/**
 * CodeMirror 6 gutter extension for MITRE ATT&CK coverage gap indicators.
 *
 * Places colored circle markers next to guards that have uncovered
 * MITRE techniques: red for >= 3 uncovered, amber for 1-2 uncovered.
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
import type { CoverageGap } from "./gutter-types";

// ---- State management ----

/** Effect to push coverage gap data into editor state. */
export const updateCoverageGaps = StateEffect.define<CoverageGap[]>();

/** State field storing current coverage gaps. */
export const coverageGapsField = StateField.define<CoverageGap[]>({
  create() {
    return [];
  },
  update(value, tr) {
    for (const effect of tr.effects) {
      if (effect.is(updateCoverageGaps)) {
        return effect.value;
      }
    }
    return value;
  },
});

/**
 * Derived state field that builds a RangeSet of CoverageGapMarkers.
 * The gutter reads this field directly via the `markers` option.
 */
const coverageMarkerSet = StateField.define<RangeSet<GutterMarker>>({
  create() {
    return RangeSet.empty;
  },
  update(value, tr) {
    // Keep marker positions in sync with document edits
    if (tr.docChanged) value = value.map(tr.changes);
    for (const effect of tr.effects) {
      if (effect.is(updateCoverageGaps)) {
        const gaps = effect.value;
        const markers: { from: number; marker: GutterMarker }[] = [];
        for (const gap of gaps) {
          if (gap.line >= 1 && gap.line <= tr.state.doc.lines) {
            const line = tr.state.doc.line(gap.line);
            markers.push({
              from: line.from,
              marker: new CoverageGapMarker(gap.uncoveredTechniques),
            });
          }
        }
        markers.sort((a, b) => a.from - b.from);
        return RangeSet.of(
          markers.map((m) => m.marker.range(m.from)),
        );
      }
    }
    return value;
  },
});

// ---- Gutter marker ----

class CoverageGapMarker extends GutterMarker {
  constructor(readonly uncoveredTechniques: string[]) {
    super();
  }

  override eq(other: GutterMarker): boolean {
    if (!(other instanceof CoverageGapMarker)) return false;
    const a = this.uncoveredTechniques;
    const b = other.uncoveredTechniques;
    return a.length === b.length && a.every((t, i) => t === b[i]);
  }

  override toDOM(): HTMLElement {
    const span = document.createElement("span");
    span.className = "cm-coverage-gap-marker";

    const count = this.uncoveredTechniques.length;
    // Red for >= 3 uncovered techniques, amber for 1-2
    const color = count >= 3 ? "#c45c5c" : "#d4a84b";
    span.style.backgroundColor = color;

    const techniqueList = this.uncoveredTechniques.join(", ");
    span.title = `${count} uncovered: ${techniqueList}`;

    return span;
  }
}

// ---- Extension factory ----

/**
 * Create the coverage gap gutter extension.
 *
 * Returns an Extension[] containing:
 * 1. The coverage gaps StateField
 * 2. A derived marker RangeSet field
 * 3. A gutter that displays CoverageGapMarker on the first line of each gap
 * 4. Theme styling for the colored circle indicators
 */
export function coverageGapGutter(): Extension[] {
  return [
    coverageGapsField,
    coverageMarkerSet,

    gutter({
      class: "cm-coverage-gap-gutter",
      markers: (view) => view.state.field(coverageMarkerSet),
    }),

    EditorView.theme({
      ".cm-coverage-gap-gutter": {
        width: "14px",
      },
      ".cm-coverage-gap-gutter .cm-gutterElement": {
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "0",
      },
      ".cm-coverage-gap-marker": {
        display: "inline-block",
        width: "6px",
        height: "6px",
        borderRadius: "50%",
      },
    }),
  ];
}
