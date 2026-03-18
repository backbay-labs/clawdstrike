import { describe, expect, it } from "vitest";
import { createInitialHuntStore } from "../../huntTypes";
import {
  createInitialSpiritRitualDraft,
  createSpiritRitualStrokeId,
  spiritRitualDraftReducer,
} from "./draft";
import type { SpiritRitualContext } from "./types";

function buildContext(): SpiritRitualContext {
  const store = createInitialHuntStore();
  return {
    hunt: store.hunts.hunt_demo_1,
    artifacts: store.artifacts,
    runs: store.runs,
    currentLens: "files",
    currentShell: "hunt",
    activeStationId: "forensics-river",
  };
}

describe("spiritRitualDraftReducer", () => {
  it("hydrates the shared draft from the current hunt spirit and anchor set", () => {
    const draft = createInitialSpiritRitualDraft(buildContext());

    expect(draft.intention.text).toContain("mounted payload path");
    expect(draft.upload.items.length).toBeGreaterThan(0);
    expect(draft.upload.selectedItemIds.length).toBe(2);
    expect(draft.isPinned).toBe(false);
  });

  it("preserves draw state while the operator moves between ritual panels", () => {
    const initial = createInitialSpiritRitualDraft(buildContext());
    const withStroke = spiritRitualDraftReducer(initial, {
      type: "append-draw-stroke",
      stroke: {
        id: createSpiritRitualStrokeId(),
        points: [
          { x: 40, y: 60 },
          { x: 120, y: 60 },
          { x: 120, y: 140 },
        ],
      },
    });
    const switched = spiritRitualDraftReducer(withStroke, {
      type: "set-active-panel",
      panel: "upload",
    });

    expect(switched.activePanel).toBe("upload");
    expect(switched.draw.strokes).toHaveLength(1);
  });

  it("auto-selects uploaded items and keeps preferred anchors aligned", () => {
    const initial = createInitialSpiritRitualDraft(buildContext());
    const next = spiritRitualDraftReducer(initial, {
      type: "add-upload-items",
      items: [{
        id: "artifact:extra",
        kind: "artifact-anchor",
        label: "Case memo",
        artifactId: "art_demo_6",
        artifactKind: "note",
        semanticHints: ["notes"],
        mimeType: null,
        extension: "md",
        byteSize: null,
      }],
    });

    expect(next.upload.selectedItemIds).toContain("artifact:extra");
    expect(next.upload.preferredAnchorIds).toContain("art_demo_6");
  });
});

