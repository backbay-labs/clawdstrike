import { describe, expect, it } from "vitest";
import { analyzeSpiritDrawDraft } from "./analysis";
import type { SpiritRitualDrawDraft } from "../state/types";

function buildCircleLikeDraft(): SpiritRitualDrawDraft {
  return {
    strokes: [{
      id: "circle",
      points: [
        { x: 320, y: 90 },
        { x: 420, y: 180 },
        { x: 320, y: 270 },
        { x: 220, y: 180 },
        { x: 320, y: 90 },
      ],
    }],
    canvasWidth: 640,
    canvasHeight: 360,
  };
}

function buildLedgerLikeDraft(): SpiritRitualDrawDraft {
  return {
    strokes: [
      { id: "line-1", points: [{ x: 120, y: 100 }, { x: 520, y: 100 }] },
      { id: "line-2", points: [{ x: 120, y: 170 }, { x: 520, y: 170 }] },
      { id: "line-3", points: [{ x: 120, y: 240 }, { x: 520, y: 240 }] },
    ],
    canvasWidth: 640,
    canvasHeight: 360,
  };
}

describe("analyzeSpiritDrawDraft", () => {
  it("reads a centered closed sketch as tracker/lantern leaning", () => {
    const analysis = analyzeSpiritDrawDraft(buildCircleLikeDraft());

    expect(analysis.scoredKinds[0]?.kind).toBe("tracker");
    expect(analysis.features.closureRatio).toBeGreaterThan(0.5);
    expect(analysis.focusSurfaces).toContain("Entities");
  });

  it("reads stacked horizontal structure as ledger leaning", () => {
    const analysis = analyzeSpiritDrawDraft(buildLedgerLikeDraft());

    expect(analysis.scoredKinds[0]?.kind).toBe("ledger");
    expect(analysis.features.horizontalRatio).toBeGreaterThan(0.4);
  });
});

