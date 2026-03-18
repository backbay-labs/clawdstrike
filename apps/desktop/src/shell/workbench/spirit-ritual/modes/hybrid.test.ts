import { describe, expect, it } from "vitest";
import { createInitialHuntStore } from "../../huntTypes";
import { createInitialSpiritRitualDraft } from "../state/draft";
import { deriveSpiritRitualSynthesis } from "./hybrid";
import type { SpiritRitualContext } from "../state/types";

function buildContext(): SpiritRitualContext {
  const store = createInitialHuntStore();
  return {
    hunt: store.hunts.hunt_demo_1,
    artifacts: store.artifacts,
    runs: store.runs,
    currentLens: "files",
    currentShell: "lab",
    activeStationId: "workflows",
  };
}

describe("deriveSpiritRitualSynthesis", () => {
  it("switches into hybrid when intention and upload signals both engage", () => {
    const context = buildContext();
    const draft = createInitialSpiritRitualDraft(context);
    draft.intention.text = "Trace the mounted payload through the evidence trail";
    draft.upload.selectedItemIds = draft.upload.items
      .filter((item) => item.artifactId === "art_demo_3" || item.artifactId === "art_demo_2")
      .map((item) => item.id);
    draft.upload.preferredAnchorIds = ["art_demo_3", "art_demo_2"];

    const synthesis = deriveSpiritRitualSynthesis(context, draft);

    expect(synthesis.resolvedMode).toBe("hybrid");
    expect(synthesis.engagedModes).toEqual(expect.arrayContaining(["intention", "upload"]));
    expect(synthesis.recommendation.kind).toBe("forge");
    expect(synthesis.anchorArtifactIds).toContain("art_demo_3");
  });

  it("falls back to the current spirit seed when the draft is untouched", () => {
    const context = buildContext();
    const draft = createInitialSpiritRitualDraft(context);
    draft.intention.text = "";
    draft.upload.selectedItemIds = [];
    draft.upload.preferredAnchorIds = [];

    const synthesis = deriveSpiritRitualSynthesis(context, draft);

    expect(synthesis.recommendation.kind).toBe(context.hunt.spirit?.kind);
    expect(synthesis.readiness.canRelease).toBe(true);
  });
});

