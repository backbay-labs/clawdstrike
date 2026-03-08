import { describe, expect, it } from "vitest";
import { createInitialWorkbenchState } from "../../workbenchState";
import { selectActiveHuntSpiritSignalSnapshot } from "./index";

describe("selectActiveHuntSpiritSignalSnapshot", () => {
  it("builds a signal snapshot from the active demo hunt", () => {
    const state = createInitialWorkbenchState();
    state.shell = "lab";
    state.lens = "files";

    const snapshot = selectActiveHuntSpiritSignalSnapshot(state);

    expect(snapshot).not.toBeNull();
    expect(snapshot?.huntId).toBe("hunt_demo_1");
    expect(snapshot?.activeRunId).toBe("run_demo_1");
    expect(snapshot?.phase).toBe("investigation");
    expect(snapshot?.artifactCounts.file).toBe(1);
    expect(snapshot?.semanticCounts.mount).toBe(1);
    expect(snapshot?.dominantArtifactKinds).toContain("file");
    expect(snapshot?.suggestedAnchorArtifactIds).toContain("art_demo_3");
  });

  it("accepts explicit signal overrides for drag intent and case context", () => {
    const state = createInitialWorkbenchState();
    state.shell = "case";
    state.lens = "notes";
    state.huntStore.hunts.hunt_demo_1.caseId = "case_demo_1";
    state.huntStore.cases.case_demo_1 = {
      id: "case_demo_1",
      title: "Case 1",
      status: "investigating",
      huntIds: ["hunt_demo_1"],
      artifactIds: ["art_demo_4"],
      semanticAssignments: { cite: ["art_demo_4"] },
    };

    const snapshot = selectActiveHuntSpiritSignalSnapshot(state, {
      draggedObjectKind: "receipt",
      likelyIntent: "cite",
      confidenceScore: 91,
    });

    expect(snapshot?.activeCaseId).toBe("case_demo_1");
    expect(snapshot?.likelyIntent).toBe("cite");
    expect(snapshot?.draggedObjectKind).toBe("receipt");
    expect(snapshot?.semanticCounts.cite).toBe(1);
    expect(snapshot?.confidenceScore).toBe(91);
  });
});
