import { describe, expect, it } from "vitest";
import { createInitialWorkbenchState } from "../../workbenchState";
import { inferHuntSpirit, createInferredHuntSpiritState } from "./index";
import { selectActiveHuntSpiritSignalSnapshot } from "../selectors";
import { createHuntSpiritState } from "../defaults";

describe("inferHuntSpirit", () => {
  it("selects forge for a run-heavy file-led hunt", () => {
    const state = createInitialWorkbenchState();
    state.shell = "lab";
    state.lens = "files";

    const snapshot = selectActiveHuntSpiritSignalSnapshot(state);
    expect(snapshot).not.toBeNull();

    const result = inferHuntSpirit(snapshot!);

    expect(result.baseSpirit.kind).toBe("forge");
    expect(result.liveMood).toBe("pressured");
    expect(result.biasLine).toContain("Files");
    expect(result.alternates).toHaveLength(2);
  });

  it("keeps a pinned spirit primary until explicitly rebound", () => {
    const state = createInitialWorkbenchState();
    state.shell = "case";
    state.lens = "notes";
    state.huntStore.hunts.hunt_demo_2.caseId = "case_demo_2";
    state.huntStore.hunts.hunt_demo_2.spirit = createHuntSpiritState({
      kind: "tracker",
      bindSource: "manual",
      isPinned: true,
      confidenceScore: 60,
    });
    state.huntStore.dock.activeHuntId = "hunt_demo_2";
    state.huntStore.cases.case_demo_2 = {
      id: "case_demo_2",
      title: "Proof Cluster",
      status: "investigating",
      huntIds: ["hunt_demo_2"],
      artifactIds: ["art_demo_4"],
      semanticAssignments: { cite: ["art_demo_4"] },
    };

    const snapshot = selectActiveHuntSpiritSignalSnapshot(state, {
      likelyIntent: "cite",
      draggedObjectKind: "receipt",
    });
    expect(snapshot).not.toBeNull();

    const result = inferHuntSpirit(snapshot!);

    expect(result.baseSpirit.kind).toBe("tracker");
    expect(result.shouldRespectPinnedSpirit).toBe(true);
    expect(result.baseSpirit.rationale).toContain("pinned");
  });

  it("does not let strong opposing signals dislodge a pinned spirit", () => {
    const state = createInitialWorkbenchState();
    state.shell = "lab";
    state.lens = "files";
    state.huntStore.hunts.hunt_demo_1.spirit = createHuntSpiritState({
      kind: "tracker",
      bindSource: "manual",
      isPinned: true,
      confidenceScore: 88,
    });

    const snapshot = selectActiveHuntSpiritSignalSnapshot(state, {
      likelyIntent: "mount",
      draggedObjectKind: "file",
    });
    expect(snapshot).not.toBeNull();

    const result = inferHuntSpirit(snapshot!);

    expect(result.baseSpirit.kind).toBe("tracker");
    expect(result.shouldRespectPinnedSpirit).toBe(true);
    expect(result.baseSpirit.rationale).toContain("pinned");
  });
});

describe("createInferredHuntSpiritState", () => {
  it("turns an inference result into a bindable spirit state", () => {
    const state = createInitialWorkbenchState();
    state.shell = "lab";
    state.lens = "files";

    const snapshot = selectActiveHuntSpiritSignalSnapshot(state, {
      likelyIntent: "mount",
    });
    expect(snapshot).not.toBeNull();

    const spirit = createInferredHuntSpiritState(snapshot!, {
      bindSource: "quick-bind",
      thesis: "Trace the mounted payload path.",
    });

    expect(spirit.kind).toBe("forge");
    expect(spirit.bindSource).toBe("quick-bind");
    expect(spirit.liveMood).toBe("pressured");
    expect(spirit.anchorArtifactIds.length).toBeGreaterThan(0);
    expect(spirit.bindReason).toContain("Biases");
  });
});
