import { describe, expect, it } from "vitest";
import type { Hunt, HuntStore } from "../huntTypes";
import { createInitialHuntStore } from "../huntTypes";
import { buildSpiritBindCommit, canBindSpiritDraft, deriveSpiritBindCandidate } from "./suggestions";
import type { SpiritBindContext, SpiritBindDraft } from "./types";

function buildContext(hunt: Hunt, store: HuntStore): SpiritBindContext {
  return {
    hunt,
    artifacts: store.artifacts,
    runs: store.runs,
    currentLens: "files",
    currentShell: "hunt",
    activeStationId: "river",
  };
}

describe("spirit bind suggestions", () => {
  it("prefers forge for run-heavy file hunts", () => {
    const store = createInitialHuntStore();
    const forgeHunt: Hunt = {
      id: "hunt_forge",
      title: "Sandbox payload execution",
      status: "active",
      artifactIds: ["art_demo_3"],
      runIds: ["run_demo_1"],
      caseId: null,
      color: "#c77d2e",
      icon: "search",
      spirit: null,
      semanticAssignments: {
        mount: ["art_demo_3"],
        "run-input": ["art_demo_3"],
      },
    };
    const context = buildContext(forgeHunt, store);
    const draft: SpiritBindDraft = {
      mode: "quick-configure",
      thesis: "",
      selectedAnchorArtifactIds: [],
      manualKind: null,
      isPinned: false,
    };

    const candidate = deriveSpiritBindCandidate(context, draft);

    expect(candidate.kind).toBe("forge");
    expect(candidate.anchorArtifactIds).toEqual(["art_demo_3"]);
    expect(candidate.predictedFocusSurfaces).toContain("Files");
    expect(candidate.rationale).toContain("runs, files");
  });

  it("leans lantern when receipt anchors define the hunt center", () => {
    const store = createInitialHuntStore();
    const hunt = store.hunts.hunt_demo_2;
    const context = buildContext(hunt, store);
    const draft: SpiritBindDraft = {
      mode: "anchor-artifacts",
      thesis: "",
      selectedAnchorArtifactIds: ["art_demo_4"],
      manualKind: null,
      isPinned: false,
    };

    const candidate = deriveSpiritBindCandidate(context, draft);

    expect(candidate.kind).toBe("lantern");
    expect(candidate.bindSource).toBe("anchor-artifacts");
  });

  it("builds a reducer-ready commit with authored thesis and pin state", () => {
    const store = createInitialHuntStore();
    const context = buildContext(store.hunts.hunt_demo_3, store);
    const draft: SpiritBindDraft = {
      mode: "thesis",
      thesis: "Build proof for the DNS exfil receipt chain",
      selectedAnchorArtifactIds: [],
      manualKind: null,
      isPinned: true,
    };

    const commit = buildSpiritBindCommit(context, draft);

    expect(commit.bindSource).toBe("thesis");
    expect(commit.thesis).toContain("DNS exfil");
    expect(commit.isPinned).toBe(true);
    expect(commit.anchorArtifactIds.length).toBeGreaterThan(0);
    expect(commit.bindReason.length).toBeGreaterThan(10);
  });

  it("enforces thresholded bind rules by mode", () => {
    expect(
      canBindSpiritDraft({
        mode: "thesis",
        thesis: "short",
        selectedAnchorArtifactIds: [],
        manualKind: null,
        isPinned: false,
      }),
    ).toBe(false);

    expect(
      canBindSpiritDraft({
        mode: "anchor-artifacts",
        thesis: "",
        selectedAnchorArtifactIds: ["art_1"],
        manualKind: null,
        isPinned: false,
      }),
    ).toBe(true);
  });
});
