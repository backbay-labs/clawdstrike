import { describe, expect, it } from "vitest";
import { createHuntSpiritState, deriveHuntSpiritRuntimeState } from "@/shell/workbench/spirit";
import type { HuntSpiritSignalSnapshot } from "@/shell/workbench/spirit/selectors";
import { deriveHuntObservatorySceneState } from "@/features/hunt-observatory";
import {
  buildNexusAtlasRead,
  buildNexusAtlasStations,
  resolveNexusObservatoryStationId,
} from "./observatory";
import { deriveNexusSpiritSceneActor } from "./scene/spirits/runtime";
import type { Strikecell } from "./types";

const STRIKECELL: Strikecell = {
  id: "security-overview",
  name: "Security Overview",
  routeId: "security-overview",
  description: "Overview",
  status: "healthy",
  activityCount: 12,
  nodeCount: 4,
  nodes: [],
  tags: ["signal"],
};

const STRIKECELLS: Strikecell[] = [
  STRIKECELL,
  {
    id: "threat-radar",
    name: "Threat Radar",
    routeId: "threat-radar",
    description: "Watch posture",
    status: "warning",
    activityCount: 8,
    nodeCount: 3,
    nodes: [],
    tags: ["watch"],
  },
];

describe("resolveNexusObservatoryStationId", () => {
  it("maps strikecells onto observatory stations", () => {
    expect(resolveNexusObservatoryStationId("security-overview")).toBe("signal");
    expect(resolveNexusObservatoryStationId("attack-graph")).toBe("targets");
    expect(resolveNexusObservatoryStationId("forensics-river")).toBe("receipts");
    expect(resolveNexusObservatoryStationId("policies")).toBe("case-notes");
  });
});

describe("buildNexusAtlasRead", () => {
  it("prefers the explicit observatory selection over the likely spirit station", () => {
    const boundSpirit = createHuntSpiritState({
      kind: "tracker",
      bindSource: "quick-configure",
      bindReason: "Target-heavy hunt with live threat pressure.",
      confidenceScore: 82,
      boundAt: 1_000,
    });
    const runtime = deriveHuntSpiritRuntimeState(boundSpirit, {
      currentShell: "hunt",
      currentLens: "scopes",
      activeStationId: STRIKECELL.id,
      likelyIntent: "watch",
      confidenceScore: 84,
      isActive: true,
    });
    const snapshot: HuntSpiritSignalSnapshot = {
      huntId: "hunt-1",
      huntTitle: "Ghostline",
      currentShell: "hunt",
      currentLens: "scopes",
      activeRunId: null,
      activeCaseId: null,
      draggedObjectKind: null,
      likelyIntent: "watch" as const,
      phaseScore: 0.74,
      confidenceScore: 84,
      phase: "investigation" as const,
      totalArtifacts: 3,
      totalRuns: 0,
      artifactCounts: { entity: 2, signal: 1 },
      semanticCounts: { watch: 1 },
      dominantArtifactKinds: ["entity", "signal"],
      dominantSemantics: ["watch"],
      runningRunCount: 0,
      suggestedAnchorArtifactIds: [],
      boundSpirit,
    };
    const actor = deriveNexusSpiritSceneActor({
      runtime,
      snapshot,
      strikecells: STRIKECELLS,
      activeStrikecellId: "security-overview",
      cue: null,
    });
    const sceneState = deriveHuntObservatorySceneState(snapshot, {
      mode: "atlas",
      activeStationId: "signal",
    });

    const read = buildNexusAtlasRead({
      sceneState,
      activeStrikecell: STRIKECELL,
      activeSpiritActor: actor,
    });

    expect(read.label).toBe("Horizon");
    expect(read.code).toBe("HRZ");
    expect(read.coreLabel).toBe("Thesis Core");
  });
});

describe("buildNexusAtlasStations", () => {
  it("marks active and likely stations in the atlas strip", () => {
    const snapshot: HuntSpiritSignalSnapshot = {
      huntId: "hunt-1",
      huntTitle: "Ghostline",
      currentShell: "hunt",
      currentLens: "scopes",
      activeRunId: null,
      activeCaseId: null,
      draggedObjectKind: null,
      likelyIntent: "watch",
      phaseScore: 0.74,
      confidenceScore: 84,
      phase: "investigation",
      totalArtifacts: 3,
      totalRuns: 0,
      artifactCounts: { entity: 2, signal: 1 },
      semanticCounts: { watch: 1 },
      dominantArtifactKinds: ["entity", "signal"],
      dominantSemantics: ["watch"],
      runningRunCount: 0,
      suggestedAnchorArtifactIds: [],
      boundSpirit: null,
    };
    const sceneState = deriveHuntObservatorySceneState(snapshot, {
      mode: "atlas",
      activeStationId: "signal",
    });
    const stations = buildNexusAtlasStations({
      sceneState,
      activeStrikecellId: "security-overview",
      activeSpiritActor: null,
    });
    expect(stations.find((station) => station.stationId === "signal")?.active).toBe(true);
    expect(stations.find((station) => station.stationId === "signal")?.code).toBe("HRZ");
  });
});
