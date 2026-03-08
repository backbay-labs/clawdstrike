import { describe, expect, it } from "vitest";
import {
  createHuntSpiritState,
  deriveHuntSpiritRuntimeState,
  type HuntSpiritSignalSnapshot,
} from "@/shell/workbench/spirit";
import type { Strikecell } from "../../types";
import {
  deriveNexusSpiritSceneActor,
  deriveNexusSpiritStationAffinities,
  detectNexusSpiritCue,
} from "./runtime";

const STRIKECELLS: Strikecell[] = [
  {
    id: "security-overview",
    name: "Security Overview",
    routeId: "security-overview",
    description: "",
    status: "healthy",
    activityCount: 5,
    nodeCount: 3,
    nodes: [],
    tags: [],
  },
  {
    id: "threat-radar",
    name: "Threat Radar",
    routeId: "threat-radar",
    description: "",
    status: "warning",
    activityCount: 7,
    nodeCount: 5,
    nodes: [],
    tags: [],
  },
  {
    id: "attack-graph",
    name: "Attack Graph",
    routeId: "attack-graph",
    description: "",
    status: "healthy",
    activityCount: 4,
    nodeCount: 4,
    nodes: [],
    tags: [],
  },
  {
    id: "network-map",
    name: "Network Map",
    routeId: "network-map",
    description: "",
    status: "healthy",
    activityCount: 6,
    nodeCount: 4,
    nodes: [],
    tags: [],
  },
  {
    id: "forensics-river",
    name: "Nexus",
    routeId: "nexus",
    description: "",
    status: "healthy",
    activityCount: 3,
    nodeCount: 2,
    nodes: [],
    tags: [],
  },
  {
    id: "workflows",
    name: "Workflows",
    routeId: "workflows",
    description: "",
    status: "healthy",
    activityCount: 2,
    nodeCount: 2,
    nodes: [],
    tags: [],
  },
];

function makeSnapshot(overrides: Partial<HuntSpiritSignalSnapshot> = {}): HuntSpiritSignalSnapshot {
  return {
    huntId: "hunt-1",
    huntTitle: "Ghostline",
    currentShell: "hunt",
    currentLens: "entities",
    activeRunId: null,
    activeCaseId: null,
    draggedObjectKind: null,
    likelyIntent: "watch",
    phase: "investigation",
    phaseScore: 74,
    confidenceScore: 82,
    totalArtifacts: 4,
    totalRuns: 1,
    runningRunCount: 0,
    artifactCounts: {
      receipt: 1,
      file: 1,
      entity: 1,
    },
    semanticCounts: {
      watch: 1,
      target: 1,
    },
    dominantArtifactKinds: ["receipt", "file", "entity"],
    dominantSemantics: ["target", "watch"],
    suggestedAnchorArtifactIds: ["artifact-1"],
    boundSpirit: createHuntSpiritState({
      kind: "tracker",
      bindSource: "quick-bind",
      bindReason: "Target-heavy hunt with live threat pressure.",
      confidenceScore: 82,
      boundAt: 1_000,
    }),
    ...overrides,
  };
}

describe("deriveNexusSpiritStationAffinities", () => {
  it("biases threat and active station emphasis without replacing topology", () => {
    const snapshot = makeSnapshot();
    const runtime = deriveHuntSpiritRuntimeState(snapshot.boundSpirit, {
      currentShell: snapshot.currentShell,
      currentLens: snapshot.currentLens,
      likelyIntent: snapshot.likelyIntent,
      confidenceScore: snapshot.confidenceScore,
      activeStationId: "security-overview",
      isActive: true,
    });

    const affinities = deriveNexusSpiritStationAffinities({
      runtime,
      snapshot,
      activeStrikecellId: "security-overview",
      strikecells: STRIKECELLS,
    });

    expect(affinities["security-overview"]).toBeGreaterThan(0.45);
    expect(affinities["threat-radar"]).toBeGreaterThan(affinities["attack-graph"] ?? 0);
    expect(affinities["network-map"]).toBeGreaterThan(0.15);
  });
});

describe("detectNexusSpiritCue", () => {
  it("emits transit when the active strikecell changes", () => {
    const snapshot = makeSnapshot();
    const runtime = deriveHuntSpiritRuntimeState(snapshot.boundSpirit, {
      currentShell: snapshot.currentShell,
      currentLens: snapshot.currentLens,
      likelyIntent: snapshot.likelyIntent,
      confidenceScore: snapshot.confidenceScore,
      activeStationId: "threat-radar",
      isActive: true,
    });

    const cue = detectNexusSpiritCue({
      runtime,
      snapshot,
      previousSnapshot: {
        ...snapshot,
        currentLens: "files",
      },
      activeStrikecellId: "threat-radar",
      previousActiveStrikecellId: "security-overview",
      recenterToken: 0,
      previousRecenterToken: 0,
      nowMs: 8_000,
    });

    expect(cue?.kind).toBe("transit");
    expect(cue?.fromStrikecellId).toBe("security-overview");
    expect(cue?.toStrikecellId).toBe("threat-radar");
  });

  it("emits recenter when the camera reset token advances on the active strikecell", () => {
    const snapshot = makeSnapshot();
    const runtime = deriveHuntSpiritRuntimeState(snapshot.boundSpirit, {
      currentShell: snapshot.currentShell,
      currentLens: snapshot.currentLens,
      likelyIntent: snapshot.likelyIntent,
      confidenceScore: snapshot.confidenceScore,
      activeStationId: "security-overview",
      isActive: true,
    });

    const cue = detectNexusSpiritCue({
      runtime,
      snapshot,
      previousSnapshot: snapshot,
      activeStrikecellId: "security-overview",
      previousActiveStrikecellId: "security-overview",
      recenterToken: 3,
      previousRecenterToken: 2,
      nowMs: 9_000,
    });

    expect(cue?.kind).toBe("recenter");
    expect(cue?.fromStrikecellId).toBe("security-overview");
  });
});

describe("deriveNexusSpiritSceneActor", () => {
  it("builds a nexus companion actor from the active spirit runtime", () => {
    const snapshot = makeSnapshot();
    const runtime = deriveHuntSpiritRuntimeState(snapshot.boundSpirit, {
      currentShell: snapshot.currentShell,
      currentLens: snapshot.currentLens,
      likelyIntent: snapshot.likelyIntent,
      confidenceScore: snapshot.confidenceScore,
      activeStationId: "security-overview",
      isActive: true,
    });

    const actor = deriveNexusSpiritSceneActor({
      runtime,
      snapshot,
      strikecells: STRIKECELLS,
      activeStrikecellId: "security-overview",
      cue: null,
    });

    expect(actor).not.toBeNull();
    expect(actor?.anchorStrikecellId).toBe("security-overview");
    expect(actor?.likelyStationId).toBe("security-overview");
    expect(actor?.presenceStrength).toBeGreaterThan(0.35);
    expect(actor?.stationAffinities["threat-radar"]).toBeGreaterThan(0.2);
  });
});
