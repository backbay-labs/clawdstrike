import { describe, expect, it } from "vitest";
import { buildSpiritManifestationModel, describeSpiritManifestationState } from "./model";
import type { SpiritBindCandidate, SpiritBindContext } from "../../spirit-bind/types";

function createContext(): SpiritBindContext {
  return {
    hunt: {
      id: "hunt-1",
      title: "Trace egress through receipts",
      status: "active",
      artifactIds: ["artifact-1", "artifact-2", "artifact-3"],
      runIds: [],
      caseId: null,
      color: "#d4a84b",
      icon: "crosshair",
      spirit: null,
      semanticAssignments: {},
    },
    artifacts: {
      "artifact-1": {
        id: "artifact-1",
        kind: "receipt",
        title: "Receipt cluster",
        sourceUri: "receipts://cluster",
        createdAt: 10,
      },
      "artifact-2": {
        id: "artifact-2",
        kind: "file",
        title: "payload.bin",
        sourceUri: "files://payload",
        createdAt: 20,
      },
      "artifact-3": {
        id: "artifact-3",
        kind: "entity",
        title: "svc-admin@corp.local",
        sourceUri: "entity://svc-admin",
        createdAt: 30,
      },
    },
    runs: {},
    currentLens: "notes",
    currentShell: "hunt",
    activeStationId: "attack-graph",
  };
}

function createCandidate(
  overrides: Partial<SpiritBindCandidate> = {},
): SpiritBindCandidate {
  return {
    kind: "lantern",
    label: "Lantern",
    confidenceScore: 84,
    rationale: "Suggested because this hunt is receipt-heavy and citation-forward.",
    biasLine: "Biases Notes, Evidence, and Receipts across dock, wake, and workspace.",
    predictedFocusSurfaces: ["Notes", "Evidence", "Receipts"],
    alternates: [
      { kind: "ledger", label: "Ledger" },
      { kind: "tracker", label: "Tracker" },
      { kind: "forge", label: "Forge" },
    ],
    liveMood: "witnessing",
    bindSource: "thesis",
    thesis: "Prove the receipt chain behind policy bypass.",
    anchorArtifactIds: ["artifact-1"],
    ...overrides,
  };
}

describe("buildSpiritManifestationModel", () => {
  it("derives a release-ready manifestation model from the bind candidate", () => {
    const model = buildSpiritManifestationModel(createContext(), createCandidate());

    expect(model.label).toBe("Lantern");
    expect(model.mode).toBe("thesis");
    expect(model.stance).toBe("witness");
    expect(model.contourPath.length).toBeGreaterThan(10);
    expect(model.stationLabel).toBe("Attack Graph");
    expect(model.release.actionLabel).toContain("Seal");
    expect(model.atmosphere.particleCount).toBe(model.atmosphere.grains?.length);
    expect(model.rings.length).toBeGreaterThanOrEqual(3);
    expect(model.stage?.inscriptions.length).toBeGreaterThan(0);
    expect(model.stage?.tethers).toHaveLength(0);
    expect(model.stage?.ghosts).toHaveLength(0);
    expect(model.stage?.stateLabel).toBe("Witnessing");
    expect(model.stage?.intentLine).toContain("authored");
    expect(model.stage?.consequenceLine).toContain("Notes");
    expect(model.stage?.exitLabel).toContain("Attack Graph");
  });

  it("builds anchor tethers when the candidate comes from anchor mode", () => {
    const model = buildSpiritManifestationModel(
      createContext(),
      createCandidate({
        bindSource: "anchor-artifacts",
        anchorArtifactIds: ["artifact-1", "artifact-2", "artifact-3"],
      }),
    );

    expect(model.mode).toBe("anchors");
    expect(model.stage?.tethers).toHaveLength(3);
    expect(model.stage?.tethers[0]?.label).toContain("Receipt");
    expect(model.stage?.inscriptions).toHaveLength(0);
  });

  it("builds alternate ghost forms in manual mode", () => {
    const model = buildSpiritManifestationModel(
      createContext(),
      createCandidate({
        bindSource: "manual",
        thesis: null,
        anchorArtifactIds: [],
      }),
    );

    expect(model.mode).toBe("manual");
    expect(model.stage?.ghosts.length).toBeGreaterThan(1);
    expect(model.stage?.ghosts[0]?.label).toBe("Ledger");
  });

  it("keeps quick mode calmer than thesis mode", () => {
    const quick = buildSpiritManifestationModel(
      createContext(),
      createCandidate({
        bindSource: "quick-configure",
        thesis: null,
        anchorArtifactIds: [],
      }),
    );
    const thesis = buildSpiritManifestationModel(createContext(), createCandidate());

    expect(quick.mode).toBe("quick");
    expect(quick.stage?.inscriptions).toHaveLength(0);
    expect(quick.rings.length).toBeGreaterThan(0);
    expect(quick.atmosphere.particleCount).toBeGreaterThan(0);
    expect(quick.atmosphere.particleCount).toBeLessThan(thesis.atmosphere.particleCount);
    expect(quick.stage?.vesselScale).toBeLessThan(thesis.stage?.vesselScale ?? 0);
    expect(quick.stage?.dominance).toBeLessThan(thesis.stage?.dominance ?? 0);
  });

  it("gives each spirit a distinct stage grammar and field signature", () => {
    const tracker = buildSpiritManifestationModel(
      createContext(),
      createCandidate({ kind: "tracker", label: "Tracker", bindSource: "manual", thesis: null, anchorArtifactIds: [] }),
    );
    const lantern = buildSpiritManifestationModel(
      createContext(),
      createCandidate({ kind: "lantern", label: "Lantern", bindSource: "thesis" }),
    );
    const forge = buildSpiritManifestationModel(
      createContext(),
      createCandidate({ kind: "forge", label: "Forge", bindSource: "anchor-artifacts", anchorArtifactIds: ["artifact-1", "artifact-2"] }),
    );
    const loom = buildSpiritManifestationModel(
      createContext(),
      createCandidate({ kind: "loom", label: "Loom", bindSource: "manual", thesis: null, anchorArtifactIds: [] }),
    );
    const ledger = buildSpiritManifestationModel(
      createContext(),
      createCandidate({ kind: "ledger", label: "Ledger", bindSource: "thesis" }),
    );

    expect(tracker.stage?.grammar?.exitCharacter).toBe("pursuit");
    expect(lantern.stage?.grammar?.exitCharacter).toBe("witness");
    expect(forge.stage?.grammar?.exitCharacter).toBe("forge");
    expect(loom.stage?.grammar?.tetherCharacter).toBe("woven");
    expect(ledger.stage?.grammar?.exitCharacter).toBe("ledger");

    expect(tracker.stage?.grammar?.beamWidthPercent).toBeGreaterThan(
      lantern.stage?.grammar?.beamWidthPercent ?? 0,
    );
    expect(lantern.stage?.grammar?.beamHeightPercent).toBeGreaterThan(
      forge.stage?.grammar?.beamHeightPercent ?? 0,
    );
    expect(forge.stage?.vesselScale).toBeGreaterThan(lantern.stage?.vesselScale ?? 0);
    expect(loom.atmosphere.particleCount).toBeGreaterThan(tracker.atmosphere.particleCount);
    expect(ledger.stage?.floorGlowOpacity).toBeGreaterThan(tracker.stage?.floorGlowOpacity ?? 0);
  });

  it("summarizes the manifestation state in operator language", () => {
    const summary = describeSpiritManifestationState(
      buildSpiritManifestationModel(createContext(), createCandidate()),
    );

    expect(summary).toContain("Lantern");
    expect(summary).toContain("field");
  });
});
