// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createRoot, type Root } from "react-dom/client";
import { SpiritAtmosphereLayer } from "./SpiritAtmosphereLayer";
import { buildSpiritManifestationModel } from "../canvas";
import type { SpiritBindCandidate, SpiritBindContext } from "../../spirit-bind/types";

function createContext(): SpiritBindContext {
  return {
    hunt: {
      id: "hunt-1",
      title: "Trace egress through receipts",
      status: "active",
      artifactIds: ["artifact-1", "artifact-2"],
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
    alternates: [],
    liveMood: "witnessing",
    bindSource: "anchor-artifacts",
    thesis: "Prove the receipt chain behind policy bypass.",
    anchorArtifactIds: ["artifact-1", "artifact-2"],
    ...overrides,
  };
}

describe("SpiritAtmosphereLayer", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    root.unmount();
    container.remove();
  });

  it("renders a click-through restrained atmosphere field with grains and anchor beacons", async () => {
    const model = buildSpiritManifestationModel(createContext(), createCandidate());

    await new Promise<void>((resolve) => {
      root.render(<SpiritAtmosphereLayer model={model} />);
      setTimeout(resolve, 0);
    });

    const layer = container.querySelector('[data-testid="spirit-atmosphere-layer"]') as HTMLDivElement | null;
    const grains = container.querySelectorAll('[data-testid="spirit-atmosphere-grain"]');
    expect(layer).toBeTruthy();
    expect(layer?.style.pointerEvents).toBe("none");
    expect(grains.length).toBe(model.atmosphere.particleCount);
    expect(layer?.children.length ?? 0).toBeGreaterThan(grains.length);
  });

  it("renders spirit-specific pressure signatures without losing the restrained field", async () => {
    const loomModel = buildSpiritManifestationModel(
      createContext(),
      createCandidate({
        kind: "loom",
        label: "Loom",
        bindSource: "manual",
        thesis: null,
        anchorArtifactIds: [],
        alternates: [{ kind: "tracker", label: "Tracker" }],
      }),
    );

    await new Promise<void>((resolve) => {
      root.render(<SpiritAtmosphereLayer model={loomModel} />);
      setTimeout(resolve, 0);
    });

    const pressure = container.querySelectorAll('[data-testid="spirit-atmosphere-pressure"]');
    const residue = container.querySelectorAll('[data-testid="spirit-atmosphere-residue"]');
    expect(pressure.length).toBe(4);
    expect(residue.length).toBe(3);
  });
});
