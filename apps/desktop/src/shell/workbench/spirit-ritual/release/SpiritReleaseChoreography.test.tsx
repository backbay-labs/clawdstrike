// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createRoot, type Root } from "react-dom/client";
import { flushSync } from "react-dom";
import {
  resolveSpiritSurfaceReceiveState,
  SpiritReleaseChoreography,
} from "./SpiritReleaseChoreography";
import { buildSpiritManifestationModel } from "../canvas";
import type { SpiritBindCandidate, SpiritBindContext } from "../../spirit-bind/types";

function createContext(): SpiritBindContext {
  return {
    hunt: {
      id: "hunt-1",
      title: "Trace egress through receipts",
      status: "active",
      artifactIds: [],
      runIds: [],
      caseId: null,
      color: "#d4a84b",
      icon: "crosshair",
      spirit: null,
      semanticAssignments: {},
    },
    artifacts: {},
    runs: {},
    currentLens: "notes",
    currentShell: "hunt",
    activeStationId: "attack-graph",
  };
}

function createCandidate(): SpiritBindCandidate {
  return {
    kind: "lantern",
    label: "Lantern",
    confidenceScore: 84,
    rationale: "Suggested because this hunt is receipt-heavy and citation-forward.",
    biasLine: "Biases Notes, Evidence, and Receipts across dock, wake, and workspace.",
    predictedFocusSurfaces: ["Notes", "Evidence", "Receipts"],
    alternates: [],
    liveMood: "witnessing",
    bindSource: "thesis",
    thesis: "Prove the receipt chain behind policy bypass.",
    anchorArtifactIds: ["artifact-1"],
  };
}

describe("SpiritReleaseChoreography", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    vi.useFakeTimers();
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(() => {
    root.unmount();
    container.remove();
    vi.useRealTimers();
  });

  it("renders the release seam and notifies on rest using the local hold time", async () => {
    const model = buildSpiritManifestationModel(createContext(), createCandidate());
    const onRest = vi.fn();

    flushSync(() => {
      root.render(
        <SpiritReleaseChoreography
          model={model}
          phase="releasing"
          onRest={onRest}
          restMs={280}
        />,
      );
    });

    const overlay = container.querySelector('[data-testid="spirit-release-choreography"]') as HTMLDivElement | null;
    const transit = container.querySelector('[data-testid="spirit-release-transit"]') as HTMLDivElement | null;
    const afterimage = container.querySelector('[data-testid="spirit-release-origin-afterimage"]') as SVGCircleElement | null;
    expect(overlay).toBeTruthy();
    expect(transit).toBeTruthy();
    expect(afterimage).toBeTruthy();
    expect(overlay?.textContent).toContain("Releasing");
    expect(overlay?.textContent).toContain(model.release.title);
    expect(overlay?.textContent).toContain("Dock");
    expect(overlay?.textContent).toContain("Wake");
    expect(overlay?.textContent).toContain("Release will leave a short mark across receiving surfaces.");
    expect(overlay?.style.pointerEvents).toBe("none");

    await vi.advanceTimersByTimeAsync(279);
    expect(onRest).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(onRest).toHaveBeenCalledTimes(1);
  });

  it("classifies the shared receive window into receiving and aftermath states", () => {
    expect(resolveSpiritSurfaceReceiveState(-1)).toBe("idle");
    expect(resolveSpiritSurfaceReceiveState(0)).toBe("receiving");
    expect(resolveSpiritSurfaceReceiveState(1_599)).toBe("receiving");
    expect(resolveSpiritSurfaceReceiveState(1_600)).toBe("aftermath");
    expect(resolveSpiritSurfaceReceiveState(3_799)).toBe("aftermath");
    expect(resolveSpiritSurfaceReceiveState(3_800)).toBe("idle");
  });
});
