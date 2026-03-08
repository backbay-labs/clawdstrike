// @vitest-environment jsdom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Hunt } from "../../huntTypes";
import { createInitialHuntStore } from "../../huntTypes";
import { createHuntSpiritState } from "..";
import {
  SpiritConsoleCard,
  SpiritInlineSummary,
  getSpiritActionLabel,
  getSpiritBiasLine,
} from "./SpiritIdentity";

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

function buildBoundHunt(): Hunt {
  const store = createInitialHuntStore();
  return {
    ...store.hunts.hunt_demo_1,
    spirit: createHuntSpiritState({
      kind: "forge",
      bindSource: "quick-bind",
      bindReason: "Run-heavy hunt with active file inputs",
      thesis: "Trace sandbox execution inputs",
      anchorArtifactIds: ["art_demo_3"],
      isPinned: true,
      confidenceScore: 84,
      liveMood: "focused",
    }),
  };
}

function buildUnboundHunt(): Hunt {
  const store = createInitialHuntStore();
  return {
    ...store.hunts.hunt_demo_2,
    spirit: null,
  };
}

describe("SpiritIdentity", () => {
  let container: HTMLDivElement;
  let root: Root;

  beforeEach(() => {
    globalThis.IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement("div");
    document.body.appendChild(container);
    root = createRoot(container);
  });

  afterEach(async () => {
    await act(async () => {
      root.unmount();
    });
    container.remove();
  });

  it("renders bound spirit label, bias, and pinned state", async () => {
    const hunt = buildBoundHunt();

    await act(async () => {
      root.render(<SpiritInlineSummary hunt={hunt} />);
    });

    expect(container.textContent).toContain("Forge");
    expect(container.textContent).toContain("Biasing");
    expect(container.textContent).toContain("Pinned");
  });

  it("renders add-spirit fallback for unbound hunts", async () => {
    const hunt = buildUnboundHunt();

    await act(async () => {
      root.render(<SpiritConsoleCard hunt={hunt} />);
    });

    expect(container.textContent).toContain("Add Spirit");
    expect(container.textContent).toContain("Add spirit when the hunt posture is clear");
    expect(getSpiritActionLabel(hunt)).toBe("Add Spirit");
  });

  it("derives a readable bias line from runtime emphasis", () => {
    const bias = getSpiritBiasLine(buildBoundHunt());
    expect(bias).toContain("Biasing");
    expect(bias).toContain("files");
  });
});
