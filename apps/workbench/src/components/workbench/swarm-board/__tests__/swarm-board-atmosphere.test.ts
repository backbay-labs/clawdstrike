import { describe, expect, it } from "vitest";

import { buildSwarmBoardAtmosphere } from "../swarm-board-atmosphere";

describe("swarm-board atmosphere", () => {
  it("stays neutral when no receipt signal exists", () => {
    const atmosphere = buildSwarmBoardAtmosphere({
      totalReceipts: 0,
      totalSignals: 0,
      allowCount: 0,
      warnCount: 0,
      denyCount: 0,
      allowRatio: 0,
      warnRatio: 0,
      denyRatio: 0,
      dominantState: "neutral",
    });

    expect(atmosphere.state).toBe("neutral");
    expect(atmosphere.noiseOpacity).toBe(0.32);
    expect(atmosphere.vignette).toContain("rgba(8, 10, 16");
  });

  it("biases toward deny posture with stronger tension", () => {
    const atmosphere = buildSwarmBoardAtmosphere({
      totalReceipts: 5,
      totalSignals: 5,
      allowCount: 1,
      warnCount: 1,
      denyCount: 3,
      allowRatio: 0.2,
      warnRatio: 0.2,
      denyRatio: 0.6,
      dominantState: "deny",
    });

    expect(atmosphere.state).toBe("deny");
    expect(atmosphere.noiseOpacity).toBeGreaterThan(0.32);
    expect(atmosphere.glow).toContain("rgba(184, 84, 80");
  });
});
