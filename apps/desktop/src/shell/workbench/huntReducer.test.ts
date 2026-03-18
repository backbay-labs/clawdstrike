import { describe, expect, it } from "vitest";
import { createHuntSpiritState } from "./spirit";
import { createInitialHuntStore } from "./huntTypes";
import { huntReducer } from "./huntReducer";

describe("huntReducer spirit contract", () => {
  it("creates every new hunt with a default spirit immediately", () => {
    const initial = createInitialHuntStore();
    const next = huntReducer(initial, {
      type: "HUNT_CREATE",
      payload: {
        title: "Replay payload mount",
        currentShell: "lab",
        currentLens: "files",
      },
    });

    const huntId = next.dock.activeHuntId;
    expect(huntId).toBeTruthy();

    const hunt = huntId ? next.hunts[huntId] : null;
    expect(hunt).toBeTruthy();
    expect(hunt?.spirit).not.toBeNull();
    expect(hunt?.spirit?.bindSource).toBe("default-create");
    expect(hunt?.spirit?.kind).toBe("forge");
  });

  it("reconfigures spirit without losing the original boundAt timestamp", () => {
    const initial = createInitialHuntStore();
    const before = initial.hunts.hunt_demo_1;
    if (!before.spirit) {
      throw new Error("Expected seeded hunt to have a spirit");
    }

    const replacement = createHuntSpiritState({
      kind: "ledger",
      bindSource: "manual",
      bindReason: "Operator shifted this hunt into proof assembly posture.",
      thesis: "Assemble the final proof chain.",
      confidenceScore: 88,
      liveMood: "witnessing",
      isPinned: true,
    });

    const next = huntReducer(initial, {
      type: "HUNT_RECONFIGURE_SPIRIT",
      payload: {
        huntId: before.id,
        spirit: replacement,
      },
    });

    const hunt = next.hunts[before.id];
    expect(hunt?.spirit?.kind).toBe("ledger");
    expect(hunt?.spirit?.boundAt).toBe(before.spirit.boundAt);
    expect(hunt?.spirit?.reboundAt).not.toBeNull();
    expect(hunt?.spirit?.isPinned).toBe(true);
  });
});
