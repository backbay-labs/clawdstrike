import { describe, expect, it } from "vitest";
import { resolveObservatoryNpcCrewMotionMode } from "@/features/observatory/world/npcCrew";

describe("resolveObservatoryNpcCrewMotionMode", () => {
  it("enables full patrol and wave behavior for focus tier", () => {
    expect(resolveObservatoryNpcCrewMotionMode("focus")).toEqual({
      canLookAt: true,
      canWave: true,
      coarseStepSeconds: null,
      patrolEnabled: true,
    });
  });

  it("keeps patrol on but strips reaction behavior in near tier", () => {
    expect(resolveObservatoryNpcCrewMotionMode("near")).toEqual({
      canLookAt: false,
      canWave: false,
      coarseStepSeconds: null,
      patrolEnabled: true,
    });
  });

  it("coarsens far tier updates and disables dormant updates", () => {
    expect(resolveObservatoryNpcCrewMotionMode("far")).toEqual({
      canLookAt: false,
      canWave: false,
      coarseStepSeconds: 0.4,
      patrolEnabled: true,
    });
    expect(resolveObservatoryNpcCrewMotionMode("dormant")).toEqual({
      canLookAt: false,
      canWave: false,
      coarseStepSeconds: null,
      patrolEnabled: false,
    });
  });
});
