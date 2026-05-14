import { describe, it, expect, beforeEach } from "vitest";
import { useSpiritEvolutionStore, deriveLevel, XP_THRESHOLDS } from "../stores/spirit-evolution-store";

describe("deriveLevel", () => {
  it("returns 1 at XP 0", () => expect(deriveLevel(0)).toBe(1));
  it("returns 1 at XP 49 (below L2)", () => expect(deriveLevel(49)).toBe(1));
  it("returns 2 at XP 50 (L2 threshold)", () => expect(deriveLevel(50)).toBe(2));
  it("returns 5 at XP 700 (max level)", () => expect(deriveLevel(700)).toBe(5));
  it("clamps at 5 above max XP", () => expect(deriveLevel(9999)).toBe(5));
});

describe("useSpiritEvolutionStore", () => {
  beforeEach(() => {
    useSpiritEvolutionStore.getState().actions._reset();
  });

  it("grantXp increases XP for the target kind only", () => {
    useSpiritEvolutionStore.getState().actions.grantXp("sentinel", 10);
    const state = useSpiritEvolutionStore.getState();
    expect(state.evolution.sentinel.xp).toBe(10);
    expect(state.evolution.oracle.xp).toBe(0);
  });

  it("grantXp advances level when XP crosses threshold", () => {
    useSpiritEvolutionStore.getState().actions.grantXp("sentinel", 100);
    const state = useSpiritEvolutionStore.getState();
    expect(state.evolution.sentinel.level).toBe(2);
  });

  it("stores data in localStorage after grantXp", () => {
    useSpiritEvolutionStore.getState().actions.grantXp("witness", 5);
    expect(localStorage.getItem("clawdstrike.spirit-evolution")).not.toBeNull();
  });
});

// Export used for type checking — ensures XP_THRESHOLDS is accessible
export { XP_THRESHOLDS };
