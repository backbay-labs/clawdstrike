// apps/workbench/src/features/spirit/__tests__/spirit-mood-reactor.test.tsx
import { describe, it, expect } from "vitest";
import { deriveSpiritMood } from "../mood";

describe("deriveSpiritMood", () => {
  it("returns 'dormant' when kind is null", () => {
    expect(
      deriveSpiritMood({ kind: null, hasLintErrors: false, probeActive: false }),
    ).toBe("dormant");
  });

  it("returns 'dormant' when kind is null even if signals are active", () => {
    expect(
      deriveSpiritMood({ kind: null, hasLintErrors: true, probeActive: true }),
    ).toBe("dormant");
  });

  it("returns 'alert' when kind is set and hasLintErrors is true", () => {
    expect(
      deriveSpiritMood({ kind: "sentinel", hasLintErrors: true, probeActive: false }),
    ).toBe("alert");
  });

  it("returns 'active' when kind is set and probeActive is true (no lint errors)", () => {
    expect(
      deriveSpiritMood({ kind: "sentinel", hasLintErrors: false, probeActive: true }),
    ).toBe("active");
  });

  it("returns 'idle' when kind is set and no signals are active", () => {
    expect(
      deriveSpiritMood({ kind: "sentinel", hasLintErrors: false, probeActive: false }),
    ).toBe("idle");
  });

  it("returns 'alert' when both hasLintErrors and probeActive are true (lint errors take priority)", () => {
    expect(
      deriveSpiritMood({ kind: "sentinel", hasLintErrors: true, probeActive: true }),
    ).toBe("alert");
  });
});
