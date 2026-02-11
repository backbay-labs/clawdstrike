import { describe, expect, it } from "vitest";

import { computePolicyWorkbenchEnabled } from "./featureFlags";

describe("computePolicyWorkbenchEnabled", () => {
  it("defaults enabled when no env or local override is set", () => {
    expect(computePolicyWorkbenchEnabled(undefined, null)).toBe(true);
  });

  it("prefers local override over env", () => {
    expect(computePolicyWorkbenchEnabled("0", "1")).toBe(true);
    expect(computePolicyWorkbenchEnabled("1", "0")).toBe(false);
  });

  it("supports env toggles when local override is unset", () => {
    expect(computePolicyWorkbenchEnabled("1", null)).toBe(true);
    expect(computePolicyWorkbenchEnabled("0", null)).toBe(false);
  });
});
