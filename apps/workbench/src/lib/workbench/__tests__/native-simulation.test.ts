import { describe, expect, it } from "vitest";

import {
  verdictFromNativeGuardResult,
  verdictFromNativeSimulation,
} from "../native-simulation";

describe("native simulation verdict mapping", () => {
  it("treats allowed warning results as warn verdicts", () => {
    expect(
      verdictFromNativeGuardResult({
        allowed: true,
        severity: "warning",
      }),
    ).toBe("warn");

    expect(
      verdictFromNativeSimulation({
        allowed: true,
        results: [
          {
            allowed: true,
            guard: "guard-a",
            message: "info",
            severity: "info",
            details: null,
          },
          {
            allowed: true,
            guard: "guard-b",
            message: "warning",
            severity: "warning",
            details: null,
          },
        ],
      }),
    ).toBe("warn");
  });

  it("keeps denied native responses as deny", () => {
    expect(
      verdictFromNativeSimulation({
        allowed: false,
        results: [
          {
            allowed: false,
            guard: "guard-a",
            message: "warning",
            severity: "warning",
            details: null,
          },
        ],
      }),
    ).toBe("deny");
  });
});
