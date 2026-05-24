import type { PolicyEngineLike } from "@clawdstrike/adapter-core";
import { describe, expect, it, vi } from "vitest";

// Force the SDK detectors to throw a WASM-init error so we can exercise the
// fail-closed branch without depending on the real WASM availability state.
vi.mock("@clawdstrike/sdk", async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  const wasmError = () => {
    throw new Error("wasm backend unavailable (mocked for fail-closed test)");
  };
  return {
    ...actual,
    InstructionHierarchyEnforcer: class {
      constructor() {
        wasmError();
      }
    },
    JailbreakDetector: class {
      constructor() {
        wasmError();
      }
    },
    OutputSanitizer: class {
      constructor() {
        wasmError();
      }
    },
  };
});

import { ClawdstrikeMiddlewareInitError, createClawdstrikeMiddleware } from "./middleware.js";

const engine: PolicyEngineLike = {
  evaluate: () => ({ allowed: true, denied: false, warn: false }),
};

describe("createClawdstrikeMiddleware — fail-closed on WASM init failure", () => {
  it("throws ClawdstrikeMiddlewareInitError when prompt security is enabled and WASM fails", () => {
    expect(() =>
      createClawdstrikeMiddleware({
        engine,
        config: {
          promptSecurity: {
            enabled: true,
            applicationId: "test-app",
          },
        },
      }),
    ).toThrow(ClawdstrikeMiddlewareInitError);
  });

  it("error lists each failed detector", () => {
    try {
      createClawdstrikeMiddleware({
        engine,
        config: {
          promptSecurity: {
            enabled: true,
            applicationId: "test-app",
          },
        },
      });
      throw new Error("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(ClawdstrikeMiddlewareInitError);
      const detectors = (err as ClawdstrikeMiddlewareInitError).detectors;
      expect(detectors).toContain("InstructionHierarchyEnforcer");
      expect(detectors).toContain("JailbreakDetector");
      expect(detectors).toContain("OutputSanitizer");
    }
  });

  it("allows construction when allowDegradedSecurity: true and fires onDegrade per detector", () => {
    const onDegrade = vi.fn();
    const mw = createClawdstrikeMiddleware({
      engine,
      config: {
        promptSecurity: {
          enabled: true,
          applicationId: "test-app",
        },
        allowDegradedSecurity: true,
        onDegrade,
      },
    });
    expect(mw).toBeDefined();
    // Three detectors are enabled by default; expect a call per failed detector.
    const reasons = onDegrade.mock.calls.map((c) => c[0] as string);
    expect(reasons.length).toBeGreaterThanOrEqual(3);
    expect(reasons.some((r) => r.includes("InstructionHierarchyEnforcer"))).toBe(true);
    expect(reasons.some((r) => r.includes("JailbreakDetector"))).toBe(true);
    expect(reasons.some((r) => r.includes("OutputSanitizer"))).toBe(true);
  });

  it("does not throw when prompt security is disabled", () => {
    expect(() =>
      createClawdstrikeMiddleware({
        engine,
        config: {},
      }),
    ).not.toThrow();
  });
});
