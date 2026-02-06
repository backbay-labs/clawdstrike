import { describe, expect, it } from "vitest";

import { Clawdstrike } from "../src/clawdstrike";
import { GuardResult, type Guard, Severity } from "../src/guards/types";

describe("Clawdstrike", () => {
  const warnGuard: Guard = {
    name: "warn-guard",
    handles: () => true,
    check: () => GuardResult.warn("warn-guard", "This is a warning"),
  };

  const denyGuard: Guard = {
    name: "deny-guard",
    handles: () => true,
    check: () => GuardResult.block("deny-guard", Severity.ERROR, "Denied"),
  };

  it("returns warn when any guard warns (even without failFast)", async () => {
    const cs = Clawdstrike.configure({ guards: [warnGuard] });

    const decision = await cs.check("some_action");
    expect(decision.status).toBe("warn");
    expect(decision.guard).toBe("warn-guard");
  });

  it("returns warn for sessions when any guard warns (even without failFast)", async () => {
    const cs = Clawdstrike.configure({ guards: [warnGuard] });
    const session = cs.session();

    const decision = await session.check("some_action");
    expect(decision.status).toBe("warn");
    expect(decision.guard).toBe("warn-guard");

    const summary = session.getSummary();
    expect(summary.checkCount).toBe(1);
    expect(summary.warnCount).toBe(1);
    expect(summary.allowCount).toBe(0);
    expect(summary.denyCount).toBe(0);
  });

  it("still returns deny if a later guard denies", async () => {
    const cs = Clawdstrike.configure({ guards: [warnGuard, denyGuard] });

    const decision = await cs.check("some_action");
    expect(decision.status).toBe("deny");
    expect(decision.guard).toBe("deny-guard");
  });

  it("withDefaults strict enforces forbidden path checks", async () => {
    const cs = Clawdstrike.withDefaults("strict");

    const decision = await cs.check("file_access", { path: "/etc/passwd" });
    expect(decision.status).toBe("deny");
    expect(decision.guard).toBe("forbidden_path");
  });

  it("fromPolicy strict aliases enforce forbidden path checks", async () => {
    const cs = await Clawdstrike.fromPolicy("strict.yaml");

    const decision = await cs.check("file_access", { path: "/etc/passwd" });
    expect(decision.status).toBe("deny");
    expect(decision.guard).toBe("forbidden_path");
  });

  it("fromPolicy does not silently fall back on invalid policy input", async () => {
    await expect(Clawdstrike.fromPolicy("this-is-not-a-policy")).rejects.toThrow("expected an object");
  });

  it("fromDaemon evaluates remotely and fails closed on transport errors", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => {
      throw new Error("network down");
    }) as typeof fetch;

    try {
      const cs = await Clawdstrike.fromDaemon("http://127.0.0.1:65530", "test-key");
      const decision = await cs.check("file_access", { path: "/etc/passwd" });

      expect(decision.status).toBe("deny");
      expect(decision.guard).toBe("daemon");
      expect(decision.message).toContain("Daemon check failed");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
