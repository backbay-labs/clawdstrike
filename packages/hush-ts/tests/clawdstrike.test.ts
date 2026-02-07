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

  it("fromPolicy honors enabled:false and skips disabled guards", async () => {
    const policy = `
version: "1.2.0"
name: "enabled flag regression"
guards:
  forbidden_path:
    enabled: false
  egress_allowlist:
    enabled: true
    allow:
      - "api.example.com"
`;

    const cs = await Clawdstrike.fromPolicy(policy);

    // forbidden_path is disabled, so a path that strict rulesets usually deny should pass.
    const fileDecision = await cs.check("file_access", { path: "/etc/passwd" });
    expect(fileDecision.status).toBe("allow");

    // enabled egress_allowlist still enforces.
    const egressDecision = await cs.check("network_egress", { host: "bad.example.com", port: 443 });
    expect(egressDecision.status).toBe("deny");
    expect(egressDecision.guard).toBe("egress_allowlist");
  });

  it("fromPolicy wires secret_leak config into SecretLeakGuard", async () => {
    const policy = `
version: "1.2.0"
name: "secret leak wiring"
guards:
  secret_leak:
    enabled: true
    secrets:
      - "sk-live-12345"
`;

    const cs = await Clawdstrike.fromPolicy(policy);
    const decision = await cs.check("custom", {
      customType: "output",
      customData: { content: "model output sk-live-12345 leaked" },
    });

    expect(decision.status).toBe("deny");
    expect(decision.guard).toBe("secret_leak");
  });

  it("fromPolicy parses secret_leak.patterns from YAML", async () => {
    const policy = `
version: "1.2.0"
name: "secret leak patterns"
guards:
  secret_leak:
    enabled: true
    patterns:
      - name: openai_key
        pattern: "sk-[A-Za-z0-9]{10}"
        severity: critical
`;

    const cs = await Clawdstrike.fromPolicy(policy);
    const decision = await cs.check("custom", {
      customType: "output",
      customData: { content: "token sk-ABC123DEF4 exposed" },
    });

    expect(decision.status).toBe("deny");
    expect(decision.guard).toBe("secret_leak");
  });

  it("fromPolicy supports non-blocking secret_leak info patterns", async () => {
    const policy = `
version: "1.2.0"
name: "secret leak info severity"
guards:
  secret_leak:
    enabled: true
    patterns:
      - name: openai_key
        pattern: "sk-[A-Za-z0-9]{10}"
        severity: info
`;

    const cs = await Clawdstrike.fromPolicy(policy);
    const decision = await cs.check("custom", {
      customType: "output",
      customData: { content: "token sk-ABC123DEF4 exposed" },
    });

    expect(decision.status).toBe("allow");
    expect(decision.guard).toBe("secret_leak");
    expect(decision.severity).toBe(Severity.INFO);
    expect(decision.message).toContain("Secret pattern matched");
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
