import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

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

  it("fromPolicy resolves multi-parent extends without false cycle errors", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-ts-policy-"));
    const commonPath = path.join(dir, "common.yaml");
    const leftPath = path.join(dir, "left.yaml");
    const rightPath = path.join(dir, "right.yaml");
    const rootPath = path.join(dir, "root.yaml");

    await fs.writeFile(
      commonPath,
      `version: "1.2.0"
name: "common"
guards:
  forbidden_path:
    patterns:
      - "/etc/**"
`
    );
    await fs.writeFile(
      leftPath,
      `version: "1.2.0"
name: "left"
extends:
  - "${commonPath}"
guards:
  egress_allowlist:
    allow:
      - "api.example.com"
    block: []
    default_action: block
`
    );
    await fs.writeFile(
      rightPath,
      `version: "1.2.0"
name: "right"
extends:
  - "${commonPath}"
guards:
  mcp_tool:
    allow: []
    block:
      - "danger_tool"
    default_action: allow
`
    );
    await fs.writeFile(
      rootPath,
      `version: "1.2.0"
name: "root"
extends:
  - "${leftPath}"
  - "${rightPath}"
`
    );

    const cs = await Clawdstrike.fromPolicy(rootPath);

    const fileDecision = await cs.check("file_access", { path: "/etc/passwd" });
    expect(fileDecision.status).toBe("deny");
    expect(fileDecision.guard).toBe("forbidden_path");

    const goodEgress = await cs.check("network_egress", { host: "api.example.com", port: 443 });
    expect(goodEgress.status).toBe("allow");

    const badEgress = await cs.check("network_egress", { host: "bad.example.com", port: 443 });
    expect(badEgress.status).toBe("deny");
    expect(badEgress.guard).toBe("egress_allowlist");

    const toolDecision = await cs.check("mcp_tool", { tool: "danger_tool", args: {} });
    expect(toolDecision.status).toBe("deny");
    expect(toolDecision.guard).toBe("mcp_tool");
  });

  it("fromPolicy deep_merge preserves inherited fields and honors explicit false overrides", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-ts-policy-"));
    const basePath = path.join(dir, "base.yaml");
    const childPath = path.join(dir, "child.yaml");

    await fs.writeFile(
      basePath,
      `version: "1.2.0"
name: "base"
guards:
  patch_integrity:
    max_additions: 5
    max_deletions: 50
    require_balance: true
    max_imbalance_ratio: 1
`
    );
    await fs.writeFile(
      childPath,
      `version: "1.2.0"
name: "child"
extends:
  - "${basePath}"
merge_strategy: deep_merge
guards:
  patch_integrity:
    require_balance: false
`
    );

    const cs = await Clawdstrike.fromPolicy(childPath);

    const tooManyAdds = await cs.check("patch", {
      path: "a.diff",
      diff: "+1\n+2\n+3\n+4\n+5\n+6",
    });
    expect(tooManyAdds.status).toBe("deny");
    expect(tooManyAdds.guard).toBe("patch_integrity");
    expect(String(tooManyAdds.message)).toContain("Too many additions");

    const imbalancedButAllowed = await cs.check("patch", {
      path: "b.diff",
      diff: "+1\n+2\n-3",
    });
    expect(imbalancedButAllowed.status).toBe("allow");
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

  it("checkNetwork accepts host:port inputs", async () => {
    const policy = `
version: "1.2.0"
name: "network parsing"
guards:
  egress_allowlist:
    enabled: true
    allow:
      - "api.example.com"
`;

    const cs = await Clawdstrike.fromPolicy(policy);

    const decision = await cs.checkNetwork("api.example.com:443");
    expect(decision.status).toBe("allow");

    const decisionWithPath = await cs.checkNetwork("api.example.com:443/v1/test");
    expect(decisionWithPath.status).toBe("allow");

    const session = cs.session();
    const sessionDecision = await session.checkNetwork("api.example.com:443");
    expect(sessionDecision.status).toBe("allow");
  });

  it("checkNetwork fails closed for hostless URIs (even when default_action=allow)", async () => {
    const policy = `
version: "1.2.0"
name: "hostless uri regression"
guards:
  egress_allowlist:
    enabled: true
    default_action: allow
    allow: []
    block: []
`;

    const cs = await Clawdstrike.fromPolicy(policy);

    const fileDecision = await cs.checkNetwork("file:///tmp/a");
    expect(fileDecision.status).toBe("deny");
    expect(fileDecision.guard).toBe("egress_allowlist");

    const mailtoDecision = await cs.checkNetwork("mailto:user@example.com");
    expect(mailtoDecision.status).toBe("deny");
    expect(mailtoDecision.guard).toBe("egress_allowlist");

    const urnDecision = await cs.checkNetwork("urn:isbn:0451450523");
    expect(urnDecision.status).toBe("deny");
    expect(urnDecision.guard).toBe("egress_allowlist");
  });

  it("checkNetwork drops invalid numeric port suffix before egress matching", async () => {
    const policy = `
version: "1.2.0"
name: "invalid port suffix"
guards:
  egress_allowlist:
    enabled: true
    allow:
      - "api.example.com"
`;

    const cs = await Clawdstrike.fromPolicy(policy);
    const decision = await cs.checkNetwork("api.example.com:0");
    expect(decision.status).toBe("allow");
  });

  it("skips prompt_injection guard when WASM is unavailable instead of fail-closing checks", async () => {
    const policy = `
version: "1.2.0"
name: "prompt injection skip without wasm"
guards:
  forbidden_path:
    enabled: true
  prompt_injection:
    enabled: true
`;

    const cs = await Clawdstrike.fromPolicy(policy);
    const decision = await cs.check("custom", {
      customType: "untrusted_text",
      customData: { text: "hello world" },
    });

    expect(decision.status).toBe("allow");
  });
});
