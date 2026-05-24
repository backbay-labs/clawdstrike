import path from "node:path";

import { loadPolicyFromString } from "./loader.js";
import { translateLegacyOpenClawPolicyV1 } from "./legacy.js";

describe("policy loader legacy translation", () => {
  it("translates OpenClaw legacy schema (clawdstrike-v1.0) to canonical", () => {
    const warnings: string[] = [];
    const legacyYaml = `
version: "clawdstrike-v1.0"
filesystem:
  forbidden_paths:
    - "~/.ssh"
egress:
  mode: allowlist
  allowed_domains:
    - "api.github.com"
tools:
  denied:
    - "shell_exec"
`;

    const policy = loadPolicyFromString(legacyYaml, {
      resolve: false,
      onWarning: (m) => warnings.push(m),
    });

    expect(policy.version).toBe("1.1.0");
    expect(warnings.join("\n")).toMatch(/legacy OpenClaw policy/i);
    expect((policy as any).legacy_openclaw).toMatchObject({
      version: "clawdstrike-v1.0",
      egress: { mode: "allowlist", allowed_domains: ["api.github.com"] },
      tools: { denied: ["shell_exec"] },
    });
    expect((policy.guards as any)?.forbidden_path?.patterns).toEqual(["~/.ssh"]);
    expect((policy.guards as any)?.egress_allowlist?.default_action).toBe("block");
    expect((policy.guards as any)?.mcp_tool?.block).toEqual(["shell_exec"]);
  });

  it("fails closed on mixed-type egress.allowed_domains (legacy translation)", () => {
    // Regression: a malformed legacy allowlist (one non-string entry) must
    // translate to an empty allow list, not a partial allowlist that trusts
    // the well-formed entries. The non-string `42` poisons the whole array.
    const { policy } = translateLegacyOpenClawPolicyV1({
      version: "clawdstrike-v1.0",
      egress: {
        mode: "allowlist",
        // Intentionally malformed: the `42` is a non-string entry that
        // exercises the fail-closed branch in stringArrayOrUndefined.
        allowed_domains: ["api.github.com", 42 as unknown as string],
      },
    });

    const egress = (policy.guards as { egress_allowlist?: { allow: string[]; default_action: string } })
      ?.egress_allowlist;
    expect(egress).toBeDefined();
    expect(egress?.allow).toEqual([]);
    expect(egress?.default_action).toBe("block");
  });

  it("fails closed on mixed-type tools.denied (legacy translation)", () => {
    // Same fail-closed contract for tools.denied: a malformed denylist must
    // not silently shrink to the well-formed entries.
    const { policy } = translateLegacyOpenClawPolicyV1({
      version: "clawdstrike-v1.0",
      tools: {
        allowed: ["shell_exec"],
        denied: ["rm_rf", 7 as unknown as string],
      },
    });

    const mcp = (policy.guards as { mcp_tool?: { allow: string[]; block: string[]; default_action: string } })
      ?.mcp_tool;
    expect(mcp).toBeDefined();
    expect(mcp?.allow).toEqual(["shell_exec"]);
    // The malformed denied entry collapses the denylist to empty, but the
    // mcp_tool guard still defaults to "block" because allow has entries.
    expect(mcp?.block).toEqual([]);
    expect(mcp?.default_action).toBe("block");
  });

  it("lets child policy override merged version when set to 1.2.0", () => {
    const yaml = `
version: "1.2.0"
name: "Version override"
extends: strict
guards:
  path_allowlist:
    enabled: true
    file_access_allow:
      - "**/my-repo/**"
`;

    const policy = loadPolicyFromString(yaml, {
      resolve: true,
      rulesetsDir: path.join(process.cwd(), "..", "..", "..", "rulesets"),
    });
    expect(policy.version).toBe("1.2.0");
    expect((policy.guards as any)?.path_allowlist?.enabled).toBe(true);
  });
});
