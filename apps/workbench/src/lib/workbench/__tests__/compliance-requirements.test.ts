import { describe, it, expect } from "vitest";
import {
  COMPLIANCE_FRAMEWORKS,
  getFrameworkRequirements,
  scoreFramework,
  type ComplianceRequirementDef,
} from "../compliance-requirements";
import type { GuardConfigMap, PolicySettings } from "../types";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** A strict policy that satisfies most compliance requirements. */
function makeStrictGuards(): GuardConfigMap {
  return {
    forbidden_path: {
      enabled: true,
      patterns: ["**/.ssh/**", "**/.aws/**", "**/.env", "/etc/shadow"],
    },
    path_allowlist: { enabled: true, file_access_allow: ["/app/**"] },
    egress_allowlist: {
      enabled: true,
      allow: ["*.openai.com"],
      default_action: "block",
    },
    secret_leak: {
      enabled: true,
      patterns: [
        { name: "aws_key", pattern: "AKIA[0-9A-Z]{16}", severity: "critical" },
        { name: "private_key", pattern: "-----BEGIN PRIVATE KEY-----", severity: "critical" },
      ],
    },
    patch_integrity: { enabled: true },
    shell_command: { enabled: true },
    mcp_tool: { enabled: true, default_action: "block" },
    prompt_injection: { enabled: true },
    jailbreak: { enabled: true },
  };
}

function makeStrictSettings(): PolicySettings {
  return {
    verbose_logging: true,
    session_timeout_secs: 1800,
  };
}

function makeEmptyGuards(): GuardConfigMap {
  return {};
}

function makeEmptySettings(): PolicySettings {
  return {};
}

// ---------------------------------------------------------------------------
// Framework structure
// ---------------------------------------------------------------------------

describe("COMPLIANCE_FRAMEWORKS", () => {
  it("contains hipaa, soc2, and pci-dss", () => {
    const ids = COMPLIANCE_FRAMEWORKS.map((f) => f.id);
    expect(ids).toContain("hipaa");
    expect(ids).toContain("soc2");
    expect(ids).toContain("pci-dss");
  });

  it("each framework has requirements", () => {
    for (const f of COMPLIANCE_FRAMEWORKS) {
      expect(f.requirements.length).toBeGreaterThan(0);
    }
  });

  it("each requirement has required fields", () => {
    for (const f of COMPLIANCE_FRAMEWORKS) {
      for (const req of f.requirements) {
        expect(req.id).toBeTruthy();
        expect(req.framework).toBe(f.id);
        expect(req.title).toBeTruthy();
        expect(req.citation).toBeTruthy();
        expect(req.description).toBeTruthy();
        expect(typeof req.check).toBe("function");
        expect(Array.isArray(req.guardDeps)).toBe(true);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// getFrameworkRequirements
// ---------------------------------------------------------------------------

describe("getFrameworkRequirements", () => {
  it("returns HIPAA requirements", () => {
    const reqs = getFrameworkRequirements("hipaa");
    expect(reqs.length).toBe(10);
    expect(reqs[0].framework).toBe("hipaa");
  });

  it("returns SOC2 requirements", () => {
    const reqs = getFrameworkRequirements("soc2");
    expect(reqs.length).toBe(8);
    expect(reqs[0].framework).toBe("soc2");
  });

  it("returns PCI-DSS requirements", () => {
    const reqs = getFrameworkRequirements("pci-dss");
    expect(reqs.length).toBe(7);
    expect(reqs[0].framework).toBe("pci-dss");
  });

  it("returns empty array for unknown framework", () => {
    const reqs = getFrameworkRequirements("unknown" as any);
    expect(reqs).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// HIPAA requirements
// ---------------------------------------------------------------------------

describe("HIPAA requirements", () => {
  const guards = makeStrictGuards();
  const settings = makeStrictSettings();

  it("hipaa-1: Access Control - requires forbidden_path with >= 3 patterns", () => {
    const reqs = getFrameworkRequirements("hipaa");
    const req = reqs.find((r) => r.id === "hipaa-1")!;
    expect(req.check(guards, settings)).toBe(true);
    // Fails with too few patterns
    expect(
      req.check(
        { forbidden_path: { enabled: true, patterns: ["/a"] } },
        settings
      )
    ).toBe(false);
  });

  it("hipaa-2: Audit Controls - requires verbose_logging", () => {
    const reqs = getFrameworkRequirements("hipaa");
    const req = reqs.find((r) => r.id === "hipaa-2")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check(guards, { verbose_logging: false })).toBe(false);
  });

  it("hipaa-3: Integrity Controls - requires patch_integrity", () => {
    const reqs = getFrameworkRequirements("hipaa");
    const req = reqs.find((r) => r.id === "hipaa-3")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check({}, settings)).toBe(false);
  });

  it("hipaa-4: Transmission Security - requires egress with block default", () => {
    const reqs = getFrameworkRequirements("hipaa");
    const req = reqs.find((r) => r.id === "hipaa-4")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(
      req.check({ egress_allowlist: { enabled: true, default_action: "allow" } }, settings)
    ).toBe(false);
  });

  it("hipaa-5: PHI Data Protection - requires secret_leak with patterns", () => {
    const reqs = getFrameworkRequirements("hipaa");
    const req = reqs.find((r) => r.id === "hipaa-5")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check({ secret_leak: { enabled: true, patterns: [] } }, settings)).toBe(false);
  });

  it("hipaa-6: Authentication - requires mcp_tool with block default", () => {
    const reqs = getFrameworkRequirements("hipaa");
    const req = reqs.find((r) => r.id === "hipaa-6")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(
      req.check({ mcp_tool: { enabled: true, default_action: "allow" } }, settings)
    ).toBe(false);
  });

  it("hipaa-7: Emergency Access - requires session_timeout > 0", () => {
    const reqs = getFrameworkRequirements("hipaa");
    const req = reqs.find((r) => r.id === "hipaa-7")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check(guards, {})).toBe(false);
  });

  it("hipaa-8: Automatic Logoff - requires session_timeout <= 3600", () => {
    const reqs = getFrameworkRequirements("hipaa");
    const req = reqs.find((r) => r.id === "hipaa-8")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check(guards, { session_timeout_secs: 7200 })).toBe(false);
  });

  it("hipaa-9: Encryption - requires secret_leak with key/private patterns", () => {
    const reqs = getFrameworkRequirements("hipaa");
    const req = reqs.find((r) => r.id === "hipaa-9")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(
      req.check(
        {
          secret_leak: {
            enabled: true,
            patterns: [{ name: "generic", pattern: "abc", severity: "warning" }],
          },
        },
        settings
      )
    ).toBe(false);
  });

  it("hipaa-10: Command Restriction - requires shell_command", () => {
    const reqs = getFrameworkRequirements("hipaa");
    const req = reqs.find((r) => r.id === "hipaa-10")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check({}, settings)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// SOC2 requirements
// ---------------------------------------------------------------------------

describe("SOC2 requirements", () => {
  const guards = makeStrictGuards();
  const settings = makeStrictSettings();

  it("soc2-1: Logical Access Controls - forbidden_path and mcp_tool", () => {
    const req = getFrameworkRequirements("soc2").find((r) => r.id === "soc2-1")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check({ forbidden_path: { enabled: true, patterns: [] } }, settings)).toBe(false);
  });

  it("soc2-2: Access Provisioning - path_allowlist or forbidden_path", () => {
    const req = getFrameworkRequirements("soc2").find((r) => r.id === "soc2-2")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check({}, settings)).toBe(false);
  });

  it("soc2-3: Access Removal - session timeout configured", () => {
    const req = getFrameworkRequirements("soc2").find((r) => r.id === "soc2-3")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check(guards, {})).toBe(false);
  });

  it("soc2-4: System Boundaries - egress_allowlist enabled", () => {
    const req = getFrameworkRequirements("soc2").find((r) => r.id === "soc2-4")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check({}, settings)).toBe(false);
  });

  it("soc2-5: Data Transmission Security - egress with block default", () => {
    const req = getFrameworkRequirements("soc2").find((r) => r.id === "soc2-5")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(
      req.check({ egress_allowlist: { enabled: true, default_action: "allow" } }, settings)
    ).toBe(false);
  });

  it("soc2-6: Detection Monitoring - prompt_injection or jailbreak", () => {
    const req = getFrameworkRequirements("soc2").find((r) => r.id === "soc2-6")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check({}, settings)).toBe(false);
    // Either one suffices
    expect(req.check({ prompt_injection: { enabled: true } }, settings)).toBe(true);
    expect(req.check({ jailbreak: { enabled: true } }, settings)).toBe(true);
  });

  it("soc2-7: Incident Detection - secret_leak enabled", () => {
    const req = getFrameworkRequirements("soc2").find((r) => r.id === "soc2-7")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check({}, settings)).toBe(false);
  });

  it("soc2-8: Change Management - patch_integrity enabled", () => {
    const req = getFrameworkRequirements("soc2").find((r) => r.id === "soc2-8")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check({}, settings)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// PCI-DSS requirements
// ---------------------------------------------------------------------------

describe("PCI-DSS requirements", () => {
  const guards = makeStrictGuards();
  const settings = makeStrictSettings();

  it("pci-1: Network Security - egress_allowlist enabled", () => {
    const req = getFrameworkRequirements("pci-dss").find((r) => r.id === "pci-1")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check({}, settings)).toBe(false);
  });

  it("pci-2: Secure Defaults - forbidden_path + egress + secret_leak", () => {
    const req = getFrameworkRequirements("pci-dss").find((r) => r.id === "pci-2")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check({ forbidden_path: { enabled: true, patterns: [] } }, settings)).toBe(false);
  });

  it("pci-3: Protect Stored Data - secret_leak with patterns", () => {
    const req = getFrameworkRequirements("pci-dss").find((r) => r.id === "pci-3")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check({ secret_leak: { enabled: true, patterns: [] } }, settings)).toBe(false);
  });

  it("pci-4: Secure Development - patch_integrity + shell_command", () => {
    const req = getFrameworkRequirements("pci-dss").find((r) => r.id === "pci-4")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check({ patch_integrity: { enabled: true } }, settings)).toBe(false);
  });

  it("pci-5: Restrict Access - forbidden_path + mcp_tool block", () => {
    const req = getFrameworkRequirements("pci-dss").find((r) => r.id === "pci-5")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(
      req.check(
        { forbidden_path: { enabled: true, patterns: [] }, mcp_tool: { enabled: true, default_action: "allow" } },
        settings
      )
    ).toBe(false);
  });

  it("pci-6: Authentication - session_timeout <= 1800", () => {
    const req = getFrameworkRequirements("pci-dss").find((r) => r.id === "pci-6")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check(guards, { session_timeout_secs: 3600 })).toBe(false);
  });

  it("pci-7: Logging & Monitoring - verbose_logging enabled", () => {
    const req = getFrameworkRequirements("pci-dss").find((r) => r.id === "pci-7")!;
    expect(req.check(guards, settings)).toBe(true);
    expect(req.check(guards, { verbose_logging: false })).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// scoreFramework
// ---------------------------------------------------------------------------

describe("scoreFramework", () => {
  it("returns 100% score when all requirements are met", () => {
    const guards = makeStrictGuards();
    const settings = makeStrictSettings();
    const result = scoreFramework("hipaa", guards, settings);
    expect(result.score).toBe(100);
    expect(result.gaps).toHaveLength(0);
    expect(result.met.length).toBe(getFrameworkRequirements("hipaa").length);
  });

  it("returns 0% score with empty policy", () => {
    const result = scoreFramework("hipaa", makeEmptyGuards(), makeEmptySettings());
    expect(result.score).toBe(0);
    expect(result.met).toHaveLength(0);
    expect(result.gaps.length).toBe(getFrameworkRequirements("hipaa").length);
  });

  it("returns partial score when some requirements are met", () => {
    const guards: GuardConfigMap = {
      forbidden_path: {
        enabled: true,
        patterns: ["**/.ssh/**", "**/.aws/**", "**/.env"],
      },
    };
    const settings: PolicySettings = { verbose_logging: true };
    const result = scoreFramework("hipaa", guards, settings);
    expect(result.score).toBeGreaterThan(0);
    expect(result.score).toBeLessThan(100);
    expect(result.met.length).toBeGreaterThan(0);
    expect(result.gaps.length).toBeGreaterThan(0);
  });

  it("met + gaps equals total requirements", () => {
    const guards: GuardConfigMap = { shell_command: { enabled: true } };
    const settings: PolicySettings = {};
    const result = scoreFramework("soc2", guards, settings);
    expect(result.met.length + result.gaps.length).toBe(getFrameworkRequirements("soc2").length);
  });

  it("returns 0 for unknown framework (no requirements)", () => {
    const result = scoreFramework("unknown" as any, makeEmptyGuards(), makeEmptySettings());
    expect(result.score).toBe(0);
    expect(result.met).toHaveLength(0);
    expect(result.gaps).toHaveLength(0);
  });

  it("scores SOC2 correctly with full strict policy", () => {
    const result = scoreFramework("soc2", makeStrictGuards(), makeStrictSettings());
    expect(result.score).toBe(100);
  });

  it("scores PCI-DSS correctly with full strict policy", () => {
    const result = scoreFramework("pci-dss", makeStrictGuards(), makeStrictSettings());
    expect(result.score).toBe(100);
  });
});

// ---------------------------------------------------------------------------
// Individual check isolation
// ---------------------------------------------------------------------------

describe("individual check functions in isolation", () => {
  it("hipaa-1 check only depends on forbidden_path patterns length", () => {
    const req = getFrameworkRequirements("hipaa").find((r) => r.id === "hipaa-1")!;
    // Exactly 3 patterns - should pass
    expect(
      req.check({ forbidden_path: { enabled: true, patterns: ["a", "b", "c"] } }, {})
    ).toBe(true);
    // 2 patterns - should fail
    expect(
      req.check({ forbidden_path: { enabled: true, patterns: ["a", "b"] } }, {})
    ).toBe(false);
    // Not enabled - should fail
    expect(
      req.check({ forbidden_path: { enabled: false, patterns: ["a", "b", "c"] } }, {})
    ).toBe(false);
  });

  it("hipaa-9 check looks for key/private/KEY in pattern names/patterns", () => {
    const req = getFrameworkRequirements("hipaa").find((r) => r.id === "hipaa-9")!;
    // Pattern name contains "key"
    expect(
      req.check(
        { secret_leak: { enabled: true, patterns: [{ name: "api_key", pattern: "abc", severity: "warning" }] } },
        {}
      )
    ).toBe(true);
    // Pattern name contains "private"
    expect(
      req.check(
        {
          secret_leak: {
            enabled: true,
            patterns: [{ name: "private_cert", pattern: "abc", severity: "warning" }],
          },
        },
        {}
      )
    ).toBe(true);
    // Pattern value contains "KEY"
    expect(
      req.check(
        {
          secret_leak: {
            enabled: true,
            patterns: [{ name: "something", pattern: "PRIVATE KEY", severity: "warning" }],
          },
        },
        {}
      )
    ).toBe(true);
  });
});
