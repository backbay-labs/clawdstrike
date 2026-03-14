import { describe, it, expect } from "vitest";
import {
  policyToYaml,
  policyToJson,
  policyToToml,
  policyToFormat,
  formatExtension,
  formatMimeType,
  yamlToPolicy,
  validatePolicy,
} from "../yaml-utils";
import type { WorkbenchPolicy } from "../types";


function makeMinimalPolicy(overrides?: Partial<WorkbenchPolicy>): WorkbenchPolicy {
  return {
    version: "1.2.0",
    name: "test-policy",
    description: "A test policy",
    guards: {},
    settings: {},
    ...overrides,
  };
}

function makeFullPolicy(): WorkbenchPolicy {
  return makeMinimalPolicy({
    name: "full-policy",
    description: "A full-featured policy",
    extends: "strict",
    guards: {
      forbidden_path: { enabled: true, patterns: ["**/.ssh/**", "/etc/shadow"] },
      egress_allowlist: { enabled: true, allow: ["*.openai.com"], default_action: "block" },
      secret_leak: {
        enabled: true,
        patterns: [{ name: "aws_key", pattern: "AKIA[0-9A-Z]{16}", severity: "critical" }],
      },
      shell_command: { enabled: true },
      patch_integrity: { enabled: true, max_additions: 500 },
      mcp_tool: { enabled: true, default_action: "block" },
      prompt_injection: { enabled: true },
      jailbreak: { enabled: true, detector: { block_threshold: 50 } },
    },
    settings: { fail_fast: true, session_timeout_secs: 3600 },
  });
}


describe("policyToYaml", () => {
  it("serializes a default policy to valid YAML string", () => {
    const policy = makeMinimalPolicy({ name: "My Policy" });
    const yaml = policyToYaml(policy);
    expect(typeof yaml).toBe("string");
    expect(yaml).toContain("version");
    expect(yaml).toContain("My Policy");
  });

  it("omits empty guards object", () => {
    const policy = makeMinimalPolicy();
    const yaml = policyToYaml(policy);
    expect(yaml).not.toContain("guards:");
  });

  it("omits empty settings object", () => {
    const policy = makeMinimalPolicy({ settings: {} });
    const yaml = policyToYaml(policy);
    expect(yaml).not.toContain("settings:");
  });

  it("includes guards when they have config", () => {
    const policy = makeMinimalPolicy({
      guards: {
        forbidden_path: {
          enabled: true,
          patterns: ["**/.ssh/**"],
        },
      },
    });
    const yaml = policyToYaml(policy);
    expect(yaml).toContain("forbidden_path");
    expect(yaml).toContain(".ssh");
  });

  it("preserves guards with semantic empty arrays after cleaning", () => {
    const policy = makeMinimalPolicy({
      guards: {
        forbidden_path: {
          enabled: undefined,
          patterns: [],
        } as any,
      },
    });
    const yaml = policyToYaml(policy);
    // patterns: [] is a semantic field (explicit empty allowlist), so it is preserved
    expect(yaml).toContain("forbidden_path");
    expect(yaml).toContain("patterns");
  });

  it("includes extends field when present", () => {
    const policy = makeMinimalPolicy({ extends: "strict" });
    const yaml = policyToYaml(policy);
    expect(yaml).toContain("extends");
    expect(yaml).toContain("strict");
  });

  it("omits extends when not set", () => {
    const policy = makeMinimalPolicy();
    const yaml = policyToYaml(policy);
    expect(yaml).not.toContain("extends");
  });

  it("includes posture when present", () => {
    const policy = makeMinimalPolicy({
      posture: {
        initial: "normal",
        states: { normal: { description: "Normal mode" } },
      },
    });
    const yaml = policyToYaml(policy);
    expect(yaml).toContain("posture");
    expect(yaml).toContain("normal");
  });

  it("includes settings when they have values", () => {
    const policy = makeMinimalPolicy({
      settings: { fail_fast: true, session_timeout_secs: 3600 },
    });
    const yaml = policyToYaml(policy);
    expect(yaml).toContain("settings");
    expect(yaml).toContain("fail_fast");
    expect(yaml).toContain("3600");
  });

  it("handles all guard types in a full policy", () => {
    const policy = makeFullPolicy();
    const yaml = policyToYaml(policy);
    expect(yaml).toContain("forbidden_path");
    expect(yaml).toContain("egress_allowlist");
    expect(yaml).toContain("secret_leak");
    expect(yaml).toContain("shell_command");
    expect(yaml).toContain("patch_integrity");
    expect(yaml).toContain("mcp_tool");
    expect(yaml).toContain("prompt_injection");
    expect(yaml).toContain("jailbreak");
  });

  it("preserves spider_sense embedding_api_key during serialization", () => {
    const policy = makeMinimalPolicy({
      guards: {
        spider_sense: {
          enabled: true,
          embedding_api_url: "https://embeddings.example.com",
          embedding_api_key: "live-secret-key",
          embedding_model: "text-embedding-3-small",
        },
      },
    });

    const yaml = policyToYaml(policy);

    expect(yaml).toContain("embedding_api_key");
    expect(yaml).toContain("live-secret-key");
    expect(yaml).not.toContain("***REDACTED***");
  });

  it("serializes origin profile metadata when present", () => {
    const policy = makeMinimalPolicy({
      version: "1.4.0",
      origins: {
        default_behavior: "deny",
        profiles: [
          {
            id: "slack-prod",
            match_rules: { provider: "slack", thread_id: "thread-1" },
            metadata: {
              channel: "eng-alerts",
              escalation: true,
            },
          },
        ],
      },
    });

    const yaml = policyToYaml(policy);

    expect(yaml).toContain("metadata");
    expect(yaml).toContain("channel");
    expect(yaml).toContain("eng-alerts");
    expect(yaml).toContain("escalation");
  });

  it("preserves intentionally empty origin metadata collections", () => {
    const policy = makeMinimalPolicy({
      version: "1.4.0",
      origins: {
        default_behavior: "deny",
        profiles: [
          {
            id: "slack-prod",
            match_rules: { provider: "slack" },
            metadata: {
              tags: [],
              nested: {
                labels: [],
              },
            },
          },
        ],
      },
    });

    const yaml = policyToYaml(policy);

    expect(yaml).toContain("metadata");
    expect(yaml).toContain("tags: []");
    expect(yaml).toContain("labels: []");
  });
});


describe("policyToJson", () => {
  it("serializes a minimal policy to valid JSON string", () => {
    const policy = makeMinimalPolicy({ name: "JSON Policy" });
    const json = policyToJson(policy);
    expect(typeof json).toBe("string");

    const parsed = JSON.parse(json);
    expect(parsed.version).toBe("1.2.0");
    expect(parsed.name).toBe("JSON Policy");
    expect(parsed.description).toBe("A test policy");
  });

  it("produces 2-space indented JSON", () => {
    const policy = makeMinimalPolicy();
    const json = policyToJson(policy);
    // Check that lines are indented with 2 spaces (not 4, not tabs)
    const lines = json.split("\n");
    const indented = lines.filter((l) => l.startsWith("  "));
    expect(indented.length).toBeGreaterThan(0);
    // No 4-space-only indentation at the first nesting level
    const firstIndented = lines.find((l) => l.match(/^\s+"/));
    expect(firstIndented).toBeDefined();
    expect(firstIndented!.startsWith("  ")).toBe(true);
  });

  it("omits empty guards and settings", () => {
    const policy = makeMinimalPolicy();
    const json = policyToJson(policy);
    const parsed = JSON.parse(json);
    expect(parsed.guards).toBeUndefined();
    expect(parsed.settings).toBeUndefined();
  });

  it("includes guards when present", () => {
    const policy = makeMinimalPolicy({
      guards: {
        forbidden_path: { enabled: true, patterns: ["**/.ssh/**"] },
      },
    });
    const json = policyToJson(policy);
    const parsed = JSON.parse(json);
    expect(parsed.guards.forbidden_path.patterns).toEqual(["**/.ssh/**"]);
  });

  it("includes extends when present", () => {
    const policy = makeMinimalPolicy({ extends: "strict" });
    const json = policyToJson(policy);
    const parsed = JSON.parse(json);
    expect(parsed.extends).toBe("strict");
  });

  it("handles full policy with all guard types", () => {
    const policy = makeFullPolicy();
    const json = policyToJson(policy);
    const parsed = JSON.parse(json);
    expect(parsed.guards.forbidden_path).toBeDefined();
    expect(parsed.guards.egress_allowlist).toBeDefined();
    expect(parsed.guards.secret_leak).toBeDefined();
    expect(parsed.guards.jailbreak.detector.block_threshold).toBe(50);
    expect(parsed.settings.fail_fast).toBe(true);
    expect(parsed.settings.session_timeout_secs).toBe(3600);
  });

  it("handles special characters in strings", () => {
    const policy = makeMinimalPolicy({
      name: 'Policy with "quotes" and\nnewline',
    });
    const json = policyToJson(policy);
    // Should be valid JSON despite special characters
    const parsed = JSON.parse(json);
    expect(parsed.name).toBe('Policy with "quotes" and\nnewline');
  });
});


describe("policyToToml", () => {
  it("serializes a minimal policy to a TOML string", () => {
    const policy = makeMinimalPolicy({ name: "TOML Policy" });
    const toml = policyToToml(policy);
    expect(typeof toml).toBe("string");
    expect(toml).toContain('version = "1.2.0"');
    expect(toml).toContain('name = "TOML Policy"');
    expect(toml).toContain('description = "A test policy"');
  });

  it("omits empty guards and settings", () => {
    const policy = makeMinimalPolicy();
    const toml = policyToToml(policy);
    expect(toml).not.toContain("[guards]");
    expect(toml).not.toContain("[settings]");
  });

  it("includes extends when present", () => {
    const policy = makeMinimalPolicy({ extends: "strict" });
    const toml = policyToToml(policy);
    expect(toml).toContain('extends = "strict"');
  });

  it("renders guards as [guards] section with subsections", () => {
    const policy = makeMinimalPolicy({
      guards: {
        forbidden_path: { enabled: true, patterns: ["**/.ssh/**", "/etc/shadow"] },
        shell_command: { enabled: true },
      },
    });
    const toml = policyToToml(policy);
    expect(toml).toContain("[guards]");
    expect(toml).toContain("[guards.forbidden_path]");
    expect(toml).toContain("enabled = true");
    expect(toml).toContain('"**/.ssh/**"');
    expect(toml).toContain('"/etc/shadow"');
  });

  it("renders string arrays correctly", () => {
    const policy = makeMinimalPolicy({
      guards: {
        egress_allowlist: { enabled: true, allow: ["*.openai.com", "api.github.com"] },
      },
    });
    const toml = policyToToml(policy);
    expect(toml).toContain('"*.openai.com"');
    expect(toml).toContain('"api.github.com"');
  });

  it("renders numeric values correctly", () => {
    const policy = makeMinimalPolicy({
      guards: {
        patch_integrity: { enabled: true, max_additions: 500 },
      },
      settings: { session_timeout_secs: 3600 },
    });
    const toml = policyToToml(policy);
    expect(toml).toContain("max_additions = 500");
    expect(toml).toContain("session_timeout_secs = 3600");
  });

  it("renders boolean values correctly", () => {
    const policy = makeMinimalPolicy({
      settings: { fail_fast: true, verbose_logging: false },
    });
    const toml = policyToToml(policy);
    expect(toml).toContain("fail_fast = true");
    expect(toml).toContain("verbose_logging = false");
  });

  it("handles nested objects in arrays as inline tables", () => {
    const policy = makeMinimalPolicy({
      guards: {
        secret_leak: {
          enabled: true,
          patterns: [{ name: "aws_key", pattern: "AKIA[0-9A-Z]{16}", severity: "critical" }],
        },
      },
    });
    const toml = policyToToml(policy);
    expect(toml).toContain("aws_key");
    expect(toml).toContain("AKIA");
    expect(toml).toContain("critical");
  });

  it("escapes special characters in strings", () => {
    const policy = makeMinimalPolicy({
      name: 'Policy with "quotes"',
      description: "Line1\nLine2",
    });
    const toml = policyToToml(policy);
    expect(toml).toContain('\\"quotes\\"');
    expect(toml).toContain("\\n");
  });

  it("handles a full policy with all guard types", () => {
    const policy = makeFullPolicy();
    const toml = policyToToml(policy);
    expect(toml).toContain("[guards.forbidden_path]");
    expect(toml).toContain("[guards.egress_allowlist]");
    expect(toml).toContain("[guards.secret_leak]");
    expect(toml).toContain("[guards.shell_command]");
    expect(toml).toContain("[guards.patch_integrity]");
    expect(toml).toContain("[guards.mcp_tool]");
    expect(toml).toContain("[guards.prompt_injection]");
    expect(toml).toContain("[guards.jailbreak]");
  });

  it("ends with a newline", () => {
    const policy = makeMinimalPolicy();
    const toml = policyToToml(policy);
    expect(toml.endsWith("\n")).toBe(true);
  });
});


describe("policyToFormat", () => {
  it("returns YAML when format is yaml", () => {
    const policy = makeMinimalPolicy();
    const result = policyToFormat(policy, "yaml");
    expect(result).toBe(policyToYaml(policy));
  });

  it("returns JSON when format is json", () => {
    const policy = makeMinimalPolicy();
    const result = policyToFormat(policy, "json");
    expect(result).toBe(policyToJson(policy));
  });

  it("returns TOML when format is toml", () => {
    const policy = makeMinimalPolicy();
    const result = policyToFormat(policy, "toml");
    expect(result).toBe(policyToToml(policy));
  });
});


describe("formatExtension", () => {
  it("returns correct extensions", () => {
    expect(formatExtension("yaml")).toBe("yaml");
    expect(formatExtension("json")).toBe("json");
    expect(formatExtension("toml")).toBe("toml");
  });
});

describe("formatMimeType", () => {
  it("returns correct MIME types", () => {
    expect(formatMimeType("yaml")).toBe("text/yaml");
    expect(formatMimeType("json")).toBe("application/json");
    expect(formatMimeType("toml")).toBe("application/toml");
  });
});


describe("yamlToPolicy", () => {
  it("parses valid YAML to a WorkbenchPolicy", () => {
    const yaml = `
version: "1.2.0"
name: "Test"
description: "A policy"
guards:
  forbidden_path:
    enabled: true
    patterns:
      - "**/.ssh/**"
settings:
  fail_fast: true
`;
    const [policy, errors] = yamlToPolicy(yaml);
    expect(errors).toEqual([]);
    expect(policy).not.toBeNull();
    expect(policy!.version).toBe("1.2.0");
    expect(policy!.name).toBe("Test");
    expect(policy!.guards.forbidden_path?.patterns).toEqual(["**/.ssh/**"]);
    expect(policy!.settings.fail_fast).toBe(true);
  });

  it("returns errors for invalid YAML syntax", () => {
    const yaml = `
version: "1.2.0
  name: broken:
    - [invalid
`;
    const [policy, errors] = yamlToPolicy(yaml);
    expect(policy).toBeNull();
    expect(errors.length).toBeGreaterThan(0);
  });

  it("rejects a YAML array (must be a mapping/object)", () => {
    const [policy, errors] = yamlToPolicy("- just\n- a\n- list");
    expect(policy).toBeNull();
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]).toContain("array");
  });

  it("defaults version to 1.2.0 when missing", () => {
    const [policy] = yamlToPolicy("name: test\n");
    expect(policy!.version).toBe("1.2.0");
  });

  it("defaults name to empty string when missing", () => {
    const [policy] = yamlToPolicy("version: '1.2.0'\n");
    expect(policy!.name).toBe("");
  });

  it("defaults guards to empty object when missing", () => {
    const [policy] = yamlToPolicy("version: '1.2.0'\nname: test\n");
    expect(policy!.guards).toEqual({});
  });

  it("handles null/empty YAML input", () => {
    const [policy, errors] = yamlToPolicy("");
    expect(policy).toBeNull();
    expect(errors).toContain("YAML must be a mapping/object");
  });

  it("handles plain scalar input", () => {
    const [policy, errors] = yamlToPolicy("hello world");
    expect(policy).toBeNull();
    expect(errors).toContain("YAML must be a mapping/object");
  });

  it("preserves posture when present", () => {
    const yaml = `
version: "1.2.0"
name: test
posture:
  initial: normal
  states:
    normal:
      description: "Normal mode"
`;
    const [policy] = yamlToPolicy(yaml);
    expect(policy!.posture).toBeDefined();
    expect(policy!.posture!.initial).toBe("normal");
  });

  it("preserves extends when present", () => {
    const yaml = `
version: "1.2.0"
name: test
extends: strict
`;
    const [policy] = yamlToPolicy(yaml);
    expect(policy!.extends).toBe("strict");
  });
});


describe("validatePolicy", () => {
  it("accepts a valid minimal policy", () => {
    const result = validatePolicy(makeMinimalPolicy());
    expect(result.valid).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("errors on unsupported schema version", () => {
    const policy = makeMinimalPolicy({ version: "0.0.1" as any });
    const result = validatePolicy(policy);
    expect(result.valid).toBe(false);
    expect(result.errors[0].path).toBe("version");
    expect(result.errors[0].message).toContain("Unsupported schema version");
  });

  it("accepts all supported schema versions", () => {
    for (const v of ["1.1.0", "1.2.0", "1.3.0", "1.4.0"] as const) {
      const result = validatePolicy(makeMinimalPolicy({ version: v }));
      expect(result.errors.filter((e) => e.path === "version")).toHaveLength(0);
    }
  });

  it("warns when policy name is empty", () => {
    const policy = makeMinimalPolicy({ name: "" });
    const result = validatePolicy(policy);
    expect(result.warnings.some((w) => w.path === "name")).toBe(true);
  });

  it("warns when policy name is whitespace-only", () => {
    const policy = makeMinimalPolicy({ name: "   " });
    const result = validatePolicy(policy);
    expect(result.warnings.some((w) => w.path === "name")).toBe(true);
  });

  it("errors on empty forbidden_path pattern", () => {
    const policy = makeMinimalPolicy({
      guards: {
        forbidden_path: { enabled: true, patterns: ["**/.ssh/**", ""] },
      },
    });
    const result = validatePolicy(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path.includes("forbidden_path.patterns"))).toBe(true);
    expect(result.errors.some((e) => e.message === "Empty pattern")).toBe(true);
  });

  it("errors on invalid regex in secret_leak patterns", () => {
    const policy = makeMinimalPolicy({
      guards: {
        secret_leak: {
          enabled: true,
          patterns: [{ name: "bad", pattern: "[invalid(", severity: "critical" }],
        },
      },
    });
    const result = validatePolicy(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes("Invalid regex"))).toBe(true);
  });

  it("errors when secret_leak pattern has empty name or pattern", () => {
    const policy = makeMinimalPolicy({
      guards: {
        secret_leak: {
          enabled: true,
          patterns: [{ name: "", pattern: "", severity: "critical" }],
        },
      },
    });
    const result = validatePolicy(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.message.includes("must have name and pattern"))).toBe(true);
  });

  it("warns when jailbreak warn_threshold >= block_threshold", () => {
    const policy = makeMinimalPolicy({
      guards: {
        jailbreak: {
          enabled: true,
          detector: { warn_threshold: 60, block_threshold: 50 },
        },
      },
    });
    const result = validatePolicy(policy);
    expect(result.warnings.some((w) => w.path.includes("jailbreak.detector"))).toBe(true);
    expect(
      result.warnings.some((w) => w.message.includes("warn_threshold should be less than block_threshold"))
    ).toBe(true);
  });

  it("no warning when jailbreak thresholds are correct", () => {
    const policy = makeMinimalPolicy({
      guards: {
        jailbreak: {
          enabled: true,
          detector: { warn_threshold: 20, block_threshold: 50 },
        },
      },
    });
    const result = validatePolicy(policy);
    expect(result.warnings.filter((w) => w.path.includes("jailbreak"))).toHaveLength(0);
  });

  it("warns on empty egress allow list with default_action block", () => {
    const policy = makeMinimalPolicy({
      guards: {
        egress_allowlist: {
          enabled: true,
          allow: [],
          default_action: "block",
        },
      },
    });
    const result = validatePolicy(policy);
    expect(result.warnings.some((w) => w.path === "guards.egress_allowlist")).toBe(true);
    expect(result.warnings.some((w) => w.message.includes("All network egress will be blocked"))).toBe(true);
  });

  it("no warning on empty egress allow list with default_action allow", () => {
    const policy = makeMinimalPolicy({
      guards: {
        egress_allowlist: {
          enabled: true,
          allow: [],
          default_action: "allow",
        },
      },
    });
    const result = validatePolicy(policy);
    expect(result.warnings.filter((w) => w.path === "guards.egress_allowlist")).toHaveLength(0);
  });

  it("warns on short session timeout (< 60s)", () => {
    const policy = makeMinimalPolicy({
      settings: { session_timeout_secs: 30 },
    });
    const result = validatePolicy(policy);
    expect(result.warnings.some((w) => w.path === "settings.session_timeout_secs")).toBe(true);
  });

  it("no warning when session timeout is >= 60", () => {
    const policy = makeMinimalPolicy({
      settings: { session_timeout_secs: 120 },
    });
    const result = validatePolicy(policy);
    expect(result.warnings.filter((w) => w.path === "settings.session_timeout_secs")).toHaveLength(0);
  });

  it("errors when posture is set with v1.1.0", () => {
    const policy = makeMinimalPolicy({
      version: "1.1.0",
      posture: { initial: "normal", states: { normal: {} } },
    });
    const result = validatePolicy(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === "posture")).toBe(true);
    expect(result.errors.some((e) => e.message.includes("Posture requires schema version 1.2.0"))).toBe(true);
  });

  it("allows posture with v1.2.0+", () => {
    const policy = makeMinimalPolicy({
      version: "1.2.0",
      posture: { initial: "normal", states: { normal: {} } },
    });
    const result = validatePolicy(policy);
    expect(result.errors.filter((e) => e.path === "posture")).toHaveLength(0);
  });

  it("errors on negative max_additions in patch_integrity", () => {
    const policy = makeMinimalPolicy({
      guards: {
        patch_integrity: { enabled: true, max_additions: -1 },
      },
    });
    const result = validatePolicy(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === "guards.patch_integrity.max_additions")).toBe(true);
  });

  it("errors on negative max_deletions in patch_integrity", () => {
    const policy = makeMinimalPolicy({
      guards: {
        patch_integrity: { enabled: true, max_deletions: -5 },
      },
    });
    const result = validatePolicy(policy);
    expect(result.valid).toBe(false);
    expect(result.errors.some((e) => e.path === "guards.patch_integrity.max_deletions")).toBe(true);
  });

  it("errors on invalid regex in patch_integrity forbidden_patterns", () => {
    const policy = makeMinimalPolicy({
      guards: {
        patch_integrity: { enabled: true, forbidden_patterns: ["[bad("] },
      },
    });
    const result = validatePolicy(policy);
    expect(result.valid).toBe(false);
    expect(
      result.errors.some((e) => e.path.includes("patch_integrity.forbidden_patterns"))
    ).toBe(true);
  });
});


describe("round-trip", () => {
  it("produces an equivalent policy after serialization and deserialization", () => {
    const original = makeMinimalPolicy({
      name: "roundtrip",
      description: "Roundtrip test",
      guards: {
        forbidden_path: { enabled: true, patterns: ["**/.ssh/**", "/etc/shadow"] },
        egress_allowlist: { enabled: true, allow: ["*.openai.com"], default_action: "block" },
        secret_leak: {
          enabled: true,
          patterns: [{ name: "aws", pattern: "AKIA[0-9A-Z]{16}", severity: "critical" }],
        },
      },
      settings: { fail_fast: true, session_timeout_secs: 3600 },
    });

    const yaml = policyToYaml(original);
    const [parsed, errors] = yamlToPolicy(yaml);

    expect(errors).toEqual([]);
    expect(parsed).not.toBeNull();
    expect(parsed!.version).toBe(original.version);
    expect(parsed!.name).toBe(original.name);
    expect(parsed!.description).toBe(original.description);
    expect(parsed!.guards.forbidden_path?.patterns).toEqual(original.guards.forbidden_path?.patterns);
    expect(parsed!.guards.egress_allowlist?.allow).toEqual(original.guards.egress_allowlist?.allow);
    expect(parsed!.guards.egress_allowlist?.default_action).toBe("block");
    expect(parsed!.guards.secret_leak?.patterns).toEqual(original.guards.secret_leak?.patterns);
    expect(parsed!.settings.fail_fast).toBe(true);
    expect(parsed!.settings.session_timeout_secs).toBe(3600);
  });

  it("round-trips a policy with extends", () => {
    const original = makeMinimalPolicy({ extends: "strict" });
    const yaml = policyToYaml(original);
    const [parsed] = yamlToPolicy(yaml);
    expect(parsed!.extends).toBe("strict");
  });

  it("round-trips a policy with posture", () => {
    const original = makeMinimalPolicy({
      posture: {
        initial: "normal",
        states: {
          normal: { description: "Normal" },
          elevated: { description: "Elevated threat" },
        },
        transitions: [{ from: "normal", to: "elevated", on: "threat_detected" }],
      },
    });
    const yaml = policyToYaml(original);
    const [parsed] = yamlToPolicy(yaml);
    expect(parsed!.posture!.initial).toBe("normal");
    expect(Object.keys(parsed!.posture!.states)).toContain("elevated");
  });

  it("JSON output is parseable and contains the same data", () => {
    const original = makeFullPolicy();
    const json = policyToJson(original);
    const parsed = JSON.parse(json);
    expect(parsed.version).toBe(original.version);
    expect(parsed.name).toBe(original.name);
    expect(parsed.guards.forbidden_path.patterns).toEqual(original.guards.forbidden_path?.patterns);
    expect(parsed.settings.fail_fast).toBe(true);
  });

  it("TOML output contains all expected fields", () => {
    const original = makeMinimalPolicy({
      name: "toml-roundtrip",
      guards: {
        forbidden_path: { enabled: true, patterns: ["**/.ssh/**"] },
      },
      settings: { fail_fast: true },
    });
    const toml = policyToToml(original);
    expect(toml).toContain("toml-roundtrip");
    expect(toml).toContain("**/.ssh/**");
    expect(toml).toContain("fail_fast = true");
  });
});
