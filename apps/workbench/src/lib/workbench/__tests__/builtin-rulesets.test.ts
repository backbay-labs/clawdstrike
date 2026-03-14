import { describe, it, expect } from "vitest";
import { BUILTIN_RULESETS } from "../builtin-rulesets";
import { yamlToPolicy } from "../yaml-utils";


function parseRuleset(yaml: string) {
  const [policy, errors] = yamlToPolicy(yaml);
  return { policy, errors };
}


describe("BUILTIN_RULESETS", () => {
  it("contains at least 5 rulesets", () => {
    expect(BUILTIN_RULESETS.length).toBeGreaterThanOrEqual(5);
  });

  it("has no duplicate IDs", () => {
    const ids = BUILTIN_RULESETS.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  const expectedIds = [
    "default",
    "strict",
    "permissive",
    "ai-agent",
    "ai-agent-posture",
    "cicd",
    "remote-desktop",
    "remote-desktop-strict",
    "remote-desktop-permissive",
    "spider-sense",
  ];

  it.each(expectedIds)("includes '%s' ruleset", (id) => {
    expect(BUILTIN_RULESETS.find((r) => r.id === id)).toBeDefined();
  });

  it("all rulesets have required metadata fields", () => {
    for (const ruleset of BUILTIN_RULESETS) {
      expect(ruleset.id).toBeTruthy();
      expect(ruleset.name).toBeTruthy();
      expect(ruleset.description).toBeTruthy();
      expect(ruleset.yaml).toBeTruthy();
    }
  });

  it("all ruleset descriptions are under 150 characters", () => {
    for (const ruleset of BUILTIN_RULESETS) {
      expect(ruleset.description.length).toBeLessThanOrEqual(150);
    }
  });
});


describe("BUILTIN_RULESETS YAML validity", () => {
  for (const ruleset of BUILTIN_RULESETS) {
    describe(`${ruleset.id}`, () => {
      it("parses without errors", () => {
        const { policy, errors } = parseRuleset(ruleset.yaml);
        expect(policy).not.toBeNull();
        expect(errors).toEqual([]);
      });

      it("has a name", () => {
        const { policy } = parseRuleset(ruleset.yaml);
        expect(policy!.name).toBeTruthy();
      });

      it("YAML contains guards section", () => {
        expect(ruleset.yaml).toContain("guards:");
      });

      it("policy name matches ruleset ID", () => {
        const { policy } = parseRuleset(ruleset.yaml);
        expect(policy!.name).toBe(ruleset.id);
      });

      it("uses schema version 1.2.0", () => {
        const { policy } = parseRuleset(ruleset.yaml);
        expect(policy!.version).toBe("1.2.0");
      });
    });
  }
});


describe("default ruleset", () => {
  const ruleset = BUILTIN_RULESETS.find((r) => r.id === "default")!;
  const { policy } = parseRuleset(ruleset.yaml);

  it("enables forbidden_path guard", () => {
    expect(policy!.guards.forbidden_path?.enabled).toBe(true);
  });

  it("enables egress_allowlist guard", () => {
    expect(policy!.guards.egress_allowlist?.enabled).toBe(true);
  });

  it("enables secret_leak guard", () => {
    expect(policy!.guards.secret_leak?.enabled).toBe(true);
  });

  it("enables shell_command guard", () => {
    expect(policy!.guards.shell_command?.enabled).toBe(true);
  });

  it("has fail_fast set to false", () => {
    expect(policy!.settings.fail_fast).toBe(false);
  });
});

describe("strict ruleset", () => {
  const ruleset = BUILTIN_RULESETS.find((r) => r.id === "strict")!;
  const { policy } = parseRuleset(ruleset.yaml);

  it("extends default", () => {
    expect(policy!.extends).toBe("default");
  });

  it("enables path_allowlist guard", () => {
    expect(policy!.guards.path_allowlist?.enabled).toBe(true);
  });

  it("enables mcp_tool guard", () => {
    expect(policy!.guards.mcp_tool?.enabled).toBe(true);
  });

  it("enables jailbreak guard", () => {
    expect(policy!.guards.jailbreak?.enabled).toBe(true);
  });

  it("has fail_fast enabled", () => {
    expect(policy!.settings.fail_fast).toBe(true);
  });

  it("has verbose_logging enabled", () => {
    expect(policy!.settings.verbose_logging).toBe(true);
  });
});

describe("remote-desktop ruleset", () => {
  const ruleset = BUILTIN_RULESETS.find((r) => r.id === "remote-desktop")!;
  const { policy } = parseRuleset(ruleset.yaml);

  it("enables computer_use guard", () => {
    expect(policy!.guards.computer_use?.enabled).toBe(true);
  });

  it("enables remote_desktop_side_channel guard", () => {
    expect(policy!.guards.remote_desktop_side_channel?.enabled).toBe(true);
  });

  it("enables input_injection_capability guard", () => {
    expect(policy!.guards.input_injection_capability?.enabled).toBe(true);
  });
});

describe("ai-agent-posture ruleset", () => {
  const ruleset = BUILTIN_RULESETS.find((r) => r.id === "ai-agent-posture")!;
  const { policy } = parseRuleset(ruleset.yaml);

  it("extends ai-agent", () => {
    expect(policy!.extends).toBe("ai-agent");
  });

  it("has posture configuration", () => {
    expect(policy!.posture).toBeDefined();
  });

  it("has posture initial state set to 'exploring'", () => {
    expect(policy!.posture?.initial).toBe("exploring");
  });

  it("has at least 2 posture states", () => {
    const stateCount = Object.keys(policy!.posture?.states ?? {}).length;
    expect(stateCount).toBeGreaterThanOrEqual(2);
  });

  it("has posture transitions", () => {
    expect(policy!.posture?.transitions).toBeDefined();
    expect(policy!.posture!.transitions!.length).toBeGreaterThan(0);
  });
});

describe("spider-sense ruleset", () => {
  const ruleset = BUILTIN_RULESETS.find((r) => r.id === "spider-sense")!;
  const { policy } = parseRuleset(ruleset.yaml);

  it("extends default", () => {
    expect(policy!.extends).toBe("default");
  });

  it("enables spider_sense guard", () => {
    expect(policy!.guards.spider_sense?.enabled).toBe(true);
  });

  it("sets similarity_threshold", () => {
    expect(policy!.guards.spider_sense?.similarity_threshold).toBeDefined();
  });

  it("sets pattern_db_path to built-in", () => {
    expect(policy!.guards.spider_sense?.pattern_db_path).toBe("builtin:s2bench-v1");
  });
});

describe("permissive ruleset", () => {
  const ruleset = BUILTIN_RULESETS.find((r) => r.id === "permissive")!;
  const { policy } = parseRuleset(ruleset.yaml);

  it("does not extend anything", () => {
    expect(policy!.extends).toBeUndefined();
  });

  it("disables shell_command guard", () => {
    expect(policy!.guards.shell_command?.enabled).toBe(false);
  });

  it("disables egress_allowlist guard", () => {
    expect(policy!.guards.egress_allowlist?.enabled).toBe(false);
  });
});
