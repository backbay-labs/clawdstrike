import { describe, it, expect } from "vitest";
import { getSourceTemplate, getTestTemplate } from "../src/templates/source";
import type { ScaffoldOptions, PluginType } from "../src/types";
import { PLUGIN_TYPES, PLUGIN_TYPE_DEFAULTS } from "../src/types";

/**
 * Create a ScaffoldOptions object with sensible defaults for testing.
 */
function makeOptions(type: PluginType): ScaffoldOptions {
  return {
    name: `test-${type}-plugin`,
    displayName: `Test ${type.charAt(0).toUpperCase() + type.slice(1)} Plugin`,
    publisher: "test-org",
    type,
    contributions: PLUGIN_TYPE_DEFAULTS[type],
    packageManager: "npm",
    outputDir: `/tmp/test-${type}-plugin`,
  };
}

describe("getSourceTemplate", () => {
  describe("guard template", () => {
    const output = getSourceTemplate(makeOptions("guard"));

    it("contains createPlugin", () => {
      expect(output).toContain("createPlugin");
    });

    it("contains GuardContribution type", () => {
      expect(output).toContain("GuardContribution");
    });

    it("contains ctx.guards.register()", () => {
      expect(output).toContain("ctx.guards.register");
    });

    it("contains the plugin name in manifest", () => {
      expect(output).toContain("test-guard-plugin");
    });
  });

  describe("detection template", () => {
    const output = getSourceTemplate(makeOptions("detection"));

    it("contains createPlugin", () => {
      expect(output).toContain("createPlugin");
    });

    it("contains FileTypeContribution type", () => {
      expect(output).toContain("FileTypeContribution");
    });

    it("does not advertise unsupported detection adapter scaffolding", () => {
      expect(output).not.toContain("DetectionAdapterContribution");
    });

    it("contains ctx.fileTypes.register()", () => {
      expect(output).toContain("ctx.fileTypes.register");
    });
  });

  describe("ui template", () => {
    const output = getSourceTemplate(makeOptions("ui"));

    it("contains createPlugin", () => {
      expect(output).toContain("createPlugin");
    });

    it("contains EditorTabContribution type", () => {
      expect(output).toContain("EditorTabContribution");
    });

    it("contains ActivityBarItemContribution type", () => {
      expect(output).toContain("ActivityBarItemContribution");
    });

    it("uses internal trust for host-rendered contributions", () => {
      expect(output).toContain('trust: "internal"');
    });
  });

  describe("intel template", () => {
    const output = getSourceTemplate(makeOptions("intel"));

    it("contains createPlugin", () => {
      expect(output).toContain("createPlugin");
    });

    it("contains ThreatIntelSourceContribution type", () => {
      expect(output).toContain("ThreatIntelSourceContribution");
    });

    it("contains requiredSecrets", () => {
      expect(output).toContain("requiredSecrets");
    });

    it("uses internal trust for host-side intel entrypoints", () => {
      expect(output).toContain('trust: "internal"');
    });
  });

  describe("compliance template", () => {
    const output = getSourceTemplate(makeOptions("compliance"));

    it("contains createPlugin", () => {
      expect(output).toContain("createPlugin");
    });

    it("does not advertise unsupported compliance framework scaffolding", () => {
      expect(output).not.toContain("ComplianceFrameworkContribution");
    });
  });

  describe("full template", () => {
    const output = getSourceTemplate(makeOptions("full"));

    it("contains createPlugin", () => {
      expect(output).toContain("createPlugin");
    });

    it("contains ctx.guards.register()", () => {
      expect(output).toContain("ctx.guards.register");
    });

    it("contains all major contribution types", () => {
      expect(output).toContain("GuardContribution");
      expect(output).toContain("FileTypeContribution");
      expect(output).toContain("ThreatIntelSourceContribution");
      expect(output).toContain("EditorTabContribution");
      expect(output).not.toContain("ComplianceFrameworkContribution");
    });

    it("uses internal trust for the scaffolded host contribution mix", () => {
      expect(output).toContain('trust: "internal"');
    });
  });

  describe("all types produce output", () => {
    it("all 6 types produce non-empty output", () => {
      for (const type of PLUGIN_TYPES) {
        const output = getSourceTemplate(makeOptions(type));
        expect(output.length).toBeGreaterThan(0);
        expect(output).toContain("createPlugin");
      }
    });
  });
});

describe("getTestTemplate", () => {
  describe("test template structure", () => {
    it("contains createSpyContext import for any type", () => {
      for (const type of PLUGIN_TYPES) {
        const output = getTestTemplate(makeOptions(type));
        expect(output).toContain("createSpyContext");
      }
    });

    it("contains plugin-sdk/testing import path for any type", () => {
      for (const type of PLUGIN_TYPES) {
        const output = getTestTemplate(makeOptions(type));
        expect(output).toContain("plugin-sdk/testing");
      }
    });

    it("contains assertContributions import for any type", () => {
      for (const type of PLUGIN_TYPES) {
        const output = getTestTemplate(makeOptions(type));
        expect(output).toContain("assertContributions");
      }
    });
  });

  describe("type-specific test assertions", () => {
    it("guard test references guards.registered", () => {
      const output = getTestTemplate(makeOptions("guard"));
      expect(output).toContain("guards.registered");
    });

    it("detection test references fileTypes.registered", () => {
      const output = getTestTemplate(makeOptions("detection"));
      expect(output).toContain("fileTypes.registered");
    });

    it("full test references guards.registered", () => {
      const output = getTestTemplate(makeOptions("full"));
      expect(output).toContain("guards.registered");
    });

    it("intel test references requiredSecrets", () => {
      const output = getTestTemplate(makeOptions("intel"));
      expect(output).toContain("requiredSecrets");
    });
  });

  describe("all types produce test output", () => {
    it("all 6 types produce non-empty test output", () => {
      for (const type of PLUGIN_TYPES) {
        const output = getTestTemplate(makeOptions(type));
        expect(output.length).toBeGreaterThan(0);
        expect(output).toContain("describe");
        expect(output).toContain("it(");
      }
    });
  });
});
