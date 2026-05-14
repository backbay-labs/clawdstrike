import { describe, it, expect, vi } from "vitest";
import { parseFlags } from "../src/flags";
import { PLUGIN_TYPE_DEFAULTS } from "../src/types";

// Suppress console.error output from parseFlags validation
vi.spyOn(console, "error").mockImplementation(() => {});

describe("parseFlags", () => {
  describe("valid inputs", () => {
    it("parses positional name and --type flag", () => {
      const result = parseFlags(["my-guard", "--type", "guard"]);
      expect(result).not.toBeNull();
      expect(result!.name).toBe("my-guard");
      expect(result!.type).toBe("guard");
    });

    it("parses --publisher flag", () => {
      const result = parseFlags(["my-guard", "--type", "guard", "--publisher", "acme"]);
      expect(result).not.toBeNull();
      expect(result!.publisher).toBe("acme");
    });

    it("parses --contributions flag as comma-separated list", () => {
      const result = parseFlags(["my-guard", "--type", "guard", "--contributions", "guards,commands"]);
      expect(result).not.toBeNull();
      expect(result!.contributions).toEqual(["guards", "commands"]);
    });

    it("accepts all valid plugin types", () => {
      const types = ["guard", "detection", "ui", "intel", "compliance", "full"] as const;
      for (const type of types) {
        const result = parseFlags([`my-${type}`, "--type", type]);
        expect(result).not.toBeNull();
        expect(result!.type).toBe(type);
      }
    });
  });

  describe("validation", () => {
    it("rejects PascalCase name (non-kebab-case)", () => {
      const result = parseFlags(["MyGuard", "--type", "guard"]);
      expect(result).toBeNull();
    });

    it("rejects name with underscores", () => {
      const result = parseFlags(["my_guard", "--type", "guard"]);
      expect(result).toBeNull();
    });

    it("rejects missing name (no positional or --name arg)", () => {
      // Note: ["--type", "guard"] would actually pick "guard" as the positional name
      // since positional detection finds the first non-dash-prefixed arg.
      // To truly have no name, all args must be dash-prefixed.
      const result = parseFlags(["--type"]);
      expect(result).toBeNull();
    });

    it("rejects missing --type flag", () => {
      const result = parseFlags(["my-guard"]);
      expect(result).toBeNull();
    });

    it("rejects invalid plugin type", () => {
      const result = parseFlags(["my-guard", "--type", "invalid"]);
      expect(result).toBeNull();
    });

    it("rejects invalid contribution points", () => {
      const result = parseFlags(["my-guard", "--type", "guard", "--contributions", "guards,nonexistent"]);
      expect(result).toBeNull();
    });

    it("rejects contribution points that are not scaffold-supported yet", () => {
      const result = parseFlags([
        "my-plugin",
        "--type",
        "full",
        "--contributions",
        "guards,detectionAdapters",
      ]);
      expect(result).toBeNull();
    });

    it("rejects invalid package manager", () => {
      const result = parseFlags(["my-guard", "--type", "guard", "--pm", "yarn"]);
      expect(result).toBeNull();
    });

    it("does not treat flag values as the positional plugin name", () => {
      const result = parseFlags(["--publisher", "acme", "--type", "guard"]);
      expect(result).toBeNull();
    });
  });

  describe("defaults", () => {
    it("derives displayName from kebab-case name", () => {
      const result = parseFlags(["my-guard", "--type", "guard"]);
      expect(result).not.toBeNull();
      expect(result!.displayName).toBe("My Guard");
    });

    it("sets contributions to PLUGIN_TYPE_DEFAULTS for the given type", () => {
      const result = parseFlags(["my-guard", "--type", "guard"]);
      expect(result).not.toBeNull();
      expect(result!.contributions).toEqual(PLUGIN_TYPE_DEFAULTS.guard);
    });

    it("defaults publisher to 'my-org' when not specified", () => {
      const result = parseFlags(["my-guard", "--type", "guard"]);
      expect(result).not.toBeNull();
      expect(result!.publisher).toBe("my-org");
    });

    it("defaults packageManager to 'npm' when not specified", () => {
      const result = parseFlags(["my-guard", "--type", "guard"]);
      expect(result).not.toBeNull();
      expect(result!.packageManager).toBe("npm");
    });

    it("sets outputDir to an absolute path based on name", () => {
      const result = parseFlags(["my-guard", "--type", "guard"]);
      expect(result).not.toBeNull();
      expect(result!.outputDir).toContain("my-guard");
      // Should be an absolute path
      expect(result!.outputDir.startsWith("/")).toBe(true);
    });

    it("uses type-specific defaults for detection type", () => {
      const result = parseFlags(["my-detector", "--type", "detection"]);
      expect(result).not.toBeNull();
      expect(result!.contributions).toEqual(PLUGIN_TYPE_DEFAULTS.detection);
    });

    it("uses type-specific defaults for full type", () => {
      const result = parseFlags(["my-full", "--type", "full"]);
      expect(result).not.toBeNull();
      expect(result!.contributions).toEqual(PLUGIN_TYPE_DEFAULTS.full);
    });
  });
});
