/**
 * Tests for assertContributions and assertManifestValid assertion helpers.
 */
import { describe, it, expect } from "vitest";
import {
  assertContributions,
  assertManifestValid,
  createTestManifest,
} from "../src/testing";
import { createPlugin } from "../src/create-plugin";
import type { PluginManifest, GuardContribution, CommandContribution, FileTypeContribution } from "../src/types";

// ---- Test Fixtures ----

function makeGuard(id: string): GuardContribution {
  return {
    id,
    name: `Guard ${id}`,
    technicalName: id,
    description: `Guard ${id} description`,
    category: "test",
    defaultVerdict: "deny",
    icon: "shield",
    configFields: [],
  };
}

function makeCommand(id: string): CommandContribution {
  return { id, title: `Command ${id}` };
}

function makeFileType(id: string): FileTypeContribution {
  return {
    id,
    label: `File Type ${id}`,
    shortLabel: id.toUpperCase(),
    extensions: [`.${id}`],
    iconColor: "#ff0000",
    defaultContent: "",
    testable: false,
  };
}

// ---- assertContributions ----

describe("assertContributions", () => {
  it("passes when plugin has exactly the expected number of guards", () => {
    const plugin = createPlugin({
      manifest: createTestManifest({
        contributions: { guards: [makeGuard("g1")] },
      }),
      activate() {},
    });
    expect(() => assertContributions(plugin, { guards: 1 })).not.toThrow();
  });

  it("throws when plugin has fewer guards than expected", () => {
    const plugin = createPlugin({
      manifest: createTestManifest({
        contributions: { guards: [] },
      }),
      activate() {},
    });
    expect(() => assertContributions(plugin, { guards: 1 })).toThrow(
      /guards: expected 1, got 0/,
    );
  });

  it("throws when plugin has more guards than expected", () => {
    const plugin = createPlugin({
      manifest: createTestManifest({
        contributions: { guards: [makeGuard("g1"), makeGuard("g2")] },
      }),
      activate() {},
    });
    expect(() => assertContributions(plugin, { guards: 1 })).toThrow(
      /guards: expected 1, got 2/,
    );
  });

  it("passes when expecting 0 commands and plugin has no commands", () => {
    const plugin = createPlugin({
      manifest: createTestManifest({
        contributions: {},
      }),
      activate() {},
    });
    expect(() => assertContributions(plugin, { commands: 0 })).not.toThrow();
  });

  it("checks multiple contribution types and reports all mismatches", () => {
    const plugin = createPlugin({
      manifest: createTestManifest({
        contributions: { guards: [makeGuard("g1")], commands: [] },
      }),
      activate() {},
    });
    expect(() =>
      assertContributions(plugin, { guards: 2, commands: 3 }),
    ).toThrow(/guards: expected 2, got 1/);

    // Also check the commands mismatch is in the same error
    try {
      assertContributions(plugin, { guards: 2, commands: 3 });
    } catch (e: unknown) {
      const msg = (e as Error).message;
      expect(msg).toContain("guards: expected 2, got 1");
      expect(msg).toContain("commands: expected 3, got 0");
    }
  });

  it("works for fileTypes contribution key", () => {
    const plugin = createPlugin({
      manifest: createTestManifest({
        contributions: { fileTypes: [makeFileType("spl")] },
      }),
      activate() {},
    });
    expect(() => assertContributions(plugin, { fileTypes: 1 })).not.toThrow();
    expect(() => assertContributions(plugin, { fileTypes: 2 })).toThrow(
      /fileTypes: expected 2, got 1/,
    );
  });

  it("treats missing contributions field as all counts 0", () => {
    const plugin = createPlugin({
      manifest: createTestManifest(),
      activate() {},
    });
    expect(() => assertContributions(plugin, { guards: 0 })).not.toThrow();
    expect(() => assertContributions(plugin, { guards: 1 })).toThrow(
      /guards: expected 1, got 0/,
    );
  });

  it("error message starts with 'Contribution count mismatch'", () => {
    const plugin = createPlugin({
      manifest: createTestManifest(),
      activate() {},
    });
    expect(() => assertContributions(plugin, { guards: 1 })).toThrow(
      /Contribution count mismatch/,
    );
  });
});

// ---- assertManifestValid ----

describe("assertManifestValid", () => {
  it("does not throw for a valid manifest", () => {
    const manifest = createTestManifest();
    expect(() => assertManifestValid(manifest)).not.toThrow();
  });

  it("throws for an empty object with field-level details", () => {
    expect(() => assertManifestValid({})).toThrow(/"id" is required/);
  });

  it("throws with details about empty id", () => {
    const manifest = createTestManifest({ id: "" });
    expect(() => assertManifestValid(manifest as unknown)).toThrow(/"id" is required/);
  });

  it("includes error count in the message", () => {
    try {
      assertManifestValid({});
    } catch (e: unknown) {
      const msg = (e as Error).message;
      expect(msg).toMatch(/Invalid manifest \(\d+ error\(s\)\)/);
    }
  });

  it("lists each error with field and message", () => {
    try {
      assertManifestValid({});
    } catch (e: unknown) {
      const msg = (e as Error).message;
      // Should have bullet-style error listing
      expect(msg).toContain("  - ");
      expect(msg).toContain("id");
      expect(msg).toContain("name");
    }
  });

  it("throws for non-object input", () => {
    expect(() => assertManifestValid(null)).toThrow(/Invalid manifest/);
    expect(() => assertManifestValid(42)).toThrow(/Invalid manifest/);
    expect(() => assertManifestValid("string")).toThrow(/Invalid manifest/);
  });

  it("validates trust tier", () => {
    const manifest = createTestManifest({ trust: "unknown" as any });
    expect(() => assertManifestValid(manifest as unknown)).toThrow(/trust/);
  });

  it("validates version format", () => {
    const manifest = createTestManifest({ version: "not-semver" });
    expect(() => assertManifestValid(manifest as unknown)).toThrow(/version/);
  });
});
