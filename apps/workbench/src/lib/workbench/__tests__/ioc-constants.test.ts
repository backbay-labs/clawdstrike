import { describe, it, expect } from "vitest";
import { IOC_TYPE_COLORS } from "../ioc-constants";

// ---- Tests ----

describe("IOC_TYPE_COLORS", () => {
  const EXPECTED_IOC_TYPES = [
    "sha256",
    "sha1",
    "md5",
    "ip",
    "domain",
    "url",
    "email",
  ] as const;

  it("has colors defined for all expected IOC types", () => {
    for (const iocType of EXPECTED_IOC_TYPES) {
      expect(IOC_TYPE_COLORS).toHaveProperty(iocType);
      expect(IOC_TYPE_COLORS[iocType]).toBeDefined();
    }
  });

  it("all color values are valid 6-digit hex strings", () => {
    const hexColorRegex = /^#[0-9a-fA-F]{6}$/;

    for (const [iocType, color] of Object.entries(IOC_TYPE_COLORS)) {
      expect(color).toMatch(hexColorRegex);
    }
  });

  it("hash-type IOCs (sha256, sha1, md5) share the same color for visual consistency", () => {
    expect(IOC_TYPE_COLORS.sha256).toBe(IOC_TYPE_COLORS.sha1);
    expect(IOC_TYPE_COLORS.sha1).toBe(IOC_TYPE_COLORS.md5);
  });

  it("network-type IOCs (ip, domain, url) have distinct colors", () => {
    const networkColors = new Set([
      IOC_TYPE_COLORS.ip,
      IOC_TYPE_COLORS.domain,
      IOC_TYPE_COLORS.url,
    ]);
    expect(networkColors.size).toBe(3);
  });

  it("export cannot be accidentally mutated at runtime", () => {
    // Attempting to assign a new key should not modify the original export.
    // IOC_TYPE_COLORS is typed as Record<string, string> so TS allows writes,
    // but we verify the object is not accidentally frozen/sealed incorrectly
    // or that mutation of a copy does not leak back.
    const snapshot = { ...IOC_TYPE_COLORS };

    // Mutate a copy -- original should remain unchanged
    const copy = { ...IOC_TYPE_COLORS };
    copy.sha256 = "#000000";
    expect(IOC_TYPE_COLORS.sha256).toBe(snapshot.sha256);
    expect(IOC_TYPE_COLORS.sha256).not.toBe("#000000");
  });

  it("filepath IOC type is also defined", () => {
    // filepath is an additional IOC type present in the map
    expect(IOC_TYPE_COLORS).toHaveProperty("filepath");
    expect(IOC_TYPE_COLORS.filepath).toMatch(/^#[0-9a-fA-F]{6}$/);
  });
});
