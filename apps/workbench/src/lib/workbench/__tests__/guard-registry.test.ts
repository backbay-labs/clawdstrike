import { describe, it, expect } from "vitest";
import { GUARD_REGISTRY, getGuardMeta, GUARD_CATEGORIES } from "../guard-registry";
import type { GuardId } from "../types";

// ---------------------------------------------------------------------------
// GUARD_REGISTRY
// ---------------------------------------------------------------------------

describe("GUARD_REGISTRY", () => {
  it("contains exactly 13 guards", () => {
    expect(GUARD_REGISTRY).toHaveLength(13);
  });

  const expectedIds: GuardId[] = [
    "forbidden_path",
    "path_allowlist",
    "egress_allowlist",
    "secret_leak",
    "patch_integrity",
    "shell_command",
    "mcp_tool",
    "prompt_injection",
    "jailbreak",
    "computer_use",
    "remote_desktop_side_channel",
    "input_injection_capability",
    "spider_sense",
  ];

  it.each(expectedIds)("includes guard %s", (id) => {
    expect(GUARD_REGISTRY.some((g) => g.id === id)).toBe(true);
  });

  it("has no duplicate guard IDs", () => {
    const ids = GUARD_REGISTRY.map((g) => g.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });

  it("all guards have required fields", () => {
    for (const guard of GUARD_REGISTRY) {
      expect(guard.id).toBeTruthy();
      expect(guard.name).toBeTruthy();
      expect(guard.technicalName).toBeTruthy();
      expect(guard.description).toBeTruthy();
      expect(guard.category).toBeTruthy();
      expect(guard.icon).toBeTruthy();
      expect(Array.isArray(guard.configFields)).toBe(true);
      expect(guard.configFields.length).toBeGreaterThan(0);
      expect(["allow", "deny", "warn"]).toContain(guard.defaultVerdict);
    }
  });

  it("all config fields have required properties", () => {
    for (const guard of GUARD_REGISTRY) {
      for (const field of guard.configFields) {
        expect(field.key).toBeTruthy();
        expect(field.label).toBeTruthy();
        expect(field.type).toBeTruthy();
        expect([
          "toggle",
          "string_list",
          "pattern_list",
          "number_slider",
          "number_input",
          "select",
          "secret_pattern_list",
        ]).toContain(field.type);
      }
    }
  });

  it("every guard has an enabled toggle field", () => {
    for (const guard of GUARD_REGISTRY) {
      const enabledField = guard.configFields.find((f) => f.key === "enabled");
      expect(enabledField).toBeDefined();
      expect(enabledField!.type).toBe("toggle");
    }
  });

  it("select fields have options array", () => {
    for (const guard of GUARD_REGISTRY) {
      for (const field of guard.configFields) {
        if (field.type === "select") {
          expect(Array.isArray(field.options)).toBe(true);
          expect(field.options!.length).toBeGreaterThan(0);
          for (const opt of field.options!) {
            expect(opt.value).toBeTruthy();
            expect(opt.label).toBeTruthy();
          }
        }
      }
    }
  });

  it("number_slider fields have min, max, step", () => {
    for (const guard of GUARD_REGISTRY) {
      for (const field of guard.configFields) {
        if (field.type === "number_slider") {
          expect(field.min).toBeDefined();
          expect(field.max).toBeDefined();
          expect(field.step).toBeDefined();
          expect(field.max!).toBeGreaterThan(field.min!);
        }
      }
    }
  });
});

// ---------------------------------------------------------------------------
// getGuardMeta
// ---------------------------------------------------------------------------

describe("getGuardMeta", () => {
  it("returns correct guard for each known ID", () => {
    for (const guard of GUARD_REGISTRY) {
      const meta = getGuardMeta(guard.id);
      expect(meta).toBeDefined();
      expect(meta!.id).toBe(guard.id);
      expect(meta!.name).toBe(guard.name);
      expect(meta!.technicalName).toBe(guard.technicalName);
    }
  });

  it("returns undefined for unknown ID", () => {
    expect(getGuardMeta("nonexistent")).toBeUndefined();
    expect(getGuardMeta("")).toBeUndefined();
  });

  it("returns the ForbiddenPathGuard for forbidden_path", () => {
    const meta = getGuardMeta("forbidden_path");
    expect(meta).toBeDefined();
    expect(meta!.technicalName).toBe("ForbiddenPathGuard");
    expect(meta!.category).toBe("filesystem");
  });

  it("returns the SpiderSenseGuard for spider_sense", () => {
    const meta = getGuardMeta("spider_sense");
    expect(meta).toBeDefined();
    expect(meta!.technicalName).toBe("SpiderSenseGuard");
    expect(meta!.category).toBe("detection");
  });
});

// ---------------------------------------------------------------------------
// GUARD_CATEGORIES
// ---------------------------------------------------------------------------

describe("GUARD_CATEGORIES", () => {
  it("has 6 categories", () => {
    expect(GUARD_CATEGORIES).toHaveLength(6);
  });

  it("covers all guard IDs", () => {
    const allGuardIdsInCategories = GUARD_CATEGORIES.flatMap((c) => c.guards);
    const registryIds = GUARD_REGISTRY.map((g) => g.id);
    for (const id of registryIds) {
      expect(allGuardIdsInCategories).toContain(id);
    }
  });

  it("has no duplicate guard IDs across categories", () => {
    const allGuardIds = GUARD_CATEGORIES.flatMap((c) => c.guards);
    const unique = new Set(allGuardIds);
    expect(unique.size).toBe(allGuardIds.length);
  });

  it("all guard IDs in categories are valid registered guards", () => {
    const registryIds = new Set(GUARD_REGISTRY.map((g) => g.id));
    for (const cat of GUARD_CATEGORIES) {
      for (const guardId of cat.guards) {
        expect(registryIds.has(guardId as GuardId)).toBe(true);
      }
    }
  });

  it("each category has a label", () => {
    for (const cat of GUARD_CATEGORIES) {
      expect(cat.label).toBeTruthy();
      expect(cat.id).toBeTruthy();
    }
  });

  it("guard categories match the category field in guard meta", () => {
    for (const cat of GUARD_CATEGORIES) {
      for (const guardId of cat.guards) {
        const meta = getGuardMeta(guardId);
        expect(meta).toBeDefined();
        expect(meta!.category).toBe(cat.id);
      }
    }
  });
});
