import { describe, it, expect, afterEach } from "vitest";
import {
  GUARD_REGISTRY,
  getGuardMeta,
  GUARD_CATEGORIES,
  ALL_GUARD_IDS,
  GUARD_DISPLAY_NAMES,
  BUILTIN_GUARDS,
  getAllGuards,
  getAllGuardIds,
  getGuardDisplayNames,
  getGuardCategories,
  registerGuard,
  unregisterGuard,
  registerGuardCategory,
} from "../guard-registry";
import type { GuardMeta } from "../types";
import { BUILTIN_GUARD_IDS } from "../types";


describe("GUARD_REGISTRY", () => {
  it("contains exactly 13 guards", () => {
    expect(GUARD_REGISTRY).toHaveLength(13);
  });

  const expectedIds: string[] = [
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
          "json",
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


describe("BUILTIN_GUARDS", () => {
  it("matches the 13 built-in guard IDs from types.ts", () => {
    const builtinIds = BUILTIN_GUARDS.map((g) => g.id);
    expect(builtinIds).toEqual([...BUILTIN_GUARD_IDS]);
  });
});


describe("getAllGuards / getAllGuardIds", () => {
  it("getAllGuards returns same guards as GUARD_REGISTRY proxy", () => {
    const all = getAllGuards();
    expect(all).toHaveLength(GUARD_REGISTRY.length);
    for (const guard of all) {
      expect(GUARD_REGISTRY.some((g) => g.id === guard.id)).toBe(true);
    }
  });

  it("getAllGuardIds returns same IDs as ALL_GUARD_IDS proxy", () => {
    const ids = getAllGuardIds();
    expect(ids).toHaveLength(ALL_GUARD_IDS.length);
    for (const id of ids) {
      expect(ALL_GUARD_IDS.includes(id)).toBe(true);
    }
  });
});


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


describe("GUARD_CATEGORIES", () => {
  it("has 6 categories", () => {
    expect(GUARD_CATEGORIES).toHaveLength(6);
  });

  it("covers all built-in guard IDs", () => {
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
        expect(registryIds.has(guardId)).toBe(true);
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


describe("GUARD_DISPLAY_NAMES", () => {
  it("has entries for all built-in guards", () => {
    for (const guard of GUARD_REGISTRY) {
      expect(GUARD_DISPLAY_NAMES[guard.id]).toBe(guard.name);
    }
  });

  it("returns undefined for unknown guard", () => {
    expect(GUARD_DISPLAY_NAMES["nonexistent"]).toBeUndefined();
  });

  it("getGuardDisplayNames returns same data", () => {
    const names = getGuardDisplayNames();
    for (const guard of GUARD_REGISTRY) {
      expect(names[guard.id]).toBe(guard.name);
    }
  });
});


describe("dynamic registration", () => {
  const makePluginGuard = (overrides: Partial<GuardMeta> = {}): GuardMeta => ({
    id: "my_custom_guard",
    name: "My Custom Guard",
    technicalName: "MyCustomGuard",
    description: "A custom plugin guard for testing.",
    category: "custom_category",
    defaultVerdict: "deny",
    icon: "IconPlugin",
    configFields: [
      { key: "enabled", label: "Enabled", type: "toggle", defaultValue: true },
    ],
    ...overrides,
  });

  afterEach(() => {
    // Clean up any registered test guards
    unregisterGuard("my_custom_guard");
    unregisterGuard("another_custom_guard");
    unregisterGuard("json_config_guard");
  });

  it("registerGuard adds a custom guard visible in getAllGuards and getGuardMeta", () => {
    const guard = makePluginGuard();
    const dispose = registerGuard(guard);

    expect(getAllGuards()).toHaveLength(14);
    expect(getGuardMeta("my_custom_guard")).toBeDefined();
    expect(getGuardMeta("my_custom_guard")!.name).toBe("My Custom Guard");

    dispose();
    expect(getAllGuards()).toHaveLength(13);
    expect(getGuardMeta("my_custom_guard")).toBeUndefined();
  });

  it("registerGuard returns a dispose function that removes the guard", () => {
    const guard = makePluginGuard();
    const dispose = registerGuard(guard);

    expect(GUARD_REGISTRY).toHaveLength(14);
    expect(GUARD_REGISTRY.some((g) => g.id === "my_custom_guard")).toBe(true);

    dispose();

    expect(GUARD_REGISTRY).toHaveLength(13);
    expect(GUARD_REGISTRY.some((g) => g.id === "my_custom_guard")).toBe(false);
  });

  it("registerGuard throws if guard ID already exists", () => {
    const guard = makePluginGuard();
    registerGuard(guard);

    expect(() => registerGuard(guard)).toThrow('Guard "my_custom_guard" is already registered');
  });

  it("registerGuard throws if registering a built-in guard ID", () => {
    const guard = makePluginGuard({ id: "forbidden_path" });
    expect(() => registerGuard(guard)).toThrow('Guard "forbidden_path" is already registered');
  });

  it("unregisterGuard removes a guard, no-op for unknown ID", () => {
    const guard = makePluginGuard();
    registerGuard(guard);
    expect(getGuardMeta("my_custom_guard")).toBeDefined();

    unregisterGuard("my_custom_guard");
    expect(getGuardMeta("my_custom_guard")).toBeUndefined();

    // No-op for unknown
    expect(() => unregisterGuard("totally_nonexistent")).not.toThrow();
  });

  it("custom guard with configFieldType 'json' is accepted", () => {
    const guard = makePluginGuard({
      id: "json_config_guard",
      configFields: [
        { key: "enabled", label: "Enabled", type: "toggle", defaultValue: true },
        { key: "custom_schema", label: "Custom Schema", type: "json", description: "Arbitrary JSON config" },
      ],
    });
    registerGuard(guard);

    const meta = getGuardMeta("json_config_guard");
    expect(meta).toBeDefined();
    const jsonField = meta!.configFields.find((f) => f.type === "json");
    expect(jsonField).toBeDefined();
    expect(jsonField!.key).toBe("custom_schema");
  });

  it("custom guard with custom category string is stored correctly", () => {
    const guard = makePluginGuard({ category: "threat_intel" });
    registerGuard(guard);

    const meta = getGuardMeta("my_custom_guard");
    expect(meta).toBeDefined();
    expect(meta!.category).toBe("threat_intel");

    // Category should be auto-created
    const categories = getGuardCategories();
    const newCat = categories.find((c) => c.id === "threat_intel");
    expect(newCat).toBeDefined();
    expect(newCat!.guards).toContain("my_custom_guard");
  });

  it("custom category is cleaned up when last guard is unregistered", () => {
    const guard = makePluginGuard({ category: "threat_intel" });
    const dispose = registerGuard(guard);

    expect(getGuardCategories().some((c) => c.id === "threat_intel")).toBe(true);

    dispose();

    expect(getGuardCategories().some((c) => c.id === "threat_intel")).toBe(false);
  });

  it("GUARD_REGISTRY proxy reflects dynamic changes", () => {
    const beforeLen = GUARD_REGISTRY.length;
    const guard = makePluginGuard();
    registerGuard(guard);

    expect(GUARD_REGISTRY.length).toBe(beforeLen + 1);
    expect(GUARD_REGISTRY.find((g) => g.id === "my_custom_guard")).toBeDefined();
  });

  it("ALL_GUARD_IDS proxy reflects dynamic changes", () => {
    const beforeLen = ALL_GUARD_IDS.length;
    registerGuard(makePluginGuard());

    expect(ALL_GUARD_IDS.length).toBe(beforeLen + 1);
    expect(ALL_GUARD_IDS.includes("my_custom_guard")).toBe(true);
  });

  it("GUARD_DISPLAY_NAMES proxy reflects dynamic changes", () => {
    registerGuard(makePluginGuard());

    expect(GUARD_DISPLAY_NAMES["my_custom_guard"]).toBe("My Custom Guard");
  });

  it("registerGuardCategory adds and removes custom categories", () => {
    const dispose = registerGuardCategory({ id: "monitoring", label: "Monitoring" });
    expect(getGuardCategories().some((c) => c.id === "monitoring")).toBe(true);

    dispose();
    expect(getGuardCategories().some((c) => c.id === "monitoring")).toBe(false);
  });

  it("registerGuardCategory is idempotent for existing categories", () => {
    const beforeLen = getGuardCategories().length;
    const dispose = registerGuardCategory({ id: "filesystem", label: "Filesystem" });

    expect(getGuardCategories().length).toBe(beforeLen);
    dispose(); // no-op
    expect(getGuardCategories().length).toBe(beforeLen);
  });
});
