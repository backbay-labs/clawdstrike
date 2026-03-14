import { describe, it, expect } from "vitest";
import {
  diffVersions,
  generateChangeSummary,
  compactChangeSummary,
  deepEqual,
  canonicalStringify,
  countArrayDiff,
} from "../version-diff";
import type { WorkbenchPolicy } from "../types";


function makePolicy(overrides?: Partial<WorkbenchPolicy>): WorkbenchPolicy {
  return {
    version: "1.2.0",
    name: "test-policy",
    description: "A test policy",
    guards: {},
    settings: {},
    ...overrides,
  };
}


describe("deepEqual", () => {
  it("returns true for identical primitives", () => {
    expect(deepEqual(1, 1)).toBe(true);
    expect(deepEqual("abc", "abc")).toBe(true);
    expect(deepEqual(true, true)).toBe(true);
    expect(deepEqual(null, null)).toBe(true);
    expect(deepEqual(undefined, undefined)).toBe(true);
  });

  it("returns false for different types", () => {
    expect(deepEqual(1, "1")).toBe(false);
    expect(deepEqual(null, undefined)).toBe(false);
    expect(deepEqual(0, false)).toBe(false);
    expect(deepEqual("", false)).toBe(false);
  });

  it("treats objects with same keys in different order as equal", () => {
    const a = { x: 1, y: 2, z: 3 };
    const b = { z: 3, x: 1, y: 2 };
    expect(deepEqual(a, b)).toBe(true);
  });

  it("compares nested objects recursively", () => {
    const a = { outer: { inner: { deep: "value" } } };
    const b = { outer: { inner: { deep: "value" } } };
    expect(deepEqual(a, b)).toBe(true);

    const c = { outer: { inner: { deep: "other" } } };
    expect(deepEqual(a, c)).toBe(false);
  });

  it("compares arrays element by element", () => {
    expect(deepEqual([1, 2, 3], [1, 2, 3])).toBe(true);
    expect(deepEqual([1, 2, 3], [1, 3, 2])).toBe(false);
    expect(deepEqual([1, 2], [1, 2, 3])).toBe(false);
  });

  it("returns false for null vs object", () => {
    expect(deepEqual(null, {})).toBe(false);
    expect(deepEqual({}, null)).toBe(false);
  });

  it("handles empty objects and arrays", () => {
    expect(deepEqual({}, {})).toBe(true);
    expect(deepEqual([], [])).toBe(true);
    expect(deepEqual({}, [])).toBe(false);
    expect(deepEqual([], {})).toBe(false);
  });

  it("handles NaN equality (uses ===, so NaN !== NaN)", () => {
    // NaN === NaN is false in JS, and deepEqual uses ===
    expect(deepEqual(NaN, NaN)).toBe(false);
  });

  it("handles objects with extra keys in one side", () => {
    const a = { x: 1 };
    const b = { x: 1, y: 2 };
    expect(deepEqual(a, b)).toBe(false);
  });

  it("handles arrays of objects", () => {
    const a = [{ name: "a" }, { name: "b" }];
    const b = [{ name: "a" }, { name: "b" }];
    expect(deepEqual(a, b)).toBe(true);

    const c = [{ name: "b" }, { name: "a" }];
    expect(deepEqual(a, c)).toBe(false);
  });

  it("distinguishes array from non-array", () => {
    expect(deepEqual([1], { 0: 1 })).toBe(false);
  });
});


describe("countArrayDiff", () => {
  it("returns zero diffs for identical arrays", () => {
    expect(countArrayDiff(["a", "b"], ["a", "b"])).toEqual({ added: 0, removed: 0 });
  });

  it("detects added elements", () => {
    expect(countArrayDiff(["a"], ["a", "b", "c"])).toEqual({ added: 2, removed: 0 });
  });

  it("detects removed elements", () => {
    expect(countArrayDiff(["a", "b", "c"], ["a"])).toEqual({ added: 0, removed: 2 });
  });

  it("handles same elements in different order", () => {
    // countArrayDiff uses Set, so same elements in different order => no diff
    expect(countArrayDiff(["a", "b", "c"], ["c", "a", "b"])).toEqual({ added: 0, removed: 0 });
  });

  it("handles both added and removed", () => {
    expect(countArrayDiff(["a", "b"], ["b", "c"])).toEqual({ added: 1, removed: 1 });
  });

  it("handles undefined before/after", () => {
    expect(countArrayDiff(undefined, ["a", "b"])).toEqual({ added: 2, removed: 0 });
    expect(countArrayDiff(["a", "b"], undefined)).toEqual({ added: 0, removed: 2 });
    expect(countArrayDiff(undefined, undefined)).toEqual({ added: 0, removed: 0 });
  });

  it("deduplicates with Set (duplicates are collapsed)", () => {
    // ["a", "a"] becomes Set(["a"]) internally
    expect(countArrayDiff(["a"], ["a", "a"])).toEqual({ added: 0, removed: 0 });
  });

  it("handles arrays of objects using canonicalStringify", () => {
    const before = [{ name: "x", val: 1 }];
    const after = [{ name: "x", val: 1 }, { name: "y", val: 2 }];
    expect(countArrayDiff(before, after)).toEqual({ added: 1, removed: 0 });
  });

  it("treats objects with different key order as equal", () => {
    const before = [{ a: 1, b: 2 }];
    const after = [{ b: 2, a: 1 }];
    expect(countArrayDiff(before, after)).toEqual({ added: 0, removed: 0 });
  });
});


describe("canonicalStringify", () => {
  it("sorts object keys alphabetically", () => {
    const result = canonicalStringify({ z: 1, a: 2, m: 3 });
    expect(result).toBe('{"a":2,"m":3,"z":1}');
  });

  it("produces same output for objects with different key order", () => {
    const a = canonicalStringify({ x: 1, y: 2 });
    const b = canonicalStringify({ y: 2, x: 1 });
    expect(a).toBe(b);
  });

  it("sorts nested objects recursively", () => {
    const result = canonicalStringify({ b: { d: 1, c: 2 }, a: 3 });
    expect(result).toBe('{"a":3,"b":{"c":2,"d":1}}');
  });

  it("handles arrays (preserves order, does not sort elements)", () => {
    const result = canonicalStringify([3, 1, 2]);
    expect(result).toBe("[3,1,2]");
  });

  it("handles null", () => {
    expect(canonicalStringify(null)).toBe("null");
  });

  it("handles primitives", () => {
    expect(canonicalStringify("hello")).toBe('"hello"');
    expect(canonicalStringify(42)).toBe("42");
    expect(canonicalStringify(true)).toBe("true");
    expect(canonicalStringify(false)).toBe("false");
  });

  it("handles nested arrays within objects", () => {
    const result = canonicalStringify({ b: [1, 2], a: "x" });
    expect(result).toBe('{"a":"x","b":[1,2]}');
  });

  it("handles empty object and empty array", () => {
    expect(canonicalStringify({})).toBe("{}");
    expect(canonicalStringify([])).toBe("[]");
  });
});


describe("diffVersions", () => {
  it("detects guard added", () => {
    const from = makePolicy({ guards: {} });
    const to = makePolicy({
      guards: {
        forbidden_path: { enabled: true, patterns: ["**/.ssh/**"] },
      },
    });

    const diff = diffVersions(from, to, 1, 2);
    expect(diff.fromVersion).toBe(1);
    expect(diff.toVersion).toBe(2);
    expect(diff.changes.length).toBe(1);
    expect(diff.changes[0].type).toBe("added");
    expect(diff.changes[0].category).toBe("guard");
    expect(diff.changes[0].path).toBe("guards.forbidden_path");
    expect(diff.changes[0].description).toContain("Forbidden Path");
    expect(diff.changes[0].description).toContain("enabled");
  });

  it("detects guard added (disabled)", () => {
    const from = makePolicy({ guards: {} });
    const to = makePolicy({
      guards: {
        shell_command: { enabled: false },
      },
    });

    const diff = diffVersions(from, to);
    expect(diff.changes[0].type).toBe("added");
    expect(diff.changes[0].description).toContain("disabled");
  });

  it("detects guard removed", () => {
    const from = makePolicy({
      guards: {
        egress_allowlist: { enabled: true, allow: ["*.example.com"] },
      },
    });
    const to = makePolicy({ guards: {} });

    const diff = diffVersions(from, to);
    expect(diff.changes.length).toBe(1);
    expect(diff.changes[0].type).toBe("removed");
    expect(diff.changes[0].category).toBe("guard");
    expect(diff.changes[0].path).toBe("guards.egress_allowlist");
    expect(diff.changes[0].description).toContain("Egress Allowlist");
  });

  it("detects guard modified — enabled toggled", () => {
    const from = makePolicy({
      guards: { shell_command: { enabled: true } },
    });
    const to = makePolicy({
      guards: { shell_command: { enabled: false } },
    });

    const diff = diffVersions(from, to);
    expect(diff.changes.length).toBe(1);
    expect(diff.changes[0].type).toBe("modified");
    expect(diff.changes[0].category).toBe("guard");
    expect(diff.changes[0].description).toContain("disabled");
  });

  it("detects guard modified — config changed", () => {
    const from = makePolicy({
      guards: {
        forbidden_path: { enabled: true, patterns: ["**/.ssh/**"] },
      },
    });
    const to = makePolicy({
      guards: {
        forbidden_path: { enabled: true, patterns: ["**/.ssh/**", "/etc/shadow"] },
      },
    });

    const diff = diffVersions(from, to);
    expect(diff.changes.length).toBe(1);
    expect(diff.changes[0].type).toBe("modified");
    expect(diff.changes[0].description).toContain("patterns");
    expect(diff.changes[0].description).toContain("+1");
  });

  it("detects metadata changes — name", () => {
    const from = makePolicy({ name: "old-name" });
    const to = makePolicy({ name: "new-name" });

    const diff = diffVersions(from, to);
    const metaChange = diff.changes.find((c) => c.path === "name");
    expect(metaChange).toBeDefined();
    expect(metaChange!.type).toBe("modified");
    expect(metaChange!.category).toBe("meta");
    expect(metaChange!.description).toContain("old-name");
    expect(metaChange!.description).toContain("new-name");
  });

  it("detects metadata changes — description", () => {
    const from = makePolicy({ description: "old desc" });
    const to = makePolicy({ description: "new desc" });

    const diff = diffVersions(from, to);
    const descChange = diff.changes.find((c) => c.path === "description");
    expect(descChange).toBeDefined();
    expect(descChange!.category).toBe("meta");
    expect(descChange!.description).toContain("Description changed");
  });

  it("detects metadata changes — schema version", () => {
    const from = makePolicy({ version: "1.2.0" });
    const to = makePolicy({ version: "1.3.0" });

    const diff = diffVersions(from, to);
    const verChange = diff.changes.find((c) => c.path === "version");
    expect(verChange).toBeDefined();
    expect(verChange!.description).toContain("1.2.0");
    expect(verChange!.description).toContain("1.3.0");
  });

  it("returns no changes for identical policies", () => {
    const policy = makePolicy({
      guards: { shell_command: { enabled: true } },
      settings: { fail_fast: true },
    });

    const diff = diffVersions(policy, policy);
    expect(diff.changes).toHaveLength(0);
    expect(diff.summary).toBe("No changes");
  });

  it("detects extends added", () => {
    const from = makePolicy();
    const to = makePolicy({ extends: "strict" });

    const diff = diffVersions(from, to);
    const extChange = diff.changes.find((c) => c.path === "extends");
    expect(extChange).toBeDefined();
    expect(extChange!.type).toBe("added");
    expect(extChange!.category).toBe("extends");
    expect(extChange!.description).toContain("strict");
  });

  it("detects extends removed", () => {
    const from = makePolicy({ extends: "strict" });
    const to = makePolicy();

    const diff = diffVersions(from, to);
    const extChange = diff.changes.find((c) => c.path === "extends");
    expect(extChange).toBeDefined();
    expect(extChange!.type).toBe("removed");
  });

  it("detects extends modified", () => {
    const from = makePolicy({ extends: "permissive" });
    const to = makePolicy({ extends: "strict" });

    const diff = diffVersions(from, to);
    const extChange = diff.changes.find((c) => c.path === "extends");
    expect(extChange).toBeDefined();
    expect(extChange!.type).toBe("modified");
    expect(extChange!.description).toContain("permissive");
    expect(extChange!.description).toContain("strict");
  });

  it("detects posture added", () => {
    const from = makePolicy();
    const to = makePolicy({
      posture: { initial: "normal", states: { normal: {} } },
    });

    const diff = diffVersions(from, to);
    const postureChange = diff.changes.find((c) => c.path === "posture");
    expect(postureChange).toBeDefined();
    expect(postureChange!.type).toBe("added");
    expect(postureChange!.category).toBe("posture");
  });

  it("detects origins added", () => {
    const from = makePolicy();
    const to = makePolicy({
      origins: {
        default_behavior: "deny",
        profiles: [
          { id: "slack-default", match_rules: { provider: "slack" } },
        ],
      },
    });

    const diff = diffVersions(from, to);
    const originChange = diff.changes.find((c) => c.path === "origins");
    expect(originChange).toBeDefined();
    expect(originChange!.type).toBe("added");
    expect(originChange!.category).toBe("origin");
    expect(originChange!.description).toContain("1 profile");
  });

  it("detects settings modified", () => {
    const from = makePolicy({ settings: { fail_fast: false } });
    const to = makePolicy({ settings: { fail_fast: true } });

    const diff = diffVersions(from, to);
    const settingChange = diff.changes.find((c) => c.path === "settings.fail_fast");
    expect(settingChange).toBeDefined();
    expect(settingChange!.type).toBe("modified");
    expect(settingChange!.category).toBe("setting");
  });

  it("detects setting added and removed", () => {
    const from = makePolicy({ settings: { fail_fast: true } });
    const to = makePolicy({ settings: { session_timeout_secs: 3600 } });

    const diff = diffVersions(from, to);
    const removed = diff.changes.find((c) => c.path === "settings.fail_fast");
    const added = diff.changes.find((c) => c.path === "settings.session_timeout_secs");
    expect(removed).toBeDefined();
    expect(removed!.type).toBe("removed");
    expect(added).toBeDefined();
    expect(added!.type).toBe("added");
  });
});


describe("generateChangeSummary", () => {
  it("returns 'No changes' for empty changes", () => {
    const result = generateChangeSummary({
      fromVersion: 1,
      toVersion: 2,
      changes: [],
      summary: "",
    });
    expect(result).toBe("No changes");
  });

  it("summarizes guard changes", () => {
    const from = makePolicy({ guards: {} });
    const to = makePolicy({
      guards: {
        forbidden_path: { enabled: true },
        shell_command: { enabled: true },
      },
    });

    const diff = diffVersions(from, to);
    expect(diff.summary).toContain("+2");
    expect(diff.summary).toContain("guard");
  });
});


describe("compactChangeSummary", () => {
  it("returns empty string for empty changes", () => {
    expect(compactChangeSummary([])).toBe("");
  });

  it("counts guard additions", () => {
    const diff = diffVersions(
      makePolicy({ guards: {} }),
      makePolicy({
        guards: {
          forbidden_path: { enabled: true },
          shell_command: { enabled: true },
        },
      }),
    );
    const summary = compactChangeSummary(diff.changes);
    expect(summary).toContain("+2");
    expect(summary).toContain("guard");
  });

  it("shows setting changes", () => {
    const diff = diffVersions(
      makePolicy({ settings: {} }),
      makePolicy({ settings: { fail_fast: true, session_timeout_secs: 60 } }),
    );
    const summary = compactChangeSummary(diff.changes);
    expect(summary).toContain("setting");
  });

  it("shows meta changes", () => {
    const diff = diffVersions(
      makePolicy({ name: "old" }),
      makePolicy({ name: "new" }),
    );
    const summary = compactChangeSummary(diff.changes);
    expect(summary).toContain("meta");
  });
});
