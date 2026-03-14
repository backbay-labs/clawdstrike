import { describe, it, expect, beforeEach, afterEach } from "vitest";
import "fake-indexeddb/auto";
import {
  VersionStore,
  isValidTagName,
  escapeMd,
} from "../version-store";
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


let store: VersionStore;

beforeEach(async () => {
  // fake-indexeddb/auto shims globalThis.indexedDB.
  // Each test gets a fresh VersionStore + fresh DB by deleting all databases.
  // Deleting databases between tests ensures isolation.
  const dbs = await indexedDB.databases();
  for (const db of dbs) {
    if (db.name) indexedDB.deleteDatabase(db.name);
  }

  store = new VersionStore();
  await store.init();
});

afterEach(() => {
  store.close();
});


describe("saveVersion", () => {
  it("creates a version with version number 1 for a new policy", async () => {
    const policy = makePolicy({ name: "First" });
    const v = await store.saveVersion("pol-1", "yaml: content", policy, "initial");

    expect(v.policyId).toBe("pol-1");
    expect(v.version).toBe(1);
    expect(v.yaml).toBe("yaml: content");
    expect(v.policy.name).toBe("First");
    expect(v.message).toBe("initial");
    expect(v.tags).toEqual([]);
    expect(v.parentId).toBeNull();
    expect(v.hash).toBeTruthy();
    expect(v.id).toBeTruthy();
    expect(v.createdAt).toBeTruthy();
  });

  it("increments version number on successive saves", async () => {
    const policy = makePolicy();
    const v1 = await store.saveVersion("pol-1", "yaml-v1", policy);
    const v2 = await store.saveVersion("pol-1", "yaml-v2", policy);

    expect(v1.version).toBe(1);
    expect(v2.version).toBe(2);
    expect(v2.parentId).toBe(v1.id);
  });

  it("deduplicates when content hash is the same", async () => {
    const policy = makePolicy();
    const v1 = await store.saveVersion("pol-1", "same-yaml", policy);
    const v2 = await store.saveVersion("pol-1", "same-yaml", policy);

    // Dedup: should return the existing version, not create a new one
    expect(v2.id).toBe(v1.id);
    expect(v2.version).toBe(1);

    const count = await store.getVersionCount("pol-1");
    expect(count).toBe(1);
  });

  it("creates a new version when content differs", async () => {
    const policy = makePolicy();
    await store.saveVersion("pol-1", "yaml-a", policy);
    await store.saveVersion("pol-1", "yaml-b", policy);

    const count = await store.getVersionCount("pol-1");
    expect(count).toBe(2);
  });

  it("auto-prunes old versions beyond keepCount (50)", async () => {
    const policy = makePolicy();

    // Create 55 versions (each with different YAML to avoid dedup)
    for (let i = 0; i < 55; i++) {
      await store.saveVersion("pol-prune", `yaml-${i}`, policy);
    }

    // The auto-prune in saveVersion keeps 50, so 5 should be deleted
    const count = await store.getVersionCount("pol-prune");
    expect(count).toBe(50);
  });

  it("sanitizes sensitive fields before writing versions to IndexedDB", async () => {
    const yaml = `version: "1.4.0"
name: "Sensitive Policy"
guards:
  spider_sense:
    enabled: true
    embedding_api_key: "super-secret"
`;
    const policy = makePolicy({
      name: "Sensitive Policy",
      guards: {
        spider_sense: {
          enabled: true,
          embedding_api_key: "super-secret",
        },
      },
    });

    const version = await store.saveVersion("pol-sensitive", yaml, policy);

    expect(version.yaml).not.toContain("embedding_api_key");
    expect(JSON.stringify(version.policy)).not.toContain("super-secret");
    expect(version.sensitiveFieldsStripped).toBe(true);
  });

  it("sanitizes fallback policy objects when sanitized yaml cannot be reparsed", async () => {
    const yaml = `version: "1.4.0"
name: "Sensitive Policy"
guards:
  spider_sense:
    enabled: true
    embedding_api_key: "super-secret"
  broken: [unterminated
`;
    const policy = makePolicy({
      name: "Sensitive Policy",
      guards: {
        spider_sense: {
          enabled: true,
          embedding_api_key: "super-secret",
        },
      },
    });

    const version = await store.saveVersion("pol-sensitive-invalid", yaml, policy);

    expect(version.yaml).not.toContain("embedding_api_key");
    expect(JSON.stringify(version.policy)).not.toContain("super-secret");
    expect(version.sensitiveFieldsStripped).toBe(true);
  });
});


describe("getVersion", () => {
  it("returns a saved version by ID", async () => {
    const policy = makePolicy({ name: "Lookup" });
    const saved = await store.saveVersion("pol-1", "yaml-test", policy);

    const retrieved = await store.getVersion(saved.id);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.id).toBe(saved.id);
    expect(retrieved!.policy.name).toBe("Lookup");
  });

  it("returns null for a missing ID", async () => {
    const result = await store.getVersion("nonexistent-id");
    expect(result).toBeNull();
  });
});


describe("getVersions", () => {
  it("returns versions for a specific policy sorted by version desc", async () => {
    const policy = makePolicy();
    await store.saveVersion("pol-1", "yaml-1", policy);
    await store.saveVersion("pol-1", "yaml-2", policy);
    await store.saveVersion("pol-1", "yaml-3", policy);

    const versions = await store.getVersions("pol-1");
    expect(versions).toHaveLength(3);
    // Most recent first
    expect(versions[0].version).toBe(3);
    expect(versions[1].version).toBe(2);
    expect(versions[2].version).toBe(1);
  });

  it("does not return versions from other policies", async () => {
    const policy = makePolicy();
    await store.saveVersion("pol-1", "yaml-a", policy);
    await store.saveVersion("pol-2", "yaml-b", policy);

    const versions = await store.getVersions("pol-1");
    expect(versions).toHaveLength(1);
    expect(versions[0].policyId).toBe("pol-1");
  });

  it("respects limit parameter", async () => {
    const policy = makePolicy();
    for (let i = 0; i < 5; i++) {
      await store.saveVersion("pol-1", `yaml-${i}`, policy);
    }

    const versions = await store.getVersions("pol-1", 2);
    expect(versions).toHaveLength(2);
    expect(versions[0].version).toBe(5);
    expect(versions[1].version).toBe(4);
  });

  it("respects offset parameter", async () => {
    const policy = makePolicy();
    for (let i = 0; i < 5; i++) {
      await store.saveVersion("pol-1", `yaml-${i}`, policy);
    }

    // Skip first 2 (versions 5 and 4), get next
    const versions = await store.getVersions("pol-1", 20, 2);
    expect(versions).toHaveLength(3);
    expect(versions[0].version).toBe(3);
  });
});


describe("addTag", () => {
  it("adds a tag to a version", async () => {
    const policy = makePolicy();
    const v = await store.saveVersion("pol-1", "yaml-1", policy);

    await store.addTag(v.id, "release-v1");

    const updated = await store.getVersion(v.id);
    expect(updated!.tags).toContain("release-v1");
  });

  it("does not duplicate tags if added twice", async () => {
    const policy = makePolicy();
    const v = await store.saveVersion("pol-1", "yaml-1", policy);

    await store.addTag(v.id, "stable");
    await store.addTag(v.id, "stable");

    const updated = await store.getVersion(v.id);
    expect(updated!.tags.filter((t) => t === "stable")).toHaveLength(1);
  });

  it("throws on invalid tag name", async () => {
    const policy = makePolicy();
    const v = await store.saveVersion("pol-1", "yaml-1", policy);

    await expect(store.addTag(v.id, "")).rejects.toThrow("Invalid tag name");
    await expect(store.addTag(v.id, "has spaces")).rejects.toThrow("Invalid tag name");
    await expect(store.addTag(v.id, "a".repeat(31))).rejects.toThrow("Invalid tag name");
  });

  it("throws when version does not exist", async () => {
    await expect(store.addTag("nonexistent-id", "release")).rejects.toThrow("not found");
  });
});

describe("removeTag", () => {
  it("removes a tag from a version", async () => {
    const policy = makePolicy();
    const v = await store.saveVersion("pol-1", "yaml-1", policy);

    await store.addTag(v.id, "release");
    await store.removeTag(v.id, "release");

    const updated = await store.getVersion(v.id);
    expect(updated!.tags).not.toContain("release");
  });

  it("is a no-op when version does not exist", async () => {
    // Should not throw
    await expect(store.removeTag("nonexistent-id", "release")).resolves.toBeUndefined();
  });

  it("is a no-op when tag is not present", async () => {
    const policy = makePolicy();
    const v = await store.saveVersion("pol-1", "yaml-1", policy);

    await store.removeTag(v.id, "not-there");
    const updated = await store.getVersion(v.id);
    expect(updated!.tags).toEqual([]);
  });
});


describe("deleteOldVersions", () => {
  it("keeps recent versions and deletes old untagged ones", async () => {
    const policy = makePolicy();
    for (let i = 0; i < 10; i++) {
      await store.saveVersion("pol-del", `yaml-${i}`, policy);
    }

    await store.deleteOldVersions("pol-del", 3);

    const remaining = await store.getVersions("pol-del", 100);
    expect(remaining).toHaveLength(3);
    // Kept the 3 most recent
    expect(remaining[0].version).toBe(10);
    expect(remaining[1].version).toBe(9);
    expect(remaining[2].version).toBe(8);
  });

  it("preserves tagged versions even beyond keepCount", async () => {
    const policy = makePolicy();
    const versions = [];
    for (let i = 0; i < 5; i++) {
      versions.push(await store.saveVersion("pol-tag", `yaml-${i}`, policy));
    }

    // Tag version 1 (the oldest)
    await store.addTag(versions[0].id, "important");

    // Keep only 2
    await store.deleteOldVersions("pol-tag", 2);

    const remaining = await store.getVersions("pol-tag", 100);
    // Kept: versions 5, 4 (recent) + version 1 (tagged) = 3
    expect(remaining).toHaveLength(3);

    const versionNums = remaining.map((v) => v.version).sort((a, b) => a - b);
    expect(versionNums).toContain(1); // tagged, preserved
    expect(versionNums).toContain(5);
    expect(versionNums).toContain(4);
  });
});


describe("exportChangelog", () => {
  it("returns placeholder when no versions exist", async () => {
    const md = await store.exportChangelog("empty-pol");
    expect(md).toContain("No versions recorded");
  });

  it("produces markdown with version headings", async () => {
    const policy = makePolicy({ name: "My Policy", guards: { shell_command: { enabled: true } } });
    await store.saveVersion("pol-md", "yaml-1", policy, "First version");
    await store.saveVersion("pol-md", "yaml-2", policy, "Second version");

    const md = await store.exportChangelog("pol-md");
    expect(md).toContain("# Changelog:");
    expect(md).toContain("My Policy");
    expect(md).toContain("## v2");
    expect(md).toContain("## v1");
    expect(md).toContain("First version");
    expect(md).toContain("Second version");
    expect(md).toContain("Hash:");
    expect(md).toContain("Schema: 1.2.0");
    expect(md).toContain("Guards: shell_command");
  });

  it("includes tags in the heading", async () => {
    const policy = makePolicy({ name: "Tagged" });
    const v = await store.saveVersion("pol-tag-md", "yaml-1", policy);
    await store.addTag(v.id, "release");

    const md = await store.exportChangelog("pol-tag-md");
    expect(md).toContain("[release]");
  });

  it("escapes markdown special characters in policy names", async () => {
    const policy = makePolicy({ name: "My *bold* [link] #heading" });
    await store.saveVersion("pol-escape", "yaml-1", policy);

    const md = await store.exportChangelog("pol-escape");
    expect(md).toContain("\\*bold\\*");
    expect(md).toContain("\\[link\\]");
    expect(md).toContain("\\#heading");
  });
});


describe("escapeMd", () => {
  it("escapes markdown special characters", () => {
    expect(escapeMd("#heading")).toBe("\\#heading");
    expect(escapeMd("*bold*")).toBe("\\*bold\\*");
    expect(escapeMd("_italic_")).toBe("\\_italic\\_");
    expect(escapeMd("[link]")).toBe("\\[link\\]");
    expect(escapeMd("`code`")).toBe("\\`code\\`");
    expect(escapeMd("|table|")).toBe("\\|table\\|");
    expect(escapeMd("~strike~")).toBe("\\~strike\\~");
    expect(escapeMd("\\backslash")).toBe("\\\\backslash");
    expect(escapeMd(">quote")).toBe("\\>quote");
  });

  it("leaves normal text unchanged", () => {
    expect(escapeMd("Hello World 123")).toBe("Hello World 123");
  });

  it("escapes multiple special characters in one string", () => {
    const result = escapeMd("# Title *bold* [link](url)");
    expect(result).toContain("\\#");
    expect(result).toContain("\\*");
    expect(result).toContain("\\[");
    expect(result).toContain("\\]");
  });
});


describe("isValidTagName", () => {
  it("accepts valid alphanumeric tags", () => {
    expect(isValidTagName("release-v1")).toBe(true);
    expect(isValidTagName("v1.0.0")).toBe(true);
    expect(isValidTagName("stable_build")).toBe(true);
    expect(isValidTagName("a")).toBe(true);
    expect(isValidTagName("A123")).toBe(true);
  });

  it("rejects empty string", () => {
    expect(isValidTagName("")).toBe(false);
  });

  it("rejects tags starting with non-alphanumeric", () => {
    expect(isValidTagName("-release")).toBe(false);
    expect(isValidTagName(".hidden")).toBe(false);
    expect(isValidTagName("_underscore")).toBe(false);
  });

  it("rejects tags longer than 30 characters", () => {
    expect(isValidTagName("a".repeat(31))).toBe(false);
    expect(isValidTagName("a".repeat(30))).toBe(true);
  });

  it("rejects tags with spaces or special characters", () => {
    expect(isValidTagName("has spaces")).toBe(false);
    expect(isValidTagName("no@symbols")).toBe(false);
    expect(isValidTagName("no#hash")).toBe(false);
  });
});


describe("VersionStore not initialized", () => {
  it("throws when calling methods before init", async () => {
    const uninitStore = new VersionStore();
    await expect(
      uninitStore.saveVersion("pol-1", "yaml", makePolicy()),
    ).rejects.toThrow("not initialized");
  });
});
