import { afterEach, beforeEach, describe, expect, it } from "vitest";
import "fake-indexeddb/auto";

import { SdkScriptStore, type StoredScript } from "../sdk-script-store";

function makeScript(
  id: string,
  policyId: string,
  updatedAt: string,
  framework: StoredScript["framework"] = "python-sdk",
): StoredScript {
  return {
    id,
    policyId,
    framework,
    name: id,
    content: `print("${id}")`,
    language: "python",
    createdAt: updatedAt,
    updatedAt,
  };
}

describe("SdkScriptStore", () => {
  let store: SdkScriptStore;

  beforeEach(async () => {
    const dbs = await indexedDB.databases();
    for (const db of dbs) {
      if (db.name) indexedDB.deleteDatabase(db.name);
    }

    store = new SdkScriptStore();
    await store.init();
  });

  afterEach(() => {
    store.close();
  });

  it("loads scripts across stable and legacy policy IDs", async () => {
    await store.saveScript(makeScript("legacy", "policy-name", "2026-03-10T12:00:00.000Z"));
    await store.saveScript(makeScript("stable", "tab-1", "2026-03-11T12:00:00.000Z"));

    const scripts = await store.getScriptsByFrameworkForPolicies(
      ["tab-1", "policy-name"],
      "python-sdk",
    );

    expect(scripts.map((script) => script.id)).toEqual(["stable", "legacy"]);
  });
});
