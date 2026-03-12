import { afterEach, beforeEach, describe, expect, it } from "vitest";
import "fake-indexeddb/auto";

import {
  TestHistoryStore,
  selectLatestRuns,
  type StoredTestRun,
} from "../test-history-store";

function makeRun(id: string, timestamp: string): StoredTestRun {
  return {
    id,
    policyId: "policy-a",
    timestamp,
    total: 1,
    passed: 1,
    failed: 0,
    results: [],
  };
}

describe("selectLatestRuns", () => {
  it("sorts by timestamp before truncating to the recent limit", () => {
    const newest = makeRun("newest", "2026-03-11T12:00:00.000Z");
    const olderRuns = Array.from({ length: 60 }, (_, index) =>
      makeRun(
        `run-${index}`,
        `2026-03-${String((index % 9) + 1).padStart(2, "0")}T00:00:00.000Z`,
      ),
    );

    const selected = selectLatestRuns([olderRuns[0], newest, ...olderRuns], 50);

    expect(selected).toHaveLength(50);
    expect(selected[0]?.id).toBe("newest");
    expect(selected.some((run) => run.id === "run-59")).toBe(true);
  });
});

describe("TestHistoryStore", () => {
  let store: TestHistoryStore;

  beforeEach(async () => {
    const dbs = await indexedDB.databases();
    for (const db of dbs) {
      if (db.name) indexedDB.deleteDatabase(db.name);
    }

    store = new TestHistoryStore();
    await store.init();
  });

  afterEach(() => {
    store.close();
  });

  it("loads runs across stable and legacy policy IDs", async () => {
    await store.addRun(makeRun("legacy", "2026-03-10T12:00:00.000Z"));
    await store.addRun({
      ...makeRun("stable", "2026-03-11T12:00:00.000Z"),
      policyId: "tab-1",
    });

    const runs = await store.getRunsForPolicies(["tab-1", "policy-a"]);

    expect(runs.map((run) => run.id)).toEqual(["stable", "legacy"]);
  });

  it("clears runs across all policy ID aliases", async () => {
    await store.addRun(makeRun("legacy", "2026-03-10T12:00:00.000Z"));
    await store.addRun({
      ...makeRun("stable", "2026-03-11T12:00:00.000Z"),
      policyId: "tab-1",
    });

    await store.clearRunsForPolicies(["tab-1", "policy-a"]);

    expect(await store.getRunsForPolicies(["tab-1", "policy-a"])).toEqual([]);
  });
});
