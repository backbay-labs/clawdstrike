import { describe, expect, it } from "vitest";

import { selectLatestRuns, type StoredTestRun } from "../test-history-store";

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
