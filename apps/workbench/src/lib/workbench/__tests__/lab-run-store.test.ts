import "fake-indexeddb/auto";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { LabRunStore } from "../detection-workflow/lab-run-store";
import type { LabRun } from "../detection-workflow/shared-types";

function makeRun(overrides: Partial<LabRun> = {}): LabRun {
  return {
    id: crypto.randomUUID(),
    documentId: "doc-1",
    evidencePackId: "pack-1",
    fileType: "clawdstrike_policy",
    startedAt: new Date().toISOString(),
    completedAt: new Date().toISOString(),
    summary: {
      totalCases: 5,
      passed: 4,
      failed: 1,
      matched: 3,
      missed: 1,
      falsePositives: 0,
      engine: "client",
    },
    results: [],
    explainability: [],
    ...overrides,
  };
}

describe("LabRunStore", () => {
  let store: LabRunStore;

  beforeEach(async () => {
    store = new LabRunStore();
    await store.init();
  });

  afterEach(() => {
    store.close();
  });

  it("saves and retrieves a run", async () => {
    const run = makeRun();
    await store.saveRun(run);
    const retrieved = await store.getRun(run.id);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.id).toBe(run.id);
    expect(retrieved!.summary.passed).toBe(4);
  });

  it("returns null for non-existent run", async () => {
    const result = await store.getRun("nonexistent");
    expect(result).toBeNull();
  });

  it("retrieves runs by documentId with pagination", async () => {
    for (let i = 0; i < 5; i++) {
      await store.saveRun(
        makeRun({
          documentId: "doc-paginated",
          completedAt: new Date(2026, 2, 15, 10, i).toISOString(),
        }),
      );
    }

    const first3 = await store.getRunsForDocument("doc-paginated", 3, 0);
    expect(first3).toHaveLength(3);

    const next2 = await store.getRunsForDocument("doc-paginated", 3, 3);
    expect(next2).toHaveLength(2);
  });

  it("retrieves runs by evidencePackId", async () => {
    await store.saveRun(makeRun({ evidencePackId: "pack-a" }));
    await store.saveRun(makeRun({ evidencePackId: "pack-a" }));
    await store.saveRun(makeRun({ evidencePackId: "pack-b" }));

    const runsA = await store.getRunsForPack("pack-a");
    expect(runsA).toHaveLength(2);
  });

  it("gets latest run for a document", async () => {
    await store.saveRun(
      makeRun({
        documentId: "doc-latest",
        completedAt: "2026-03-15T10:00:00.000Z",
      }),
    );
    const latestRun = makeRun({
      documentId: "doc-latest",
      completedAt: "2026-03-15T11:00:00.000Z",
    });
    await store.saveRun(latestRun);

    const latest = await store.getLatestRun("doc-latest");
    expect(latest).not.toBeNull();
    expect(latest!.id).toBe(latestRun.id);
  });

  it("deletes a run", async () => {
    const run = makeRun();
    await store.saveRun(run);
    await store.deleteRun(run.id);
    const result = await store.getRun(run.id);
    expect(result).toBeNull();
  });

  it("deletes all runs for a document", async () => {
    await store.saveRun(makeRun({ documentId: "doc-del" }));
    await store.saveRun(makeRun({ documentId: "doc-del" }));
    await store.saveRun(makeRun({ documentId: "doc-keep" }));

    await store.deleteRunsForDocument("doc-del");

    const count = await store.getRunCount("doc-del");
    expect(count).toBe(0);

    const keepCount = await store.getRunCount("doc-keep");
    expect(keepCount).toBe(1);
  });

  it("counts runs per document", async () => {
    await store.saveRun(makeRun({ documentId: "doc-count" }));
    await store.saveRun(makeRun({ documentId: "doc-count" }));

    const count = await store.getRunCount("doc-count");
    expect(count).toBe(2);
  });

  it("throws when store not initialized", async () => {
    const uninitStore = new LabRunStore();
    await expect(uninitStore.saveRun(makeRun())).rejects.toThrow("not initialized");
  });
});
