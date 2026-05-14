import "fake-indexeddb/auto";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { EvidencePackStore } from "../detection-workflow/evidence-pack-store";
import type { EvidencePack, EvidenceItem } from "../detection-workflow/shared-types";
import { createEmptyDatasets } from "../detection-workflow/shared-types";

function makeItem(overrides: Partial<EvidenceItem & { kind: "structured_event" }> = {}): EvidenceItem {
  return {
    id: crypto.randomUUID(),
    kind: "structured_event",
    format: "json",
    payload: { test: true },
    expected: "match",
    ...overrides,
  };
}

function makePack(overrides: Partial<EvidencePack> = {}): EvidencePack {
  return {
    id: crypto.randomUUID(),
    documentId: "doc-1",
    fileType: "clawdstrike_policy",
    title: "Test Pack",
    createdAt: new Date().toISOString(),
    datasets: createEmptyDatasets(),
    redactionState: "clean",
    ...overrides,
  };
}

describe("EvidencePackStore", () => {
  let store: EvidencePackStore;

  beforeEach(async () => {
    store = new EvidencePackStore();
    await store.init();
  });

  afterEach(() => {
    store.close();
  });

  it("saves and retrieves a pack", async () => {
    const pack = makePack();
    await store.savePack(pack);
    const retrieved = await store.getPack(pack.id);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.id).toBe(pack.id);
    expect(retrieved!.documentId).toBe("doc-1");
    expect(retrieved!.title).toBe("Test Pack");
  });

  it("returns null for non-existent pack", async () => {
    const result = await store.getPack("nonexistent");
    expect(result).toBeNull();
  });

  it("retrieves packs by documentId", async () => {
    await store.savePack(makePack({ documentId: "doc-a" }));
    await store.savePack(makePack({ documentId: "doc-a" }));
    await store.savePack(makePack({ documentId: "doc-b" }));

    const packsA = await store.getPacksForDocument("doc-a");
    expect(packsA).toHaveLength(2);

    const packsB = await store.getPacksForDocument("doc-b");
    expect(packsB).toHaveLength(1);
  });

  it("deletes a pack", async () => {
    const pack = makePack();
    await store.savePack(pack);
    await store.deletePack(pack.id);
    const result = await store.getPack(pack.id);
    expect(result).toBeNull();
  });

  it("deletes all packs for a document", async () => {
    await store.savePack(makePack({ documentId: "doc-x" }));
    await store.savePack(makePack({ documentId: "doc-x" }));
    await store.savePack(makePack({ documentId: "doc-y" }));

    await store.deletePacksForDocument("doc-x");

    const packsX = await store.getPacksForDocument("doc-x");
    expect(packsX).toHaveLength(0);

    const packsY = await store.getPacksForDocument("doc-y");
    expect(packsY).toHaveLength(1);
  });

  it("counts packs per document", async () => {
    await store.savePack(makePack({ documentId: "doc-c" }));
    await store.savePack(makePack({ documentId: "doc-c" }));
    await store.savePack(makePack({ documentId: "doc-c" }));

    const count = await store.getPackCount("doc-c");
    expect(count).toBe(3);
  });

  it("updates pack title", async () => {
    const pack = makePack({ title: "Original" });
    await store.savePack(pack);
    await store.updatePackTitle(pack.id, "Updated Title");

    const retrieved = await store.getPack(pack.id);
    expect(retrieved!.title).toBe("Updated Title");
  });

  it("adds item to pack", async () => {
    const pack = makePack();
    await store.savePack(pack);

    const item = makeItem();
    await store.addItemToPack(pack.id, "positive", item);

    const retrieved = await store.getPack(pack.id);
    expect(retrieved!.datasets.positive).toHaveLength(1);
    expect(retrieved!.datasets.positive[0].id).toBe(item.id);
  });

  it("removes item from pack", async () => {
    const item = makeItem();
    const pack = makePack({
      datasets: {
        ...createEmptyDatasets(),
        positive: [item],
      },
    });
    await store.savePack(pack);

    await store.removeItemFromPack(pack.id, item.id);

    const retrieved = await store.getPack(pack.id);
    expect(retrieved!.datasets.positive).toHaveLength(0);
  });

  it("redacts sensitive fields in stored packs", async () => {
    const sensitiveItem: EvidenceItem = {
      id: crypto.randomUUID(),
      kind: "structured_event",
      format: "json",
      payload: {
        username: "admin",
        password: "s3cret",
        api_key: "sk-12345",
        data: { token: "abc123", normal: "visible" },
      },
      expected: "match",
    };

    const pack = makePack({
      datasets: {
        ...createEmptyDatasets(),
        positive: [sensitiveItem],
      },
    });

    await store.savePack(pack);
    const retrieved = await store.getPack(pack.id);
    const storedPayload = (retrieved!.datasets.positive[0] as { payload: Record<string, unknown> }).payload;
    expect(storedPayload.password).toBe("[REDACTED]");
    expect(storedPayload.api_key).toBe("[REDACTED]");
    expect((storedPayload.data as Record<string, unknown>).token).toBe("[REDACTED]");
    expect((storedPayload.data as Record<string, unknown>).normal).toBe("visible");
    expect(storedPayload.username).toBe("admin"); // not sensitive
  });

  it("throws when store not initialized", async () => {
    const uninitStore = new EvidencePackStore();
    await expect(uninitStore.savePack(makePack())).rejects.toThrow("not initialized");
  });
});
