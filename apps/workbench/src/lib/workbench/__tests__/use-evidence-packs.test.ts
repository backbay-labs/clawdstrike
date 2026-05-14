import "fake-indexeddb/auto";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { useEvidencePacks } from "../detection-workflow/use-evidence-packs";
import { EvidencePackStore } from "../detection-workflow/evidence-pack-store";
import type { EvidencePack, EvidenceItem } from "../detection-workflow/shared-types";
import { createEmptyDatasets } from "../detection-workflow/shared-types";
import {
  MAX_STRUCTURED_EVENT_SIZE,
  MAX_BYTE_SAMPLE_SIZE,
} from "../detection-workflow/evidence-redaction";

// Reset the singleton between tests
let _storeInstance: EvidencePackStore | null = null;

vi.mock("../detection-workflow/evidence-pack-store", async () => {
  const actual = await vi.importActual<typeof import("../detection-workflow/evidence-pack-store")>(
    "../detection-workflow/evidence-pack-store",
  );
  return {
    ...actual,
    getEvidencePackStore: () => {
      if (!_storeInstance) {
        _storeInstance = new actual.EvidencePackStore();
      }
      return _storeInstance;
    },
  };
});

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

describe("useEvidencePacks", () => {
  beforeEach(() => {
    _storeInstance = null;
  });

  afterEach(() => {
    if (_storeInstance) {
      _storeInstance.close();
      _storeInstance = null;
    }
  });

  it("loads packs for a documentId", async () => {
    // Pre-seed packs
    const store = new EvidencePackStore();
    await store.init();
    await store.savePack(makePack({ documentId: "doc-load" }));
    await store.savePack(makePack({ documentId: "doc-load" }));
    store.close();

    // Use the hook's store (which is a different instance)
    _storeInstance = new EvidencePackStore();
    await _storeInstance.init();
    // Copy packs to the singleton store
    const seededStore = new EvidencePackStore();
    await seededStore.init();
    const existingPacks = await seededStore.getPacksForDocument("doc-load");
    for (const p of existingPacks) {
      await _storeInstance.savePack(p);
    }
    seededStore.close();

    const { result } = renderHook(() => useEvidencePacks("doc-load", "sigma_rule"));

    // Wait for async loading
    await vi.waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.packs).toHaveLength(2);
  });

  it("creates new packs", async () => {
    const { result } = renderHook(() => useEvidencePacks("doc-create", "sigma_rule"));

    await vi.waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    let newPack: EvidencePack | null = null;
    await act(async () => {
      newPack = await result.current.createPack("My Test Pack");
    });

    expect(newPack).not.toBeNull();
    expect(newPack!.title).toBe("My Test Pack");
    expect(result.current.packs).toHaveLength(1);
    expect(result.current.selectedPackId).toBe(newPack!.id);
  });

  it("deletes packs", async () => {
    const { result } = renderHook(() => useEvidencePacks("doc-delete", "sigma_rule"));

    await vi.waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    let packId: string | undefined;
    await act(async () => {
      const pack = await result.current.createPack("To Delete");
      packId = pack?.id;
    });

    expect(result.current.packs).toHaveLength(1);

    await act(async () => {
      await result.current.deletePack(packId!);
    });

    expect(result.current.packs).toHaveLength(0);
    expect(result.current.selectedPackId).toBeNull();
  });

  it("adds items to packs", async () => {
    const { result } = renderHook(() => useEvidencePacks("doc-add-item", "sigma_rule"));

    await vi.waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    let packId: string | undefined;
    await act(async () => {
      const pack = await result.current.createPack();
      packId = pack?.id;
    });

    const item = makeItem();
    await act(async () => {
      await result.current.addItem(packId!, "positive", item);
    });

    const updatedPack = result.current.packs.find((p) => p.id === packId);
    expect(updatedPack?.datasets.positive).toHaveLength(1);
  });

  it("removes items from packs", async () => {
    const { result } = renderHook(() => useEvidencePacks("doc-remove-item", "sigma_rule"));

    await vi.waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    let packId: string | undefined;
    const item = makeItem();

    await act(async () => {
      const pack = await result.current.createPack();
      packId = pack?.id;
    });

    await act(async () => {
      await result.current.addItem(packId!, "negative", item);
    });

    expect(
      result.current.packs.find((p) => p.id === packId)?.datasets.negative,
    ).toHaveLength(1);

    await act(async () => {
      await result.current.removeItem(packId!, item.id);
    });

    expect(
      result.current.packs.find((p) => p.id === packId)?.datasets.negative,
    ).toHaveLength(0);
  });

  it("reclassifies items between datasets", async () => {
    const { result } = renderHook(() => useEvidencePacks("doc-reclass", "sigma_rule"));

    await vi.waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    let packId: string | undefined;
    const item = makeItem();

    await act(async () => {
      const pack = await result.current.createPack();
      packId = pack?.id;
    });

    await act(async () => {
      await result.current.addItem(packId!, "positive", item);
    });

    await act(async () => {
      await result.current.reclassifyItem(packId!, item.id, "positive", "false_positive");
    });

    const updatedPack = result.current.packs.find((p) => p.id === packId);
    expect(updatedPack?.datasets.positive).toHaveLength(0);
    expect(updatedPack?.datasets.false_positive).toHaveLength(1);
    expect(updatedPack?.datasets.false_positive[0].id).toBe(item.id);
  });

  it("import validates and reports partial failures for oversized items", async () => {
    const { result } = renderHook(() => useEvidencePacks("doc-import", "sigma_rule"));

    await vi.waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    // Create a pack JSON with one valid and one oversized item
    const oversizedPayload: Record<string, unknown> = {};
    // Build a payload that exceeds MAX_STRUCTURED_EVENT_SIZE (64KB)
    const bigValue = "x".repeat(MAX_STRUCTURED_EVENT_SIZE + 1000);
    oversizedPayload.big_field = bigValue;

    const importData = {
      title: "Import Test",
      datasets: {
        positive: [
          {
            id: "valid-item",
            kind: "structured_event",
            format: "json",
            payload: { small: "data" },
            expected: "match",
          },
          {
            id: "oversized-item",
            kind: "structured_event",
            format: "json",
            payload: oversizedPayload,
            expected: "match",
          },
        ],
        negative: [],
        regression: [],
        false_positive: [],
      },
    };

    const blob = new Blob([JSON.stringify(importData)], { type: "application/json" });
    const file = new File([blob], "test.json", { type: "application/json" });

    let importResult: { imported: number; failed: Array<{ reason: string }> } | undefined;
    await act(async () => {
      importResult = await result.current.importPack(file);
    });

    expect(importResult).toBeDefined();
    expect(importResult!.imported).toBe(1);
    expect(importResult!.failed).toHaveLength(1);
    expect(importResult!.failed[0].reason).toContain("exceeds");
  });

  it("import rejects invalid JSON", async () => {
    const { result } = renderHook(() => useEvidencePacks("doc-import-invalid", "sigma_rule"));

    await vi.waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    const file = new File(["not valid json"], "bad.json", { type: "application/json" });

    let importResult: { imported: number; failed: Array<{ reason: string }> } | undefined;
    await act(async () => {
      importResult = await result.current.importPack(file);
    });

    expect(importResult!.imported).toBe(0);
    expect(importResult!.failed).toHaveLength(1);
    expect(importResult!.failed[0].reason).toBe("Invalid JSON");
  });

  it("returns empty packs when documentId is undefined", async () => {
    const { result } = renderHook(() => useEvidencePacks(undefined, undefined));

    // Should immediately have empty packs, no loading
    expect(result.current.packs).toHaveLength(0);
    expect(result.current.selectedPackId).toBeNull();
  });

  it("validates byte payload size on import", async () => {
    const { result } = renderHook(() => useEvidencePacks("doc-import-bytes", "yara_rule"));

    await vi.waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    const oversizedBytePayload = "x".repeat(MAX_BYTE_SAMPLE_SIZE + 100);

    const importData = {
      title: "Byte Import Test",
      datasets: {
        positive: [
          {
            id: "oversized-bytes",
            kind: "bytes",
            encoding: "utf8",
            payload: oversizedBytePayload,
            expected: "match",
          },
        ],
        negative: [],
        regression: [],
        false_positive: [],
      },
    };

    const file = new File([JSON.stringify(importData)], "bytes.json", {
      type: "application/json",
    });

    let importResult: { imported: number; failed: Array<{ reason: string }> } | undefined;
    await act(async () => {
      importResult = await result.current.importPack(file);
    });

    expect(importResult!.imported).toBe(0);
    expect(importResult!.failed).toHaveLength(1);
    expect(importResult!.failed[0].reason).toContain("byte payload exceeds");
  });
});
