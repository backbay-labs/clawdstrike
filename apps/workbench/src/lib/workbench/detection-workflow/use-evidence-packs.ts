/**
 * React hook for managing evidence packs tied to a detection document.
 *
 * Wraps EvidencePackStore with React state management, providing CRUD
 * operations, import/export, and reclassification of evidence items.
 */

import { useState, useEffect, useCallback, useRef } from "react";
import type {
  EvidencePack,
  EvidenceDatasetKind,
  EvidenceItem,
} from "./shared-types";
import { createEmptyDatasets } from "./shared-types";
import { getEvidencePackStore, EvidencePackStore } from "./evidence-pack-store";
import {
  MAX_STRUCTURED_EVENT_SIZE,
  MAX_BYTE_SAMPLE_SIZE,
} from "./evidence-redaction";

// ---- Import validation types ----

export interface ImportFailure {
  index: number;
  itemId?: string;
  reason: string;
}

export interface ImportResult {
  imported: number;
  failed: ImportFailure[];
}

// ---- Hook ----

export function useEvidencePacks(
  documentId: string | undefined,
  fileType?: EvidencePack["fileType"],
) {
  const [packs, setPacks] = useState<EvidencePack[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedPackId, setSelectedPackId] = useState<string | null>(null);
  const storeRef = useRef<EvidencePackStore | null>(null);
  const initRef = useRef<Promise<void> | null>(null);

  // Initialize store once
  useEffect(() => {
    if (storeRef.current) return;
    const store = getEvidencePackStore();
    storeRef.current = store;
    initRef.current = store.init();
  }, []);

  // Load packs whenever documentId changes
  useEffect(() => {
    if (!documentId) {
      setPacks([]);
      setSelectedPackId(null);
      return;
    }

    let cancelled = false;

    async function load() {
      setLoading(true);
      try {
        await initRef.current;
        const store = storeRef.current;
        if (!store || cancelled) return;
        const result = await store.getPacksForDocument(documentId!);
        if (cancelled) return;
        // Sort by createdAt descending
        result.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
        setPacks(result);
        setSelectedPackId((prev) => {
          if (result.length === 0) return null;
          if (prev && result.some((pack) => pack.id === prev)) return prev;
          return result[0].id;
        });
      } catch (err) {
        console.error("[use-evidence-packs] Failed to load packs:", err);
        if (!cancelled) {
          setPacks([]);
          setSelectedPackId(null);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, [documentId]);

  const selectPack = useCallback((packId: string | null) => {
    setSelectedPackId(packId);
  }, []);

  const refreshPacks = useCallback(async () => {
    if (!documentId || !storeRef.current) return;
    await initRef.current;
    const result = await storeRef.current.getPacksForDocument(documentId);
    result.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
    setPacks(result);
  }, [documentId]);

  const createPack = useCallback(
    async (title?: string): Promise<EvidencePack | null> => {
      if (!documentId || !fileType || !storeRef.current) return null;
      await initRef.current;

      const newPack: EvidencePack = {
        id: crypto.randomUUID(),
        documentId,
        fileType,
        title: title ?? `Evidence Pack ${packs.length + 1}`,
        createdAt: new Date().toISOString(),
        datasets: createEmptyDatasets(),
        redactionState: "clean",
      };

      const saved = await storeRef.current.savePack(newPack);
      await refreshPacks();
      setSelectedPackId(saved.id);
      return saved;
    },
    [documentId, fileType, packs.length, refreshPacks],
  );

  const deletePack = useCallback(
    async (packId: string): Promise<void> => {
      if (!storeRef.current) return;
      await initRef.current;
      await storeRef.current.deletePack(packId);
      if (selectedPackId === packId) {
        setSelectedPackId(null);
      }
      await refreshPacks();
    },
    [selectedPackId, refreshPacks],
  );

  const addItem = useCallback(
    async (packId: string, dataset: EvidenceDatasetKind, item: EvidenceItem): Promise<void> => {
      if (!storeRef.current) return;
      await initRef.current;
      await storeRef.current.addItemToPack(packId, dataset, item);
      await refreshPacks();
    },
    [refreshPacks],
  );

  const removeItem = useCallback(
    async (packId: string, itemId: string): Promise<void> => {
      if (!storeRef.current) return;
      await initRef.current;
      await storeRef.current.removeItemFromPack(packId, itemId);
      await refreshPacks();
    },
    [refreshPacks],
  );

  const reclassifyItem = useCallback(
    async (
      packId: string,
      itemId: string,
      fromDataset: EvidenceDatasetKind,
      toDataset: EvidenceDatasetKind,
    ): Promise<void> => {
      if (!storeRef.current || fromDataset === toDataset) return;
      await initRef.current;
      const store = storeRef.current;

      const pack = await store.getPack(packId);
      if (!pack) return;

      const item = pack.datasets[fromDataset].find((i) => i.id === itemId);
      if (!item) return;

      // Remove from source, add to target
      await store.removeItemFromPack(packId, itemId);
      await store.addItemToPack(packId, toDataset, item);
      await refreshPacks();
    },
    [refreshPacks],
  );

  const exportPack = useCallback(
    async (packId: string): Promise<void> => {
      if (!storeRef.current) return;
      await initRef.current;

      const pack = await storeRef.current.getPack(packId);
      if (!pack) return;

      const json = JSON.stringify(pack, null, 2);
      const blob = new Blob([json], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `${pack.title.replace(/[^a-zA-Z0-9_-]/g, "_")}.evidence.json`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
    },
    [],
  );

  const importPack = useCallback(
    async (file: File): Promise<ImportResult> => {
      if (!documentId || !fileType || !storeRef.current) {
        return { imported: 0, failed: [{ index: -1, reason: "Store not available" }] };
      }
      await initRef.current;

      const failures: ImportFailure[] = [];
      let text: string;

      try {
        text = await file.text();
      } catch {
        return { imported: 0, failed: [{ index: -1, reason: "Failed to read file" }] };
      }

      let raw: unknown;
      try {
        raw = JSON.parse(text);
      } catch {
        return { imported: 0, failed: [{ index: -1, reason: "Invalid JSON" }] };
      }

      if (!raw || typeof raw !== "object") {
        return { imported: 0, failed: [{ index: -1, reason: "Expected an object" }] };
      }

      const data = raw as Record<string, unknown>;

      // Build a new pack from the imported data
      const newPack: EvidencePack = {
        id: crypto.randomUUID(),
        documentId,
        fileType,
        title: typeof data.title === "string" ? data.title : `Imported Pack`,
        createdAt: new Date().toISOString(),
        datasets: createEmptyDatasets(),
        redactionState: "clean",
      };

      // Validate and import items from datasets
      const datasets = data.datasets;
      if (datasets && typeof datasets === "object") {
        const datasetObj = datasets as Record<string, unknown>;
        const validKinds: EvidenceDatasetKind[] = ["positive", "negative", "regression", "false_positive"];

        for (const kind of validKinds) {
          const items = datasetObj[kind];
          if (!Array.isArray(items)) continue;

          for (let i = 0; i < items.length; i++) {
            const item = items[i];
            if (!item || typeof item !== "object" || !("id" in item) || !("kind" in item)) {
              failures.push({ index: i, reason: `Invalid item structure in ${kind}[${i}]` });
              continue;
            }

            const evidenceItem = item as EvidenceItem;

            // Size checks
            if (evidenceItem.kind === "structured_event" || evidenceItem.kind === "ocsf_event") {
              const size = new TextEncoder().encode(JSON.stringify(evidenceItem.payload)).length;
              if (size > MAX_STRUCTURED_EVENT_SIZE) {
                failures.push({
                  index: i,
                  itemId: evidenceItem.id,
                  reason: `${kind}[${i}]: structured payload exceeds ${MAX_STRUCTURED_EVENT_SIZE} bytes (${size} bytes)`,
                });
                continue;
              }
            }

            if (evidenceItem.kind === "bytes") {
              if (evidenceItem.payload.length > MAX_BYTE_SAMPLE_SIZE) {
                failures.push({
                  index: i,
                  itemId: evidenceItem.id,
                  reason: `${kind}[${i}]: byte payload exceeds ${MAX_BYTE_SAMPLE_SIZE} bytes (${evidenceItem.payload.length} bytes)`,
                });
                continue;
              }
            }

            newPack.datasets[kind].push(evidenceItem);
          }
        }
      }

      const totalItems = Object.values(newPack.datasets).reduce(
        (sum, items) => sum + items.length,
        0,
      );

      await storeRef.current!.savePack(newPack);
      await refreshPacks();
      setSelectedPackId(newPack.id);

      return { imported: totalItems, failed: failures };
    },
    [documentId, fileType, refreshPacks],
  );

  return {
    packs,
    loading,
    selectedPackId,
    selectPack,
    createPack,
    deletePack,
    addItem,
    removeItem,
    reclassifyItem,
    importPack,
    exportPack,
  };
}
