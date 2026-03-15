/**
 * IndexedDB-backed storage for evidence packs.
 * Follows the same raw IndexedDB pattern as version-store.ts.
 *
 * Keyed by documentId — each detection document can have multiple packs.
 * Large evidence bodies stay in IndexedDB, never in the tab store.
 */

import type { EvidencePack, EvidenceDatasetKind, EvidenceItem } from "./shared-types";
import { createEmptyDatasets } from "./shared-types";
import { redactEvidencePack } from "./evidence-redaction";

const DB_NAME = "clawdstrike_evidence_packs";
const DB_VERSION = 1;
const PACKS_STORE = "packs";

// ---- IndexedDB helpers (same pattern as version-store.ts) ----

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(PACKS_STORE)) {
        const store = db.createObjectStore(PACKS_STORE, { keyPath: "id" });
        store.createIndex("documentId", "documentId", { unique: false });
        store.createIndex("documentId_createdAt", ["documentId", "createdAt"], { unique: false });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function txPromise<T>(tx: IDBTransaction, resultFn?: () => T): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve(resultFn ? resultFn() : undefined);
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? new Error("Transaction aborted"));
  });
}

function requestPromise<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// ---- EvidencePackStore ----

export class EvidencePackStore {
  private db: IDBDatabase | null = null;

  async init(): Promise<void> {
    if (this.db) return;
    try {
      this.db = await openDB();
    } catch (err) {
      console.error("[evidence-pack-store] Failed to open IndexedDB:", err);
    }
  }

  private ensureDB(): IDBDatabase {
    if (!this.db) throw new Error("EvidencePackStore not initialized. Call init() first.");
    return this.db;
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  async savePack(pack: EvidencePack): Promise<EvidencePack> {
    const db = this.ensureDB();

    // Redact before storing
    const { pack: redacted } = redactEvidencePack(pack);

    const tx = db.transaction(PACKS_STORE, "readwrite");
    tx.objectStore(PACKS_STORE).put(redacted);
    await txPromise(tx);
    return redacted;
  }

  async getPack(packId: string): Promise<EvidencePack | null> {
    const db = this.ensureDB();
    const tx = db.transaction(PACKS_STORE, "readonly");
    const result = await requestPromise(tx.objectStore(PACKS_STORE).get(packId));
    return (result as EvidencePack) ?? null;
  }

  async getPacksForDocument(documentId: string): Promise<EvidencePack[]> {
    const db = this.ensureDB();
    const tx = db.transaction(PACKS_STORE, "readonly");
    const index = tx.objectStore(PACKS_STORE).index("documentId");
    const result = await requestPromise(index.getAll(documentId));
    return (result as EvidencePack[]) ?? [];
  }

  async deletePack(packId: string): Promise<void> {
    const db = this.ensureDB();
    const tx = db.transaction(PACKS_STORE, "readwrite");
    tx.objectStore(PACKS_STORE).delete(packId);
    await txPromise(tx);
  }

  async deletePacksForDocument(documentId: string): Promise<void> {
    const db = this.ensureDB();
    const tx = db.transaction(PACKS_STORE, "readwrite");
    const index = tx.objectStore(PACKS_STORE).index("documentId");
    const req = index.openCursor(documentId);

    await new Promise<void>((resolve, reject) => {
      req.onsuccess = () => {
        const cursor = req.result;
        if (!cursor) {
          resolve();
          return;
        }
        cursor.delete();
        cursor.continue();
      };
      req.onerror = () => reject(req.error);
    });

    await txPromise(tx);
  }

  async getPackCount(documentId: string): Promise<number> {
    const db = this.ensureDB();
    const tx = db.transaction(PACKS_STORE, "readonly");
    const index = tx.objectStore(PACKS_STORE).index("documentId");
    return requestPromise(index.count(documentId));
  }

  async updatePackTitle(packId: string, title: string): Promise<void> {
    const db = this.ensureDB();
    const tx = db.transaction(PACKS_STORE, "readwrite");
    const store = tx.objectStore(PACKS_STORE);
    const existing = await requestPromise(store.get(packId)) as EvidencePack | undefined;
    if (!existing) return;
    store.put({ ...existing, title });
    await txPromise(tx);
  }

  async addItemToPack(
    packId: string,
    dataset: EvidenceDatasetKind,
    item: EvidenceItem,
  ): Promise<void> {
    const db = this.ensureDB();
    const tx = db.transaction(PACKS_STORE, "readwrite");
    const store = tx.objectStore(PACKS_STORE);
    const existing = await requestPromise(store.get(packId)) as EvidencePack | undefined;
    if (!existing) throw new Error(`Pack ${packId} not found`);

    const datasets = { ...existing.datasets };
    datasets[dataset] = [...(datasets[dataset] ?? []), item];
    store.put({ ...existing, datasets });
    await txPromise(tx);
  }

  async removeItemFromPack(packId: string, itemId: string): Promise<void> {
    const db = this.ensureDB();
    const tx = db.transaction(PACKS_STORE, "readwrite");
    const store = tx.objectStore(PACKS_STORE);
    const existing = await requestPromise(store.get(packId)) as EvidencePack | undefined;
    if (!existing) return;

    const datasets = { ...existing.datasets };
    for (const key of Object.keys(datasets) as EvidenceDatasetKind[]) {
      datasets[key] = datasets[key].filter((item) => item.id !== itemId);
    }
    store.put({ ...existing, datasets });
    await txPromise(tx);
  }
}

// ---- Singleton ----

let _instance: EvidencePackStore | null = null;

export function getEvidencePackStore(): EvidencePackStore {
  if (!_instance) {
    _instance = new EvidencePackStore();
  }
  return _instance;
}

if (typeof window !== "undefined") {
  window.addEventListener("beforeunload", () => { _instance?.close(); });
}
