/**
 * IndexedDB-backed storage for detection lab runs.
 * Follows the same raw IndexedDB pattern as version-store.ts.
 *
 * Lab runs are keyed by documentId and linked to evidence packs.
 */

import type { LabRun } from "./shared-types";

const DB_NAME = "clawdstrike_lab_runs";
const DB_VERSION = 1;
const RUNS_STORE = "runs";
const MAX_RUNS_PER_DOCUMENT = 50;

// ---- IndexedDB helpers ----

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(RUNS_STORE)) {
        const store = db.createObjectStore(RUNS_STORE, { keyPath: "id" });
        store.createIndex("documentId", "documentId", { unique: false });
        store.createIndex("documentId_completedAt", ["documentId", "completedAt"], { unique: false });
        store.createIndex("evidencePackId", "evidencePackId", { unique: false });
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

// ---- LabRunStore ----

export class LabRunStore {
  private db: IDBDatabase | null = null;

  async init(): Promise<void> {
    if (this.db) return;
    try {
      this.db = await openDB();
    } catch (err) {
      console.error("[lab-run-store] Failed to open IndexedDB:", err);
    }
  }

  private ensureDB(): IDBDatabase {
    if (!this.db) throw new Error("LabRunStore not initialized. Call init() first.");
    return this.db;
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  async saveRun(run: LabRun): Promise<LabRun> {
    const db = this.ensureDB();
    const tx = db.transaction(RUNS_STORE, "readwrite");
    tx.objectStore(RUNS_STORE).put(run);
    await txPromise(tx);

    // Auto-prune old runs
    try {
      await this.pruneOldRuns(run.documentId, MAX_RUNS_PER_DOCUMENT);
    } catch (err) {
      console.warn("[lab-run-store] Auto-prune failed (non-fatal):", err);
    }

    return run;
  }

  async getRun(runId: string): Promise<LabRun | null> {
    const db = this.ensureDB();
    const tx = db.transaction(RUNS_STORE, "readonly");
    const result = await requestPromise(tx.objectStore(RUNS_STORE).get(runId));
    return (result as LabRun) ?? null;
  }

  async getRunsForDocument(documentId: string, limit = 20, offset = 0): Promise<LabRun[]> {
    const db = this.ensureDB();
    const tx = db.transaction(RUNS_STORE, "readonly");
    const index = tx.objectStore(RUNS_STORE).index("documentId_completedAt");
    const range = IDBKeyRange.bound(
      [documentId, ""],
      [documentId, "\uffff"],
    );
    const req = index.openCursor(range, "prev");

    return new Promise((resolve, reject) => {
      const results: LabRun[] = [];
      let skipped = 0;
      req.onsuccess = () => {
        const cursor = req.result;
        if (!cursor || results.length >= limit) {
          resolve(results);
          return;
        }
        if (skipped < offset) {
          skipped++;
          cursor.continue();
          return;
        }
        results.push(cursor.value as LabRun);
        cursor.continue();
      };
      req.onerror = () => reject(req.error);
    });
  }

  async getRunsForPack(evidencePackId: string): Promise<LabRun[]> {
    const db = this.ensureDB();
    const tx = db.transaction(RUNS_STORE, "readonly");
    const index = tx.objectStore(RUNS_STORE).index("evidencePackId");
    const result = await requestPromise(index.getAll(evidencePackId));
    return (result as LabRun[]) ?? [];
  }

  async getLatestRun(documentId: string): Promise<LabRun | null> {
    const db = this.ensureDB();
    const tx = db.transaction(RUNS_STORE, "readonly");
    const index = tx.objectStore(RUNS_STORE).index("documentId_completedAt");
    const range = IDBKeyRange.bound(
      [documentId, ""],
      [documentId, "\uffff"],
    );
    const req = index.openCursor(range, "prev");

    return new Promise((resolve, reject) => {
      req.onsuccess = () => {
        const cursor = req.result;
        resolve(cursor ? (cursor.value as LabRun) : null);
      };
      req.onerror = () => reject(req.error);
    });
  }

  async deleteRun(runId: string): Promise<void> {
    const db = this.ensureDB();
    const tx = db.transaction(RUNS_STORE, "readwrite");
    tx.objectStore(RUNS_STORE).delete(runId);
    await txPromise(tx);
  }

  async deleteRunsForDocument(documentId: string): Promise<void> {
    const db = this.ensureDB();
    const tx = db.transaction(RUNS_STORE, "readwrite");
    const index = tx.objectStore(RUNS_STORE).index("documentId");
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

  async getRunCount(documentId: string): Promise<number> {
    const db = this.ensureDB();
    const tx = db.transaction(RUNS_STORE, "readonly");
    const index = tx.objectStore(RUNS_STORE).index("documentId");
    return requestPromise(index.count(documentId));
  }

  private async pruneOldRuns(documentId: string, keepCount: number): Promise<void> {
    const db = this.ensureDB();
    const tx = db.transaction(RUNS_STORE, "readwrite");
    const index = tx.objectStore(RUNS_STORE).index("documentId_completedAt");
    const range = IDBKeyRange.bound(
      [documentId, ""],
      [documentId, "\uffff"],
    );
    const req = index.openCursor(range, "prev");

    let kept = 0;
    await new Promise<void>((resolve, reject) => {
      req.onsuccess = () => {
        const cursor = req.result;
        if (!cursor) {
          resolve();
          return;
        }
        if (kept < keepCount) {
          kept++;
        } else {
          cursor.delete();
        }
        cursor.continue();
      };
      req.onerror = () => reject(req.error);
    });

    await txPromise(tx);
  }
}

// ---- Singleton ----

let _instance: LabRunStore | null = null;

export function getLabRunStore(): LabRunStore {
  if (!_instance) {
    _instance = new LabRunStore();
  }
  return _instance;
}

if (typeof window !== "undefined") {
  window.addEventListener("beforeunload", () => { _instance?.close(); });
}
