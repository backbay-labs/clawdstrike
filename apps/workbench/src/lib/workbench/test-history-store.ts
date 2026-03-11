import type { TestResult } from "./test-store";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StoredTestRun {
  id: string;
  policyId: string;
  timestamp: string;
  total: number;
  passed: number;
  failed: number;
  results: TestResult[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DB_NAME = "clawdstrike_test_history";
const DB_VERSION = 1;
const RUNS_STORE = "runs";

// ---------------------------------------------------------------------------
// IndexedDB helpers
// ---------------------------------------------------------------------------

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;

      if (!db.objectStoreNames.contains(RUNS_STORE)) {
        const store = db.createObjectStore(RUNS_STORE, { keyPath: "id" });
        store.createIndex("policyId", "policyId", { unique: false });
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

function cursorCollect<T>(req: IDBRequest<IDBCursorWithValue | null>, limit?: number): Promise<T[]> {
  return new Promise((resolve, reject) => {
    const results: T[] = [];
    req.onsuccess = () => {
      const cursor = req.result;
      if (!cursor || (limit !== undefined && results.length >= limit)) {
        resolve(results);
        return;
      }
      results.push(cursor.value as T);
      cursor.continue();
    };
    req.onerror = () => reject(req.error);
  });
}

// ---------------------------------------------------------------------------
// TestHistoryStore
// ---------------------------------------------------------------------------

export class TestHistoryStore {
  private db: IDBDatabase | null = null;

  async init(): Promise<void> {
    if (this.db) return;
    try {
      this.db = await openDB();
    } catch (err) {
      console.error("[test-history-store] Failed to open IndexedDB:", err);
      // Graceful degradation: store stays null, all operations become no-ops or return empty
    }
  }

  private ensureDB(): IDBDatabase {
    if (!this.db) throw new Error("TestHistoryStore not initialized. Call init() first.");
    return this.db;
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  /**
   * Get test runs for a specific policy, sorted by timestamp descending.
   * Limited to the most recent 50 entries.
   */
  async getRunsForPolicy(policyId: string): Promise<StoredTestRun[]> {
    const db = this.ensureDB();
    const tx = db.transaction(RUNS_STORE, "readonly");
    const store = tx.objectStore(RUNS_STORE);
    const index = store.index("policyId");
    const req = index.openCursor(policyId, "prev");

    const runs = await cursorCollect<StoredTestRun>(req, 50);

    // Sort by timestamp descending (cursor order is by key, not timestamp)
    runs.sort((a, b) => b.timestamp.localeCompare(a.timestamp));

    return runs;
  }

  /** Add a test run to the store. */
  async addRun(run: StoredTestRun): Promise<void> {
    const db = this.ensureDB();
    const tx = db.transaction(RUNS_STORE, "readwrite");
    const store = tx.objectStore(RUNS_STORE);

    try {
      store.add(run);
      await txPromise(tx);
    } catch (err) {
      if (err instanceof DOMException && err.name === "ConstraintError") {
        console.warn("[test-history-store] ConstraintError on addRun, skipping duplicate");
        return;
      }
      throw err;
    }
  }

  /** Clear all test runs for a specific policy. */
  async clearRunsForPolicy(policyId: string): Promise<void> {
    const db = this.ensureDB();
    const tx = db.transaction(RUNS_STORE, "readwrite");
    const store = tx.objectStore(RUNS_STORE);
    const index = store.index("policyId");
    const req = index.openCursor(policyId);

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
}

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------

let _instance: TestHistoryStore | null = null;

export const testHistoryStore: TestHistoryStore = (() => {
  if (!_instance) {
    _instance = new TestHistoryStore();
  }
  return _instance;
})();

if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', () => { _instance?.close(); });
}
