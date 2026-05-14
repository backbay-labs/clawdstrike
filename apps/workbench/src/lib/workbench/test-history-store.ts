import type { TestResult } from "./test-store";


export interface StoredTestRun {
  id: string;
  policyId: string;
  timestamp: string;
  total: number;
  passed: number;
  failed: number;
  results: TestResult[];
}


const DB_NAME = "clawdstrike_test_history";
const DB_VERSION = 1;
const RUNS_STORE = "runs";
const MAX_RECENT_RUNS = 50;


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

function cursorCollect<T>(req: IDBRequest<IDBCursorWithValue | null>, limit?: number): Promise<T[]> {
  return new Promise((resolve, reject) => {
    const results: T[] = [];
    req.onsuccess = () => {
      const cursor = req.result;
      if (!cursor || (typeof limit === "number" && results.length >= limit)) {
        resolve(results);
        return;
      }
      results.push(cursor.value as T);
      cursor.continue();
    };
    req.onerror = () => reject(req.error);
  });
}

export function selectLatestRuns(runs: StoredTestRun[], limit = MAX_RECENT_RUNS): StoredTestRun[] {
  return [...runs]
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
    .slice(0, limit);
}

function normalizePolicyIds(policyIds: string[]): string[] {
  return Array.from(new Set(policyIds.map((id) => id.trim()).filter(Boolean)));
}


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
    return this.getRunsForPolicies([policyId]);
  }

  async getRunsForPolicies(policyIds: string[]): Promise<StoredTestRun[]> {
    const normalizedIds = normalizePolicyIds(policyIds);
    if (normalizedIds.length === 0) return [];

    const db = this.ensureDB();
    const runs: StoredTestRun[] = [];

    for (const policyId of normalizedIds) {
      const tx = db.transaction(RUNS_STORE, "readonly");
      const store = tx.objectStore(RUNS_STORE);
      const index = store.index("policyId");
      const req = index.openCursor(policyId, "prev");
      runs.push(...(await cursorCollect<StoredTestRun>(req)));
    }

    return selectLatestRuns(runs);
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
    await this.clearRunsForPolicies([policyId]);
  }

  async clearRunsForPolicies(policyIds: string[]): Promise<void> {
    const normalizedIds = normalizePolicyIds(policyIds);
    if (normalizedIds.length === 0) return;

    const db = this.ensureDB();

    for (const policyId of normalizedIds) {
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
}


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
