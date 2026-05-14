/**
 * IndexedDB-backed storage for publication manifests.
 * Follows the same raw IndexedDB pattern as version-store.ts.
 */

import type { PublicationManifest } from "./shared-types";

const DB_NAME = "clawdstrike_publications";
const DB_VERSION = 2;
const MANIFESTS_STORE = "manifests";
const ARTIFACTS_STORE = "artifacts";

interface PublicationArtifactRecord {
  manifestId: string;
  outputContent: string;
  outputHash: string;
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(MANIFESTS_STORE)) {
        const store = db.createObjectStore(MANIFESTS_STORE, { keyPath: "id" });
        store.createIndex("documentId", "documentId", { unique: false });
        store.createIndex("documentId_createdAt", ["documentId", "createdAt"], { unique: false });
        store.createIndex("target", "target", { unique: false });
      }
      if (!db.objectStoreNames.contains(ARTIFACTS_STORE)) {
        db.createObjectStore(ARTIFACTS_STORE, { keyPath: "manifestId" });
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

// ---- PublicationStore ----

export class PublicationStore {
  private db: IDBDatabase | null = null;

  async init(): Promise<void> {
    if (this.db) return;
    try {
      this.db = await openDB();
    } catch (err) {
      console.error("[publication-store] Failed to open IndexedDB:", err);
    }
  }

  private ensureDB(): IDBDatabase {
    if (!this.db) throw new Error("PublicationStore not initialized. Call init() first.");
    return this.db;
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  async saveManifest(manifest: PublicationManifest): Promise<PublicationManifest> {
    const db = this.ensureDB();
    const tx = db.transaction(MANIFESTS_STORE, "readwrite");
    tx.objectStore(MANIFESTS_STORE).put(manifest);
    await txPromise(tx);
    return manifest;
  }

  async savePublication(
    manifest: PublicationManifest,
    outputContent: string,
  ): Promise<PublicationManifest> {
    const db = this.ensureDB();
    const tx = db.transaction([MANIFESTS_STORE, ARTIFACTS_STORE], "readwrite");
    tx.objectStore(MANIFESTS_STORE).put(manifest);
    tx.objectStore(ARTIFACTS_STORE).put({
      manifestId: manifest.id,
      outputContent,
      outputHash: manifest.outputHash,
    } satisfies PublicationArtifactRecord);
    await txPromise(tx);
    return manifest;
  }

  async getManifest(manifestId: string): Promise<PublicationManifest | null> {
    const db = this.ensureDB();
    const tx = db.transaction(MANIFESTS_STORE, "readonly");
    const result = await requestPromise(tx.objectStore(MANIFESTS_STORE).get(manifestId));
    return (result as PublicationManifest) ?? null;
  }

  async getManifestsForDocument(documentId: string): Promise<PublicationManifest[]> {
    const db = this.ensureDB();
    const tx = db.transaction(MANIFESTS_STORE, "readonly");
    const index = tx.objectStore(MANIFESTS_STORE).index("documentId_createdAt");
    const range = IDBKeyRange.bound(
      [documentId, ""],
      [documentId, "\uffff"],
    );
    const req = index.openCursor(range, "prev");

    return new Promise((resolve, reject) => {
      const results: PublicationManifest[] = [];
      req.onsuccess = () => {
        const cursor = req.result;
        if (!cursor) {
          resolve(results);
          return;
        }
        results.push(cursor.value as PublicationManifest);
        cursor.continue();
      };
      req.onerror = () => reject(req.error);
    });
  }

  async getLatestManifest(documentId: string): Promise<PublicationManifest | null> {
    const db = this.ensureDB();
    const tx = db.transaction(MANIFESTS_STORE, "readonly");
    const index = tx.objectStore(MANIFESTS_STORE).index("documentId_createdAt");
    const range = IDBKeyRange.bound(
      [documentId, ""],
      [documentId, "\uffff"],
    );
    const req = index.openCursor(range, "prev");

    return new Promise((resolve, reject) => {
      req.onsuccess = () => {
        const cursor = req.result;
        resolve(cursor ? (cursor.value as PublicationManifest) : null);
      };
      req.onerror = () => reject(req.error);
    });
  }

  async getAllManifests(): Promise<PublicationManifest[]> {
    const db = this.ensureDB();
    const tx = db.transaction(MANIFESTS_STORE, "readonly");
    const req = tx.objectStore(MANIFESTS_STORE).getAll();
    const result = await requestPromise(req);
    return ((result as PublicationManifest[]) ?? []).sort(
      (left, right) => new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime(),
    );
  }

  async deleteManifest(manifestId: string): Promise<void> {
    const db = this.ensureDB();
    const tx = db.transaction([MANIFESTS_STORE, ARTIFACTS_STORE], "readwrite");
    tx.objectStore(MANIFESTS_STORE).delete(manifestId);
    tx.objectStore(ARTIFACTS_STORE).delete(manifestId);
    await txPromise(tx);
  }

  async getOutputContent(manifestId: string): Promise<string | null> {
    const db = this.ensureDB();
    const tx = db.transaction(ARTIFACTS_STORE, "readonly");
    const result = await requestPromise(tx.objectStore(ARTIFACTS_STORE).get(manifestId));
    const artifact = (result as PublicationArtifactRecord | undefined) ?? null;
    return artifact?.outputContent ?? null;
  }

  async getManifestCount(documentId: string): Promise<number> {
    const db = this.ensureDB();
    const tx = db.transaction(MANIFESTS_STORE, "readonly");
    const index = tx.objectStore(MANIFESTS_STORE).index("documentId");
    return requestPromise(index.count(documentId));
  }
}

// ---- Singleton ----

let _instance: PublicationStore | null = null;

export function getPublicationStore(): PublicationStore {
  if (!_instance) {
    _instance = new PublicationStore();
  }
  return _instance;
}

if (typeof window !== "undefined") {
  window.addEventListener("beforeunload", () => { _instance?.close(); });
}
