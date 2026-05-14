/** IndexedDB persistence with graceful no-op fallback when unavailable. */

export class IdbBackend {
  private db: IDBDatabase | null = null;
  private readonly dbName: string;
  private readonly storeName: string;

  constructor(dbName: string, storeName = "swarm-memory") {
    this.dbName = dbName;
    this.storeName = storeName;
  }

  async open(): Promise<boolean> {
    if (typeof indexedDB === "undefined") {
      return false;
    }

    try {
      return await new Promise<boolean>((resolve) => {
        const request = indexedDB.open(this.dbName, 1);

        request.onupgradeneeded = () => {
          const db = request.result;
          if (!db.objectStoreNames.contains(this.storeName)) {
            db.createObjectStore(this.storeName);
          }
        };

        request.onsuccess = () => {
          this.db = request.result;
          resolve(true);
        };

        request.onerror = () => {
          resolve(false);
        };
      });
    } catch {
      return false;
    }
  }

  async put(key: string, value: unknown): Promise<void> {
    if (!this.db) return;
    try {
      await new Promise<void>((resolve, reject) => {
        const tx = this.db!.transaction(this.storeName, "readwrite");
        const store = tx.objectStore(this.storeName);
        const request = store.put(value, key);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    } catch {
      // Safari eviction / quota errors
    }
  }

  async get<T>(key: string): Promise<T | undefined> {
    if (!this.db) return undefined;
    try {
      return await new Promise<T | undefined>((resolve, reject) => {
        const tx = this.db!.transaction(this.storeName, "readonly");
        const store = tx.objectStore(this.storeName);
        const request = store.get(key);
        request.onsuccess = () => resolve(request.result as T | undefined);
        request.onerror = () => reject(request.error);
      });
    } catch {
      return undefined;
    }
  }

  async delete(key: string): Promise<void> {
    if (!this.db) return;
    try {
      await new Promise<void>((resolve, reject) => {
        const tx = this.db!.transaction(this.storeName, "readwrite");
        const store = tx.objectStore(this.storeName);
        const request = store.delete(key);
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    } catch {}
  }

  async getAll<T>(): Promise<Array<{ key: string; value: T }>> {
    if (!this.db) return [];
    try {
      return await new Promise<Array<{ key: string; value: T }>>(
        (resolve, reject) => {
          const tx = this.db!.transaction(this.storeName, "readonly");
          const store = tx.objectStore(this.storeName);
          const request = store.openCursor();
          const results: Array<{ key: string; value: T }> = [];

          request.onsuccess = () => {
            const cursor = request.result;
            if (cursor) {
              results.push({
                key: cursor.key as string,
                value: cursor.value as T,
              });
              cursor.continue();
            } else {
              resolve(results);
            }
          };
          request.onerror = () => reject(request.error);
        },
      );
    } catch {
      return [];
    }
  }

  async clear(): Promise<void> {
    if (!this.db) return;
    try {
      await new Promise<void>((resolve, reject) => {
        const tx = this.db!.transaction(this.storeName, "readwrite");
        const store = tx.objectStore(this.storeName);
        const request = store.clear();
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
      });
    } catch {}
  }

  close(): void {
    this.db?.close();
    this.db = null;
  }

  get isAvailable(): boolean {
    return this.db !== null;
  }
}
