import type { WorkbenchPolicy } from "./types";

// ---- Types ----

export interface PolicyVersion {
  id: string;
  policyId: string;
  version: number;
  yaml: string;
  policy: WorkbenchPolicy;
  createdAt: string;
  message?: string;
  tags: string[];
  parentId: string | null;
  hash: string;
}

export interface VersionTag {
  name: string;
  versionId: string;
  policyId: string;
  createdAt: string;
  color?: string;
}

// ---- Constants ----

const DB_NAME = "clawdstrike_versions";
const DB_VERSION = 1;
const VERSIONS_STORE = "versions";
const TAGS_STORE = "tags";

// ---- SHA-256 hashing ----

async function sha256Hex(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  const hashArray = new Uint8Array(hashBuffer);
  return Array.from(hashArray)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ---- Tag validation ----

const TAG_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{0,29}$/;

export function isValidTagName(name: string): boolean {
  return TAG_RE.test(name);
}

// ---- Markdown escaping ----

/** @internal Exported for testing. */
export function escapeMd(s: string): string {
  return s.replace(/([#*_\[\]`|~\\>])/g, "\\$1");
}

// ---- IndexedDB wrapper ----

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;

      if (!db.objectStoreNames.contains(VERSIONS_STORE)) {
        const vStore = db.createObjectStore(VERSIONS_STORE, { keyPath: "id" });
        // Composite index for querying versions of a policy, ordered by version number
        vStore.createIndex("policyId_version", ["policyId", "version"], { unique: true });
        // Composite index for querying versions of a policy, ordered by createdAt
        vStore.createIndex("policyId_createdAt", ["policyId", "createdAt"], { unique: false });
        // Index for looking up by policyId alone
        vStore.createIndex("policyId", "policyId", { unique: false });
      }

      if (!db.objectStoreNames.contains(TAGS_STORE)) {
        const tStore = db.createObjectStore(TAGS_STORE, { keyPath: ["name", "policyId"] });
        tStore.createIndex("policyId", "policyId", { unique: false });
        tStore.createIndex("versionId", "versionId", { unique: false });
        tStore.createIndex("name", "name", { unique: false });
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

// ---- VersionStore ----

export class VersionStore {
  private db: IDBDatabase | null = null;

  async init(): Promise<void> {
    if (this.db) return;
    try {
      this.db = await openDB();
    } catch (err) {
      console.error("[version-store] Failed to open IndexedDB:", err);
      // Graceful degradation: store stays null, all operations become no-ops or return empty
    }
  }

  private ensureDB(): IDBDatabase {
    if (!this.db) throw new Error("VersionStore not initialized. Call init() first.");
    return this.db;
  }

  async saveVersion(
    policyId: string,
    yaml: string,
    policy: WorkbenchPolicy,
    message?: string,
  ): Promise<PolicyVersion> {
    const db = this.ensureDB();
    const hash = await sha256Hex(yaml);

    // Single readwrite transaction: dedup-check + insert atomically
    const tx = db.transaction(VERSIONS_STORE, "readwrite");
    const store = tx.objectStore(VERSIONS_STORE);
    const index = store.index("policyId_version");
    const range = IDBKeyRange.bound([policyId, 0], [policyId, Number.MAX_SAFE_INTEGER]);
    const cursorReq = index.openCursor(range, "prev");

    const latest = await new Promise<PolicyVersion | null>((resolve, reject) => {
      cursorReq.onsuccess = () => {
        const cursor = cursorReq.result;
        resolve(cursor ? (cursor.value as PolicyVersion) : null);
      };
      cursorReq.onerror = () => reject(cursorReq.error);
    });

    // Dedup: if latest version has the same hash, skip
    if (latest && latest.hash === hash) {
      return latest;
    }

    const nextVersion = latest ? latest.version + 1 : 1;
    const now = new Date().toISOString();

    const version: PolicyVersion = {
      id: crypto.randomUUID(),
      policyId,
      version: nextVersion,
      yaml,
      policy,
      createdAt: now,
      message: message || undefined,
      tags: [],
      parentId: latest?.id ?? null,
      hash,
    };

    try {
      store.add(version);
      await txPromise(tx);
    } catch (err) {
      // Handle ConstraintError gracefully (e.g. duplicate key from concurrent save)
      if (err instanceof DOMException && err.name === "ConstraintError") {
        console.warn("[version-store] ConstraintError on save, returning latest version");
        return latest ?? version;
      }
      throw err;
    }

    // Auto-prune old versions to prevent unbounded growth (#33)
    try {
      await this.deleteOldVersions(policyId, 50);
    } catch (pruneErr) {
      console.warn("[version-store] Auto-prune failed (non-fatal):", pruneErr);
    }

    return version;
  }

  close(): void {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  async getVersions(policyId: string, limit = 20, offset = 0): Promise<PolicyVersion[]> {
    const db = this.ensureDB();
    const tx = db.transaction(VERSIONS_STORE, "readonly");
    const store = tx.objectStore(VERSIONS_STORE);
    const index = store.index("policyId_version");

    // We want descending order (most recent first). Use a key range on policyId
    // and open a cursor in "prev" direction.
    const range = IDBKeyRange.bound([policyId, 0], [policyId, Number.MAX_SAFE_INTEGER]);
    const req = index.openCursor(range, "prev");

    return new Promise((resolve, reject) => {
      const results: PolicyVersion[] = [];
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
        results.push(cursor.value as PolicyVersion);
        cursor.continue();
      };
      req.onerror = () => reject(req.error);
    });
  }

  async getVersion(versionId: string): Promise<PolicyVersion | null> {
    const db = this.ensureDB();
    const tx = db.transaction(VERSIONS_STORE, "readonly");
    const result = await requestPromise(tx.objectStore(VERSIONS_STORE).get(versionId));
    return (result as PolicyVersion) ?? null;
  }

  async getLatestVersion(policyId: string): Promise<PolicyVersion | null> {
    const db = this.ensureDB();
    const tx = db.transaction(VERSIONS_STORE, "readonly");
    const index = tx.objectStore(VERSIONS_STORE).index("policyId_version");
    const range = IDBKeyRange.bound([policyId, 0], [policyId, Number.MAX_SAFE_INTEGER]);
    const req = index.openCursor(range, "prev");

    return new Promise((resolve, reject) => {
      req.onsuccess = () => {
        const cursor = req.result;
        resolve(cursor ? (cursor.value as PolicyVersion) : null);
      };
      req.onerror = () => reject(req.error);
    });
  }

  async addTag(versionId: string, tag: string, color?: string): Promise<void> {
    if (!isValidTagName(tag)) {
      throw new Error(`Invalid tag name: "${tag}". Must be alphanumeric/dashes/dots/underscores, 1-30 chars.`);
    }

    const db = this.ensureDB();

    // Single readwrite transaction: read + modify + write to avoid TOCTOU race (#16)
    const tx = db.transaction([VERSIONS_STORE, TAGS_STORE], "readwrite");
    const versionReq = tx.objectStore(VERSIONS_STORE).get(versionId);
    const version = await requestPromise(versionReq) as PolicyVersion | undefined;
    if (!version) {
      tx.abort();
      throw new Error(`Version ${versionId} not found`);
    }

    const now = new Date().toISOString();
    const tagEntry: VersionTag = {
      name: tag,
      versionId,
      policyId: version.policyId,
      createdAt: now,
      color,
    };

    // Update the version's tags array
    const updatedTags = version.tags.includes(tag) ? version.tags : [...version.tags, tag];

    tx.objectStore(TAGS_STORE).put(tagEntry);
    tx.objectStore(VERSIONS_STORE).put({ ...version, tags: updatedTags });
    await txPromise(tx);
  }

  async removeTag(versionId: string, tag: string): Promise<void> {
    const db = this.ensureDB();

    // Single readwrite transaction: read + modify + write to avoid TOCTOU race (#16)
    const tx = db.transaction([VERSIONS_STORE, TAGS_STORE], "readwrite");
    const versionReq = tx.objectStore(VERSIONS_STORE).get(versionId);
    const version = await requestPromise(versionReq) as PolicyVersion | undefined;
    if (!version) return;

    const updatedTags = version.tags.filter((t) => t !== tag);

    tx.objectStore(TAGS_STORE).delete([tag, version.policyId]);
    tx.objectStore(VERSIONS_STORE).put({ ...version, tags: updatedTags });
    await txPromise(tx);
  }

  async getTaggedVersions(policyId: string): Promise<PolicyVersion[]> {
    const db = this.ensureDB();

    // Get all tags for this policy
    const tx = db.transaction([TAGS_STORE, VERSIONS_STORE], "readonly");
    const tagIndex = tx.objectStore(TAGS_STORE).index("policyId");
    const tagReq = tagIndex.getAll(policyId);
    const tags = await requestPromise(tagReq) as VersionTag[];

    if (tags.length === 0) return [];

    // Collect unique version IDs
    const versionIds = [...new Set(tags.map((t) => t.versionId))];

    const vStore = tx.objectStore(VERSIONS_STORE);
    const versions: PolicyVersion[] = [];
    for (const vid of versionIds) {
      const v = await requestPromise(vStore.get(vid));
      if (v) versions.push(v as PolicyVersion);
    }

    // Sort by version number descending
    versions.sort((a, b) => b.version - a.version);
    return versions;
  }

  async findByTag(tag: string): Promise<PolicyVersion | null> {
    const db = this.ensureDB();
    const tx = db.transaction([TAGS_STORE, VERSIONS_STORE], "readonly");
    const tagIndex = tx.objectStore(TAGS_STORE).index("name");
    const tagReq = tagIndex.get(tag);
    const tagEntry = await requestPromise(tagReq) as VersionTag | undefined;

    if (!tagEntry) return null;

    const version = await requestPromise(
      tx.objectStore(VERSIONS_STORE).get(tagEntry.versionId),
    );
    return (version as PolicyVersion) ?? null;
  }

  async deleteOldVersions(policyId: string, keepCount: number): Promise<void> {
    const db = this.ensureDB();

    // Single readwrite transaction: delete inline during cursor walk
    const tx = db.transaction([VERSIONS_STORE, TAGS_STORE], "readwrite");
    const index = tx.objectStore(VERSIONS_STORE).index("policyId_version");
    const range = IDBKeyRange.bound([policyId, 0], [policyId, Number.MAX_SAFE_INTEGER]);
    const req = index.openCursor(range, "prev");

    let kept = 0;

    await new Promise<void>((resolve, reject) => {
      req.onsuccess = () => {
        const cursor = req.result;
        if (!cursor) {
          resolve();
          return;
        }
        const version = cursor.value as PolicyVersion;
        if (kept < keepCount) {
          kept++;
        } else {
          // Only delete untagged versions — delete within the same transaction
          if (version.tags.length === 0) {
            cursor.delete();
          }
        }
        cursor.continue();
      };
      req.onerror = () => reject(req.error);
    });

    await txPromise(tx);
  }

  async getVersionCount(policyId: string): Promise<number> {
    const db = this.ensureDB();
    const tx = db.transaction(VERSIONS_STORE, "readonly");
    const index = tx.objectStore(VERSIONS_STORE).index("policyId");
    const req = index.count(policyId);
    return requestPromise(req);
  }

  async exportChangelog(policyId: string): Promise<string> {
    const db = this.ensureDB();

    // Get all versions, newest first
    const versions = await this.getVersions(policyId, 1000, 0);
    if (versions.length === 0) return "# Changelog\n\nNo versions recorded.\n";

    // Get the policy name from the latest version
    const policyName = versions[0]?.policy.name ?? "Policy";

    const lines: string[] = [
      `# Changelog: ${escapeMd(policyName)}`,
      "",
      `Generated: ${new Date().toISOString()}`,
      "",
      "---",
      "",
    ];

    for (const v of versions) {
      const date = new Date(v.createdAt).toLocaleDateString("en-US", {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });

      let heading = `## v${v.version} - ${date}`;
      if (v.tags.length > 0) {
        heading += ` [${v.tags.map(escapeMd).join(", ")}]`;
      }

      lines.push(heading);
      lines.push("");

      if (v.message) {
        lines.push(escapeMd(v.message));
        lines.push("");
      }

      lines.push(`- Hash: \`${v.hash.slice(0, 8)}\``);
      lines.push(`- Schema: ${v.policy.version}`);

      // Count enabled guards
      const enabledGuards = Object.entries(v.policy.guards)
        .filter(([, cfg]) => cfg && (cfg as Record<string, unknown>).enabled === true)
        .map(([id]) => id);
      if (enabledGuards.length > 0) {
        lines.push(`- Guards: ${enabledGuards.join(", ")}`);
      }

      lines.push("");
    }

    return lines.join("\n");
  }
}

// ---- Singleton ----

let _instance: VersionStore | null = null;

export function getVersionStore(): VersionStore {
  if (!_instance) {
    _instance = new VersionStore();
  }
  return _instance;
}
