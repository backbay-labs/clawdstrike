/**
 * Document identity alias store — maps normalized file paths to stable documentIds.
 *
 * When a file is opened, saved, or renamed, this store registers an alias
 * from the normalized file path to its documentId. On reopen, the store
 * resolves the existing documentId so that version history, evidence packs,
 * lab runs, and publication manifests remain linked to the same identity.
 *
 * Unsaved drafts keep generated documentIds until first save, at which point
 * the alias is registered.
 *
 * Storage: localStorage (small index, no need for IndexedDB).
 */

const STORAGE_KEY = "clawdstrike_document_identity_aliases";
const MAX_ALIASES = 500;

// ---- Path normalization ----

/**
 * Normalize a file path for alias resolution.
 * Strips trailing slashes, collapses runs of separators, and lowercases
 * on case-insensitive platforms (detected heuristically).
 */
export function normalizePath(filePath: string): string {
  let normalized = filePath
    .replace(/\\/g, "/")
    .replace(/\/+/g, "/")
    .replace(/\/+$/, "");

  // On macOS/Windows, file paths are case-insensitive
  if (typeof navigator !== "undefined") {
    const platform = navigator.platform?.toLowerCase() ?? "";
    if (platform.includes("mac") || platform.includes("win")) {
      normalized = normalized.toLowerCase();
    }
  }

  return normalized;
}

// ---- Alias entry ----

interface AliasEntry {
  normalizedPath: string;
  documentId: string;
  updatedAt: string;
}

// ---- Store ----

export class DocumentIdentityStore {
  private aliases: Map<string, AliasEntry>;

  constructor() {
    this.aliases = new Map();
    this.load();
  }

  /**
   * Resolve a file path to an existing documentId, or return null if
   * no alias exists.
   */
  resolve(filePath: string): string | null {
    const key = normalizePath(filePath);
    const entry = this.aliases.get(key);
    return entry?.documentId ?? null;
  }

  /**
   * Register an alias from a file path to a documentId.
   * If the path already maps to a different documentId, the alias is updated.
   */
  register(filePath: string, documentId: string): void {
    const key = normalizePath(filePath);
    this.aliases.set(key, {
      normalizedPath: key,
      documentId,
      updatedAt: new Date().toISOString(),
    });
    this.prune();
    this.persist();
  }

  /**
   * Remove the alias for a file path.
   */
  unregister(filePath: string): void {
    const key = normalizePath(filePath);
    this.aliases.delete(key);
    this.persist();
  }

  /**
   * Update aliases when a file is moved/renamed.
   * Removes the old alias and registers the new one with the same documentId.
   */
  move(oldPath: string, newPath: string): void {
    const oldKey = normalizePath(oldPath);
    const entry = this.aliases.get(oldKey);
    if (!entry) return;

    this.aliases.delete(oldKey);
    this.register(newPath, entry.documentId);
  }

  /**
   * Get all registered aliases (for debugging/inspection).
   */
  entries(): Array<{ path: string; documentId: string; updatedAt: string }> {
    return [...this.aliases.values()].map((e) => ({
      path: e.normalizedPath,
      documentId: e.documentId,
      updatedAt: e.updatedAt,
    }));
  }

  /**
   * Clear all aliases (for testing).
   */
  clear(): void {
    this.aliases.clear();
    this.persist();
  }

  // ---- Persistence ----

  private load(): void {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return;

      for (const entry of parsed) {
        if (
          typeof entry === "object" &&
          entry !== null &&
          typeof entry.normalizedPath === "string" &&
          typeof entry.documentId === "string"
        ) {
          this.aliases.set(entry.normalizedPath, entry as AliasEntry);
        }
      }
    } catch {
      // Fail-safe: start with empty aliases on corrupt data
      this.aliases.clear();
    }
  }

  private persist(): void {
    try {
      const entries = [...this.aliases.values()];
      localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
    } catch (e) {
      console.warn("[document-identity-store] persist failed:", e);
    }
  }

  private prune(): void {
    if (this.aliases.size <= MAX_ALIASES) return;

    // Evict oldest entries
    const sorted = [...this.aliases.entries()].sort(
      (a, b) => (a[1].updatedAt ?? "").localeCompare(b[1].updatedAt ?? ""),
    );
    const toRemove = sorted.slice(0, sorted.length - MAX_ALIASES);
    for (const [key] of toRemove) {
      this.aliases.delete(key);
    }
  }
}

// ---- Singleton ----

let _instance: DocumentIdentityStore | null = null;

export function getDocumentIdentityStore(): DocumentIdentityStore {
  if (!_instance) {
    _instance = new DocumentIdentityStore();
  }
  return _instance;
}
