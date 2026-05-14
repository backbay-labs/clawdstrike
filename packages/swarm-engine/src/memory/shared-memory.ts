/**
 * Unified memory manager wrapping HNSW, KnowledgeGraph, and IdbBackend.
 * Writes are guarded via the ClawdStrike guard pipeline (fail-closed).
 */

import { HnswLite } from "./hnsw.js";
import { KnowledgeGraph } from "./graph.js";
import type { Entity, Relation } from "./graph.js";
import { IdbBackend } from "./idb-backend.js";
import type { TypedEventEmitter } from "../events.js";
import type { SwarmEngineEventMap } from "../events.js";
import type { GuardEvaluator, GuardedAction } from "../types.js";

export interface SharedMemoryConfig {
  guardEvaluator?: GuardEvaluator;
  idbName?: string;
  dimensions?: number;
  enableIdb?: boolean;
}

export interface MemoryEntry {
  value: unknown;
  tags: string[];
  ttlMs: number | null;
  storedAt: number;
  namespace: string;
  vector?: Float32Array;
  _key?: string;
}

export interface StoreOptions {
  agentId?: string;
  taskId?: string;
  tags?: string[];
  ttlMs?: number;
  vector?: Float32Array;
}

export interface SearchOptions {
  tags?: string[];
  vector?: Float32Array;
  k?: number;
}

export class SharedMemory {
  private readonly events: TypedEventEmitter<SwarmEngineEventMap>;
  private readonly guardEvaluator: GuardEvaluator | undefined;
  private readonly hnsw: HnswLite;
  private readonly graph: KnowledgeGraph;
  private readonly idb: IdbBackend | null;
  private readonly idbReady: Promise<boolean> | null;
  private readonly data = new Map<string, MemoryEntry>();

  constructor(
    events: TypedEventEmitter<SwarmEngineEventMap>,
    config?: SharedMemoryConfig,
  ) {
    this.events = events;
    this.guardEvaluator = config?.guardEvaluator;
    this.hnsw = new HnswLite(config?.dimensions ?? 128, 16, 200, "cosine");
    this.graph = new KnowledgeGraph();

    if (config?.enableIdb) {
      this.idb = new IdbBackend(config.idbName ?? "swarm-memory");
      this.idbReady = this.idb.open();
    } else {
      this.idb = null;
      this.idbReady = null;
    }
  }

  async store(
    namespace: string,
    key: string,
    value: unknown,
    options?: StoreOptions,
  ): Promise<boolean> {
    // Fail-closed: no evaluator means deny
    if (!this.guardEvaluator) {
      return false;
    }

    const action: GuardedAction = {
      agentId: options?.agentId ?? "system",
      taskId: options?.taskId ?? null,
      actionType: "file_write",
      target: `memory://${namespace}/${key}`,
      context: {
        namespace,
        key,
        sizeBytes: JSON.stringify(value).length,
      },
      requestedAt: Date.now(),
    };

    const result = await this.guardEvaluator.evaluate(action);
    if (!result.allowed) {
      return false;
    }

    const compositeKey = `${namespace}:${key}`;
    const entry: MemoryEntry = {
      value,
      tags: options?.tags ?? [],
      ttlMs: options?.ttlMs ?? null,
      storedAt: Date.now(),
      namespace,
      vector: options?.vector,
      _key: compositeKey,
    };

    this.data.set(compositeKey, entry);

    if (options?.vector) {
      this.hnsw.add(compositeKey, options.vector);
    }

    if (this.idb && this.idbReady) {
      await this.idbReady;
      if (this.idb.isAvailable) {
        await this.idb.put(compositeKey, { ...entry, vector: undefined });
      }
    }

    this.events.emit("memory.store", {
      kind: "memory.store",
      sourceAgentId: options?.agentId ?? null,
      timestamp: Date.now(),
      namespace,
      key,
      sizeBytes: JSON.stringify(value).length,
    });

    return true;
  }

  get(namespace: string, key: string): MemoryEntry | undefined {
    const compositeKey = `${namespace}:${key}`;
    const entry = this.data.get(compositeKey);
    if (!entry) return undefined;

    if (entry.ttlMs !== null && Date.now() - entry.storedAt > entry.ttlMs) {
      this.data.delete(compositeKey);
      if (entry.vector) {
        this.hnsw.remove(compositeKey);
      }
      return undefined;
    }

    return entry;
  }

  search(namespace: string, options: SearchOptions): MemoryEntry[] {
    const start = Date.now();

    let results: MemoryEntry[];

    if (options.vector) {
      const k = options.k ?? 10;
      const hnswResults = this.hnsw.search(options.vector, k);

      results = [];
      for (const hr of hnswResults) {
        const entry = this.data.get(hr.id);
        if (!entry) continue;
        if (entry.namespace !== namespace) continue;

        if (
          entry.ttlMs !== null &&
          Date.now() - entry.storedAt > entry.ttlMs
        ) {
          this.data.delete(hr.id);
          this.hnsw.remove(hr.id);
          continue;
        }

        if (options.tags && options.tags.length > 0) {
          if (!options.tags.some((t) => entry.tags.includes(t))) continue;
        }

        results.push(entry);
      }
    } else {
      results = [];
      for (const [_compositeKey, entry] of this.data) {
        if (entry.namespace !== namespace) continue;

        if (
          entry.ttlMs !== null &&
          Date.now() - entry.storedAt > entry.ttlMs
        ) {
          this.data.delete(_compositeKey);
          if (entry.vector) this.hnsw.remove(_compositeKey);
          continue;
        }

        if (options.tags && options.tags.length > 0) {
          if (!options.tags.some((t) => entry.tags.includes(t))) continue;
        }

        results.push(entry);
      }
    }

    const durationMs = Date.now() - start;

    this.events.emit("memory.search", {
      kind: "memory.search",
      sourceAgentId: null,
      timestamp: Date.now(),
      namespace,
      query: options.vector ? "vector" : options.tags?.join(",") ?? "*",
      resultCount: results.length,
      durationMs,
    });

    return results;
  }

  delete(namespace: string, key: string): void {
    const compositeKey = `${namespace}:${key}`;
    const entry = this.data.get(compositeKey);
    if (entry?.vector) {
      this.hnsw.remove(compositeKey);
    }
    this.data.delete(compositeKey);
  }

  addEntity(entity: Entity): void {
    this.graph.addEntity(entity);
  }

  addRelation(relation: Relation): void {
    this.graph.addRelation(relation);
  }

  queryEntities(
    type: string,
    properties?: Record<string, unknown>,
  ): Entity[] {
    return this.graph.query(type, properties);
  }

  getState(): {
    entries: Record<string, MemoryEntry>;
    graph: ReturnType<KnowledgeGraph["getState"]>;
    vectorCount: number;
  } {
    const entries: Record<string, MemoryEntry> = {};
    for (const [key, entry] of this.data) {
      entries[key] = entry;
    }
    return {
      entries,
      graph: this.graph.getState(),
      vectorCount: this.hnsw.size,
    };
  }

  dispose(): void {
    this.idb?.close();
    this.data.clear();
    this.graph.clear();
  }
}
