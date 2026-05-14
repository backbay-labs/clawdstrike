/**
 * Tests for the memory subsystem: HNSW vector index, KnowledgeGraph,
 * IdbBackend, and SharedMemory manager with guard pipeline integration.
 *
 * Coverage: vector search, entity/relation CRUD, IndexedDB fallback,
 * namespace scoping, tag search, TTL expiration, guarded writes.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { HnswLite, cosineSimilarity } from "./hnsw.js";
import { KnowledgeGraph } from "./graph.js";
import type { Entity, Relation } from "./graph.js";
import { IdbBackend } from "./idb-backend.js";
import { SharedMemory } from "./shared-memory.js";
import { TypedEventEmitter } from "../events.js";
import type { SwarmEngineEventMap } from "../events.js";
import type {
  GuardEvaluator,
  GuardedAction,
  GuardEvaluationResult,
} from "../types.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function vec(values: number[]): Float32Array {
  return new Float32Array(values);
}

function makeAllowEvaluator(): GuardEvaluator {
  return {
    async evaluate(action: GuardedAction): Promise<GuardEvaluationResult> {
      return {
        verdict: "allow",
        allowed: true,
        guardResults: [],
        receipt: {
          id: "r_test",
          timestamp: new Date().toISOString(),
          verdict: "allow",
          guard: "test-guard",
          valid: true,
          policyName: "test-policy",
          action: { type: action.actionType, target: action.target },
          evidence: {},
          signature: "sig_test",
          publicKey: "pk_test",
        },
        durationMs: 1,
        evaluatedAt: Date.now(),
      };
    },
  };
}

function makeDenyEvaluator(): GuardEvaluator {
  return {
    async evaluate(action: GuardedAction): Promise<GuardEvaluationResult> {
      return {
        verdict: "deny",
        allowed: false,
        guardResults: [],
        receipt: {
          id: "r_deny",
          timestamp: new Date().toISOString(),
          verdict: "deny",
          guard: "test-guard",
          valid: false,
          policyName: "test-policy",
          action: { type: action.actionType, target: action.target },
          evidence: {},
          signature: "sig_deny",
          publicKey: "pk_deny",
        },
        durationMs: 1,
        evaluatedAt: Date.now(),
      };
    },
  };
}

// ---------------------------------------------------------------------------
// HNSW
// ---------------------------------------------------------------------------

describe("hnsw", () => {
  it("adds vectors and searches nearest by cosine", () => {
    const index = new HnswLite(3, 4, 10, "cosine");
    index.add("a", vec([1, 0, 0]));
    index.add("b", vec([0, 1, 0]));
    index.add("c", vec([0.9, 0.1, 0]));

    const results = index.search(vec([1, 0, 0]), 2);
    expect(results).toHaveLength(2);
    // "a" is identical to query, "c" is close
    expect(results[0].id).toBe("a");
    expect(results[0].score).toBeCloseTo(1.0);
    expect(results[1].id).toBe("c");
  });

  it("cosineSimilarity of identical vectors is 1.0", () => {
    const v = vec([1, 2, 3]);
    expect(cosineSimilarity(v, v)).toBeCloseTo(1.0);
  });

  it("remove vector, search no longer returns it", () => {
    const index = new HnswLite(3, 4, 10, "cosine");
    index.add("a", vec([1, 0, 0]));
    index.add("b", vec([0, 1, 0]));
    expect(index.size).toBe(2);

    index.remove("a");
    expect(index.size).toBe(1);

    const results = index.search(vec([1, 0, 0]), 2);
    expect(results.every((r) => r.id !== "a")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// KnowledgeGraph
// ---------------------------------------------------------------------------

describe("graph", () => {
  let graph: KnowledgeGraph;

  beforeEach(() => {
    graph = new KnowledgeGraph();
  });

  it("addEntity + getEntity roundtrip", () => {
    const entity: Entity = {
      id: "e1",
      type: "person",
      properties: { name: "Alice" },
      createdAt: Date.now(),
    };
    graph.addEntity(entity);
    expect(graph.getEntity("e1")).toEqual(entity);
  });

  it("addRelation + getRelations returns relation", () => {
    const rel: Relation = {
      from: "e1",
      to: "e2",
      type: "knows",
      properties: {},
      createdAt: Date.now(),
    };
    graph.addRelation(rel);
    const rels = graph.getRelations("e1");
    expect(rels).toHaveLength(1);
    expect(rels[0]).toEqual(rel);
  });

  it("query by type filters correctly", () => {
    graph.addEntity({
      id: "e1",
      type: "person",
      properties: { role: "admin" },
      createdAt: 1,
    });
    graph.addEntity({
      id: "e2",
      type: "org",
      properties: { name: "Acme" },
      createdAt: 2,
    });
    graph.addEntity({
      id: "e3",
      type: "person",
      properties: { role: "user" },
      createdAt: 3,
    });

    expect(graph.query("person")).toHaveLength(2);
    expect(graph.query("org")).toHaveLength(1);
    expect(graph.query("person", { role: "admin" })).toHaveLength(1);
  });

  it("removeEntity also removes its relations", () => {
    graph.addEntity({ id: "e1", type: "a", properties: {}, createdAt: 1 });
    graph.addEntity({ id: "e2", type: "a", properties: {}, createdAt: 2 });
    graph.addRelation({
      from: "e1",
      to: "e2",
      type: "rel",
      properties: {},
      createdAt: 1,
    });
    graph.addRelation({
      from: "e2",
      to: "e1",
      type: "rel",
      properties: {},
      createdAt: 2,
    });

    graph.removeEntity("e1");
    expect(graph.getEntity("e1")).toBeUndefined();
    expect(graph.getRelations("e1")).toHaveLength(0);
    // Incoming relation from e2 -> e1 should also be gone
    expect(graph.getRelations("e2")).toHaveLength(0);
  });

  it("getState returns Record (not Map)", () => {
    graph.addEntity({ id: "e1", type: "a", properties: {}, createdAt: 1 });
    const state = graph.getState();
    expect(state.entities).toBeTypeOf("object");
    expect(state.entities).not.toBeInstanceOf(Map);
    expect(state.relations).toBeTypeOf("object");
    expect(state.relations).not.toBeInstanceOf(Map);
    // Serializable
    expect(() => JSON.stringify(state)).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// IdbBackend
// ---------------------------------------------------------------------------

describe("idb", () => {
  it("open() returns false in Node.js environment", async () => {
    const idb = new IdbBackend("test-db");
    const result = await idb.open();
    expect(result).toBe(false);
  });

  it("put/get are no-ops when db is null (no throw)", async () => {
    const idb = new IdbBackend("test-db");
    // Not opened, so db is null
    await expect(idb.put("key", "value")).resolves.toBeUndefined();
    const val = await idb.get("key");
    expect(val).toBeUndefined();
  });

  it("isAvailable returns false when db is null", async () => {
    const idb = new IdbBackend("test-db");
    expect(idb.isAvailable).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// SharedMemory
// ---------------------------------------------------------------------------

describe("shared", () => {
  let events: TypedEventEmitter<SwarmEngineEventMap>;
  let memory: SharedMemory;

  beforeEach(() => {
    events = new TypedEventEmitter<SwarmEngineEventMap>();
    memory = new SharedMemory(events, {
      dimensions: 3,
      guardEvaluator: makeAllowEvaluator(),
    });
  });

  afterEach(() => {
    memory.dispose();
    vi.restoreAllMocks();
  });

  it("store + get roundtrip", async () => {
    const stored = await memory.store("ns", "key1", { data: "hello" });
    expect(stored).toBe(true);

    const entry = memory.get("ns", "key1");
    expect(entry).toBeDefined();
    expect(entry!.value).toEqual({ data: "hello" });
    expect(entry!.namespace).toBe("ns");
  });

  it("TTL expiration: get returns undefined after timeout", async () => {
    await memory.store("ns", "ttl-key", "temp", { ttlMs: 50 });

    // Immediately after: still present
    expect(memory.get("ns", "ttl-key")).toBeDefined();

    // Wait past TTL
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(memory.get("ns", "ttl-key")).toBeUndefined();
  });

  it("tag-based search: returns entries matching tags", async () => {
    await memory.store("ns", "k1", "v1", { tags: ["alpha", "beta"] });
    await memory.store("ns", "k2", "v2", { tags: ["beta", "gamma"] });
    await memory.store("ns", "k3", "v3", { tags: ["gamma"] });

    const results = memory.search("ns", { tags: ["beta"] });
    expect(results).toHaveLength(2);
    // Both k1 and k2 have "beta" tag
    expect(results.every((r) => r.tags.includes("beta"))).toBe(true);
  });

  it("vector search: returns by similarity", async () => {
    await memory.store("ns", "v1", "near", {
      vector: vec([0.9, 0.1, 0]),
    });
    await memory.store("ns", "v2", "far", {
      vector: vec([0, 0, 1]),
    });
    await memory.store("ns", "v3", "close", {
      vector: vec([0.8, 0.2, 0]),
    });

    const results = memory.search("ns", {
      vector: vec([1, 0, 0]),
      k: 2,
    });
    expect(results).toHaveLength(2);
  });

  it("namespace isolation: entries in different namespaces don't mix", async () => {
    await memory.store("ns-a", "key", "val-a");
    await memory.store("ns-b", "key", "val-b");

    expect(memory.get("ns-a", "key")!.value).toBe("val-a");
    expect(memory.get("ns-b", "key")!.value).toBe("val-b");

    const resultsA = memory.search("ns-a", {});
    const resultsB = memory.search("ns-b", {});
    expect(resultsA).toHaveLength(1);
    expect(resultsB).toHaveLength(1);
  });

  it("opens IndexedDB and persists entries when enableIdb is true", async () => {
    const close = vi.fn();
    const openSpy = vi
      .spyOn(IdbBackend.prototype, "open")
      .mockImplementation(async function mockOpen(this: IdbBackend) {
        (this as any).db = { close } as IDBDatabase;
        return true;
      });
    const putSpy = vi.spyOn(IdbBackend.prototype, "put").mockResolvedValue();

    const idbMemory = new SharedMemory(events, {
      dimensions: 3,
      enableIdb: true,
      idbName: "test-memory",
      guardEvaluator: makeAllowEvaluator(),
    });

    try {
      const stored = await idbMemory.store("ns", "persisted", { data: "hello" });
      expect(stored).toBe(true);
      expect(openSpy).toHaveBeenCalledOnce();
      expect(putSpy).toHaveBeenCalledWith(
        "ns:persisted",
        expect.objectContaining({
          namespace: "ns",
          value: { data: "hello" },
          _key: "ns:persisted",
        }),
      );
    } finally {
      idbMemory.dispose();
    }
  });
});

// ---------------------------------------------------------------------------
// Guarded writes
// ---------------------------------------------------------------------------

describe("guarded", () => {
  let events: TypedEventEmitter<SwarmEngineEventMap>;

  beforeEach(() => {
    events = new TypedEventEmitter<SwarmEngineEventMap>();
  });

  it("deny evaluator: store() returns false, entry not persisted", async () => {
    const memory = new SharedMemory(events, {
      guardEvaluator: makeDenyEvaluator(),
      dimensions: 3,
    });

    const result = await memory.store("ns", "key", "secret");
    expect(result).toBe(false);
    expect(memory.get("ns", "key")).toBeUndefined();
    memory.dispose();
  });

  it("allow evaluator: store() returns true, entry persisted", async () => {
    const memory = new SharedMemory(events, {
      guardEvaluator: makeAllowEvaluator(),
      dimensions: 3,
    });

    const result = await memory.store("ns", "key", "data");
    expect(result).toBe(true);
    expect(memory.get("ns", "key")).toBeDefined();
    memory.dispose();
  });

  it("no evaluator: store() returns false (fail-closed)", async () => {
    const memory = new SharedMemory(events, { dimensions: 3 });

    const result = await memory.store("ns", "key", "data");
    expect(result).toBe(false);
    expect(memory.get("ns", "key")).toBeUndefined();
    memory.dispose();
  });

  it("SharedMemory without evaluator rejects writes (fail-closed, C-02)", async () => {
    const memory = new SharedMemory(events, { dimensions: 3 });

    const result = await memory.store("ns", "key", "sensitive-data");
    expect(result).toBe(false);
    expect(memory.get("ns", "key")).toBeUndefined();
    memory.dispose();
  });

  it("GuardedAction has actionType file_write and target memory://", async () => {
    let captured: GuardedAction | undefined;
    const spy: GuardEvaluator = {
      async evaluate(action: GuardedAction): Promise<GuardEvaluationResult> {
        captured = action;
        return {
          verdict: "allow",
          allowed: true,
          guardResults: [],
          receipt: {
            id: "r_spy",
            timestamp: new Date().toISOString(),
            verdict: "allow",
            guard: "spy-guard",
            valid: true,
            policyName: "test",
            action: { type: action.actionType, target: action.target },
            evidence: {},
            signature: "sig",
            publicKey: "pk",
          },
          durationMs: 0,
          evaluatedAt: Date.now(),
        };
      },
    };

    const memory = new SharedMemory(events, {
      guardEvaluator: spy,
      dimensions: 3,
    });

    await memory.store("myns", "mykey", "val");

    expect(captured).toBeDefined();
    expect(captured!.actionType).toBe("file_write");
    expect(captured!.target).toBe("memory://myns/mykey");
    memory.dispose();
  });

  it("memory.store event fires on success, not on deny", async () => {
    const storeEvents: unknown[] = [];
    events.on("memory.store", (e) => storeEvents.push(e));

    // Deny case: no event
    const denyMem = new SharedMemory(events, {
      guardEvaluator: makeDenyEvaluator(),
      dimensions: 3,
    });
    await denyMem.store("ns", "k", "v");
    expect(storeEvents).toHaveLength(0);
    denyMem.dispose();

    // Allow case: event fires
    const allowMem = new SharedMemory(events, {
      guardEvaluator: makeAllowEvaluator(),
      dimensions: 3,
    });
    await allowMem.store("ns", "k", "v");
    expect(storeEvents).toHaveLength(1);
    allowMem.dispose();
  });
});
