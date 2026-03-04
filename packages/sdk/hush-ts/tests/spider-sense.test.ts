import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { SpiderSenseDetector, type PatternEntry } from "../src/spider-sense";
import { SpiderSenseGuard } from "../src/guards/spider-sense";
import { GuardAction, GuardContext } from "../src/guards/types";

// biome-ignore lint/suspicious/noExplicitAny: vitest global from setup.ts
const wasmAvailable = (globalThis as any).__WASM_SPIDER_SENSE_AVAILABLE__ as boolean;

const testPatterns: PatternEntry[] = [
  {
    id: "p1",
    category: "prompt_injection",
    stage: "perception",
    label: "ignore previous",
    embedding: [1.0, 0.0, 0.0],
  },
  {
    id: "p2",
    category: "data_exfiltration",
    stage: "action",
    label: "exfil data",
    embedding: [0.0, 1.0, 0.0],
  },
  {
    id: "p3",
    category: "privilege_escalation",
    stage: "cognition",
    label: "escalate",
    embedding: [0.0, 0.0, 1.0],
  },
];

describe.skipIf(!wasmAvailable)("spider-sense detection", () => {
  it("constructs with default config", () => {
    const d = new SpiderSenseDetector();
    expect(d.patternCount()).toBe(0);
    expect(d.expectedDim()).toBeUndefined();
  });

  it("constructs with custom config", () => {
    const d = new SpiderSenseDetector({
      similarityThreshold: 0.90,
      ambiguityBand: 0.05,
      topK: 3,
    });
    expect(d.patternCount()).toBe(0);
  });

  it("loads patterns and reports count and dimension", () => {
    const d = new SpiderSenseDetector();
    d.loadPatterns(testPatterns);
    expect(d.patternCount()).toBe(3);
    expect(d.expectedDim()).toBe(3);
  });

  it("screens identical vectors as deny", () => {
    const d = new SpiderSenseDetector();
    d.loadPatterns(testPatterns);
    const result = d.screen([1.0, 0.0, 0.0]);
    expect(result.verdict).toBe("deny");
    expect(result.topScore).toBeCloseTo(1.0, 5);
    expect(result.topMatches.length).toBeGreaterThan(0);
    expect(result.topMatches[0].entry.id).toBe("p1");
  });

  it("screens orthogonal vectors as allow", () => {
    const d = new SpiderSenseDetector();
    d.loadPatterns(testPatterns);
    // This vector is equidistant from all basis vectors (cos sim ~0.577)
    // With default threshold 0.85 and band 0.10, lower bound is 0.75
    // 0.577 < 0.75 => allow
    const result = d.screen([0.577, 0.577, 0.577]);
    expect(result.verdict).toBe("allow");
    expect(result.topScore).toBeLessThan(0.75);
  });

  it("screens ambiguous vectors correctly", () => {
    const d = new SpiderSenseDetector({
      similarityThreshold: 0.50,
      ambiguityBand: 0.10,
      topK: 5,
    });
    d.loadPatterns(testPatterns);
    // Equidistant vector: cos sim ~0.577, within band [0.40, 0.60]
    const result = d.screen([0.577, 0.577, 0.577]);
    expect(result.verdict).toBe("ambiguous");
    expect(result.topScore).toBeGreaterThan(0.40);
    expect(result.topScore).toBeLessThan(0.60);
  });

  it("returns result shape with expected fields", () => {
    const d = new SpiderSenseDetector();
    d.loadPatterns(testPatterns);
    const result = d.screen([1.0, 0.0, 0.0]);
    expect(result).toHaveProperty("verdict");
    expect(result).toHaveProperty("topScore");
    expect(result).toHaveProperty("threshold");
    expect(result).toHaveProperty("ambiguityBand");
    expect(result).toHaveProperty("topMatches");
    expect(Array.isArray(result.topMatches)).toBe(true);
  });

  it("throws when screening without loaded patterns", () => {
    const d = new SpiderSenseDetector();
    expect(() => d.screen([1.0, 0.0, 0.0])).toThrow(/patterns/i);
  });

  it("respects topK config", () => {
    const d = new SpiderSenseDetector({ topK: 1 });
    d.loadPatterns(testPatterns);
    const result = d.screen([1.0, 0.0, 0.0]);
    expect(result.topMatches.length).toBe(1);
  });

  it("rejects empty patterns array", () => {
    const d = new SpiderSenseDetector();
    expect(() => d.loadPatterns([])).toThrow();
  });

  it("rejects dimension mismatch in patterns", () => {
    const d = new SpiderSenseDetector();
    const bad: PatternEntry[] = [
      { id: "a", category: "x", stage: "y", label: "z", embedding: [1.0, 0.0] },
      { id: "b", category: "x", stage: "y", label: "z", embedding: [1.0, 0.0, 0.0] },
    ];
    expect(() => d.loadPatterns(bad)).toThrow(/dimension/i);
  });

  it("returns topMatches with entry and score fields", () => {
    const d = new SpiderSenseDetector();
    d.loadPatterns(testPatterns);
    const result = d.screen([1.0, 0.0, 0.0]);
    const match = result.topMatches[0];
    expect(match).toHaveProperty("entry");
    expect(match).toHaveProperty("score");
    expect(match.entry).toHaveProperty("id");
    expect(match.entry).toHaveProperty("category");
    expect(match.entry).toHaveProperty("stage");
    expect(match.entry).toHaveProperty("label");
    expect(match.entry).toHaveProperty("embedding");
    expect(typeof match.score).toBe("number");
  });

  it("rejects invalid config values", () => {
    // Threshold outside [0, 1] should fail
    expect(
      () => {
        const d = new SpiderSenseDetector({ similarityThreshold: 1.5 });
        d.loadPatterns(testPatterns);
      },
    ).toThrow();
  });
});

describe("spider-sense guard", () => {
  const ctx = new GuardContext();

  function makeGuard(): SpiderSenseGuard {
    const guard = new SpiderSenseGuard();
    guard.loadPatterns(testPatterns);
    return guard;
  }

  it("handles all action types", () => {
    const guard = makeGuard();
    expect(guard.handles(GuardAction.fileAccess("/tmp/test"))).toBe(true);
    expect(guard.handles(GuardAction.shellCommand("ls"))).toBe(true);
    expect(guard.handles(GuardAction.custom("any_type", {}))).toBe(true);
  });

  it("allows when no embedding is present", async () => {
    const guard = makeGuard();
    const action = GuardAction.custom("test", { text: "hello" });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(true);
  });

  it("blocks when embedding matches a threat pattern", async () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [1.0, 0.0, 0.0] },
    });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(false);
    expect(result.message).toContain("threat detected");
    expect(result.details?.verdict).toBe("deny");
  });

  it("warns on ambiguous embeddings", async () => {
    const guard = new SpiderSenseGuard({
      similarityThreshold: 0.50,
      ambiguityBand: 0.10,
    });
    guard.loadPatterns(testPatterns);
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [0.577, 0.577, 0.577] },
    });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe("warning");
    expect(result.details?.verdict).toBe("ambiguous");
  });

  it("allows safe embeddings", async () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [0.577, 0.577, 0.577] },
    });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe("info");
  });

  it("allows when disabled", async () => {
    const guard = new SpiderSenseGuard({ enabled: false });
    guard.loadPatterns(testPatterns);
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [1.0, 0.0, 0.0] },
    });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(true);
  });

  it("ignores non-array embedding data", async () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: "not an array" },
    });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(true);
  });

  it("includes details on block result", async () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [1.0, 0.0, 0.0] },
    });
    const result = await guard.check(action, ctx);
    expect(result.details).toBeDefined();
    expect(result.details?.top_score).toBeCloseTo(1.0, 5);
    expect(result.details?.threshold).toBeDefined();
    expect(result.details?.ambiguity_band).toBeDefined();
    expect(Array.isArray(result.details?.top_matches)).toBe(true);
  });

  it("allows when patterns are not loaded", async () => {
    const guard = new SpiderSenseGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [1.0, 0.0, 0.0] },
    });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(true);
  });

  it("ignores mixed-type arrays in embedding data", async () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [1.0, "bad", 0.0] },
    });
    const result = await guard.check(action, ctx);
    // extractEmbedding validates every element is a number
    expect(result.allowed).toBe(true);
  });

  it("ignores null customData", async () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
    });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(true);
  });

  it("ignores empty embedding array", async () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [] },
    });
    const result = await guard.check(action, ctx);
    expect(result.allowed).toBe(false);
  });

  it("uses embedding provider when action embedding is missing", async () => {
    const guard = new SpiderSenseGuard({
      patterns: testPatterns,
      embeddingApiUrl: "https://api.openai.com/v1/embeddings",
      embeddingApiKey: "test-key",
      embeddingModel: "text-embedding-3-small",
      fetchFn: async () =>
        new Response(
          JSON.stringify({
            data: [{ embedding: [1.0, 0.0, 0.0] }],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    });
    const result = await guard.check(GuardAction.custom("user_input", { text: "hello" }), ctx);
    expect(result.allowed).toBe(false);
    expect(result.details?.embedding_from).toBe("provider");
  });

  it("fails closed on provider failure", async () => {
    const guard = new SpiderSenseGuard({
      patterns: testPatterns,
      embeddingApiUrl: "https://api.openai.com/v1/embeddings",
      embeddingApiKey: "test-key",
      embeddingModel: "text-embedding-3-small",
      fetchFn: async () => new Response("boom", { status: 500 }),
    });
    const result = await guard.check(GuardAction.custom("user_input", { text: "hello" }), ctx);
    expect(result.allowed).toBe(false);
    expect(result.message).toContain("provider error");
  });

  it("validates pattern DB checksum for path-based loading", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "spider-sense-ts-"));
    const dbPath = path.join(dir, "patterns.json");
    const dbJson = JSON.stringify([
      {
        id: "p1",
        category: "prompt_injection",
        stage: "perception",
        label: "ignore previous",
        embedding: [1.0, 0.0, 0.0],
      },
    ]);
    await writeFile(dbPath, dbJson, "utf8");
    const checksum = createHash("sha256").update(dbJson).digest("hex");

    const guard = new SpiderSenseGuard({
      patternDbPath: dbPath,
      patternDbVersion: "test-v1",
      patternDbChecksum: checksum,
    });
    const result = await guard.check(
      GuardAction.custom("embedding_check", { embedding: [1.0, 0.0, 0.0] }),
      ctx,
    );
    expect(result.allowed).toBe(false);

    expect(
      () =>
        new SpiderSenseGuard({
          patternDbPath: dbPath,
          patternDbVersion: "test-v1",
          patternDbChecksum: "deadbeef",
        }),
    ).not.toThrow();
    await expect(
      new SpiderSenseGuard({
        patternDbPath: dbPath,
        patternDbVersion: "test-v1",
        patternDbChecksum: "deadbeef",
      }).check(GuardAction.custom("embedding_check", { embedding: [1.0, 0.0, 0.0] }), ctx),
    ).rejects.toThrow(/checksum mismatch/i);

    await rm(dir, { recursive: true, force: true });
  });

  it("emits metrics snapshots", async () => {
    const events: Array<Record<string, unknown>> = [];
    const guard = new SpiderSenseGuard({
      patterns: testPatterns,
      metricsHook: (event) => events.push(event as unknown as Record<string, unknown>),
    });
    await guard.check(GuardAction.custom("embedding_check", { embedding: [1.0, 0.0, 0.0] }), ctx);
    await guard.check(
      GuardAction.custom("embedding_check", { embedding: [0.577, 0.577, 0.577] }),
      ctx,
    );
    expect(events.length).toBe(2);
    expect(events[1].total_count).toBe(2);
    expect(events[1]).toHaveProperty("ambiguity_rate");
  });
});
