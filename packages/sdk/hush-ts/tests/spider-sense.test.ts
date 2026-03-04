import { describe, it, expect } from "vitest";

import { SpiderSenseDetector, type PatternEntry } from "../src/spider-sense";
import { SpiderSenseGuard } from "../src/guards/spider-sense";
import { GuardAction, GuardContext } from "../src/guards/types";

// biome-ignore lint/suspicious/noExplicitAny: vitest global from setup.ts
const wasmAvailable = (globalThis as any).__WASM_ADVANCED_AVAILABLE__ as boolean;

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

describe.skipIf(!wasmAvailable)("spider-sense guard", () => {
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

  it("allows when no embedding is present", () => {
    const guard = makeGuard();
    const action = GuardAction.custom("test", { text: "hello" });
    const result = guard.check(action, ctx);
    expect(result.allowed).toBe(true);
  });

  it("blocks when embedding matches a threat pattern", () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [1.0, 0.0, 0.0] },
    });
    const result = guard.check(action, ctx);
    expect(result.allowed).toBe(false);
    expect(result.message).toContain("threat detected");
    expect(result.details?.verdict).toBe("deny");
  });

  it("warns on ambiguous embeddings", () => {
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
    const result = guard.check(action, ctx);
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe("warning");
    expect(result.details?.verdict).toBe("ambiguous");
  });

  it("allows safe embeddings", () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [0.577, 0.577, 0.577] },
    });
    const result = guard.check(action, ctx);
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe("info");
  });

  it("allows when disabled", () => {
    const guard = new SpiderSenseGuard({ enabled: false });
    guard.loadPatterns(testPatterns);
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [1.0, 0.0, 0.0] },
    });
    const result = guard.check(action, ctx);
    expect(result.allowed).toBe(true);
  });

  it("ignores non-array embedding data", () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: "not an array" },
    });
    const result = guard.check(action, ctx);
    expect(result.allowed).toBe(true);
  });

  it("includes details on block result", () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [1.0, 0.0, 0.0] },
    });
    const result = guard.check(action, ctx);
    expect(result.details).toBeDefined();
    expect(result.details?.top_score).toBeCloseTo(1.0, 5);
    expect(result.details?.threshold).toBeDefined();
    expect(result.details?.ambiguity_band).toBeDefined();
    expect(result.details?.top_matches_count).toBeGreaterThan(0);
  });

  it("fails closed when patterns not loaded (deny)", () => {
    const guard = new SpiderSenseGuard();
    // No loadPatterns() call — screen() will throw
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [1.0, 0.0, 0.0] },
    });
    const result = guard.check(action, ctx);
    expect(result.allowed).toBe(false);
    expect(result.message).toContain("screening error");
  });

  it("ignores mixed-type arrays in embedding data", () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [1.0, "bad", 0.0] },
    });
    const result = guard.check(action, ctx);
    // extractEmbedding validates every element is a number
    expect(result.allowed).toBe(true);
  });

  it("ignores null customData", () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
    });
    const result = guard.check(action, ctx);
    expect(result.allowed).toBe(true);
  });

  it("ignores empty embedding array", () => {
    const guard = makeGuard();
    const action = new GuardAction({
      actionType: "custom",
      customType: "embedding_check",
      customData: { embedding: [] },
    });
    const result = guard.check(action, ctx);
    // Empty array passes the type check but screen() returns allow (0.0 score)
    expect(result.allowed).toBe(true);
  });
});
