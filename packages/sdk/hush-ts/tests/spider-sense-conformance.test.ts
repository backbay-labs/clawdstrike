import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { SpiderSenseGuard } from "../src/guards/spider-sense";
import { GuardAction, GuardContext } from "../src/guards/types";

interface SpiderSenseConformanceCheck {
  name: string;
  embedding: number[];
  expected_allowed: boolean;
  expected_severity: "info" | "warning" | "error" | "critical";
  expected_verdict: "allow" | "ambiguous" | "deny";
  expected_embedding_from: "action" | "provider";
  expected_analysis: string;
  expected_top_matches_len: number;
  top_score_min: number;
  top_score_max: number;
}

interface SpiderSenseConformanceVector {
  name: string;
  config: {
    similarity_threshold: number;
    ambiguity_band: number;
    top_k: number;
    patterns: Array<{
      id: string;
      category: string;
      stage: string;
      label: string;
      embedding: number[];
    }>;
  };
  checks: SpiderSenseConformanceCheck[];
}

describe("spider-sense conformance vectors", () => {
  const HERE = path.dirname(fileURLToPath(import.meta.url));
  const REPO_ROOT = path.resolve(HERE, "../../../../");

  it("matches shared spider-sense vectors", async () => {
    const vectorsPath = path.join(REPO_ROOT, "fixtures/spider-sense/conformance_vectors.json");
    const vectors = JSON.parse(fs.readFileSync(vectorsPath, "utf8")) as SpiderSenseConformanceVector[];

    for (const vector of vectors) {
      const guard = new SpiderSenseGuard({
        similarityThreshold: vector.config.similarity_threshold,
        ambiguityBand: vector.config.ambiguity_band,
        topK: vector.config.top_k,
        patterns: vector.config.patterns,
      });
      for (const check of vector.checks) {
        const result = await guard.check(
          GuardAction.custom("spider_sense", { embedding: check.embedding }),
          new GuardContext(),
        );
        expect(result.allowed, `${vector.name}:${check.name}:allowed`).toBe(check.expected_allowed);
        expect(result.severity, `${vector.name}:${check.name}:severity`).toBe(check.expected_severity);
        expect(result.details, `${vector.name}:${check.name}:details`).toBeTruthy();
        expect(result.details?.verdict, `${vector.name}:${check.name}:verdict`).toBe(
          check.expected_verdict,
        );
        expect(result.details?.embedding_from, `${vector.name}:${check.name}:embedding_from`).toBe(
          check.expected_embedding_from,
        );
        expect(result.details?.analysis, `${vector.name}:${check.name}:analysis`).toBe(
          check.expected_analysis,
        );
        const topScore = Number(result.details?.top_score ?? 0);
        expect(topScore, `${vector.name}:${check.name}:top_score_min`).toBeGreaterThanOrEqual(
          check.top_score_min,
        );
        expect(topScore, `${vector.name}:${check.name}:top_score_max`).toBeLessThanOrEqual(
          check.top_score_max,
        );
        expect(Array.isArray(result.details?.top_matches)).toBe(true);
        const topMatches = result.details?.top_matches as Array<Record<string, unknown>>;
        expect(topMatches.length, `${vector.name}:${check.name}:top_matches_len`).toBe(
          check.expected_top_matches_len,
        );
        expect(topMatches[0]).toHaveProperty("id");
        expect(topMatches[0]).toHaveProperty("category");
        expect(topMatches[0]).toHaveProperty("stage");
        expect(topMatches[0]).toHaveProperty("label");
        expect(topMatches[0]).toHaveProperty("score");
      }
    }
  });
});
