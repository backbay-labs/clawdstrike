import { ensureWasmSync, getWasmModule } from "./crypto/backend.js";
import { toSnakeCaseKeys } from "./case-convert.js";

export type ScreeningVerdict = "deny" | "ambiguous" | "allow";

export interface PatternEntry {
  id: string;
  category: string;
  stage: string;
  label: string;
  embedding: number[];
}

export interface PatternMatchResult {
  entry: PatternEntry;
  score: number;
}

export interface ScreeningResult {
  verdict: ScreeningVerdict;
  topScore: number;
  threshold: number;
  ambiguityBand: number;
  topMatches: PatternMatchResult[];
}

export interface SpiderSenseDetectorConfig {
  similarityThreshold?: number;
  ambiguityBand?: number;
  topK?: number;
}

/**
 * Spider-Sense detector backed by Rust compiled to WASM.
 * Screens embedding vectors against a pre-computed pattern database
 * using cosine similarity.
 *
 * WASM is loaded lazily on construction.
 */
export class SpiderSenseDetector {
  // biome-ignore lint/suspicious/noExplicitAny: WasmSpiderSenseDetector is untyped
  private readonly inner: any;

  constructor(config?: SpiderSenseDetectorConfig) {
    ensureWasmSync();
    const wasm = getWasmModule();
    if (!wasm?.WasmSpiderSenseDetector) {
      throw new Error(
        "WASM backend does not expose SpiderSenseDetector APIs.",
      );
    }
    const RUST_FIELDS = new Set([
      "similarityThreshold", "ambiguityBand", "topK",
    ]);
    const filtered: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(config ?? {})) {
      if (RUST_FIELDS.has(k) && v !== undefined) filtered[k] = v;
    }
    const hasConfig = Object.keys(filtered).length > 0;
    this.inner = new wasm.WasmSpiderSenseDetector(
      hasConfig ? JSON.stringify(toSnakeCaseKeys(filtered)) : undefined,
    );
  }

  /**
   * Load a pattern database from an array of pattern entries.
   *
   * @param patterns - Array of pattern entries with pre-computed embeddings.
   */
  loadPatterns(patterns: PatternEntry[]): void {
    this.inner.load_patterns(JSON.stringify(patterns));
  }

  /**
   * Screen an embedding vector against the loaded pattern database.
   *
   * @param embedding - Array of f32 values representing the embedding to screen.
   * @returns Structured screening result with verdict and top matches.
   */
  screen(embedding: number[]): ScreeningResult {
    const json: string = this.inner.screen(JSON.stringify(embedding));
    return JSON.parse(json) as ScreeningResult;
  }

  /**
   * Get the expected embedding dimension from the loaded pattern database.
   *
   * @returns The expected dimension, or undefined if no patterns are loaded.
   */
  expectedDim(): number | undefined {
    return this.inner.expected_dim() ?? undefined;
  }

  /**
   * Get the number of patterns in the loaded database.
   *
   * @returns The number of patterns, or 0 if no patterns are loaded.
   */
  patternCount(): number {
    return this.inner.pattern_count();
  }
}
