// ---------------------------------------------------------------------------
// Trustprint Screening Engine (Demo Mode)
//
// Provides deterministic Spider Sense screening using the S2Bench v1 pattern
// DB with 3-dim demo embeddings.  Input text is hashed to generate a fake
// embedding and real cosine similarity is computed against all 36 patterns.
// ---------------------------------------------------------------------------

import type { SpiderSenseConfig } from "./types";
import {
  S2BENCH_PATTERNS,
  CATEGORY_LABELS,
  STAGE_LABELS,
} from "./trustprint-patterns";

// Re-export for consumers that import from this module
export { S2BENCH_PATTERNS, CATEGORY_LABELS, STAGE_LABELS };

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ScreeningInput {
  text: string;
  actionType: string;
}

export interface PatternMatch {
  id: string;
  category: string;
  stage: string;
  label: string;
  score: number;
}

export interface ScreeningResult {
  verdict: "allow" | "ambiguous" | "deny";
  topScore: number;
  threshold: number;
  ambiguityBand: number;
  topMatches: PatternMatch[];
  screeningTimeMs: number;
}

export interface ScreeningHistoryEntry {
  id: string;
  timestamp: string;
  textPreview: string;
  actionType: string;
  result: ScreeningResult;
}

// ---------------------------------------------------------------------------
// Category display colors (not in patterns module since it's UI-only)
// ---------------------------------------------------------------------------

export const CATEGORY_COLORS: Record<string, string> = {
  prompt_injection: "#c45c5c",
  jailbreak: "#e06050",
  social_engineering: "#d4a84b",
  data_poisoning: "#9b7dd4",
  evasion: "#6f7f9a",
  reconnaissance: "#5c9ac4",
  supply_chain: "#c48a5c",
  data_exfiltration: "#c45c8a",
  privilege_escalation: "#5cc4a8",
};

// ---------------------------------------------------------------------------
// Math helpers
// ---------------------------------------------------------------------------

/** Cosine similarity between two vectors. Returns 0 for zero-magnitude vectors. */
export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length || a.length === 0) return 0;

  let dot = 0;
  let magA = 0;
  let magB = 0;

  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    magA += a[i] * a[i];
    magB += b[i] * b[i];
  }

  const denom = Math.sqrt(magA) * Math.sqrt(magB);
  if (denom === 0) return 0;

  return dot / denom;
}

// ---------------------------------------------------------------------------
// Deterministic demo embedding generation
// ---------------------------------------------------------------------------

/** Simple 32-bit hash (djb2 variant). */
function hashString(str: string): number {
  let hash = 5381;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) + hash + str.charCodeAt(i)) | 0;
  }
  return hash >>> 0;
}

/** Normalize a hash to [0, 1). */
function hashToFloat(hash: number, salt: number): number {
  const mixed = ((hash ^ (salt * 2654435761)) >>> 0) % 1000000;
  return mixed / 1000000;
}

/**
 * Attack-like keywords that bias the embedding toward known threat patterns.
 * Kept case-insensitive during matching.
 */
const ATTACK_KEYWORDS: ReadonlyArray<{ keyword: string; stage: "perception" | "cognition" | "action" | "feedback" }> = [
  // perception stage (high dim-0)
  { keyword: "ignore previous", stage: "perception" },
  { keyword: "ignore all", stage: "perception" },
  { keyword: "ignore your", stage: "perception" },
  { keyword: "ignore safety", stage: "perception" },
  { keyword: "system prompt", stage: "perception" },
  { keyword: "you are now", stage: "perception" },
  { keyword: "disregard", stage: "perception" },
  { keyword: "new instructions", stage: "perception" },
  { keyword: "override", stage: "perception" },
  { keyword: "pretend you", stage: "perception" },
  { keyword: "act as if", stage: "perception" },
  { keyword: "safety guidelines", stage: "perception" },
  { keyword: "forget your", stage: "perception" },
  // cognition stage (high dim-1)
  { keyword: "hypothetically", stage: "cognition" },
  { keyword: "imagine", stage: "cognition" },
  { keyword: "roleplay", stage: "cognition" },
  { keyword: "in theory", stage: "cognition" },
  { keyword: "what if", stage: "cognition" },
  { keyword: "bypass", stage: "cognition" },
  // action stage (high dim-2)
  { keyword: "rm -rf", stage: "action" },
  { keyword: "exfiltrate", stage: "action" },
  { keyword: "exfil", stage: "action" },
  { keyword: "curl", stage: "action" },
  { keyword: "wget", stage: "action" },
  { keyword: "eval(", stage: "action" },
  { keyword: "exec(", stage: "action" },
  { keyword: "sudo", stage: "action" },
  { keyword: "chmod", stage: "action" },
  { keyword: "/etc/passwd", stage: "action" },
  { keyword: "/etc/shadow", stage: "action" },
  { keyword: ".ssh", stage: "action" },
  { keyword: "api key", stage: "action" },
  { keyword: "api_key", stage: "action" },
  { keyword: "apikey", stage: "action" },
  { keyword: "send to my", stage: "action" },
  { keyword: "sends them to", stage: "action" },
  { keyword: "extract", stage: "action" },
  { keyword: "environment variable", stage: "action" },
  { keyword: "env var", stage: "action" },
  { keyword: "secret key", stage: "action" },
  { keyword: "private key", stage: "action" },
  { keyword: "credentials", stage: "action" },
  { keyword: "password", stage: "action" },
  // feedback stage (spread dims)
  { keyword: "repeat", stage: "feedback" },
  { keyword: "confirm", stage: "feedback" },
  { keyword: "reinforce", stage: "feedback" },
];

/**
 * Generate a deterministic 3-dim demo embedding from input text.
 *
 * For attack-like text, the embedding is biased toward the relevant stage's
 * cluster center (all positive components, matching S2Bench patterns).
 *
 * For benign text, the embedding uses all-negative components.  Since all
 * S2Bench pattern embeddings are non-negative, an all-negative vector is
 * guaranteed to have non-positive cosine similarity against every pattern,
 * making false positives impossible regardless of the angle.
 */
export function generateDemoEmbedding(text: string): [number, number, number] {
  const lower = text.toLowerCase();
  const h = hashString(text);

  // Count keyword hits and determine dominant stage
  const stageCounts: Record<string, number> = {
    perception: 0,
    cognition: 0,
    action: 0,
    feedback: 0,
  };

  let totalHits = 0;
  for (const { keyword, stage } of ATTACK_KEYWORDS) {
    if (lower.includes(keyword)) {
      stageCounts[stage]++;
      totalHits++;
    }
  }

  if (totalHits === 0) {
    // Benign text: produce a vector with ALL negative components so that
    // cosine similarity against all-positive S2Bench patterns is always
    // non-positive.  The hash varies the magnitude per dimension while
    // keeping the result deterministic.
    const base0 = -(hashToFloat(h, 1) * 0.4 + 0.10);   // range: -0.50 to -0.10
    const base1 = -(hashToFloat(h, 2) * 0.4 + 0.10);   // range: -0.50 to -0.10
    const base2 = -(hashToFloat(h, 3) * 0.4 + 0.10);   // range: -0.50 to -0.10
    return [base0, base1, base2];
  }

  // Attack text: bias toward the dominant stage
  const dominantStage = (Object.entries(stageCounts) as [string, number][])
    .sort((a, b) => b[1] - a[1])[0][0];

  // Attack intensity grows with keyword count
  const intensity = Math.min(0.95, 0.55 + totalHits * 0.08);
  const secondary = (1 - intensity) / 2;

  // Add a small hash-based perturbation for variety
  const noise0 = hashToFloat(h, 10) * 0.05;
  const noise1 = hashToFloat(h, 20) * 0.05;
  const noise2 = hashToFloat(h, 30) * 0.05;

  switch (dominantStage) {
    case "perception":
      return [intensity + noise0, secondary + noise1, noise2];
    case "cognition":
      return [secondary + noise0, intensity + noise1, noise2];
    case "action":
      return [noise0, secondary + noise1, intensity + noise2];
    case "feedback":
      return [0.40 + noise0, 0.15 + noise1, 0.45 + noise2];
    default:
      return [intensity + noise0, secondary + noise1, noise2];
  }
}

// ---------------------------------------------------------------------------
// Screening Engine
// ---------------------------------------------------------------------------

/** Default config values matching the Rust Spider Sense / guard-registry defaults. */
const DEFAULT_THRESHOLD = 0.85;
const DEFAULT_AMBIGUITY_BAND = 0.10;
const DEFAULT_TOP_K = 5;

/**
 * Screen an action's text content against the S2Bench v1 pattern database.
 *
 * Uses deterministic demo embedding generation and real cosine similarity.
 * Results are consistent for the same input text.
 */
export function screenAction(
  input: ScreeningInput,
  config?: SpiderSenseConfig,
): ScreeningResult {
  const start = performance.now();

  const threshold = config?.similarity_threshold ?? DEFAULT_THRESHOLD;
  const ambiguityBand = config?.ambiguity_band ?? DEFAULT_AMBIGUITY_BAND;
  const topK = config?.top_k ?? DEFAULT_TOP_K;

  // Generate demo embedding for the input text
  const embedding = generateDemoEmbedding(input.text);

  // Compute cosine similarity against all patterns
  const scored: PatternMatch[] = S2BENCH_PATTERNS.map((p) => ({
    id: p.id,
    category: p.category,
    stage: p.stage,
    label: p.label,
    score: cosineSimilarity(embedding, p.embedding),
  }));

  // Sort by descending score
  scored.sort((a, b) => b.score - a.score);

  const topMatches = scored.slice(0, topK);
  const topScore = topMatches.length > 0 ? topMatches[0].score : 0;

  // Verdict determination
  let verdict: "allow" | "ambiguous" | "deny";
  if (topScore >= threshold) {
    verdict = "deny";
  } else if (topScore >= threshold - ambiguityBand) {
    verdict = "ambiguous";
  } else {
    verdict = "allow";
  }

  const screeningTimeMs = Math.round((performance.now() - start) * 100) / 100;

  return {
    verdict,
    topScore,
    threshold,
    ambiguityBand,
    topMatches,
    screeningTimeMs,
  };
}
