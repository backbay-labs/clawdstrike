// ---------------------------------------------------------------------------
// Trustprint Screening Engine (Demo Mode)
//
// Provides deterministic Spider Sense screening using the S2Bench v1 pattern
// DB with 3-dim demo embeddings.  Input text is hashed to generate a fake
// embedding and real cosine similarity is computed against all 36 patterns.
// ---------------------------------------------------------------------------

import type { SpiderSenseConfig } from "./types";

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
// S2Bench v1 Pattern Database (36 entries, 3-dim demo embeddings)
// ---------------------------------------------------------------------------

interface PatternEntry {
  id: string;
  category: string;
  stage: string;
  label: string;
  embedding: [number, number, number];
}

export const S2BENCH_PATTERNS: PatternEntry[] = [
  // perception stage (9 categories)
  { id: "s2b-perception-prompt_injection", category: "prompt_injection", stage: "perception", label: "Prompt injection via system override", embedding: [0.95, 0.05, 0.0] },
  { id: "s2b-perception-jailbreak", category: "jailbreak", stage: "perception", label: "Jailbreak attempt via role-play", embedding: [0.90, 0.10, 0.05] },
  { id: "s2b-perception-social_engineering", category: "social_engineering", stage: "perception", label: "Social engineering lure", embedding: [0.80, 0.20, 0.10] },
  { id: "s2b-perception-data_poisoning", category: "data_poisoning", stage: "perception", label: "Training data poisoning probe", embedding: [0.70, 0.25, 0.15] },
  { id: "s2b-perception-evasion", category: "evasion", stage: "perception", label: "Evasion via encoding obfuscation", embedding: [0.85, 0.10, 0.10] },
  { id: "s2b-perception-reconnaissance", category: "reconnaissance", stage: "perception", label: "Capability reconnaissance probe", embedding: [0.75, 0.15, 0.20] },
  { id: "s2b-perception-supply_chain", category: "supply_chain", stage: "perception", label: "Malicious dependency injection", embedding: [0.65, 0.30, 0.10] },
  { id: "s2b-perception-data_exfiltration", category: "data_exfiltration", stage: "perception", label: "Data exfiltration via prompt leak", embedding: [0.60, 0.35, 0.05] },
  { id: "s2b-perception-privilege_escalation", category: "privilege_escalation", stage: "perception", label: "Privilege escalation via context manipulation", embedding: [0.55, 0.40, 0.05] },
  // cognition stage
  { id: "s2b-cognition-prompt_injection", category: "prompt_injection", stage: "cognition", label: "Instruction hijack in reasoning", embedding: [0.05, 0.95, 0.0] },
  { id: "s2b-cognition-jailbreak", category: "jailbreak", stage: "cognition", label: "Logic bypass via hypothetical framing", embedding: [0.10, 0.90, 0.05] },
  { id: "s2b-cognition-social_engineering", category: "social_engineering", stage: "cognition", label: "Authority impersonation in reasoning", embedding: [0.20, 0.80, 0.10] },
  { id: "s2b-cognition-data_poisoning", category: "data_poisoning", stage: "cognition", label: "Bias injection in chain-of-thought", embedding: [0.25, 0.70, 0.15] },
  { id: "s2b-cognition-evasion", category: "evasion", stage: "cognition", label: "Semantic evasion in reasoning", embedding: [0.10, 0.85, 0.10] },
  { id: "s2b-cognition-reconnaissance", category: "reconnaissance", stage: "cognition", label: "Internal state probing", embedding: [0.15, 0.75, 0.20] },
  { id: "s2b-cognition-supply_chain", category: "supply_chain", stage: "cognition", label: "Tool trust manipulation", embedding: [0.30, 0.65, 0.10] },
  { id: "s2b-cognition-data_exfiltration", category: "data_exfiltration", stage: "cognition", label: "Memory extraction via reasoning", embedding: [0.35, 0.60, 0.05] },
  { id: "s2b-cognition-privilege_escalation", category: "privilege_escalation", stage: "cognition", label: "Role escalation in reasoning", embedding: [0.40, 0.55, 0.05] },
  // action stage
  { id: "s2b-action-prompt_injection", category: "prompt_injection", stage: "action", label: "Action hijack via injected tool call", embedding: [0.0, 0.05, 0.95] },
  { id: "s2b-action-jailbreak", category: "jailbreak", stage: "action", label: "Unauthorized action execution", embedding: [0.05, 0.10, 0.90] },
  { id: "s2b-action-social_engineering", category: "social_engineering", stage: "action", label: "Deceptive output generation", embedding: [0.10, 0.20, 0.80] },
  { id: "s2b-action-data_poisoning", category: "data_poisoning", stage: "action", label: "Malicious file write", embedding: [0.15, 0.25, 0.70] },
  { id: "s2b-action-evasion", category: "evasion", stage: "action", label: "Detection bypass in tool use", embedding: [0.10, 0.10, 0.85] },
  { id: "s2b-action-reconnaissance", category: "reconnaissance", stage: "action", label: "Environment probing via tools", embedding: [0.20, 0.15, 0.75] },
  { id: "s2b-action-supply_chain", category: "supply_chain", stage: "action", label: "Dependency download from untrusted source", embedding: [0.10, 0.30, 0.65] },
  { id: "s2b-action-data_exfiltration", category: "data_exfiltration", stage: "action", label: "Data exfiltration via network egress", embedding: [0.05, 0.35, 0.60] },
  { id: "s2b-action-privilege_escalation", category: "privilege_escalation", stage: "action", label: "Shell escape for privilege escalation", embedding: [0.05, 0.40, 0.55] },
  // feedback stage
  { id: "s2b-feedback-prompt_injection", category: "prompt_injection", stage: "feedback", label: "Feedback loop injection", embedding: [0.50, 0.05, 0.45] },
  { id: "s2b-feedback-jailbreak", category: "jailbreak", stage: "feedback", label: "Self-reinforcing jailbreak via feedback", embedding: [0.45, 0.10, 0.50] },
  { id: "s2b-feedback-social_engineering", category: "social_engineering", stage: "feedback", label: "Trust amplification via repeated feedback", embedding: [0.40, 0.20, 0.45] },
  { id: "s2b-feedback-data_poisoning", category: "data_poisoning", stage: "feedback", label: "Feedback-driven model drift", embedding: [0.35, 0.25, 0.40] },
  { id: "s2b-feedback-evasion", category: "evasion", stage: "feedback", label: "Adaptive evasion from feedback", embedding: [0.42, 0.12, 0.48] },
  { id: "s2b-feedback-reconnaissance", category: "reconnaissance", stage: "feedback", label: "Response analysis for reconnaissance", embedding: [0.40, 0.15, 0.50] },
  { id: "s2b-feedback-supply_chain", category: "supply_chain", stage: "feedback", label: "Supply chain persistence via feedback", embedding: [0.35, 0.30, 0.40] },
  { id: "s2b-feedback-data_exfiltration", category: "data_exfiltration", stage: "feedback", label: "Gradual data leak via feedback", embedding: [0.30, 0.35, 0.40] },
  { id: "s2b-feedback-privilege_escalation", category: "privilege_escalation", stage: "feedback", label: "Incremental privilege gain via feedback", embedding: [0.25, 0.40, 0.40] },
];

// ---------------------------------------------------------------------------
// Category display metadata
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

export const CATEGORY_LABELS: Record<string, string> = {
  prompt_injection: "Prompt Injection",
  jailbreak: "Jailbreak",
  social_engineering: "Social Engineering",
  data_poisoning: "Data Poisoning",
  evasion: "Evasion",
  reconnaissance: "Reconnaissance",
  supply_chain: "Supply Chain",
  data_exfiltration: "Data Exfiltration",
  privilege_escalation: "Privilege Escalation",
};

export const STAGE_LABELS: Record<string, string> = {
  perception: "Perception",
  cognition: "Cognition",
  action: "Action",
  feedback: "Feedback",
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
  { keyword: "system prompt", stage: "perception" },
  { keyword: "you are now", stage: "perception" },
  { keyword: "disregard", stage: "perception" },
  { keyword: "new instructions", stage: "perception" },
  { keyword: "override", stage: "perception" },
  { keyword: "pretend you", stage: "perception" },
  { keyword: "act as", stage: "perception" },
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
  { keyword: "curl", stage: "action" },
  { keyword: "wget", stage: "action" },
  { keyword: "eval(", stage: "action" },
  { keyword: "exec(", stage: "action" },
  { keyword: "sudo", stage: "action" },
  { keyword: "chmod", stage: "action" },
  { keyword: "/etc/passwd", stage: "action" },
  { keyword: "/etc/shadow", stage: "action" },
  { keyword: ".ssh", stage: "action" },
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
 * For benign text, the embedding uses a mix of positive and negative
 * components.  Since all S2Bench pattern embeddings are non-negative,
 * the negative components reduce cosine similarity to well below the
 * default threshold of 0.70.
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
    // Benign text: produce a vector with negative components so that
    // cosine similarity against all-positive S2Bench patterns stays low.
    // The hash controls which dimensions are negative and by how much,
    // keeping the result deterministic.
    const base0 = hashToFloat(h, 1) * 0.4 - 0.3;   // range: -0.3 to 0.1
    const base1 = hashToFloat(h, 2) * 0.4 - 0.2;   // range: -0.2 to 0.2
    const base2 = hashToFloat(h, 3) * 0.4 - 0.25;   // range: -0.25 to 0.15
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

/** Default config values matching the Rust Spider Sense defaults. */
const DEFAULT_THRESHOLD = 0.70;
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
