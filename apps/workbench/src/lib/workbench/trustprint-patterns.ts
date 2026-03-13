/**
 * Spider Sense pattern database types and demo data (s2bench-v1 format).
 *
 * The S2Bench v1 database contains 36 entries: 4 stages x 9 categories,
 * each with 3-dimensional demo embeddings.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PatternEntry {
  id: string;
  category: PatternCategory;
  stage: PatternStage;
  label: string;
  embedding: number[];
}

export type PatternCategory =
  | "prompt_injection"
  | "jailbreak"
  | "social_engineering"
  | "data_poisoning"
  | "evasion"
  | "reconnaissance"
  | "supply_chain"
  | "data_exfiltration"
  | "privilege_escalation";

export type PatternStage =
  | "perception"
  | "cognition"
  | "action"
  | "feedback";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const ALL_STAGES: PatternStage[] = [
  "perception",
  "cognition",
  "action",
  "feedback",
];

export const ALL_CATEGORIES: PatternCategory[] = [
  "prompt_injection",
  "jailbreak",
  "social_engineering",
  "data_poisoning",
  "evasion",
  "reconnaissance",
  "supply_chain",
  "data_exfiltration",
  "privilege_escalation",
];

export const STAGE_LABELS: Record<PatternStage, string> = {
  perception: "Perception",
  cognition: "Cognition",
  action: "Action",
  feedback: "Feedback",
};

export const CATEGORY_LABELS: Record<PatternCategory, string> = {
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

export const CATEGORY_SHORT_LABELS: Record<PatternCategory, string> = {
  prompt_injection: "Prompt Inj",
  jailbreak: "Jailbreak",
  social_engineering: "Social Eng",
  data_poisoning: "Data Poison",
  evasion: "Evasion",
  reconnaissance: "Recon",
  supply_chain: "Supply Chain",
  data_exfiltration: "Data Exfil",
  privilege_escalation: "Priv Esc",
};

// ---------------------------------------------------------------------------
// S2Bench v1 demo data (mirrors rulesets/patterns/s2bench-v1.json)
// ---------------------------------------------------------------------------

export const S2BENCH_PATTERNS: PatternEntry[] = [
  // Perception stage
  { id: "s2b-perception-prompt_injection", category: "prompt_injection", stage: "perception", label: "Prompt injection via system override", embedding: [0.95, 0.05, 0.0] },
  { id: "s2b-perception-jailbreak", category: "jailbreak", stage: "perception", label: "Jailbreak attempt via role-play", embedding: [0.90, 0.10, 0.05] },
  { id: "s2b-perception-social_engineering", category: "social_engineering", stage: "perception", label: "Social engineering lure", embedding: [0.80, 0.20, 0.10] },
  { id: "s2b-perception-data_poisoning", category: "data_poisoning", stage: "perception", label: "Training data poisoning probe", embedding: [0.70, 0.25, 0.15] },
  { id: "s2b-perception-evasion", category: "evasion", stage: "perception", label: "Evasion via encoding obfuscation", embedding: [0.85, 0.10, 0.10] },
  { id: "s2b-perception-reconnaissance", category: "reconnaissance", stage: "perception", label: "Capability reconnaissance probe", embedding: [0.75, 0.15, 0.20] },
  { id: "s2b-perception-supply_chain", category: "supply_chain", stage: "perception", label: "Malicious dependency injection", embedding: [0.65, 0.30, 0.10] },
  { id: "s2b-perception-data_exfiltration", category: "data_exfiltration", stage: "perception", label: "Data exfiltration via prompt leak", embedding: [0.60, 0.35, 0.05] },
  { id: "s2b-perception-privilege_escalation", category: "privilege_escalation", stage: "perception", label: "Privilege escalation via context manipulation", embedding: [0.55, 0.40, 0.05] },

  // Cognition stage
  { id: "s2b-cognition-prompt_injection", category: "prompt_injection", stage: "cognition", label: "Instruction hijack in reasoning", embedding: [0.05, 0.95, 0.0] },
  { id: "s2b-cognition-jailbreak", category: "jailbreak", stage: "cognition", label: "Logic bypass via hypothetical framing", embedding: [0.10, 0.90, 0.05] },
  { id: "s2b-cognition-social_engineering", category: "social_engineering", stage: "cognition", label: "Authority impersonation in reasoning", embedding: [0.20, 0.80, 0.10] },
  { id: "s2b-cognition-data_poisoning", category: "data_poisoning", stage: "cognition", label: "Bias injection in chain-of-thought", embedding: [0.25, 0.70, 0.15] },
  { id: "s2b-cognition-evasion", category: "evasion", stage: "cognition", label: "Semantic evasion in reasoning", embedding: [0.10, 0.85, 0.10] },
  { id: "s2b-cognition-reconnaissance", category: "reconnaissance", stage: "cognition", label: "Internal state probing", embedding: [0.15, 0.75, 0.20] },
  { id: "s2b-cognition-supply_chain", category: "supply_chain", stage: "cognition", label: "Tool trust manipulation", embedding: [0.30, 0.65, 0.10] },
  { id: "s2b-cognition-data_exfiltration", category: "data_exfiltration", stage: "cognition", label: "Memory extraction via reasoning", embedding: [0.35, 0.60, 0.05] },
  { id: "s2b-cognition-privilege_escalation", category: "privilege_escalation", stage: "cognition", label: "Role escalation in reasoning", embedding: [0.40, 0.55, 0.05] },

  // Action stage
  { id: "s2b-action-prompt_injection", category: "prompt_injection", stage: "action", label: "Action hijack via injected tool call", embedding: [0.0, 0.05, 0.95] },
  { id: "s2b-action-jailbreak", category: "jailbreak", stage: "action", label: "Unauthorized action execution", embedding: [0.05, 0.10, 0.90] },
  { id: "s2b-action-social_engineering", category: "social_engineering", stage: "action", label: "Deceptive output generation", embedding: [0.10, 0.20, 0.80] },
  { id: "s2b-action-data_poisoning", category: "data_poisoning", stage: "action", label: "Malicious file write", embedding: [0.15, 0.25, 0.70] },
  { id: "s2b-action-evasion", category: "evasion", stage: "action", label: "Detection bypass in tool use", embedding: [0.10, 0.10, 0.85] },
  { id: "s2b-action-reconnaissance", category: "reconnaissance", stage: "action", label: "Environment probing via tools", embedding: [0.20, 0.15, 0.75] },
  { id: "s2b-action-supply_chain", category: "supply_chain", stage: "action", label: "Dependency download from untrusted source", embedding: [0.10, 0.30, 0.65] },
  { id: "s2b-action-data_exfiltration", category: "data_exfiltration", stage: "action", label: "Data exfiltration via network egress", embedding: [0.05, 0.35, 0.60] },
  { id: "s2b-action-privilege_escalation", category: "privilege_escalation", stage: "action", label: "Shell escape for privilege escalation", embedding: [0.05, 0.40, 0.55] },

  // Feedback stage
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
// Analysis helpers
// ---------------------------------------------------------------------------

export interface HeatmapCell {
  stage: PatternStage;
  category: PatternCategory;
  count: number;
  patternIds: string[];
}

export interface GapInfo {
  stage: PatternStage;
  category: PatternCategory;
  stageLabel: string;
  categoryLabel: string;
}

/**
 * Build a 4x9 heatmap from the given patterns.
 * Returns a flat array of cells (row-major: categories are rows, stages are columns).
 */
export function buildHeatmap(patterns: PatternEntry[]): HeatmapCell[] {
  const cells: HeatmapCell[] = [];
  for (const category of ALL_CATEGORIES) {
    for (const stage of ALL_STAGES) {
      const matching = patterns.filter(
        (p) => p.category === category && p.stage === stage,
      );
      cells.push({
        stage,
        category,
        count: matching.length,
        patternIds: matching.map((p) => p.id),
      });
    }
  }
  return cells;
}

/**
 * Detect gaps (stage+category pairs with zero patterns).
 */
export function detectGaps(patterns: PatternEntry[]): GapInfo[] {
  const gaps: GapInfo[] = [];
  for (const category of ALL_CATEGORIES) {
    for (const stage of ALL_STAGES) {
      const hasPattern = patterns.some(
        (p) => p.category === category && p.stage === stage,
      );
      if (!hasPattern) {
        gaps.push({
          stage,
          category,
          stageLabel: STAGE_LABELS[stage],
          categoryLabel: CATEGORY_LABELS[category],
        });
      }
    }
  }
  return gaps;
}

/**
 * Compute total coverage stats.
 */
export function computeCoverageStats(patterns: PatternEntry[]): {
  totalCells: number;
  coveredCells: number;
  gapCount: number;
} {
  const totalCells = ALL_STAGES.length * ALL_CATEGORIES.length;
  const gaps = detectGaps(patterns);
  return {
    totalCells,
    coveredCells: totalCells - gaps.length,
    gapCount: gaps.length,
  };
}
