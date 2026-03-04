import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Clawdstrike } from "@clawdstrike/sdk";

type PolicyChoice = "baseline" | "hardened";
type DriftState = "normal" | "elevated" | "anomalous";
type SpiderVerdict = "deny" | "ambiguous" | "allow";

const THRESHOLD = 0.86;
const AMBIGUITY_BAND = 0.06;

interface BehaviorProfile {
  profile_id: string;
  role: string;
  embedding: number[];
  drift_warn_threshold: number;
  drift_deny_threshold: number;
}

interface Scenario {
  scenario_id: string;
  profile_id: string;
  description: string;
  action_text: string;
  embedding: number[];
}

interface PatternEntry {
  id: string;
  category: string;
  stage: string;
  label: string;
  embedding: number[];
}

interface SpiderTopMatch {
  id?: string;
  category?: string;
  stage?: string;
  label?: string;
}

interface NormalizedRow {
  scenario_id: string;
  profile_id: string;
  spider_verdict: SpiderVerdict;
  decision_status: string;
  severity: string;
  top_score: number;
  top_match: SpiderTopMatch;
  profile_similarity: number;
  profile_drift_score: number;
  profile_drift_state: DriftState;
  combined_recommendation: string;
}

function parseArgs(argv: string[]): { policy: PolicyChoice; json: boolean; scenario: string } {
  let policy: PolicyChoice = "baseline";
  let json = false;
  let scenario = "all";

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if ((token === "--policy" || token === "-p") && i + 1 < argv.length) {
      const value = argv[i + 1].toLowerCase();
      i += 1;
      if (value !== "baseline" && value !== "hardened") {
        throw new Error(`invalid --policy value: ${value}`);
      }
      policy = value;
      continue;
    }
    if ((token === "--scenario" || token === "-s") && i + 1 < argv.length) {
      scenario = argv[i + 1];
      i += 1;
      continue;
    }
    if (token === "--json") {
      json = true;
      continue;
    }
    if (token === "--help" || token === "-h") {
      printHelp();
      process.exit(0);
    }
    throw new Error(`unknown argument: ${token}`);
  }

  return { policy, json, scenario };
}

function printHelp(): void {
  console.log("Spider-Sense Threat Intel example (TypeScript)");
  console.log("");
  console.log("Usage:");
  console.log("  npm start -- [--policy baseline|hardened] [--scenario id|all] [--json]");
}

async function loadJson<T>(path: string): Promise<T> {
  const raw = await readFile(path, "utf8");
  return JSON.parse(raw) as T;
}

function cosine(a: number[], b: number[]): number {
  if (a.length !== b.length || a.length === 0) {
    return 0;
  }
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i += 1) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  const denom = Math.sqrt(na) * Math.sqrt(nb);
  if (!Number.isFinite(denom) || denom === 0) {
    return 0;
  }
  return dot / denom;
}

function screenEmbedding(embedding: number[], patterns: PatternEntry[]): { score: number; topMatch: SpiderTopMatch } {
  if (patterns.length === 0) {
    return { score: 0, topMatch: {} };
  }
  let bestScore = Number.NEGATIVE_INFINITY;
  let best: PatternEntry | null = null;
  for (const pattern of patterns) {
    const score = cosine(embedding, pattern.embedding);
    if (score > bestScore) {
      bestScore = score;
      best = pattern;
    }
  }
  return {
    score: Number.isFinite(bestScore) ? bestScore : 0,
    topMatch: best
      ? { id: best.id, category: best.category, stage: best.stage, label: best.label }
      : {},
  };
}

function verdictFromTopScore(score: number): SpiderVerdict {
  if (score >= THRESHOLD + AMBIGUITY_BAND) {
    return "deny";
  }
  if (score <= THRESHOLD - AMBIGUITY_BAND) {
    return "allow";
  }
  return "ambiguous";
}

function statusFromVerdict(verdict: SpiderVerdict): "allow" | "warn" | "deny" {
  if (verdict === "deny") return "deny";
  if (verdict === "ambiguous") return "warn";
  return "allow";
}

function severityFromVerdict(verdict: SpiderVerdict): "info" | "warning" | "error" {
  if (verdict === "deny") return "error";
  if (verdict === "ambiguous") return "warning";
  return "info";
}

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) {
    return min;
  }
  if (value < min) {
    return min;
  }
  if (value > max) {
    return max;
  }
  return value;
}

function classifyDrift(profile: BehaviorProfile, drift: number): DriftState {
  if (drift >= profile.drift_deny_threshold) {
    return "anomalous";
  }
  if (drift >= profile.drift_warn_threshold) {
    return "elevated";
  }
  return "normal";
}

function combinedRecommendation(decisionStatus: string, driftState: DriftState): string {
  if (decisionStatus === "deny") {
    return "block";
  }
  if (decisionStatus === "warn" && driftState === "anomalous") {
    return "block";
  }
  if (decisionStatus === "warn") {
    return "review";
  }
  if (driftState === "anomalous") {
    return "review_high";
  }
  if (driftState === "elevated") {
    return "review";
  }
  return "allow";
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function asTopMatch(value: unknown): SpiderTopMatch {
  const record = asRecord(value);
  return {
    id: typeof record.id === "string" ? record.id : undefined,
    category: typeof record.category === "string" ? record.category : undefined,
    stage: typeof record.stage === "string" ? record.stage : undefined,
    label: typeof record.label === "string" ? record.label : undefined,
  };
}

function printTable(rows: NormalizedRow[], policy: PolicyChoice): void {
  console.log(`=== Spider-Sense Threat Intel Example (TypeScript, ${policy}) ===`);
  console.log("");
  const header = [
    "scenario".padEnd(32),
    "status".padEnd(6),
    "verdict".padEnd(10),
    "top".padEnd(7),
    "drift".padEnd(7),
    "drift_state".padEnd(10),
    "recommendation",
  ].join(" ");
  console.log(header);
  console.log("-".repeat(header.length));
  for (const row of rows) {
    const line = [
      row.scenario_id.padEnd(32),
      row.decision_status.padEnd(6),
      row.spider_verdict.padEnd(10),
      row.top_score.toFixed(3).padEnd(7),
      row.profile_drift_score.toFixed(3).padEnd(7),
      row.profile_drift_state.padEnd(10),
      row.combined_recommendation,
    ].join(" ");
    console.log(line);
    if (row.top_match.id) {
      console.log(`  top_match: ${row.top_match.id} (${row.top_match.category}/${row.top_match.stage})`);
    }
  }
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const thisFile = fileURLToPath(import.meta.url);
  const tsDir = dirname(thisFile);
  const exampleRoot = resolve(tsDir, "..");
  process.chdir(exampleRoot);

  const policyPath = resolve(
    exampleRoot,
    args.policy === "baseline" ? "policy.baseline.yaml" : "policy.hardened.yaml",
  );
  const profilesPath = resolve(exampleRoot, "data/behavior_profiles.json");
  const scenariosPath = resolve(exampleRoot, "data/scenarios.json");
  const patternDbPath = resolve(exampleRoot, "data/pattern_db.s2intel-v1.json");

  const profilesDoc = await loadJson<{ profiles: BehaviorProfile[] }>(profilesPath);
  const scenariosDoc = await loadJson<{ scenarios: Scenario[] }>(scenariosPath);
  const patternDb = await loadJson<PatternEntry[]>(patternDbPath);
  const profileById = new Map<string, BehaviorProfile>(
    profilesDoc.profiles.map((profile) => [profile.profile_id, profile]),
  );

  const selectedScenarios = args.scenario === "all"
    ? scenariosDoc.scenarios
    : scenariosDoc.scenarios.filter((s) => s.scenario_id === args.scenario);
  if (selectedScenarios.length === 0) {
    throw new Error(`scenario not found: ${args.scenario}`);
  }

  const cs = await Clawdstrike.fromPolicy(policyPath);
  const rows: NormalizedRow[] = [];

  for (const scenario of selectedScenarios) {
    const profile = profileById.get(scenario.profile_id);
    if (!profile) {
      throw new Error(`missing profile ${scenario.profile_id} for scenario ${scenario.scenario_id}`);
    }

    const decision = await cs.check("custom", {
      customType: "spider_sense",
      customData: { embedding: scenario.embedding },
    });

    const details = asRecord(decision.details);
    const screened = screenEmbedding(scenario.embedding, patternDb);
    const spiderVerdict = verdictFromTopScore(screened.score);
    const decisionStatus = statusFromVerdict(spiderVerdict);
    const profileSimilarity = clamp(cosine(profile.embedding, scenario.embedding), -1, 1);
    const profileDrift = clamp(1 - profileSimilarity, 0, 2);
    const driftState = classifyDrift(profile, profileDrift);
    const recommendation = combinedRecommendation(decisionStatus, driftState);

    rows.push({
      scenario_id: scenario.scenario_id,
      profile_id: scenario.profile_id,
      spider_verdict: spiderVerdict,
      decision_status: decisionStatus,
      severity: severityFromVerdict(spiderVerdict),
      top_score: screened.score,
      top_match: Object.keys(screened.topMatch).length > 0 ? screened.topMatch : asTopMatch(details.top_match),
      profile_similarity: profileSimilarity,
      profile_drift_score: profileDrift,
      profile_drift_state: driftState,
      combined_recommendation: recommendation,
    });
  }

  if (args.json) {
    console.log(JSON.stringify({ policy: args.policy, rows }, null, 2));
    return;
  }
  printTable(rows, args.policy);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
