import { HUNT_SPIRIT_KINDS, getHuntSpiritMeta, type HuntSpiritKind, type HuntSpiritMood } from "../../spirit";
import type {
  SpiritRitualKindScore,
  SpiritRitualPanelMode,
  SpiritRitualSuggestion,
} from "../state/types";

export const SURFACE_LABELS: Record<string, string> = {
  entities: "Entities",
  evidence: "Evidence",
  receipts: "Receipts",
  notes: "Notes",
  files: "Files",
  mounts: "Mounts",
  "run-input": "Run Input",
  history: "History",
  scopes: "Scopes",
  cite: "Citations",
  compare: "Compare",
  target: "Targets",
  watch: "Watch",
  sandboxes: "Sandboxes",
};

export function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

export function createKindScoreMap(): Record<HuntSpiritKind, number> {
  return {
    tracker: 0,
    lantern: 0,
    forge: 0,
    loom: 0,
    ledger: 0,
  };
}

export function addKindScore(
  scores: Record<HuntSpiritKind, number>,
  kind: HuntSpiritKind,
  weight: number,
): void {
  scores[kind] += weight;
}

export function rankKindScores(
  scores: Record<HuntSpiritKind, number>,
): SpiritRitualKindScore[] {
  return [...HUNT_SPIRIT_KINDS]
    .map((kind) => ({ kind, score: Number(scores[kind].toFixed(2)) }))
    .sort((left, right) => right.score - left.score);
}

export function labelForKind(kind: HuntSpiritKind): string {
  return getHuntSpiritMeta(kind)?.label ?? kind;
}

export function focusSurfacesForKind(kind: HuntSpiritKind): string[] {
  return (getHuntSpiritMeta(kind)?.defaultBiases ?? []).map((entry) => SURFACE_LABELS[entry] ?? entry);
}

export function uniqueStrings(values: Iterable<string>): string[] {
  const result: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const normalized = value.trim();
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    result.push(normalized);
  }
  return result;
}

export function uniqueSuggestions(
  suggestions: SpiritRitualSuggestion[],
): SpiritRitualSuggestion[] {
  const deduped = new Map<string, SpiritRitualSuggestion>();
  for (const suggestion of suggestions) {
    if (!deduped.has(suggestion.id)) {
      deduped.set(suggestion.id, suggestion);
    }
  }
  return [...deduped.values()];
}

export function formatBiasLine(focusSurfaces: string[]): string {
  const limited = uniqueStrings(focusSurfaces).slice(0, 3);
  if (limited.length === 0) {
    return "Biases local hunt surfaces once more signal arrives.";
  }
  return `Biases ${limited.join(", ")} once released into dock, wake, and workspace.`;
}

export function deriveConfidenceScore(
  ranking: SpiritRitualKindScore[],
  bonus = 0,
): number {
  const top = ranking[0]?.score ?? 0;
  const runnerUp = ranking[1]?.score ?? 0;
  return clamp(
    Math.round(46 + Math.min(28, top * 1.1) + Math.max(0, (top - runnerUp) * 1.4) + bonus),
    38,
    96,
  );
}

export function deriveLiveMood(
  kind: HuntSpiritKind,
  confidenceScore: number,
  engagedModes: SpiritRitualPanelMode[],
  fallbackMood: HuntSpiritMood | null = null,
): HuntSpiritMood {
  if (engagedModes.length === 0 && fallbackMood) {
    return fallbackMood;
  }
  if (engagedModes.length > 1 && confidenceScore >= 80) {
    return "pressured";
  }
  if (confidenceScore >= 84) {
    return "focused";
  }
  if (kind === "lantern" || kind === "ledger") {
    return "witnessing";
  }
  return "attuned";
}

export function summarizeRationale(lines: string[], fallback: string): string {
  const normalized = uniqueStrings(lines);
  if (normalized.length === 0) return fallback;
  return normalized.slice(0, 2).join(" ");
}

export function makeSuggestionId(
  sourceMode: SpiritRitualSuggestion["sourceMode"],
  seed: string,
): string {
  return `${sourceMode}:${seed.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "")}`;
}

