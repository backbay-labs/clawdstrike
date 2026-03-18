import type {
  HuntSpiritBindSource,
  HuntSpiritKind,
  HuntSpiritMeta,
  HuntSpiritMood,
  HuntSpiritState,
} from "./types";
import {
  HUNT_SPIRIT_BIND_SOURCES,
  HUNT_SPIRIT_KINDS,
  HUNT_SPIRIT_MOODS,
} from "./types";

const HUNT_SPIRIT_KIND_SET = new Set<string>(HUNT_SPIRIT_KINDS);
const HUNT_SPIRIT_MOOD_SET = new Set<string>(HUNT_SPIRIT_MOODS);
const HUNT_SPIRIT_BIND_SOURCE_SET = new Set<string>(HUNT_SPIRIT_BIND_SOURCES);

export const HUNT_SPIRIT_META: Record<HuntSpiritKind, HuntSpiritMeta> = {
  tracker: {
    kind: "tracker",
    label: "Tracker",
    accentColor: "#d4a84b",
    contour: "reticle-vector",
    defaultBiases: ["entities", "watch", "target"],
  },
  lantern: {
    kind: "lantern",
    label: "Lantern",
    accentColor: "#d8c37d",
    contour: "aperture-reveal",
    defaultBiases: ["evidence", "receipts", "notes"],
  },
  forge: {
    kind: "forge",
    label: "Forge",
    accentColor: "#c77d2e",
    contour: "chamber-bracket",
    defaultBiases: ["files", "mounts", "run-input"],
  },
  loom: {
    kind: "loom",
    label: "Loom",
    accentColor: "#6b8cbe",
    contour: "thread-arc",
    defaultBiases: ["scopes", "history", "entities"],
  },
  ledger: {
    kind: "ledger",
    label: "Ledger",
    accentColor: "#8fa87a",
    contour: "proof-stack",
    defaultBiases: ["notes", "cite", "compare"],
  },
};

const DEFAULT_SPIRIT_ORDER: HuntSpiritKind[] = [
  "tracker",
  "lantern",
  "forge",
  "loom",
  "ledger",
];

const TITLE_HINTS: Array<{ pattern: RegExp; kind: HuntSpiritKind; weight: number }> = [
  { pattern: /\b(trace|track|watch|target|pivot)\b/i, kind: "tracker", weight: 3.2 },
  { pattern: /\b(receipt|cite|prove|proof|evidence)\b/i, kind: "lantern", weight: 3.2 },
  { pattern: /\b(file|mount|sandbox|payload|run|replay)\b/i, kind: "forge", weight: 3.2 },
  { pattern: /\b(map|cluster|graph|thread|scope|infra|infrastructure)\b/i, kind: "loom", weight: 3.2 },
  { pattern: /\b(case|report|compare|audit|history|brief)\b/i, kind: "ledger", weight: 3.2 },
];

const ICON_HINTS: Record<string, Partial<Record<HuntSpiritKind, number>>> = {
  crosshair: { tracker: 2.6 },
  target: { tracker: 2.4 },
  shield: { lantern: 2.2 },
  search: { loom: 2.1, tracker: 1.1 },
  alert: { lantern: 1.8, ledger: 0.8 },
  radar: { loom: 2.4 },
  bug: { tracker: 1.4, forge: 0.8 },
  lock: { ledger: 2.2, lantern: 1 },
};

const SHELL_HINTS: Record<string, Partial<Record<HuntSpiritKind, number>>> = {
  wire: { loom: 1.5, tracker: 1.2 },
  hunt: { tracker: 1.4, lantern: 0.9 },
  lab: { forge: 1.9 },
  case: { ledger: 1.9, lantern: 1.1 },
};

const LENS_HINTS: Record<string, Partial<Record<HuntSpiritKind, number>>> = {
  entities: { tracker: 1.8 },
  notes: { ledger: 1.7, lantern: 1.1 },
  files: { forge: 1.8 },
  sandboxes: { forge: 1.9 },
  scopes: { loom: 1.8 },
  history: { loom: 1.4, ledger: 0.9 },
  swarms: { tracker: 1.1, loom: 1.1 },
};

export interface DefaultHuntSpiritInput {
  title: string;
  icon?: string | null;
  currentShell?: string | null;
  currentLens?: string | null;
  fallbackIndex?: number;
  boundAt?: number;
}

function normalizeIdList(values: string[] | null | undefined): string[] {
  if (!values) return [];
  return Array.from(
    new Set(
      values
        .filter((value): value is string => typeof value === "string")
        .map((value) => value.trim())
        .filter(Boolean),
    ),
  );
}

function isHuntSpiritKind(value: unknown): value is HuntSpiritKind {
  return typeof value === "string" && HUNT_SPIRIT_KIND_SET.has(value);
}

function isHuntSpiritMood(value: unknown): value is HuntSpiritMood {
  return typeof value === "string" && HUNT_SPIRIT_MOOD_SET.has(value);
}

function isHuntSpiritBindSource(value: unknown): value is HuntSpiritBindSource {
  return typeof value === "string" && HUNT_SPIRIT_BIND_SOURCE_SET.has(value);
}

function applyWeightMap(
  scores: Record<HuntSpiritKind, number>,
  weights: Partial<Record<HuntSpiritKind, number>> | undefined,
): void {
  if (!weights) return;
  for (const kind of HUNT_SPIRIT_KINDS) {
    scores[kind] += weights[kind] ?? 0;
  }
}

function inferDefaultSpiritKind(input: DefaultHuntSpiritInput): {
  kind: HuntSpiritKind;
  confidenceScore: number;
  reason: string;
} {
  const scores = {
    tracker: 0,
    lantern: 0,
    forge: 0,
    loom: 0,
    ledger: 0,
  } satisfies Record<HuntSpiritKind, number>;
  const title = input.title.trim();
  let usedTitleHint = false;

  for (const hint of TITLE_HINTS) {
    if (hint.pattern.test(title)) {
      scores[hint.kind] += hint.weight;
      usedTitleHint = true;
    }
  }

  applyWeightMap(scores, input.icon ? ICON_HINTS[input.icon] : undefined);
  applyWeightMap(scores, input.currentShell ? SHELL_HINTS[input.currentShell] : undefined);
  applyWeightMap(scores, input.currentLens ? LENS_HINTS[input.currentLens] : undefined);

  if (scores.tracker === 0 && scores.lantern === 0 && scores.forge === 0 && scores.loom === 0 && scores.ledger === 0) {
    const fallbackKind = DEFAULT_SPIRIT_ORDER[(input.fallbackIndex ?? 0) % DEFAULT_SPIRIT_ORDER.length];
    return {
      kind: fallbackKind,
      confidenceScore: 54,
      reason: "Default spirit established from hunt creation and stable fallback rotation.",
    };
  }

  const ranked = [...DEFAULT_SPIRIT_ORDER]
    .map((kind) => ({ kind, score: scores[kind] }))
    .sort((left, right) => right.score - left.score);
  const top = ranked[0];
  const runnerUp = ranked[1];
  const confidenceScore = Math.max(
    58,
    Math.min(86, Math.round(60 + top.score * 5 + Math.max(0, (top.score - (runnerUp?.score ?? 0)) * 4))),
  );

  let reason = "Default spirit established from hunt creation context.";
  if (usedTitleHint) {
    reason = "Default spirit established from the hunt title and current context.";
  } else if (input.currentLens) {
    reason = `Default spirit established from the ${input.currentLens} lane and current shell context.`;
  } else if (input.currentShell) {
    reason = `Default spirit established from the ${input.currentShell} shell context.`;
  } else if (input.icon) {
    reason = "Default spirit established from hunt identity cues.";
  }

  return {
    kind: top.kind,
    confidenceScore,
    reason,
  };
}

export function createDefaultHuntSpiritState(input: DefaultHuntSpiritInput): HuntSpiritState {
  const inferred = inferDefaultSpiritKind(input);
  const meta = getHuntSpiritMeta(inferred.kind);
  const defaultBiases = (meta?.defaultBiases ?? [])
    .slice(0, 3)
    .map((entry) => entry.replace(/-/g, " "));
  const liveMood: HuntSpiritMood =
    input.currentShell === "lab" || inferred.kind === "forge"
      ? "focused"
      : input.currentShell === "case" || inferred.kind === "ledger" || inferred.kind === "lantern"
        ? "witnessing"
        : "attuned";

  return createHuntSpiritState({
    kind: inferred.kind,
    bindSource: "default-create",
    bindReason: defaultBiases.length > 0
      ? `${inferred.reason} Biases ${defaultBiases.join(", ")} across local hunt surfaces.`
      : inferred.reason,
    confidenceScore: inferred.confidenceScore,
    liveMood,
    boundAt: input.boundAt,
  });
}

export function ensureHuntSpiritState(
  input: Partial<HuntSpiritState> | null | undefined,
  fallback: DefaultHuntSpiritInput,
): HuntSpiritState {
  return normalizeHuntSpiritState(input) ?? createDefaultHuntSpiritState(fallback);
}

export function createHuntSpiritState(input: {
  kind: HuntSpiritKind;
  bindSource: HuntSpiritBindSource;
  bindReason?: string | null;
  thesis?: string | null;
  anchorArtifactIds?: string[];
  isPinned?: boolean;
  liveMood?: HuntSpiritMood;
  version?: number;
  confidenceScore?: number;
  boundAt?: number;
  reboundAt?: number | null;
}): HuntSpiritState {
  return {
    kind: input.kind,
    thesis: input.thesis ?? null,
    anchorArtifactIds: normalizeIdList(input.anchorArtifactIds),
    bindSource: input.bindSource,
    bindReason: input.bindReason ?? null,
    isPinned: input.isPinned ?? false,
    liveMood: input.liveMood ?? "attuned",
    version: input.version ?? 1,
    confidenceScore: Math.max(0, Math.min(100, input.confidenceScore ?? 50)),
    boundAt: input.boundAt ?? Date.now(),
    reboundAt: input.reboundAt ?? null,
  };
}

export function normalizeHuntSpiritState(
  input: Partial<HuntSpiritState> | null | undefined,
): HuntSpiritState | null {
  if (!input || !isHuntSpiritKind(input.kind) || !isHuntSpiritBindSource(input.bindSource)) {
    return null;
  }

  return {
    kind: input.kind,
    thesis: typeof input.thesis === "string" ? input.thesis : null,
    anchorArtifactIds: normalizeIdList(input.anchorArtifactIds),
    bindSource: input.bindSource,
    bindReason: typeof input.bindReason === "string" ? input.bindReason : null,
    isPinned: Boolean(input.isPinned),
    liveMood: isHuntSpiritMood(input.liveMood) ? input.liveMood : "attuned",
    version: typeof input.version === "number" ? input.version : 1,
    confidenceScore:
      typeof input.confidenceScore === "number"
        ? Math.max(0, Math.min(100, input.confidenceScore))
        : 50,
    boundAt: typeof input.boundAt === "number" ? input.boundAt : Date.now(),
    reboundAt: typeof input.reboundAt === "number" ? input.reboundAt : null,
  };
}

export function getHuntSpiritMeta(kind: HuntSpiritKind | null | undefined): HuntSpiritMeta | null {
  if (!kind) return null;
  return HUNT_SPIRIT_META[kind] ?? null;
}

export function isBoundHuntSpirit(
  spirit: HuntSpiritState | null | undefined,
): spirit is HuntSpiritState {
  return spirit !== null && spirit !== undefined;
}
