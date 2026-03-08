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
