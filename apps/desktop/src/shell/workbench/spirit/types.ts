export const HUNT_SPIRIT_KINDS = [
  "tracker",
  "lantern",
  "forge",
  "loom",
  "ledger",
] as const;

export type HuntSpiritKind = (typeof HUNT_SPIRIT_KINDS)[number];

export const HUNT_SPIRIT_MOODS = [
  "dormant",
  "attuned",
  "focused",
  "pressured",
  "witnessing",
  "transit",
] as const;

export type HuntSpiritMood = (typeof HUNT_SPIRIT_MOODS)[number];

export const HUNT_SPIRIT_BIND_SOURCES = [
  "quick-bind",
  "thesis",
  "anchor-artifacts",
  "manual",
  "system-inferred",
  "rebind",
] as const;

export type HuntSpiritBindSource = (typeof HUNT_SPIRIT_BIND_SOURCES)[number];

export interface HuntSpiritState {
  kind: HuntSpiritKind;
  thesis: string | null;
  anchorArtifactIds: string[];
  bindSource: HuntSpiritBindSource;
  bindReason: string | null;
  isPinned: boolean;
  liveMood: HuntSpiritMood;
  version: number;
  confidenceScore: number;
  boundAt: number;
  reboundAt: number | null;
}

export interface HuntSpiritMeta {
  kind: HuntSpiritKind;
  label: string;
  accentColor: string;
  contour: string;
  defaultBiases: string[];
}

export type HuntSpiritStance =
  | "idle"
  | "attune"
  | "focus"
  | "witness"
  | "absorb"
  | "transit";

export interface HuntSpiritRuntimeInput {
  currentShell?: string | null;
  currentLens?: string | null;
  activeStationId?: string | null;
  likelyIntent?: string | null;
  confidenceScore?: number | null;
  isAttachMode?: boolean;
  isActive?: boolean;
}

export interface HuntSpiritMotionEnvelope {
  arousal: number;
  valence: number;
  openness: number;
  aura: number;
  pulse: number;
  tilt: number;
}

export interface HuntSpiritRuntimeState {
  kind: HuntSpiritKind | null;
  label: string | null;
  accentColor: string | null;
  contour: string | null;
  mood: HuntSpiritMood;
  stance: HuntSpiritStance;
  reason: string | null;
  emphasis: string[];
  fieldStrength: number;
  shouldRender: boolean;
  motion: HuntSpiritMotionEnvelope;
  activeStationId: string | null;
  currentShell: string | null;
  currentLens: string | null;
}
