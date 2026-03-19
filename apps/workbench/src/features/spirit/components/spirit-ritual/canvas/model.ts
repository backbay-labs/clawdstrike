// Ported from huntronomer spirit-ritual/canvas/model.ts
// Huntronomer dependencies replaced with inline stubs + synthetic context pattern.

// --- Inline type definitions (replacing huntronomer spirit/ imports) ---

type HuntSpiritKind = "tracker" | "lantern" | "forge" | "loom" | "ledger";
type HuntSpiritStance = "idle" | "attune" | "focus" | "witness" | "absorb" | "transit";
type HuntSpiritMood = "dormant" | "attuned" | "focused" | "pressured" | "witnessing" | "transit";
type HuntSpiritBindSource =
  | "default-create"
  | "quick-configure"
  | "thesis"
  | "anchor-artifacts"
  | "manual"
  | "system-inferred"
  | "reconfigure";

interface HuntSpiritMotionEnvelope {
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

// --- Synthetic context types (no huntronomer imports) ---

export interface SpiritBindCandidate {
  kind: HuntSpiritKind;
  label: string;
  confidenceScore: number;
  rationale: string;
  biasLine: string;
  predictedFocusSurfaces: string[];
  alternates: Array<{ kind: HuntSpiritKind; label: string }>;
  liveMood: HuntSpiritMood;
  bindSource: HuntSpiritBindSource;
  thesis: string | null;
  anchorArtifactIds: string[];
}

export interface SpiritBindContext {
  hunt: {
    id: string;
    title: string;
    spirit: null | {
      kind: HuntSpiritKind;
      bindSource: HuntSpiritBindSource;
      thesis: string | null;
    };
    artifactIds: string[];
    color: string;
  };
  artifacts: Record<string, { id: string; kind: string; title: string } | undefined>;
  runs: Record<string, unknown>;
  currentLens: string | null;
  currentShell: string | null;
  activeStationId: string | null;
}

// --- Inline spirit meta (replacing getHuntSpiritMeta from huntronomer) ---

interface HuntSpiritMeta {
  kind: HuntSpiritKind;
  label: string;
  accentColor: string;
  contour: string;
  defaultBiases: string[];
}

const HUNT_SPIRIT_META: Record<HuntSpiritKind, HuntSpiritMeta> = {
  tracker: {
    kind: "tracker",
    label: "Sentinel",
    accentColor: "#3dbf84",
    contour: "reticle-vector",
    defaultBiases: ["filesystem", "process", "network"],
  },
  lantern: {
    kind: "lantern",
    label: "Oracle",
    accentColor: "#7b68ee",
    contour: "aperture-reveal",
    defaultBiases: ["inference", "context", "pattern"],
  },
  ledger: {
    kind: "ledger",
    label: "Witness",
    accentColor: "#d4a84b",
    contour: "proof-stack",
    defaultBiases: ["audit", "evidence", "chain"],
  },
  forge: {
    kind: "forge",
    label: "Specter",
    accentColor: "#c45c5c",
    contour: "chamber-bracket",
    defaultBiases: ["threat", "exploit", "evasion"],
  },
  loom: {
    kind: "loom",
    label: "Loom",
    accentColor: "#7ba3cc",
    contour: "thread-arc",
    defaultBiases: ["weave", "correlation", "multi-signal"],
  },
};

function getHuntSpiritMeta(kind: HuntSpiritKind): HuntSpiritMeta {
  return HUNT_SPIRIT_META[kind] ?? HUNT_SPIRIT_META.tracker;
}

// --- Inline HuntSpiritState factory + runtime derivation stubs ---

interface HuntSpiritStateInput {
  kind: HuntSpiritKind;
  bindSource: HuntSpiritBindSource;
  bindReason: string | null;
  thesis: string | null;
  anchorArtifactIds: string[];
  isPinned: boolean;
  confidenceScore: number;
  liveMood: HuntSpiritMood;
}

interface HuntSpiritState {
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

function createHuntSpiritState(input: HuntSpiritStateInput): HuntSpiritState {
  return {
    kind: input.kind,
    thesis: input.thesis,
    anchorArtifactIds: input.anchorArtifactIds,
    bindSource: input.bindSource,
    bindReason: input.bindReason,
    isPinned: input.isPinned,
    liveMood: input.liveMood,
    version: 1,
    confidenceScore: input.confidenceScore,
    boundAt: Date.now(),
    reboundAt: null,
  };
}

interface HuntSpiritRuntimeInput {
  currentLens?: string | null;
  currentShell?: string | null;
  activeStationId?: string | null;
  confidenceScore?: number | null;
  isActive?: boolean;
}

function deriveHuntSpiritRuntimeState(
  spirit: HuntSpiritState,
  input: HuntSpiritRuntimeInput,
): HuntSpiritRuntimeState {
  const meta = getHuntSpiritMeta(spirit.kind);
  const confidence = input.confidenceScore ?? spirit.confidenceScore;
  const fieldStrength = clamp01(confidence * 0.82 + 0.18);

  // Derive stance from bind source
  const stance: HuntSpiritStance =
    spirit.bindSource === "thesis"
      ? "witness"
      : spirit.bindSource === "anchor-artifacts"
        ? "absorb"
        : spirit.bindSource === "manual"
          ? "focus"
          : input.isActive
            ? "attune"
            : "idle";

  // Derive mood from liveMood
  const mood: HuntSpiritMood = spirit.liveMood ?? "attuned";

  // Stable synthetic motion envelope from fieldStrength
  const arousal = clamp01(fieldStrength * 0.72 + 0.28);
  const aura = clamp01(fieldStrength * 0.68 + 0.2);
  const pulse = clamp01(fieldStrength * 0.6 + 0.3);
  const openness =
    spirit.bindSource === "manual"
      ? clamp01(fieldStrength * 0.5 + 0.38)
      : clamp01(fieldStrength * 0.42 + 0.28);

  return {
    kind: spirit.kind,
    label: meta.label,
    accentColor: meta.accentColor,
    contour: meta.contour,
    mood,
    stance,
    reason: spirit.bindReason,
    emphasis: [],
    fieldStrength,
    shouldRender: true,
    motion: {
      arousal,
      valence: 0.5,
      openness,
      aura,
      pulse,
      tilt: 0,
    },
    activeStationId: input.activeStationId ?? null,
    currentShell: input.currentShell ?? null,
    currentLens: input.currentLens ?? null,
  };
}

// --- Data tables (verbatim from huntronomer) ---

const CONTOUR_PATHS: Record<string, string> = {
  "reticle-vector": "M8 3v2M8 11v2M3 8h2M11 8h2M8 5.25a2.75 2.75 0 110 5.5 2.75 2.75 0 010-5.5z",
  "aperture-reveal": "M8 3.2c2.6 0 4.6 2.1 4.6 4.8S10.6 12.8 8 12.8 3.4 10.7 3.4 8 5.4 3.2 8 3.2zm0 1.9c-1.6 0-2.8 1.3-2.8 2.9S6.4 10.9 8 10.9s2.8-1.3 2.8-2.9S9.6 5.1 8 5.1z",
  "chamber-bracket": "M4.1 4.2h2.2M4.1 4.2v7.6M4.1 11.8h2.2M11.9 4.2H9.7M11.9 4.2v7.6M11.9 11.8H9.7M6.3 6.1h3.4v3.8H6.3z",
  "thread-arc": "M3.2 9.8c1.4-3.8 4.5-5.9 9.6-6.3M4.1 4.5c2.2 0 3.6 1 4.3 3M7.8 7.5c1.1 0 2 .9 2 2s-.9 2-2 2-2-.9-2-2 .9-2 2-2z",
  "proof-stack": "M4.1 5.1h7.8M4.1 8h7.8M4.1 10.9h5.6M2.9 4h1.2M2.9 6.9h1.2M2.9 9.8h1.2",
};

const STANCE_LABELS: Record<HuntSpiritStance, string> = {
  idle: "holding a quiet field",
  attune: "reading the local field",
  focus: "tightening onto the likely lane",
  witness: "sealing proof into the posture",
  absorb: "drawing material into the chamber",
  transit: "crossing into the active workspace",
};

type SpiritTetherCharacter = "taut" | "witness" | "forge" | "woven" | "stepped";
type SpiritGhostCharacter = "reticle" | "beam" | "ember" | "thread" | "stack";
type SpiritExitCharacter = "pursuit" | "witness" | "forge" | "woven" | "ledger";

interface TraceLayout {
  leftPercent: number;
  topPercent: number;
  widthPercent: number;
  rotationDeg: number;
}

interface TetherLayout {
  startXPercent: number;
  startYPercent: number;
  endXPercent: number;
  endYPercent: number;
}

interface GhostLayout {
  leftPercent: number;
  topPercent: number;
  scale: number;
  opacity: number;
  driftMs: number;
  rotationDeg: number;
}

export interface SpiritManifestationGrammar {
  vesselShellRadius: string;
  vesselCoreRadius: string;
  shellWidthPercent: number;
  shellHeightPercent: number;
  coreWidthPercent: number;
  coreHeightPercent: number;
  shellTiltDeg: number;
  contourScale: number;
  contourStrokeWidth: number;
  contourOpacity: number;
  ringScaleY: number;
  ringRotationDeg: number;
  ringOffsetXPercent: number;
  ringOffsetYPercent: number;
  ringGlowOpacity: number;
  beamWidthPercent: number;
  beamHeightPercent: number;
  beamLeftPercent: number;
  beamTopPercent: number;
  beamRotationDeg: number;
  beamOpacity: number;
  haloWidthPercent: number;
  haloHeightPercent: number;
  haloTopPercent: number;
  haloBlurPx: number;
  floorGlowWidthPercent: number;
  floorGlowHeightPercent: number;
  floorGlowTopPercent: number;
  floorGlowBlurPx: number;
  tetherCharacter: SpiritTetherCharacter;
  ghostCharacter: SpiritGhostCharacter;
  exitCharacter: SpiritExitCharacter;
  ornamentCount: number;
}

const THESIS_TRACE_LAYOUTS: Record<HuntSpiritKind, TraceLayout[]> = {
  tracker: [
    { leftPercent: 18, topPercent: 26, widthPercent: 26, rotationDeg: -18 },
    { leftPercent: 58, topPercent: 22, widthPercent: 24, rotationDeg: 8 },
    { leftPercent: 30, topPercent: 68, widthPercent: 30, rotationDeg: 12 },
  ],
  lantern: [
    { leftPercent: 24, topPercent: 18, widthPercent: 24, rotationDeg: -8 },
    { leftPercent: 56, topPercent: 34, widthPercent: 22, rotationDeg: 6 },
    { leftPercent: 36, topPercent: 72, widthPercent: 26, rotationDeg: 4 },
  ],
  forge: [
    { leftPercent: 18, topPercent: 24, widthPercent: 30, rotationDeg: -20 },
    { leftPercent: 60, topPercent: 36, widthPercent: 24, rotationDeg: 16 },
    { leftPercent: 28, topPercent: 72, widthPercent: 28, rotationDeg: -6 },
  ],
  loom: [
    { leftPercent: 18, topPercent: 22, widthPercent: 32, rotationDeg: -12 },
    { leftPercent: 58, topPercent: 28, widthPercent: 30, rotationDeg: 13 },
    { leftPercent: 24, topPercent: 66, widthPercent: 34, rotationDeg: 10 },
  ],
  ledger: [
    { leftPercent: 22, topPercent: 24, widthPercent: 30, rotationDeg: 0 },
    { leftPercent: 22, topPercent: 40, widthPercent: 30, rotationDeg: 0 },
    { leftPercent: 22, topPercent: 56, widthPercent: 30, rotationDeg: 0 },
  ],
};

const TETHER_LAYOUTS: Record<HuntSpiritKind, TetherLayout[]> = {
  tracker: [
    { startXPercent: 16, startYPercent: 30, endXPercent: 54, endYPercent: 50 },
    { startXPercent: 84, startYPercent: 34, endXPercent: 54, endYPercent: 50 },
    { startXPercent: 28, startYPercent: 76, endXPercent: 54, endYPercent: 50 },
  ],
  lantern: [
    { startXPercent: 24, startYPercent: 18, endXPercent: 50, endYPercent: 50 },
    { startXPercent: 76, startYPercent: 22, endXPercent: 50, endYPercent: 50 },
    { startXPercent: 34, startYPercent: 80, endXPercent: 50, endYPercent: 50 },
  ],
  forge: [
    { startXPercent: 14, startYPercent: 42, endXPercent: 52, endYPercent: 50 },
    { startXPercent: 86, startYPercent: 30, endXPercent: 52, endYPercent: 50 },
    { startXPercent: 68, startYPercent: 82, endXPercent: 52, endYPercent: 50 },
  ],
  loom: [
    { startXPercent: 18, startYPercent: 24, endXPercent: 50, endYPercent: 50 },
    { startXPercent: 82, startYPercent: 28, endXPercent: 50, endYPercent: 50 },
    { startXPercent: 26, startYPercent: 78, endXPercent: 50, endYPercent: 50 },
  ],
  ledger: [
    { startXPercent: 18, startYPercent: 30, endXPercent: 50, endYPercent: 46 },
    { startXPercent: 18, startYPercent: 48, endXPercent: 50, endYPercent: 50 },
    { startXPercent: 18, startYPercent: 66, endXPercent: 50, endYPercent: 54 },
  ],
};

const GHOST_LAYOUTS: Record<HuntSpiritKind, GhostLayout[]> = {
  tracker: [
    { leftPercent: 18, topPercent: 34, scale: 0.58, opacity: 0.36, driftMs: 6200, rotationDeg: -8 },
    { leftPercent: 78, topPercent: 28, scale: 0.52, opacity: 0.28, driftMs: 7000, rotationDeg: 10 },
    { leftPercent: 74, topPercent: 72, scale: 0.46, opacity: 0.22, driftMs: 7600, rotationDeg: 4 },
  ],
  lantern: [
    { leftPercent: 24, topPercent: 26, scale: 0.64, opacity: 0.3, driftMs: 6600, rotationDeg: 0 },
    { leftPercent: 76, topPercent: 34, scale: 0.56, opacity: 0.24, driftMs: 7200, rotationDeg: 0 },
    { leftPercent: 66, topPercent: 74, scale: 0.48, opacity: 0.18, driftMs: 7800, rotationDeg: -4 },
  ],
  forge: [
    { leftPercent: 18, topPercent: 38, scale: 0.56, opacity: 0.38, driftMs: 6000, rotationDeg: -12 },
    { leftPercent: 80, topPercent: 30, scale: 0.5, opacity: 0.28, driftMs: 7000, rotationDeg: 14 },
    { leftPercent: 72, topPercent: 74, scale: 0.44, opacity: 0.2, driftMs: 7400, rotationDeg: 8 },
  ],
  loom: [
    { leftPercent: 20, topPercent: 32, scale: 0.62, opacity: 0.32, driftMs: 6800, rotationDeg: -10 },
    { leftPercent: 78, topPercent: 28, scale: 0.56, opacity: 0.26, driftMs: 7600, rotationDeg: 12 },
    { leftPercent: 70, topPercent: 72, scale: 0.5, opacity: 0.22, driftMs: 8200, rotationDeg: -6 },
  ],
  ledger: [
    { leftPercent: 20, topPercent: 34, scale: 0.58, opacity: 0.28, driftMs: 7200, rotationDeg: 0 },
    { leftPercent: 76, topPercent: 30, scale: 0.52, opacity: 0.22, driftMs: 7800, rotationDeg: 0 },
    { leftPercent: 72, topPercent: 72, scale: 0.46, opacity: 0.18, driftMs: 8400, rotationDeg: 0 },
  ],
};

const SPIRIT_STAGE_GRAMMARS: Record<HuntSpiritKind, SpiritManifestationGrammar> = {
  tracker: {
    vesselShellRadius: "46% 40% 52% 40% / 34% 34% 62% 62%",
    vesselCoreRadius: "50% 50% 46% 46% / 40% 40% 60% 60%",
    shellWidthPercent: 30,
    shellHeightPercent: 27,
    coreWidthPercent: 24,
    coreHeightPercent: 21,
    shellTiltDeg: -10,
    contourScale: 1.04,
    contourStrokeWidth: 1.24,
    contourOpacity: 0.98,
    ringScaleY: 0.82,
    ringRotationDeg: -10,
    ringOffsetXPercent: 4,
    ringOffsetYPercent: -1,
    ringGlowOpacity: 0.22,
    beamWidthPercent: 44,
    beamHeightPercent: 10,
    beamLeftPercent: 56,
    beamTopPercent: 48,
    beamRotationDeg: -8,
    beamOpacity: 0.2,
    haloWidthPercent: 34,
    haloHeightPercent: 42,
    haloTopPercent: 48,
    haloBlurPx: 14,
    floorGlowWidthPercent: 56,
    floorGlowHeightPercent: 18,
    floorGlowTopPercent: 58,
    floorGlowBlurPx: 22,
    tetherCharacter: "taut",
    ghostCharacter: "reticle",
    exitCharacter: "pursuit",
    ornamentCount: 2,
  },
  lantern: {
    vesselShellRadius: "50% 50% 48% 48% / 34% 34% 66% 66%",
    vesselCoreRadius: "48% 48% 50% 50% / 30% 30% 70% 70%",
    shellWidthPercent: 24,
    shellHeightPercent: 28,
    coreWidthPercent: 18,
    coreHeightPercent: 20,
    shellTiltDeg: 0,
    contourScale: 0.94,
    contourStrokeWidth: 1.12,
    contourOpacity: 0.9,
    ringScaleY: 1.18,
    ringRotationDeg: 2,
    ringOffsetXPercent: 0,
    ringOffsetYPercent: -2,
    ringGlowOpacity: 0.3,
    beamWidthPercent: 18,
    beamHeightPercent: 56,
    beamLeftPercent: 50,
    beamTopPercent: 38,
    beamRotationDeg: 0,
    beamOpacity: 0.34,
    haloWidthPercent: 46,
    haloHeightPercent: 58,
    haloTopPercent: 44,
    haloBlurPx: 18,
    floorGlowWidthPercent: 42,
    floorGlowHeightPercent: 14,
    floorGlowTopPercent: 60,
    floorGlowBlurPx: 24,
    tetherCharacter: "witness",
    ghostCharacter: "beam",
    exitCharacter: "witness",
    ornamentCount: 2,
  },
  forge: {
    vesselShellRadius: "32% 32% 38% 38% / 26% 26% 46% 46%",
    vesselCoreRadius: "28% 28% 34% 34% / 24% 24% 40% 40%",
    shellWidthPercent: 28,
    shellHeightPercent: 22,
    coreWidthPercent: 22,
    coreHeightPercent: 18,
    shellTiltDeg: 14,
    contourScale: 0.98,
    contourStrokeWidth: 1.34,
    contourOpacity: 1,
    ringScaleY: 0.72,
    ringRotationDeg: 16,
    ringOffsetXPercent: 6,
    ringOffsetYPercent: 0,
    ringGlowOpacity: 0.26,
    beamWidthPercent: 54,
    beamHeightPercent: 12,
    beamLeftPercent: 56,
    beamTopPercent: 50,
    beamRotationDeg: -18,
    beamOpacity: 0.26,
    haloWidthPercent: 30,
    haloHeightPercent: 34,
    haloTopPercent: 49,
    haloBlurPx: 12,
    floorGlowWidthPercent: 48,
    floorGlowHeightPercent: 16,
    floorGlowTopPercent: 58,
    floorGlowBlurPx: 18,
    tetherCharacter: "forge",
    ghostCharacter: "ember",
    exitCharacter: "forge",
    ornamentCount: 3,
  },
  loom: {
    vesselShellRadius: "48% 52% 44% 56% / 42% 42% 58% 58%",
    vesselCoreRadius: "50% 50% 48% 48% / 46% 46% 54% 54%",
    shellWidthPercent: 31,
    shellHeightPercent: 26,
    coreWidthPercent: 24,
    coreHeightPercent: 20,
    shellTiltDeg: 8,
    contourScale: 1.08,
    contourStrokeWidth: 1.1,
    contourOpacity: 0.92,
    ringScaleY: 1.12,
    ringRotationDeg: 18,
    ringOffsetXPercent: 0,
    ringOffsetYPercent: -1,
    ringGlowOpacity: 0.24,
    beamWidthPercent: 52,
    beamHeightPercent: 18,
    beamLeftPercent: 50,
    beamTopPercent: 48,
    beamRotationDeg: 4,
    beamOpacity: 0.16,
    haloWidthPercent: 48,
    haloHeightPercent: 50,
    haloTopPercent: 48,
    haloBlurPx: 16,
    floorGlowWidthPercent: 64,
    floorGlowHeightPercent: 20,
    floorGlowTopPercent: 58,
    floorGlowBlurPx: 28,
    tetherCharacter: "woven",
    ghostCharacter: "thread",
    exitCharacter: "woven",
    ornamentCount: 4,
  },
  ledger: {
    vesselShellRadius: "28% 28% 34% 34% / 24% 24% 42% 42%",
    vesselCoreRadius: "24% 24% 28% 28% / 20% 20% 36% 36%",
    shellWidthPercent: 30,
    shellHeightPercent: 24,
    coreWidthPercent: 22,
    coreHeightPercent: 17,
    shellTiltDeg: 0,
    contourScale: 0.96,
    contourStrokeWidth: 1.08,
    contourOpacity: 0.9,
    ringScaleY: 0.66,
    ringRotationDeg: 0,
    ringOffsetXPercent: 0,
    ringOffsetYPercent: 1,
    ringGlowOpacity: 0.16,
    beamWidthPercent: 50,
    beamHeightPercent: 8,
    beamLeftPercent: 50,
    beamTopPercent: 50,
    beamRotationDeg: 0,
    beamOpacity: 0.12,
    haloWidthPercent: 36,
    haloHeightPercent: 34,
    haloTopPercent: 50,
    haloBlurPx: 10,
    floorGlowWidthPercent: 68,
    floorGlowHeightPercent: 14,
    floorGlowTopPercent: 60,
    floorGlowBlurPx: 22,
    tetherCharacter: "stepped",
    ghostCharacter: "stack",
    exitCharacter: "ledger",
    ornamentCount: 3,
  },
};

export type SpiritManifestationMode = "quick" | "thesis" | "anchors" | "manual" | "other";

export interface SpiritManifestationRing {
  radiusPercent: number;
  opacity: number;
  strokeWidth: number;
  dashPattern: string | null;
  driftMs: number;
  scaleY?: number;
  rotateDeg?: number;
  offsetXPercent?: number;
  offsetYPercent?: number;
  glowOpacity?: number;
}

export interface SpiritManifestationInscription {
  id: string;
  text: string;
  leftPercent: number;
  topPercent: number;
  widthPercent: number;
  rotationDeg: number;
  delayMs: number;
  emphasis: number;
}

export interface SpiritManifestationTether {
  id: string;
  label: string;
  kindLabel: string;
  startXPercent: number;
  startYPercent: number;
  endXPercent: number;
  endYPercent: number;
  strength: number;
  delayMs: number;
  curveBias?: number;
  dashPattern?: string;
}

export interface SpiritManifestationGhost {
  id: string;
  label: string;
  contourPath: string;
  leftPercent: number;
  topPercent: number;
  scale: number;
  opacity: number;
  driftMs: number;
  rotationDeg?: number;
}

export interface SpiritAtmosphereGrain {
  id: string;
  leftPercent: number;
  topPercent: number;
  sizePx: number;
  opacity: number;
  blurPx: number;
  driftMs: number;
  delayMs: number;
}

export interface SpiritManifestationStage {
  kind?: HuntSpiritKind;
  mode: SpiritManifestationMode;
  modeLabel: string;
  subtitle: string;
  stateLabel: string;
  intentLine: string;
  consequenceLine: string;
  exitLabel: string;
  dominance: number;
  vesselScale: number;
  haloOpacity: number;
  floorGlowOpacity: number;
  grammar?: SpiritManifestationGrammar;
  inscriptions: SpiritManifestationInscription[];
  tethers: SpiritManifestationTether[];
  ghosts: SpiritManifestationGhost[];
}

export interface SpiritAtmosphereModel {
  veilOpacity: number;
  bloomOpacity: number;
  particleCount: number;
  pulseMs: number;
  driftMs: number;
  railOpacity: number;
  grainOpacity?: number;
  grains?: SpiritAtmosphereGrain[];
}

export interface SpiritReleaseCue {
  title: string;
  subtitle: string;
  actionLabel: string;
  targetLabel: string;
  durationMs: number;
  tetherStrength: number;
  pulseScale: number;
}

export interface SpiritManifestationModel {
  label: string;
  accentColor: string;
  contour: string;
  contourPath: string;
  stance: HuntSpiritStance;
  mode?: SpiritManifestationMode;
  motionLabel: string;
  moodLabel: string;
  fieldStrength: number;
  fieldPercent: number;
  reasonLine: string;
  biasLine: string;
  thesisLine: string | null;
  focusLine: string;
  chamberTitle: string;
  stationLabel: string;
  rings: SpiritManifestationRing[];
  atmosphere: SpiritAtmosphereModel;
  release: SpiritReleaseCue;
  runtime: HuntSpiritRuntimeState;
  stage?: SpiritManifestationStage;
}

// --- Utility functions (verbatim from huntronomer) ---

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function hashSeed(value: string): number {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) % 1_000_003;
  }
  return hash;
}

function formatFieldStrength(value: number, mode: SpiritManifestationMode): string {
  if (mode === "quick" && value < 0.72) return "quiet field";
  if (mode === "manual") return value >= 0.66 ? "live field" : "hovering field";
  if (mode === "anchors") return value >= 0.58 ? "pulled field" : "warming field";
  if (mode === "thesis") return value >= 0.58 ? "inscribed field" : "gathering field";
  if (value >= 0.82) return "high field";
  if (value >= 0.62) return "steady field";
  if (value >= 0.38) return "warming field";
  return "quiet field";
}

function formatMoodLabel(runtime: HuntSpiritRuntimeState): string {
  const mood = runtime.mood.replace(/-/g, " ");
  return mood.charAt(0).toUpperCase() + mood.slice(1);
}

function resolveStationLabel(context: SpiritBindContext): string {
  if (!context.activeStationId) {
    return "the workbench field";
  }

  return context.activeStationId
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function resolveManifestationMode(candidate: SpiritBindCandidate): SpiritManifestationMode {
  switch (candidate.bindSource) {
    case "quick-configure":
      return "quick";
    case "thesis":
      return "thesis";
    case "anchor-artifacts":
      return "anchors";
    case "manual":
      return "manual";
    default:
      return "other";
  }
}

function modeLabel(mode: SpiritManifestationMode): string {
  switch (mode) {
    case "quick":
      return "Quick";
    case "thesis":
      return "Thesis";
    case "anchors":
      return "Anchors";
    case "manual":
      return "Manual";
    default:
      return "Spirit field";
  }
}

function modeSubtitle(mode: SpiritManifestationMode, candidate: SpiritBindCandidate): string {
  switch (mode) {
    case "quick":
      return "Holding current read";
    case "thesis":
      return "Following authored pull";
    case "anchors":
      return "Pulled by live anchors";
    case "manual":
      return "Weighing alternate presences";
    default:
      return candidate.rationale;
  }
}

function formatStateLabel(runtime: HuntSpiritRuntimeState): string {
  const label = runtime.mood.replace(/-/g, " ");
  return label.charAt(0).toUpperCase() + label.slice(1);
}

function buildIntentLine(
  mode: SpiritManifestationMode,
  candidate: SpiritBindCandidate,
  context: SpiritBindContext,
): string {
  switch (mode) {
    case "quick":
      return "Holding current pressure";
    case "thesis":
      return "Following authored pressure";
    case "anchors": {
      const anchorKinds = candidate.anchorArtifactIds
        .slice(0, 3)
        .map((artifactId) => context.artifacts[artifactId]?.kind ?? "artifact");
      return `Pulled by ${anchorKinds.join(", ")}`;
    }
    case "manual": {
      const first = candidate.alternates[0]?.label;
      const second = candidate.alternates[1]?.label;
      if (first && second) return `Weighing ${first} and ${second}`;
      if (first) return `Weighing ${first}`;
      return "Retuning the vessel";
    }
    default:
      return "Reading the field";
  }
}

function buildConsequenceLine(candidate: SpiritBindCandidate): string {
  const surfaces = candidate.predictedFocusSurfaces.slice(0, 3).join(", ");
  return surfaces ? `Pulls toward ${surfaces}` : "Pulls toward the likely lane";
}

function buildExitLabel(stationLabel: string): string {
  return `to ${stationLabel}`;
}

function resolveStageGrammar(
  kind: HuntSpiritKind,
  mode: SpiritManifestationMode,
  fieldStrength: number,
): SpiritManifestationGrammar {
  const base = SPIRIT_STAGE_GRAMMARS[kind];
  const calmFactor = mode === "quick" ? 0.42 : 1;
  const emergenceFactor =
    mode === "anchors"
      ? 1.12
      : mode === "manual"
        ? 1.08
        : mode === "thesis"
          ? 1.14
          : mode === "quick"
            ? 0.72
            : 1;
  const kindCompression =
    kind === "forge"
      ? 1.18
      : kind === "tracker"
        ? 1.08
        : kind === "loom"
          ? 1.12
          : kind === "lantern"
            ? 0.96
            : 1;

  return {
    ...base,
    shellWidthPercent:
      base.shellWidthPercent
      + (emergenceFactor - 1) * 4
      + (kind === "loom" ? 1.8 : kind === "tracker" ? -1.2 : 0)
      - (mode === "quick" ? 1.6 : 0),
    shellHeightPercent:
      base.shellHeightPercent
      + (emergenceFactor - 1) * 2.6
      + (kind === "lantern" ? 1.4 : kind === "forge" ? -1.2 : 0)
      - (mode === "quick" ? 1 : 0),
    coreWidthPercent:
      base.coreWidthPercent
      + fieldStrength * (kind === "forge" ? 3.3 : kind === "lantern" ? 1.6 : 2.4)
      + (mode === "anchors" ? 0.8 : 0),
    coreHeightPercent:
      base.coreHeightPercent
      + fieldStrength * (kind === "forge" ? 2.8 : kind === "lantern" ? 1.8 : 2)
      + (mode === "thesis" ? 0.6 : 0),
    shellTiltDeg:
      base.shellTiltDeg * (mode === "quick" ? 0.34 : 1)
      + (kind === "forge" ? 2 : kind === "tracker" ? -2 : 0),
    contourScale:
      base.contourScale
      + (mode === "manual" ? 0.05 : 0)
      + (kind === "tracker" ? 0.05 : kind === "loom" ? 0.04 : kind === "lantern" ? -0.04 : 0)
      - (mode === "quick" ? 0.02 : 0),
    contourStrokeWidth:
      base.contourStrokeWidth
      + (kind === "forge" ? 0.08 : kind === "tracker" ? 0.04 : kind === "ledger" ? -0.02 : 0),
    contourOpacity:
      clamp01(base.contourOpacity + (kind === "lantern" ? -0.04 : kind === "forge" ? 0.04 : 0)),
    ringRotationDeg:
      base.ringRotationDeg * calmFactor
      + (kind === "tracker" ? -4 : kind === "loom" ? 6 : kind === "forge" ? 4 : 0),
    ringOffsetXPercent:
      base.ringOffsetXPercent * (mode === "quick" ? 0.34 : 1)
      + (kind === "tracker" ? 1.2 : kind === "forge" ? 0.8 : 0),
    ringOffsetYPercent:
      base.ringOffsetYPercent * (mode === "quick" ? 0.34 : 1)
      + (kind === "lantern" ? -0.8 : 0),
    ringGlowOpacity:
      clamp01(base.ringGlowOpacity * (mode === "quick" ? 0.68 : 1.14) + (kind === "forge" ? 0.04 : 0)),
    beamWidthPercent:
      base.beamWidthPercent
      + (mode === "anchors" ? 2 : 0)
      + (kind === "tracker" ? 6 : kind === "forge" ? 4 : kind === "lantern" ? -4 : 0)
      - (mode === "quick" ? 3 : 0),
    beamHeightPercent:
      base.beamHeightPercent
      + (mode === "anchors" ? 2 : 0)
      + (kind === "lantern" ? 8 : kind === "loom" ? 4 : kind === "forge" ? -1 : 0)
      - (mode === "quick" ? 3 : 0),
    beamOpacity:
      clamp01(
        base.beamOpacity * calmFactor
        + fieldStrength * (mode === "quick" ? 0.02 : 0.06)
        + (kind === "lantern" ? 0.06 : kind === "forge" ? 0.04 : kind === "ledger" ? -0.02 : 0),
      ),
    haloWidthPercent:
      base.haloWidthPercent
      + fieldStrength * (kind === "lantern" ? 3.2 : 2.2)
      + (kind === "tracker" ? -2 : 0)
      - (mode === "quick" ? 2 : 0),
    haloHeightPercent:
      base.haloHeightPercent
      + fieldStrength * (kind === "lantern" ? 3.6 : 2.1)
      + (kind === "forge" ? -2 : 0)
      - (mode === "quick" ? 2 : 0),
    haloBlurPx: base.haloBlurPx + (kind === "lantern" ? 3 : kind === "forge" ? -1 : 1) + (mode === "quick" ? -2 : 0),
    floorGlowWidthPercent:
      base.floorGlowWidthPercent
      + fieldStrength * (kind === "loom" ? 4.2 : 3)
      + (mode === "anchors" ? 2 : 0)
      + (kind === "ledger" ? 2 : 0),
    floorGlowHeightPercent:
      base.floorGlowHeightPercent
      + fieldStrength * (kind === "forge" ? 2.2 : 1.5)
      + (kind === "ledger" ? -1 : 0),
    floorGlowBlurPx: base.floorGlowBlurPx + (kind === "loom" ? 4 : kind === "forge" ? -2 : 0) + (mode === "quick" ? -4 : 0),
    ornamentCount: Math.max(1, Math.round(base.ornamentCount * kindCompression) - (mode === "quick" ? 1 : 0) + (mode === "anchors" ? 1 : 0)),
  };
}

function splitThesisIntoTraces(thesis: string): string[] {
  const trimmed = thesis.trim().replace(/\s+/g, " ");
  if (!trimmed) return [];
  const words = trimmed.split(" ");
  const traces: string[] = [];
  const chunkSize = Math.max(2, Math.min(4, Math.ceil(words.length / 3)));
  for (let index = 0; index < words.length; index += chunkSize) {
    traces.push(words.slice(index, index + chunkSize).join(" "));
  }
  return traces.slice(0, 3);
}

function describeArtifactLabel(artifactId: string, artifact: SpiritBindContext["artifacts"][string]): string {
  if (!artifact) {
    return artifactId.replace(/[-_]/g, " ");
  }
  return artifact.title.length > 24 ? `${artifact.title.slice(0, 21)}...` : artifact.title;
}

function buildInscriptions(
  candidate: SpiritBindCandidate,
  mode: SpiritManifestationMode,
  fieldStrength: number,
  kind: HuntSpiritKind,
): SpiritManifestationInscription[] {
  if (mode !== "thesis") return [];

  const layouts = THESIS_TRACE_LAYOUTS[kind];
  return splitThesisIntoTraces(candidate.thesis ?? "").map((text, index) => {
    const position = layouts[index] ?? layouts[layouts.length - 1];
    return {
      id: `inscription-${index}`,
      text,
      leftPercent: position.leftPercent,
      topPercent: position.topPercent,
      widthPercent: position.widthPercent,
      rotationDeg: position.rotationDeg,
      delayMs: index * 140,
      emphasis: clamp01(0.52 + fieldStrength * 0.3 - index * 0.08),
    };
  });
}

function buildTethers(
  context: SpiritBindContext,
  candidate: SpiritBindCandidate,
  mode: SpiritManifestationMode,
  fieldStrength: number,
  kind: HuntSpiritKind,
): SpiritManifestationTether[] {
  if (mode !== "anchors") return [];

  const layouts = TETHER_LAYOUTS[kind];
  const grammar = SPIRIT_STAGE_GRAMMARS[kind];
  return candidate.anchorArtifactIds.slice(0, 3).map((artifactId, index) => {
    const artifact = context.artifacts[artifactId];
    const position = layouts[index] ?? layouts[layouts.length - 1];
    return {
      id: artifactId,
      label: describeArtifactLabel(artifactId, artifact),
      kindLabel: artifact?.kind ?? "artifact",
      startXPercent: position.startXPercent,
      startYPercent: position.startYPercent,
      endXPercent: position.endXPercent,
      endYPercent: position.endYPercent,
      strength: clamp01(0.58 + fieldStrength * 0.28 - index * 0.08),
      delayMs: index * 160,
      curveBias:
        grammar.tetherCharacter === "woven"
          ? 14 - index * 3
          : grammar.tetherCharacter === "witness"
            ? 18 - index * 2
            : grammar.tetherCharacter === "forge"
              ? -10 + index * 4
              : grammar.tetherCharacter === "stepped"
                ? 0
                : 6 - index * 2,
      dashPattern:
        grammar.tetherCharacter === "taut"
          ? "2.4 4.8"
          : grammar.tetherCharacter === "witness"
            ? "1.8 6.4"
            : grammar.tetherCharacter === "forge"
              ? "5.2 3.4"
              : grammar.tetherCharacter === "woven"
                ? "2.1 3.6"
                : "6.6 2.4",
    };
  });
}

function buildGhosts(
  candidate: SpiritBindCandidate,
  mode: SpiritManifestationMode,
  kind: HuntSpiritKind,
): SpiritManifestationGhost[] {
  if (mode !== "manual") return [];

  const layouts = GHOST_LAYOUTS[kind];
  return candidate.alternates.slice(0, 3).map((alternate, index) => {
    const meta = getHuntSpiritMeta(alternate.kind);
    const position = layouts[index] ?? layouts[layouts.length - 1];
    const contour = meta.contour;
    return {
      id: `${alternate.kind}-${index}`,
      label: alternate.label,
      contourPath: CONTOUR_PATHS[contour] ?? CONTOUR_PATHS["reticle-vector"],
      leftPercent: position.leftPercent,
      topPercent: position.topPercent,
      scale: position.scale,
      opacity: position.opacity,
      driftMs: position.driftMs,
      rotationDeg: position.rotationDeg,
    };
  });
}

function buildRings(
  runtime: HuntSpiritRuntimeState,
  mode: SpiritManifestationMode,
  kind: HuntSpiritKind,
  grammar: SpiritManifestationGrammar,
): SpiritManifestationRing[] {
  const baseCount = mode === "quick"
    ? 2
    : kind === "loom"
      ? 5
      : kind === "forge" || kind === "tracker" || kind === "ledger"
        ? 4
        : mode === "anchors"
          ? 4
          : 3;

  return Array.from({ length: baseCount }, (_, index) => {
    const step = index / Math.max(1, baseCount - 1);
    const dashPattern = kind === "tracker"
      ? `${Math.round(4 + step * 4)} ${Math.round(10 + step * 5)}`
      : kind === "lantern"
        ? index === 0
          ? null
          : `${Math.round(14 + step * 6)} ${Math.round(10 + step * 6)}`
        : kind === "forge"
          ? `${Math.round(6 + step * 3)} ${Math.round(6 + step * 3)}`
          : kind === "loom"
            ? `${Math.round(10 + step * 5)} ${Math.round(6 + step * 4)}`
            : kind === "ledger"
              ? `${Math.round(18 + step * 4)} ${Math.round(4 + step * 3)}`
              : mode === "manual"
                ? `${Math.round(8 + step * 4)} ${Math.round(14 + step * 8)}`
                : mode === "thesis"
                  ? `${Math.round(12 + step * 6)} ${Math.round(8 + step * 4)}`
                  : runtime.stance === "focus" || runtime.stance === "transit"
                    ? `${Math.round(6 + step * 6)} ${Math.round(8 + step * 8)}`
                    : null;

    return {
      radiusPercent:
        40
        + step * (kind === "lantern" ? 38 : kind === "tracker" ? 30 : 34)
        + runtime.motion.openness * 6
        + grammar.ringOffsetXPercent * 0.3
        + (mode === "anchors" ? step * 4 : 0),
      opacity: clamp01(
        (mode === "quick" ? 0.12 : 0.18)
          + runtime.motion.aura * 0.18
          - step * (mode === "quick" ? 0.04 : 0.03),
      ),
      strokeWidth:
        1.05
        + runtime.motion.pulse * 0.8
        + (kind === "forge" ? 0.22 : kind === "ledger" ? -0.06 : 0)
        - step * 0.16
        + (mode === "anchors" ? 0.1 : 0),
      dashPattern,
      driftMs: Math.round(
        (mode === "quick" ? 7200 : 6200)
          + index * 860
          - runtime.motion.arousal * (mode === "quick" ? 420 : 760),
      ),
      scaleY:
        grammar.ringScaleY
        + (kind === "lantern" ? step * 0.06 : kind === "ledger" ? -step * 0.04 : 0),
      rotateDeg: grammar.ringRotationDeg + (index - baseCount / 2) * (kind === "loom" ? 6 : 4),
      offsetXPercent: grammar.ringOffsetXPercent + step * (kind === "tracker" ? 2.6 : kind === "forge" ? 1.8 : 0),
      offsetYPercent: grammar.ringOffsetYPercent + (kind === "lantern" ? -step * 1.2 : 0),
      glowOpacity: grammar.ringGlowOpacity,
    };
  });
}

function buildAtmosphereGrains(
  modelSeed: string,
  kind: HuntSpiritKind,
  mode: SpiritManifestationMode,
  fieldStrength: number,
): SpiritAtmosphereGrain[] {
  const grainCount = mode === "quick"
    ? 12
    : kind === "loom"
      ? 20
      : kind === "forge"
        ? 18
        : kind === "tracker"
          ? 14
          : mode === "thesis"
            ? 18
            : mode === "anchors"
              ? 16
              : mode === "manual"
                ? 15
                : 14;

  return Array.from({ length: grainCount }, (_, index) => {
    const seed = hashSeed(`${modelSeed}-${index}`);
    const leftPercent = kind === "tracker"
      ? 18 + ((seed % 64) * 0.92)
      : kind === "lantern"
        ? 34 + ((seed % 30) * 0.9)
        : kind === "forge"
          ? 28 + ((seed % 44) * 0.8)
          : kind === "loom"
            ? 6 + (seed % 86)
            : 14 + ((seed % 72) * 0.88);
    const topPercent = kind === "tracker"
      ? 20 + (Math.floor(seed / 19) % 54)
      : kind === "lantern"
        ? 10 + (Math.floor(seed / 17) % 76)
        : kind === "forge"
          ? 24 + (Math.floor(seed / 13) % 46)
          : kind === "loom"
            ? 8 + (Math.floor(seed / 17) % 78)
            : 18 + ((Math.floor(seed / 29) % 5) * 12) + (seed % 7);
    const sizePx = 1.6 + (seed % 4) * 0.75 + fieldStrength * 0.4;
    const modeOpacity = mode === "quick"
      ? 0.05
      : kind === "lantern"
        ? 0.07
        : kind === "forge"
          ? 0.082
          : kind === "loom"
            ? 0.088
            : kind === "ledger"
              ? 0.062
              : mode === "thesis"
                ? 0.085
                : mode === "anchors"
                  ? 0.078
                  : 0.072;

    return {
      id: `grain-${index}`,
      leftPercent,
      topPercent,
      sizePx,
      opacity: clamp01(modeOpacity + ((seed % 7) / 100) + fieldStrength * 0.06),
      blurPx: mode === "thesis" ? 0.8 : 0.4 + (seed % 3) * 0.3,
      driftMs: Math.round(7800 + index * 170 + (mode === "quick" ? 700 : 0)),
      delayMs: (seed % 2200) * -1,
    };
  });
}

function resolveReleaseCue(
  label: string,
  stance: HuntSpiritStance,
  stationLabel: string,
  fieldStrength: number,
): SpiritReleaseCue {
  const intensity = clamp01(fieldStrength);
  const targetLabel = `dock, sidebar, and ${stationLabel}`;

  switch (stance) {
    case "witness":
      return {
        title: `Release ${label} as witness posture`,
        subtitle: `Seal the current proof gravity and hand it into ${targetLabel}.`,
        actionLabel: "Seal into the workspace",
        targetLabel,
        durationMs: 2200,
        tetherStrength: 0.84,
        pulseScale: 1.12 + intensity * 0.1,
      };
    case "absorb":
      return {
        title: `Release ${label} as intake posture`,
        subtitle: `Draw anchors and active material through the chamber into ${targetLabel}.`,
        actionLabel: "Draw into the workspace",
        targetLabel,
        durationMs: 2100,
        tetherStrength: 0.78,
        pulseScale: 1.08 + intensity * 0.08,
      };
    case "focus":
      return {
        title: `Release ${label} toward the active lane`,
        subtitle: `Sharpen the likely next lane before the hunt leaves the chamber.`,
        actionLabel: "Focus the workspace",
        targetLabel,
        durationMs: 2000,
        tetherStrength: 0.74,
        pulseScale: 1.05 + intensity * 0.07,
      };
    case "transit":
      return {
        title: `Release ${label} into transit`,
        subtitle: `Send the spirit as a visible handoff into ${stationLabel}.`,
        actionLabel: "Transit into the workspace",
        targetLabel,
        durationMs: 2400,
        tetherStrength: 0.9,
        pulseScale: 1.16 + intensity * 0.1,
      };
    case "attune":
      return {
        title: `Release ${label} into the local field`,
        subtitle: `Let the spirit attune around ${targetLabel} without overpowering the room.`,
        actionLabel: "Attune the workspace",
        targetLabel,
        durationMs: 1900,
        tetherStrength: 0.66,
        pulseScale: 1.04 + intensity * 0.05,
      };
    case "idle":
    default:
      return {
        title: `Release ${label} into the hunt`,
        subtitle: `Set a stable field presence across ${targetLabel}.`,
        actionLabel: "Release into the workspace",
        targetLabel,
        durationMs: 1800,
        tetherStrength: 0.6,
        pulseScale: 1 + intensity * 0.05,
      };
  }
}

export function buildSpiritManifestationModel(
  context: SpiritBindContext,
  candidate: SpiritBindCandidate,
): SpiritManifestationModel {
  const previewSpirit = createHuntSpiritState({
    kind: candidate.kind,
    bindSource: candidate.bindSource,
    bindReason: candidate.rationale,
    thesis: candidate.thesis,
    anchorArtifactIds: candidate.anchorArtifactIds,
    isPinned: false,
    confidenceScore: candidate.confidenceScore,
    liveMood: candidate.liveMood,
  });

  const runtime = deriveHuntSpiritRuntimeState(previewSpirit, {
    currentLens: context.currentLens,
    currentShell: context.currentShell,
    activeStationId: context.activeStationId,
    confidenceScore: candidate.confidenceScore,
    isActive: true,
  });

  const mode = resolveManifestationMode(candidate);
  const meta = getHuntSpiritMeta(candidate.kind);
  const accentColor = runtime.accentColor ?? meta.accentColor;
  const contour = runtime.contour ?? meta.contour;
  const stationLabel = resolveStationLabel(context);
  const fieldStrength = clamp01(runtime.fieldStrength);
  const grammar = resolveStageGrammar(candidate.kind, mode, fieldStrength);
  const inscriptions = buildInscriptions(candidate, mode, fieldStrength, candidate.kind);
  const tethers = buildTethers(context, candidate, mode, fieldStrength, candidate.kind);
  const ghosts = buildGhosts(candidate, mode, candidate.kind);
  const grains = buildAtmosphereGrains(
    `${context.hunt.id}-${candidate.kind}-${mode}`,
    candidate.kind,
    mode,
    fieldStrength,
  );

  return {
    label: meta.label,
    accentColor,
    contour,
    contourPath: CONTOUR_PATHS[contour] ?? CONTOUR_PATHS["reticle-vector"],
    stance: runtime.stance,
    mode,
    motionLabel: formatFieldStrength(fieldStrength, mode),
    moodLabel: formatMoodLabel(runtime),
    fieldStrength,
    fieldPercent: Math.round(fieldStrength * 100),
    reasonLine: candidate.rationale,
    biasLine: candidate.biasLine,
    thesisLine: candidate.thesis,
    focusLine: candidate.predictedFocusSurfaces.join(" • "),
    chamberTitle: `${meta.label} manifestation`,
    stationLabel,
    rings: buildRings(runtime, mode, candidate.kind, grammar),
    atmosphere: {
      veilOpacity:
        0.08
        + runtime.motion.aura * 0.16
        + (candidate.kind === "loom" ? 0.06 : candidate.kind === "lantern" ? 0.04 : 0)
        + (mode === "thesis" ? 0.04 : 0),
      bloomOpacity:
        0.07
        + runtime.motion.pulse * 0.16
        + (candidate.kind === "forge" ? 0.06 : candidate.kind === "lantern" ? 0.04 : 0)
        + (mode === "anchors" ? 0.04 : 0),
      particleCount: grains.length,
      pulseMs: Math.round(
        2400
        - runtime.motion.pulse * 760
        + (mode === "quick" ? 220 : 0)
        + (candidate.kind === "ledger" ? 260 : candidate.kind === "forge" ? -180 : 0),
      ),
      driftMs: Math.round(
        7200
        - runtime.motion.arousal * 1100
        + (mode === "quick" ? 520 : 0)
        + (candidate.kind === "loom" ? 400 : candidate.kind === "tracker" ? -260 : 0),
      ),
      railOpacity:
        0.08
        + fieldStrength * 0.18
        + (mode === "manual" ? 0.04 : 0)
        + (candidate.kind === "tracker" ? 0.04 : candidate.kind === "ledger" ? 0.02 : 0),
      grainOpacity: 0.14 + fieldStrength * 0.12 + (candidate.kind === "loom" ? 0.04 : 0),
      grains,
    },
    release: resolveReleaseCue(meta.label, runtime.stance, stationLabel, fieldStrength),
    runtime,
    stage: {
      kind: candidate.kind,
      mode,
      modeLabel: modeLabel(mode),
      subtitle: modeSubtitle(mode, candidate),
      stateLabel: formatStateLabel(runtime),
      intentLine: buildIntentLine(mode, candidate, context),
      consequenceLine: buildConsequenceLine(candidate),
      exitLabel: buildExitLabel(stationLabel),
      dominance:
        (candidate.kind === "loom"
          ? 0.94
          : candidate.kind === "forge"
            ? 0.92
            : candidate.kind === "tracker"
              ? 0.89
              : candidate.kind === "lantern"
                ? 0.86
                : 0.83)
        + (mode === "anchors" ? 0.04 : mode === "thesis" ? 0.02 : mode === "quick" ? -0.12 : 0),
      vesselScale:
        (candidate.kind === "forge"
          ? 1.16
          : candidate.kind === "loom"
            ? 1.14
            : candidate.kind === "tracker"
              ? 1.11
              : candidate.kind === "lantern"
                ? 1.04
                : 1.02)
        + fieldStrength * (candidate.kind === "forge" ? 0.16 : 0.14)
        + (mode === "thesis" ? 0.05 : 0)
        + (mode === "manual" ? 0.03 : 0)
        + (mode === "anchors" ? 0.07 : 0)
        - (mode === "quick" ? 0.08 : 0),
      haloOpacity:
        (candidate.kind === "lantern"
          ? 0.34
          : candidate.kind === "loom"
            ? 0.28
            : candidate.kind === "tracker"
              ? 0.24
              : candidate.kind === "forge"
                ? 0.2
                : 0.18)
        + runtime.motion.aura * 0.12
        + (mode === "thesis" ? 0.04 : 0)
        - (mode === "quick" ? 0.04 : 0),
      floorGlowOpacity:
        (candidate.kind === "forge"
          ? 0.28
          : candidate.kind === "ledger"
            ? 0.26
            : candidate.kind === "loom"
              ? 0.24
              : 0.18)
        + runtime.motion.pulse * 0.11
        + (mode === "manual" ? 0.03 : 0)
        - (mode === "quick" ? 0.03 : 0),
      grammar,
      inscriptions,
      tethers,
      ghosts,
    },
  };
}

export function describeSpiritManifestationState(model: SpiritManifestationModel): string {
  return `${model.label} is ${STANCE_LABELS[model.stance]} with ${model.motionLabel}.`;
}
