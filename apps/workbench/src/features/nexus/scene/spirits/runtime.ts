// Ported from huntronomer apps/desktop/src/features/cyber-nexus/scene/spirits/runtime.ts
// Spirit types inlined since workbench does not have @/shell/workbench/spirit.
// The full interface is preserved; the workbench NexusTab passes null for spirit props
// so this module primarily provides type definitions for the CyberNexusView overlay.

import type { HuntStationId, SpiritFieldActor } from "@/features/observatory/world/types";
import type { Strikecell, StrikecellDomainId } from "../../types";

// Inlined from huntronomer @/shell/workbench/spirit
export type HuntSpiritKind = "tracker" | "lantern" | "ledger" | "forge" | "loom";

export interface HuntSpiritRuntimeState {
  kind: HuntSpiritKind | null;
  label: string | null;
  accentColor: string | null;
  contour: string | null;
  mood: string;
  stance: "idle" | "attune" | "focus" | "witness" | "absorb" | "transit";
  reason: string | null;
  emphasis: string[];
  fieldStrength: number;
  shouldRender: boolean;
  motion: {
    arousal: number;
    valence: number;
    openness: number;
    aura: number;
    pulse: number;
    tilt: number;
  };
  activeStationId: StrikecellDomainId | null;
  currentShell: string | null;
  currentLens: string | null;
}

export interface HuntSpiritSignalSnapshot {
  huntId: string;
  huntTitle: string;
  boundSpirit: { bindReason: string | null } | null;
  currentShell: string | null;
  currentLens: string | null;
  likelyIntent: string | null;
  confidenceScore: number;
  phase: string | null;
  runningRunCount: number;
  artifactCounts: Record<string, number>;
  semanticCounts: Record<string, number>;
}

// Inlined helpers
function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function countOf(counts: Record<string, number> | undefined, key: string): number {
  return counts?.[key] ?? 0;
}

function hasRecentBind(
  snapshot: HuntSpiritSignalSnapshot | null,
  previousSnapshot: HuntSpiritSignalSnapshot | null,
  _nowMs: number,
): boolean {
  if (!snapshot?.boundSpirit) return false;
  if (previousSnapshot?.boundSpirit) return false;
  return true;
}

export type NexusSpiritCueKind = "bind" | "transit" | "focus" | "recenter";

export interface NexusSpiritCueEvent {
  kind: NexusSpiritCueKind;
  reason: string;
  durationMs: number;
  startedAt: number;
  expiresAt: number;
  fromStrikecellId: StrikecellDomainId | null;
  toStrikecellId: StrikecellDomainId | null;
}

export interface NexusSpiritSceneActor {
  huntId: string;
  huntTitle: string;
  kind: HuntSpiritKind;
  label: string;
  accentColor: string;
  contour: string;
  stance: HuntSpiritRuntimeState["stance"];
  cue: NexusSpiritCueEvent | null;
  emphasis: string[];
  reason: string | null;
  anchorStrikecellId: StrikecellDomainId;
  likelyStationId: StrikecellDomainId | null;
  observatoryAnchorStationId?: HuntStationId | null;
  observatoryLikelyStationId?: HuntStationId | null;
  observatoryStationAffinities?: Partial<Record<HuntStationId, number>>;
  observatoryActor?: SpiritFieldActor;
  presenceStrength: number;
  orbitRadius: number;
  altitude: number;
  focusBeam: number;
  stationAffinities: Partial<Record<StrikecellDomainId, number>>;
}

function mapStrikecellToObservatoryStation(
  strikecellId: StrikecellDomainId | null,
): HuntStationId | null {
  switch (strikecellId) {
    case "security-overview":
      return "signal";
    case "attack-graph":
      return "targets";
    case "workflows":
      return "run";
    case "forensics-river":
      return "receipts";
    case "threat-radar":
      return "watch";
    case "network-map":
      return "run";
    default:
      return null;
  }
}

function mapRuntimeStanceToObservatory(
  stance: HuntSpiritRuntimeState["stance"],
): SpiritFieldActor["stance"] {
  switch (stance) {
    case "attune":
    case "idle":
      return "watchful";
    case "focus":
      return "focus";
    case "witness":
      return "witness";
    case "absorb":
      return "absorb";
    case "transit":
      return "transit";
  }
}

function mapCueKindToObservatory(
  cueKind: NexusSpiritCueEvent["kind"] | null,
): SpiritFieldActor["cueKind"] {
  switch (cueKind) {
    case "bind":
    case "transit":
    case "focus":
      return cueKind;
    case "recenter":
      return "focus";
    default:
      return null;
  }
}

function collapseToObservatoryStationAffinities(
  stationAffinities: Partial<Record<StrikecellDomainId, number>>,
): Partial<Record<HuntStationId, number>> {
  const collapsed: Partial<Record<HuntStationId, number>> = {};

  for (const [strikecellId, affinity] of Object.entries(stationAffinities) as Array<
    [StrikecellDomainId, number | undefined]
  >) {
    const stationId = mapStrikecellToObservatoryStation(strikecellId);
    if (!stationId) continue;
    collapsed[stationId] = clamp01((collapsed[stationId] ?? 0) + (affinity ?? 0));
  }

  return collapsed;
}

function resolveObservatoryLikelyStationId(
  stationAffinities: Partial<Record<HuntStationId, number>>,
  activeStrikecellId: StrikecellDomainId | null,
): HuntStationId | null {
  let bestId = mapStrikecellToObservatoryStation(activeStrikecellId);
  let bestScore = bestId ? (stationAffinities[bestId] ?? 0) : 0;

  for (const [stationId, score] of Object.entries(stationAffinities) as Array<
    [HuntStationId, number | undefined]
  >) {
    const currentScore = score ?? 0;
    if (currentScore > bestScore) {
      bestId = stationId;
      bestScore = currentScore;
    }
  }

  return bestId;
}

function applyWeight(
  scores: Partial<Record<StrikecellDomainId, number>>,
  targetId: StrikecellDomainId,
  amount: number,
): void {
  scores[targetId] = (scores[targetId] ?? 0) + amount;
}

function likelyStationCandidates(
  snapshot: HuntSpiritSignalSnapshot,
): Array<[StrikecellDomainId, number]> {
  const candidates: Array<[StrikecellDomainId, number]> = [];
  const push = (id: StrikecellDomainId, amount: number) => {
    candidates.push([id, amount]);
  };

  switch (snapshot.likelyIntent) {
    case "watch":
    case "attach-target":
      push("threat-radar", 0.26);
      push("network-map", 0.18);
      break;
    case "attach-evidence":
      push("forensics-river", 0.28);
      push("security-overview", 0.14);
      break;
    case "cite":
    case "compare":
      push("attack-graph", 0.24);
      push("forensics-river", 0.18);
      break;
    case "mount":
      push("network-map", 0.28);
      push("workflows", 0.12);
      break;
    case "run-input":
      push("workflows", 0.28);
      push("network-map", 0.16);
      break;
    default:
      break;
  }

  if (
    countOf(snapshot.artifactCounts, "receipt") > 0 ||
    countOf(snapshot.artifactCounts, "evidence") > 0
  ) {
    push("forensics-river", 0.16);
  }
  if (countOf(snapshot.artifactCounts, "file") > 0) {
    push("network-map", 0.14);
  }
  if (
    countOf(snapshot.semanticCounts, "target") > 0 ||
    countOf(snapshot.artifactCounts, "entity") > 0
  ) {
    push("threat-radar", 0.16);
  }
  if (snapshot.runningRunCount > 0) {
    push("workflows", 0.12);
  }
  if (snapshot.phase === "triage" || snapshot.phase === "reporting") {
    push("security-overview", 0.12);
  }

  return candidates;
}

export function deriveNexusSpiritStationAffinities(input: {
  runtime: HuntSpiritRuntimeState;
  snapshot: HuntSpiritSignalSnapshot | null;
  activeStrikecellId: StrikecellDomainId | null;
  strikecells: Strikecell[];
}): Partial<Record<StrikecellDomainId, number>> {
  const { runtime, snapshot, activeStrikecellId, strikecells } = input;
  if (!snapshot?.boundSpirit || !runtime.shouldRender || !runtime.kind) return {};

  const scores: Partial<Record<StrikecellDomainId, number>> = {};
  const confidence = clamp01(snapshot.confidenceScore / 100);

  for (const strikecell of strikecells) {
    scores[strikecell.id] = 0.04;
  }

  if (activeStrikecellId) {
    applyWeight(scores, activeStrikecellId, 0.32 + confidence * 0.2);
  }

  for (const [stationId, amount] of likelyStationCandidates(snapshot)) {
    applyWeight(scores, stationId, amount + confidence * 0.08);
  }

  if (runtime.stance === "transit" && activeStrikecellId) {
    applyWeight(scores, activeStrikecellId, 0.2);
  }
  if (runtime.stance === "focus" && activeStrikecellId) {
    applyWeight(scores, activeStrikecellId, 0.16);
  }

  const normalized: Partial<Record<StrikecellDomainId, number>> = {};
  for (const strikecell of strikecells) {
    normalized[strikecell.id] = clamp01(scores[strikecell.id] ?? 0);
  }
  return normalized;
}

function resolveLikelyStationId(
  stationAffinities: Partial<Record<StrikecellDomainId, number>>,
  activeStrikecellId: StrikecellDomainId | null,
): StrikecellDomainId | null {
  let bestId = activeStrikecellId ?? null;
  let bestScore = bestId ? (stationAffinities[bestId] ?? 0) : 0;

  for (const [stationId, score] of Object.entries(stationAffinities) as Array<
    [StrikecellDomainId, number | undefined]
  >) {
    const currentScore = score ?? 0;
    if (currentScore > bestScore) {
      bestId = stationId;
      bestScore = currentScore;
    }
  }

  return bestId;
}

export function detectNexusSpiritCue(input: {
  runtime: HuntSpiritRuntimeState;
  previousRuntime?: HuntSpiritRuntimeState | null;
  snapshot: HuntSpiritSignalSnapshot | null;
  previousSnapshot: HuntSpiritSignalSnapshot | null;
  activeStrikecellId: StrikecellDomainId | null;
  previousActiveStrikecellId: StrikecellDomainId | null;
  recenterToken: number;
  previousRecenterToken: number;
  nowMs: number;
}): NexusSpiritCueEvent | null {
  const {
    runtime,
    previousRuntime = null,
    snapshot,
    previousSnapshot,
    activeStrikecellId,
    previousActiveStrikecellId,
    recenterToken,
    previousRecenterToken,
    nowMs,
  } = input;

  if (!snapshot?.boundSpirit || !runtime.shouldRender || !runtime.kind) return null;

  const emit = (
    kind: NexusSpiritCueKind,
    reason: string,
    durationMs: number,
    fromStrikecellId: StrikecellDomainId | null = previousActiveStrikecellId,
    toStrikecellId: StrikecellDomainId | null = activeStrikecellId,
  ) => ({
    kind,
    reason,
    durationMs,
    startedAt: nowMs,
    expiresAt: nowMs + durationMs,
    fromStrikecellId,
    toStrikecellId,
  });

  if (hasRecentBind(snapshot, previousSnapshot, nowMs)) {
    return emit("bind", "Spirit bind settles into the active strikecell ring.", 3_400);
  }

  if (recenterToken !== previousRecenterToken && activeStrikecellId) {
    return emit(
      "recenter",
      "Recentering the active spirit and rehearsing station rationale.",
      2_200,
      activeStrikecellId,
      activeStrikecellId,
    );
  }

  if (
    activeStrikecellId &&
    previousActiveStrikecellId &&
    previousActiveStrikecellId !== activeStrikecellId
  ) {
    return emit(
      "transit",
      "Spirit posture transfers with the active strikecell focus.",
      2_600,
      previousActiveStrikecellId,
      activeStrikecellId,
    );
  }

  const previousIntent = previousSnapshot?.likelyIntent ?? null;
  const previousLens = previousSnapshot?.currentLens ?? null;
  const enteredFocus = runtime.stance === "focus" && previousRuntime?.stance !== "focus";
  if (
    enteredFocus ||
    (snapshot.confidenceScore >= 56 &&
      (previousIntent !== snapshot.likelyIntent || previousLens !== snapshot.currentLens))
  ) {
    return emit("focus", "Tightening station emphasis around the current hunt posture.", 2_000);
  }

  return null;
}

export function deriveNexusSpiritSceneActor(input: {
  runtime: HuntSpiritRuntimeState;
  snapshot: HuntSpiritSignalSnapshot | null;
  strikecells: Strikecell[];
  activeStrikecellId: StrikecellDomainId | null;
  cue: NexusSpiritCueEvent | null;
}): NexusSpiritSceneActor | null {
  const { runtime, snapshot, strikecells, activeStrikecellId, cue } = input;
  if (!snapshot?.boundSpirit || !runtime.shouldRender || !runtime.kind || !runtime.label) {
    return null;
  }

  const stationAffinities = deriveNexusSpiritStationAffinities({
    runtime,
    snapshot,
    activeStrikecellId,
    strikecells,
  });
  const likelyStationId = resolveLikelyStationId(stationAffinities, activeStrikecellId);
  const anchorStrikecellId = activeStrikecellId ?? likelyStationId;
  if (!anchorStrikecellId) return null;
  const observatoryStationAffinities = collapseToObservatoryStationAffinities(stationAffinities);
  const observatoryLikelyStationId = resolveObservatoryLikelyStationId(
    observatoryStationAffinities,
    activeStrikecellId,
  );
  const observatoryAnchorStationId =
    mapStrikecellToObservatoryStation(anchorStrikecellId) ?? observatoryLikelyStationId;

  const cueBoost = cue?.kind === "bind" ? 0.16 : cue?.kind === "transit" ? 0.14 : 0.08;
  const affinityFocus = likelyStationId ? (stationAffinities[likelyStationId] ?? 0) : 0;

  return {
    huntId: snapshot.huntId,
    huntTitle: snapshot.huntTitle,
    kind: runtime.kind,
    label: runtime.label,
    accentColor: runtime.accentColor ?? "#d4a84b",
    contour: runtime.contour ?? "field",
    stance: runtime.stance,
    cue,
    emphasis: runtime.emphasis.slice(0, 3),
    reason: runtime.reason ?? snapshot.boundSpirit.bindReason ?? null,
    anchorStrikecellId,
    likelyStationId,
    observatoryAnchorStationId,
    observatoryLikelyStationId,
    observatoryStationAffinities,
    observatoryActor: {
      type: "spirit-field",
      kind: runtime.kind,
      stance: mapRuntimeStanceToObservatory(runtime.stance),
      likelyStationId: observatoryLikelyStationId,
      emphasis: runtime.emphasis.slice(0, 3),
      cueKind: mapCueKindToObservatory(cue?.kind ?? null),
    },
    presenceStrength: clamp01(runtime.fieldStrength * 0.72 + affinityFocus * 0.24 + cueBoost),
    orbitRadius: 1.1 + runtime.motion.aura * 1.2 + (cue?.kind === "recenter" ? 0.16 : 0),
    altitude: 1.28 + runtime.motion.openness * 0.9 + (cue?.kind === "focus" ? 0.18 : 0),
    focusBeam: clamp01(runtime.motion.pulse * 0.76 + affinityFocus * 0.34),
    stationAffinities,
  };
}
