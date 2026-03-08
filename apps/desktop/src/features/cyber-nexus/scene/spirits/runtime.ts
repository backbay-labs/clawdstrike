import type { HuntSpiritRuntimeState, HuntSpiritSignalSnapshot } from "@/shell/workbench/spirit";
import type { Strikecell, StrikecellDomainId } from "../../types";

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
  label: string;
  accentColor: string;
  contour: string;
  stance: HuntSpiritRuntimeState["stance"];
  cue: NexusSpiritCueEvent | null;
  emphasis: string[];
  reason: string | null;
  anchorStrikecellId: StrikecellDomainId;
  likelyStationId: StrikecellDomainId | null;
  presenceStrength: number;
  orbitRadius: number;
  altitude: number;
  focusBeam: number;
  stationAffinities: Partial<Record<StrikecellDomainId, number>>;
}

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function countOf(
  counts: HuntSpiritSignalSnapshot["artifactCounts"] | HuntSpiritSignalSnapshot["semanticCounts"],
  key: string,
): number {
  const value = counts[key as keyof typeof counts];
  return typeof value === "number" ? value : 0;
}

function hasRecentBind(
  snapshot: HuntSpiritSignalSnapshot,
  previousSnapshot: HuntSpiritSignalSnapshot | null,
  nowMs: number,
): boolean {
  const spirit = snapshot.boundSpirit;
  if (!spirit) return false;

  const previousSpirit = previousSnapshot?.boundSpirit ?? null;
  const latestBindAt = Math.max(spirit.boundAt, spirit.reboundAt ?? 0);
  if (previousSpirit === null) return true;
  if (spirit.reboundAt !== previousSpirit.reboundAt) return true;
  return nowMs - latestBindAt <= 4_500;
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
  if (
    runtime.stance === "focus" ||
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

  const cueBoost = cue?.kind === "bind" ? 0.16 : cue?.kind === "transit" ? 0.14 : 0.08;
  const affinityFocus = likelyStationId ? (stationAffinities[likelyStationId] ?? 0) : 0;

  return {
    huntId: snapshot.huntId,
    huntTitle: snapshot.huntTitle,
    label: runtime.label,
    accentColor: runtime.accentColor ?? "#d4a84b",
    contour: runtime.contour ?? "field",
    stance: runtime.stance,
    cue,
    emphasis: runtime.emphasis.slice(0, 3),
    reason: runtime.reason ?? snapshot.boundSpirit.bindReason ?? null,
    anchorStrikecellId,
    likelyStationId,
    presenceStrength: clamp01(runtime.fieldStrength * 0.72 + affinityFocus * 0.24 + cueBoost),
    orbitRadius: 1.1 + runtime.motion.aura * 1.2 + (cue?.kind === "recenter" ? 0.16 : 0),
    altitude: 1.28 + runtime.motion.openness * 0.9 + (cue?.kind === "focus" ? 0.18 : 0),
    focusBeam: clamp01(runtime.motion.pulse * 0.76 + affinityFocus * 0.34),
    stationAffinities,
  };
}
