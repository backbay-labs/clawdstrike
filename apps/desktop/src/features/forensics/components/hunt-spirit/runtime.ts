import type { HuntSpiritRuntimeState, HuntSpiritSignalSnapshot } from "@/shell/workbench/spirit";

export type HuntSpiritSceneCueKind = "bind" | "witness" | "absorb" | "focus";

export interface HuntSpiritSceneCueEvent {
  kind: HuntSpiritSceneCueKind;
  reason: string;
  durationMs: number;
  startedAt: number;
  expiresAt: number;
}

export interface HuntSpiritSceneActor {
  huntId: string;
  huntTitle: string;
  label: string;
  accentColor: string;
  contour: string;
  stance: HuntSpiritRuntimeState["stance"];
  cue: HuntSpiritSceneCueEvent | null;
  emphasis: string[];
  reason: string | null;
  activeStationId: string | null;
  presenceStrength: number;
  orbitRadius: number;
  altitude: number;
  laneBias: number;
  focusBeam: number;
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

export function detectHuntSpiritSceneCue(input: {
  runtime: HuntSpiritRuntimeState;
  snapshot: HuntSpiritSignalSnapshot | null;
  previousSnapshot: HuntSpiritSignalSnapshot | null;
  activeStationId: string | null;
  previousActiveStationId: string | null;
  nowMs: number;
}): HuntSpiritSceneCueEvent | null {
  const { runtime, snapshot, previousSnapshot, activeStationId, previousActiveStationId, nowMs } =
    input;

  if (!snapshot?.boundSpirit || !runtime.shouldRender || !runtime.kind) return null;

  const emit = (kind: HuntSpiritSceneCueKind, reason: string, durationMs: number) => ({
    kind,
    reason,
    durationMs,
    startedAt: nowMs,
    expiresAt: nowMs + durationMs,
  });

  if (hasRecentBind(snapshot, previousSnapshot, nowMs)) {
    return emit("bind", "Spirit bind pulse entering the river field.", 3_600);
  }

  const previousArtifactCounts = previousSnapshot?.artifactCounts ?? {};
  const receiptDelta =
    countOf(snapshot.artifactCounts, "receipt") - countOf(previousArtifactCounts, "receipt");
  const evidenceDelta =
    countOf(snapshot.artifactCounts, "evidence") - countOf(previousArtifactCounts, "evidence");
  if (receiptDelta > 0 || evidenceDelta > 0 || runtime.stance === "witness") {
    return emit("witness", "Witnessing new proof on the active hunt lane.", 2_800);
  }

  const fileDelta =
    countOf(snapshot.artifactCounts, "file") - countOf(previousArtifactCounts, "file");
  const entityDelta =
    countOf(snapshot.artifactCounts, "entity") - countOf(previousArtifactCounts, "entity");
  const targetDelta =
    countOf(snapshot.semanticCounts, "target") -
    countOf(previousSnapshot?.semanticCounts ?? {}, "target");
  if (fileDelta > 0 || entityDelta > 0 || targetDelta > 0 || runtime.stance === "absorb") {
    return emit("absorb", "Absorbing evidence and target mass into the hunt field.", 2_400);
  }

  const lensChanged = previousSnapshot?.currentLens !== snapshot.currentLens;
  const intentChanged = previousSnapshot?.likelyIntent !== snapshot.likelyIntent;
  const stationChanged = previousActiveStationId !== activeStationId;
  if (
    runtime.stance === "focus" ||
    (snapshot.confidenceScore >= 56 && (lensChanged || intentChanged || stationChanged))
  ) {
    return emit("focus", "Tightening focus on the active river lane.", 2_100);
  }

  return null;
}

export function deriveHuntSpiritSceneActor(input: {
  runtime: HuntSpiritRuntimeState;
  snapshot: HuntSpiritSignalSnapshot | null;
  activeStationId: string | null;
  cue: HuntSpiritSceneCueEvent | null;
}): HuntSpiritSceneActor | null {
  const { runtime, snapshot, activeStationId, cue } = input;
  if (!snapshot?.boundSpirit || !runtime.shouldRender || !runtime.kind || !runtime.label)
    return null;

  const laneBiasByStation: Record<string, number> = {
    "security-overview": -0.58,
    "attack-graph": -0.18,
    "threat-radar": 0.22,
    "network-map": 0.58,
  };
  const laneBias = laneBiasByStation[activeStationId ?? ""] ?? 0;
  const cueBoost = cue ? 0.14 : 0;
  const cueFocusBoost = cue?.kind === "focus" ? 0.26 : cue?.kind === "bind" ? 0.18 : 0.1;

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
    activeStationId,
    presenceStrength: clamp01(runtime.fieldStrength * 0.76 + cueBoost + 0.12),
    orbitRadius: 1.05 + runtime.motion.aura * 1.35 + (cue?.kind === "bind" ? 0.2 : 0),
    altitude: 1.1 + runtime.motion.openness * 0.92 + (cue?.kind === "focus" ? 0.18 : 0),
    laneBias,
    focusBeam: clamp01(runtime.motion.pulse * 0.7 + cueFocusBoost),
  };
}
