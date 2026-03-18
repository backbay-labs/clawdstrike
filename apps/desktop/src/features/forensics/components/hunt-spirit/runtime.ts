import type {
  HuntSpiritKind,
  HuntSpiritRuntimeState,
  HuntSpiritSignalSnapshot,
} from "@/shell/workbench/spirit";
import { clamp01, countOf, hasRecentBind } from "@/shell/workbench/spirit/sceneMath";
import type { HuntStationId, SpiritFieldActor } from "@/features/hunt-observatory";

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
  kind: HuntSpiritKind;
  label: string;
  accentColor: string;
  contour: string;
  stance: HuntSpiritRuntimeState["stance"];
  cue: HuntSpiritSceneCueEvent | null;
  emphasis: string[];
  reason: string | null;
  activeStationId: string | null;
  observatoryActiveStationId?: HuntStationId | null;
  observatoryLikelyStationId?: HuntStationId | null;
  observatoryActor?: SpiritFieldActor;
  presenceStrength: number;
  orbitRadius: number;
  altitude: number;
  laneBias: number;
  focusBeam: number;
}

function mapForensicsStationToObservatory(activeStationId: string | null): HuntStationId | null {
  switch (activeStationId) {
    case "signal":
    case "targets":
    case "run":
    case "receipts":
    case "case-notes":
    case "watch":
      return activeStationId;
    case "security-overview":
      return "signal";
    case "attack-graph":
      return "targets";
    case "network-map":
      return "run";
    case "threat-radar":
      return "watch";
    default:
      return null;
  }
}

function deriveObservatoryLikelyStationId(
  snapshot: HuntSpiritSignalSnapshot,
  activeStationId: string | null,
): HuntStationId | null {
  switch (snapshot.likelyIntent) {
    case "watch":
      return "watch";
    case "attach-target":
      return "targets";
    case "attach-evidence":
    case "compare":
      return "receipts";
    case "cite":
      return "case-notes";
    case "mount":
    case "run-input":
      return "run";
    default:
      break;
  }

  if (
    countOf(snapshot.artifactCounts, "receipt") > 0 ||
    countOf(snapshot.artifactCounts, "evidence") > 0
  ) {
    return "receipts";
  }
  if (
    countOf(snapshot.semanticCounts, "watch") > 0 ||
    countOf(snapshot.artifactCounts, "signal") > 0
  ) {
    return "watch";
  }
  if (
    countOf(snapshot.semanticCounts, "target") > 0 ||
    countOf(snapshot.artifactCounts, "entity") > 0
  ) {
    return "targets";
  }
  if (snapshot.runningRunCount > 0 || countOf(snapshot.artifactCounts, "file") > 0) {
    return "run";
  }
  if (snapshot.phase === "reporting" || snapshot.currentLens === "notes") {
    return "case-notes";
  }

  return mapForensicsStationToObservatory(activeStationId) ?? "signal";
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
  cueKind: HuntSpiritSceneCueEvent["kind"] | null,
): SpiritFieldActor["cueKind"] {
  switch (cueKind) {
    case "bind":
    case "focus":
    case "witness":
    case "absorb":
      return cueKind;
    default:
      return null;
  }
}

export function detectHuntSpiritSceneCue(input: {
  runtime: HuntSpiritRuntimeState;
  previousRuntime?: HuntSpiritRuntimeState | null;
  snapshot: HuntSpiritSignalSnapshot | null;
  previousSnapshot: HuntSpiritSignalSnapshot | null;
  activeStationId: string | null;
  previousActiveStationId: string | null;
  nowMs: number;
}): HuntSpiritSceneCueEvent | null {
  const {
    runtime,
    previousRuntime = null,
    snapshot,
    previousSnapshot,
    activeStationId,
    previousActiveStationId,
    nowMs,
  } = input;

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
  const enteredWitness = runtime.stance === "witness" && previousRuntime?.stance !== "witness";
  if (receiptDelta > 0 || evidenceDelta > 0 || enteredWitness) {
    return emit("witness", "Witnessing new proof on the active hunt lane.", 2_800);
  }

  const fileDelta =
    countOf(snapshot.artifactCounts, "file") - countOf(previousArtifactCounts, "file");
  const entityDelta =
    countOf(snapshot.artifactCounts, "entity") - countOf(previousArtifactCounts, "entity");
  const targetDelta =
    countOf(snapshot.semanticCounts, "target") -
    countOf(previousSnapshot?.semanticCounts ?? {}, "target");
  const enteredAbsorb = runtime.stance === "absorb" && previousRuntime?.stance !== "absorb";
  if (fileDelta > 0 || entityDelta > 0 || targetDelta > 0 || enteredAbsorb) {
    return emit("absorb", "Absorbing evidence and target mass into the hunt field.", 2_400);
  }

  const lensChanged = previousSnapshot?.currentLens !== snapshot.currentLens;
  const intentChanged = previousSnapshot?.likelyIntent !== snapshot.likelyIntent;
  const stationChanged = previousActiveStationId !== activeStationId;
  const enteredFocus = runtime.stance === "focus" && previousRuntime?.stance !== "focus";
  if (
    enteredFocus ||
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
    signal: -0.58,
    "security-overview": -0.58,
    targets: -0.18,
    "attack-graph": -0.18,
    watch: 0.22,
    "threat-radar": 0.22,
    run: 0.58,
    "network-map": 0.58,
    receipts: 0.36,
    "case-notes": 0.08,
  };
  const laneBias = laneBiasByStation[activeStationId ?? ""] ?? 0;
  const cueBoost = cue ? 0.14 : 0;
  const cueFocusBoost = cue?.kind === "focus" ? 0.26 : cue?.kind === "bind" ? 0.18 : 0.1;
  const observatoryActiveStationId = mapForensicsStationToObservatory(activeStationId);
  const observatoryLikelyStationId = deriveObservatoryLikelyStationId(snapshot, activeStationId);

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
    activeStationId,
    observatoryActiveStationId,
    observatoryLikelyStationId,
    observatoryActor: {
      type: "spirit-field",
      kind: runtime.kind,
      stance: mapRuntimeStanceToObservatory(runtime.stance),
      likelyStationId: observatoryLikelyStationId,
      emphasis: runtime.emphasis.slice(0, 3),
      cueKind: mapCueKindToObservatory(cue?.kind ?? null),
    },
    presenceStrength: clamp01(runtime.fieldStrength * 0.76 + cueBoost + 0.12),
    orbitRadius: 1.05 + runtime.motion.aura * 1.35 + (cue?.kind === "bind" ? 0.2 : 0),
    altitude: 1.1 + runtime.motion.openness * 0.92 + (cue?.kind === "focus" ? 0.18 : 0),
    laneBias,
    focusBeam: clamp01(runtime.motion.pulse * 0.7 + cueFocusBoost),
  };
}
