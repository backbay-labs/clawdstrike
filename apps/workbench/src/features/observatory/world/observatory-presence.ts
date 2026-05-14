import type { ObservatoryStation } from "../types";
import { resolveObservatoryStationRoute } from "./observatory-telemetry";
import type { ObservatoryProbeState } from "./probeRuntime";
import type { HuntObservatoryMode, HuntStationId, HuntStationStatus } from "./types";

export interface ObservatorySpikeCueCause {
  label: string;
  detail: string;
}

export interface ObservatorySpikeCueRecommendation {
  stationId: HuntStationId;
  route: string;
  routeLabel: string;
  actionLabel: string;
}

export interface ObservatorySpikeCue {
  cueKey: string;
  causes: ObservatorySpikeCueCause[];
  emphasis: number;
  recommendation: ObservatorySpikeCueRecommendation;
  stationId: HuntStationId;
  stationLabel: string;
  status: HuntStationStatus | null;
  title: string;
  timestampMs: number;
}

export interface DeriveObservatorySpikeCueInput {
  flyByActive?: boolean;
  ghostMode?: "off" | "auto" | "focused" | "full";
  likelyStationId?: HuntStationId | null;
  missionTargetStationId?: HuntStationId | null;
  nowMs: number;
  previousCueKey?: string | null;
  previousLikelyStationId?: HuntStationId | null;
  previousProbeStatus?: ObservatoryProbeState["status"] | null;
  previousStationEmphasis?: Partial<Record<HuntStationId, number>>;
  probeState?: ObservatoryProbeState | null;
  replayEnabled?: boolean;
  selectedStationId?: HuntStationId | null;
  stations: ObservatoryStation[];
  mode?: HuntObservatoryMode;
}

function clamp01(value: number): number {
  return Math.max(0, Math.min(1, value));
}

function asImportanceScore(input: {
  artifactCount: number;
  emphasisDelta: number;
  hasReason: boolean;
  isLikely: boolean;
  isMissionTarget: boolean;
  isProbeTarget: boolean;
  isSelected: boolean;
  statusTransition: number;
}): number {
  return (
    input.statusTransition +
    Math.max(0, input.emphasisDelta) * 8 +
    Math.min(1.5, input.artifactCount * 0.18) +
    (input.hasReason ? 1.2 : -0.35) +
    (input.isLikely ? 0.6 : 0) +
    (input.isMissionTarget ? 0.75 : 0) +
    (input.isSelected ? 0.4 : 0) +
    (input.isProbeTarget ? 1.4 : 0)
  );
}

function buildCauseLines(input: {
  hasReason: boolean;
  isMissionTarget: boolean;
  isProbeTarget: boolean;
  missionTargetStationId?: HuntStationId | null;
  probeState?: ObservatoryProbeState | null;
  routeLabel: string;
  status: HuntStationStatus | null;
  stationLabel: string;
  emphasisDelta: number;
  reason: string | null;
}): ObservatorySpikeCueCause[] {
  const causes: ObservatorySpikeCueCause[] = [];

  if (input.reason) {
    causes.push({
      label: "Primary cause",
      detail: input.reason,
    });
  } else if (input.status === "active" || input.status === "receiving") {
    causes.push({
      label: "Status change",
      detail: `${input.stationLabel} moved into ${input.status} posture.`,
    });
  } else {
    causes.push({
      label: "Pressure rise",
      detail: `${input.stationLabel} gained ${Math.round(input.emphasisDelta * 100)} points of emphasis.`,
    });
  }

  if (input.isMissionTarget && input.missionTargetStationId) {
    causes.push({
      label: "Mission alignment",
      detail: `Current mission work is already tracking ${input.routeLabel.toLowerCase()}.`,
    });
  }

  if (input.isProbeTarget && input.probeState?.status === "active") {
    causes.push({
      label: "Probe alignment",
      detail: `The active probe is already pointed at ${input.stationLabel}.`,
    });
  }

  if (causes.length < 3) {
    causes.push({
      label: "Route",
      detail: `Open ${input.routeLabel} to continue the live investigation.`,
    });
  }

  return causes.slice(0, 3);
}

function buildTitle(input: {
  hasReason: boolean;
  reason: string | null;
  stationLabel: string;
  status: HuntStationStatus | null;
}): string {
  if (input.reason) {
    return `${input.stationLabel} is drawing attention`;
  }
  if (input.status === "receiving") {
    return `${input.stationLabel} just started receiving pressure`;
  }
  if (input.status === "active") {
    return `${input.stationLabel} just became active`;
  }
  return `${input.stationLabel} is climbing`;
}

function isMeaningfulCandidate(input: {
  emphasisDelta: number;
  likelyTransition: boolean;
  probeTarget: boolean;
  probeTransition: boolean;
  status: HuntStationStatus | null;
  reason: string | null;
  artifactCount: number;
}): boolean {
  const statusHot = input.status === "active" || input.status === "receiving";
  const probeHot =
    input.probeTarget
    && (input.probeTransition || input.reason != null || input.artifactCount > 0);
  const statusEscalating = statusHot && (input.likelyTransition || input.emphasisDelta >= 0.08);
  return statusEscalating || input.emphasisDelta >= 0.18 || probeHot;
}

function buildCueKey(cue: ObservatorySpikeCue): string {
  return [
    cue.stationId,
    cue.title,
    cue.status ?? "idle",
    cue.recommendation.stationId,
    cue.causes.map((cause) => `${cause.label}:${cause.detail}`).join("|"),
    cue.emphasis.toFixed(2),
  ].join("::");
}

export function buildObservatorySpikeCueKey(cue: ObservatorySpikeCue): string {
  return buildCueKey(cue);
}

export function deriveObservatorySpikeCue(input: DeriveObservatorySpikeCueInput): ObservatorySpikeCue | null {
  if (input.replayEnabled || input.flyByActive) {
    return null;
  }

  const stationsById = new Map(input.stations.map((station) => [station.id, station]));
  const candidateStations = input.stations
    .map((station) => {
      const previousEmphasis = input.previousStationEmphasis?.[station.id] ?? 0;
      const stationEmphasis = station.emphasis ?? 0;
      const emphasisDelta = stationEmphasis - previousEmphasis;
      const isProbeTarget = input.probeState?.targetStationId === station.id;
      const probeTransition =
        isProbeTarget
        && input.probeState?.status === "active"
        && input.previousProbeStatus !== "active";
      const isMissionTarget = input.missionTargetStationId === station.id;
      const isLikely = input.likelyStationId === station.id;
      const likelyTransition = isLikely && input.previousLikelyStationId !== station.id;
      const isSelected = input.selectedStationId === station.id;
      const reason = station.reason ?? null;
      const statusTransition =
        station.status === "receiving"
          ? (likelyTransition || probeTransition || emphasisDelta >= 0.08 ? 3.2 : 0)
          : station.status === "active"
            ? (likelyTransition || probeTransition || emphasisDelta >= 0.08 ? 3.5 : 0)
            : 0;

      return {
        artifactCount: station.artifactCount,
        emphasisDelta,
        hasReason: Boolean(reason?.trim()),
        isLikely,
        likelyTransition,
        isMissionTarget,
        isProbeTarget,
        probeTransition,
        isSelected,
        reason,
        score: asImportanceScore({
          artifactCount: station.artifactCount,
          emphasisDelta,
          hasReason: Boolean(reason?.trim()),
          isLikely,
          isMissionTarget,
          isProbeTarget,
          isSelected,
          statusTransition,
        }),
        station,
        statusTransition,
      };
    })
    .filter((candidate) =>
      isMeaningfulCandidate({
        artifactCount: candidate.artifactCount,
        emphasisDelta: candidate.emphasisDelta,
        likelyTransition: candidate.likelyTransition,
        probeTarget: candidate.isProbeTarget,
        probeTransition: candidate.probeTransition,
        reason: candidate.reason,
        status: candidate.station.status ?? null,
      }),
    )
    .sort((left, right) => {
      if (right.score !== left.score) {
        return right.score - left.score;
      }
      if ((right.station.emphasis ?? 0) !== (left.station.emphasis ?? 0)) {
        return (right.station.emphasis ?? 0) - (left.station.emphasis ?? 0);
      }
      return left.station.label.localeCompare(right.station.label);
    });

  const candidate =
    candidateStations[0] ?? null;

  if (!candidate) {
    return null;
  }

  const route = resolveObservatoryStationRoute(candidate.station.id);
  const causes = buildCauseLines({
    emphasisDelta: candidate.emphasisDelta,
    hasReason: candidate.hasReason,
    isMissionTarget: candidate.isMissionTarget,
    isProbeTarget: candidate.isProbeTarget,
    missionTargetStationId: input.missionTargetStationId,
    probeState: input.probeState,
    reason: candidate.reason,
    routeLabel: route.label,
    stationLabel: candidate.station.label,
    status: candidate.station.status ?? null,
  });

  const cue: ObservatorySpikeCue = {
    causes,
    cueKey: "",
    emphasis: clamp01(Math.max(candidate.station.emphasis ?? 0, candidate.station.affinity ?? 0)),
    recommendation: {
      actionLabel: `Open ${route.label}`,
      route: route.route,
      routeLabel: route.label,
      stationId: candidate.station.id,
    },
    stationId: candidate.station.id,
    stationLabel: candidate.station.label,
    status: candidate.station.status ?? null,
    title: buildTitle({
      hasReason: candidate.hasReason,
      reason: candidate.reason,
      stationLabel: candidate.station.label,
      status: candidate.station.status ?? null,
    }),
    timestampMs: input.nowMs,
  };

  cue.cueKey = buildCueKey(cue);

  if (input.previousCueKey && input.previousCueKey === cue.cueKey) {
    return null;
  }

  return cue;
}
