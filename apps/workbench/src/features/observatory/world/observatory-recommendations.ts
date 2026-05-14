import type { ObservatoryPressureLane } from "../types";
import type { DerivedObservatoryTelemetry } from "./observatory-telemetry";
import type { HuntStationId } from "./types";
import type { ObservatoryProbeState } from "./probeRuntime";
import { resolveObservatoryStationRoute } from "./observatory-telemetry";

export interface ObservatoryRecommendation {
  stationId: HuntStationId;
  title: string;
  summary: string;
  route: string;
  routeLabel: string;
  confidence: number;
  supportingStationIds: HuntStationId[];
}

export interface ObservatoryProbeDelta {
  kind: "steady" | "lane-up" | "cause-shift" | "pressure-shift";
  summary: string;
  supportingStationIds: HuntStationId[];
}

export interface ObservatoryProbeGuidance {
  stationId: HuntStationId;
  stationLabel: string;
  state: ObservatoryProbeState["status"];
  delta: ObservatoryProbeDelta;
  whyItMatters: string;
  confidence: number;
  recommendation: ObservatoryRecommendation | null;
  supportingStationIds: HuntStationId[];
}

export interface BuildObservatoryProbeGuidanceInput {
  currentTelemetry: DerivedObservatoryTelemetry;
  missionObjective?: {
    stationId: HuntStationId;
    title: string;
  } | null;
  previousTelemetry?: DerivedObservatoryTelemetry | null;
  probeState: ObservatoryProbeState;
}

function findLane(
  telemetry: DerivedObservatoryTelemetry | null | undefined,
  stationId: HuntStationId,
): ObservatoryPressureLane | null {
  return telemetry?.pressureLanes.find((lane) => lane.stationId === stationId) ?? null;
}

function buildProbeDelta(input: {
  currentTelemetry: DerivedObservatoryTelemetry;
  previousTelemetry?: DerivedObservatoryTelemetry | null;
  stationId: HuntStationId;
}): ObservatoryProbeDelta {
  const currentLane = findLane(input.currentTelemetry, input.stationId);
  const previousLane = findLane(input.previousTelemetry, input.stationId);
  const currentStation = input.currentTelemetry.stations.find((station) => station.id === input.stationId);
  const previousStation = input.previousTelemetry?.stations.find((station) => station.id === input.stationId);
  const supportingStationIds = input.currentTelemetry.pressureLanes
    .filter((lane) => lane.stationId !== input.stationId)
    .slice(0, 2)
    .map((lane) => lane.stationId);

  if (!currentLane || !currentStation) {
    return {
      kind: "steady",
      summary: "Probe telemetry is holding the district steady while new evidence accumulates.",
      supportingStationIds,
    };
  }

  const previousTopCause = previousStation?.explanation?.causes[0]?.id ?? null;
  const currentTopCause = currentStation.explanation?.causes[0]?.id ?? null;
  if (previousLane && currentLane.rank < previousLane.rank) {
    return {
      kind: "lane-up",
      summary: `${currentStation.label} rose from rank ${previousLane.rank} to rank ${currentLane.rank}.`,
      supportingStationIds,
    };
  }
  if (previousTopCause && currentTopCause && previousTopCause !== currentTopCause) {
    return {
      kind: "cause-shift",
      summary: `${currentStation.label} pivoted to a new leading cause: ${currentStation.explanation?.causes[0]?.label ?? "telemetry shift"}.`,
      supportingStationIds,
    };
  }
  if (previousLane && currentLane.score - previousLane.score > 0.08) {
    return {
      kind: "pressure-shift",
      summary: `${currentStation.label} gained ${Math.round((currentLane.score - previousLane.score) * 100)} points of pressure during the current probe window.`,
      supportingStationIds,
    };
  }
  return {
    kind: "steady",
    summary: `${currentStation.label} is holding its current posture while the probe confirms the latest read.`,
    supportingStationIds,
  };
}

export function buildObservatoryProbeGuidance({
  currentTelemetry,
  missionObjective = null,
  previousTelemetry = null,
  probeState,
}: BuildObservatoryProbeGuidanceInput): ObservatoryProbeGuidance | null {
  const stationId = probeState.targetStationId;
  if (!stationId || probeState.status === "ready") {
    return null;
  }

  const route = resolveObservatoryStationRoute(stationId);
  const station = currentTelemetry.stations.find((candidate) => candidate.id === stationId);
  const lane = findLane(currentTelemetry, stationId);
  const delta = buildProbeDelta({
    currentTelemetry,
    previousTelemetry,
    stationId,
  });
  const supportingStationIds = Array.from(
    new Set([
      ...delta.supportingStationIds,
      ...(missionObjective && missionObjective.stationId !== stationId ? [missionObjective.stationId] : []),
    ]),
  );
  const confidence = Math.min(
    1,
    Math.max(
      0,
      (lane?.score ?? currentTelemetry.confidence) * 0.7 + currentTelemetry.confidence * 0.3,
    ),
  );
  const whyItMatters =
    missionObjective?.stationId === stationId
      ? `${missionObjective.title} is directly aligned with the current probe target.`
      : station?.explanation?.summary
        ?? `${route.label} remains the best next surface for this district.`;

  return {
    confidence,
    delta,
    recommendation: {
      confidence,
      route: route.route,
      routeLabel: route.label,
      stationId,
      summary: station?.explanation?.summary ?? `Open ${route.label} to continue the current district investigation.`,
      supportingStationIds,
      title: missionObjective?.stationId === stationId
        ? `Open ${route.label} for ${missionObjective.title}`
        : `Open ${route.label}`,
    },
    stationId,
    stationLabel: station?.label ?? route.label,
    state: probeState.status,
    supportingStationIds,
    whyItMatters,
  };
}
