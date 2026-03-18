import {
  HUNT_CORE_LABEL,
  HUNT_STATION_LABELS,
  type HuntObservatorySceneState,
  type HuntStationId,
  type HuntStationState,
} from "@/features/hunt-observatory";

const STATION_CODE: Record<HuntStationId, string> = {
  signal: "HRZ",
  targets: "SBJ",
  run: "OPS",
  receipts: "EVD",
  "case-notes": "JDG",
  watch: "WFD",
};

export interface ForensicsFlowRead {
  stationId: HuntStationId | null;
  label: string;
  code: string;
  reason: string;
  coreLabel: string;
  stations: Array<{
    stationId: HuntStationId;
    label: string;
    code: string;
    active: boolean;
    likely: boolean;
    status: HuntStationState["status"];
    emphasis: number;
  }>;
}

export function resolveForensicsObservatoryStationId(activeStationId: string | null): HuntStationId | null {
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
    case "forensics-river":
      return "receipts";
    case "policies":
      return "case-notes";
    case "threat-radar":
    case "marketplace":
      return "watch";
    default:
      return null;
  }
}

export function buildForensicsFlowRead(
  sceneState: HuntObservatorySceneState | null,
  activeStationId: HuntStationId | null,
): ForensicsFlowRead {
  const likelyStationId = sceneState?.likelyStationId ?? activeStationId;
  const resolvedStationId = likelyStationId ?? activeStationId;
  const activeStation = sceneState?.stations.find((station) => station.id === activeStationId) ?? null;
  const likelyStation = sceneState?.stations.find((station) => station.id === likelyStationId) ?? null;
  const label = resolvedStationId ? HUNT_STATION_LABELS[resolvedStationId] : "Flow";
  const code = resolvedStationId ? STATION_CODE[resolvedStationId] : "FLW";
  const reason =
    likelyStation?.reason ??
    activeStation?.reason ??
    (resolvedStationId
      ? `${HUNT_STATION_LABELS[resolvedStationId]} is carrying the active hunt field.`
      : "The hunt field is waiting for a live station focus.");

  return {
    stationId: resolvedStationId,
    label,
    code,
    reason,
    coreLabel: HUNT_CORE_LABEL,
    stations:
      sceneState?.stations.map((station) => ({
        stationId: station.id,
        label: station.label,
        code: STATION_CODE[station.id],
        active: station.id === activeStationId,
        likely: station.id === likelyStationId,
        status: station.status,
        emphasis: station.emphasis,
      })) ?? [],
  };
}
