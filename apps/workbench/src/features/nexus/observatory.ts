import {
  HUNT_CORE_LABEL,
  HUNT_STATION_LABELS,
  HUNT_STATION_ORDER,
  HUNT_PRIMARY_STATION_ORDER,
} from "@/features/observatory/world/stations";
import type {
  HuntObservatorySceneState,
  HuntStationId,
  SpiritFieldActor,
} from "@/features/observatory/world/types";
import type { NexusSpiritSceneActor } from "./scene/spirits/runtime";
import type { Strikecell, StrikecellDomainId } from "./types";

const STATION_CODE: Record<HuntStationId, string> = {
  signal: "HRZ",
  targets: "SBJ",
  run: "OPS",
  receipts: "EVD",
  "case-notes": "JDG",
  watch: "WFD",
};

const STATION_REASON: Record<HuntStationId, string> = {
  signal: "Fresh change is arriving at the edge of the hunt world.",
  targets: "The room is choosing who or what actually matters.",
  run: "Operator machinery and intervention are driving the world.",
  receipts: "Proof objects and replayable traces are accumulating weight.",
  "case-notes": "Authored understanding is hardening into judgment.",
  watch: "Peripheral attention is holding long-tail pressure around the world.",
};

export interface NexusAtlasStationRead {
  stationId: HuntStationId;
  label: string;
  code: string;
  affinity: number;
  active: boolean;
  likely: boolean;
}

export interface NexusAtlasRead {
  stationId: HuntStationId | null;
  label: string;
  code: string;
  reason: string;
  coreLabel: string;
  activeStationId: HuntStationId | null;
  likelyStationId: HuntStationId | null;
}

export const NEXUS_ATLAS_GROUP_ORDER: HuntStationId[] = HUNT_STATION_ORDER;

export function resolveNexusObservatoryStationId(
  strikecellId: StrikecellDomainId | null,
): HuntStationId | null {
  switch (strikecellId) {
    case "security-overview":
    case "events":
      return "signal";
    case "attack-graph":
      return "targets";
    case "network-map":
    case "workflows":
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

export function getNexusStationCode(stationId: HuntStationId | null): string {
  return stationId ? STATION_CODE[stationId] : "NEX";
}

export function getNexusStationLabel(stationId: HuntStationId | null): string {
  return stationId ? HUNT_STATION_LABELS[stationId] : "Atlas";
}

export function getNexusStationReason(stationId: HuntStationId | null): string {
  return stationId ? STATION_REASON[stationId] : "Topology is holding the active hunt field.";
}

export function buildNexusAtlasRead(input: {
  sceneState?: HuntObservatorySceneState | null;
  activeStrikecell: Strikecell | null;
  activeSpiritActor: NexusSpiritSceneActor | null;
}): NexusAtlasRead {
  const { sceneState, activeStrikecell, activeSpiritActor } = input;
  const activeStationId =
    resolveNexusObservatoryStationId(activeStrikecell?.id ?? null) ??
    sceneState?.stations.find((station) => station.status === "active")?.id ??
    activeSpiritActor?.observatoryAnchorStationId ??
    null;
  const likelyStationId =
    sceneState?.likelyStationId ?? activeSpiritActor?.observatoryLikelyStationId ?? activeStationId;
  const stationId = activeStationId ?? likelyStationId;
  const label = getNexusStationLabel(stationId);
  const code = getNexusStationCode(stationId);
  const reason =
    activeSpiritActor?.cue?.reason ??
    activeSpiritActor?.reason ??
    sceneState?.stations.find((station) => station.id === stationId)?.reason ??
    getNexusStationReason(stationId);

  return {
    stationId,
    label,
    code,
    reason,
    coreLabel: HUNT_CORE_LABEL,
    activeStationId,
    likelyStationId,
  };
}

export function buildNexusAtlasStations(input: {
  sceneState?: HuntObservatorySceneState | null;
  activeStrikecellId: StrikecellDomainId | null;
  activeSpiritActor: NexusSpiritSceneActor | null;
}): NexusAtlasStationRead[] {
  const { sceneState, activeStrikecellId, activeSpiritActor } = input;
  const activeStationId = resolveNexusObservatoryStationId(activeStrikecellId);
  const affinityMap = activeSpiritActor?.observatoryStationAffinities ?? {};
  const likelyStationId = activeSpiritActor?.observatoryLikelyStationId ?? activeStationId;

  return HUNT_PRIMARY_STATION_ORDER.map((stationId) => ({
    stationId,
    label: HUNT_STATION_LABELS[stationId],
    code: STATION_CODE[stationId],
    affinity:
      (sceneState?.stations.find((station) => station.id === stationId)?.affinity ?? 0) +
      (affinityMap[stationId] ?? 0) * 0.35 +
      (activeStationId === stationId ? 0.15 : 0) +
      (likelyStationId === stationId ? 0.08 : 0),
    active:
      sceneState?.stations.find((station) => station.id === stationId)?.status === "active" ||
      activeStationId === stationId,
    likely: (sceneState?.likelyStationId ?? likelyStationId) === stationId,
  }));
}
