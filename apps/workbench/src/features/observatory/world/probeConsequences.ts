// Ported from huntronomer apps/desktop/src/features/hunt-observatory/world/probeConsequences.ts
// Adaptation: missionLoop dependency removed (missions deferred to OBS-07).
// buildMissionRead simplified to not accept a mission parameter.

import { HUNT_STATION_LABELS, type HuntStationId } from "./stations";
import type {
  DerivedObservatoryWorld,
  ObservatoryCrewRecipe,
  ObservatoryDistrictProbeReaction,
  ObservatoryProbeReactionState,
} from "./deriveObservatoryWorld";
import type { ObservatoryProbeState } from "./probeRuntime";

interface ObservatoryProbeStationProfile {
  activeRead: string;
  cooldownRead: string;
  crewDirectiveActive: string;
  crewDirectiveCooldown: string;
}

export interface ObservatoryProbeWorldDirective {
  stationId: HuntStationId;
  stationLabel: string;
  state: ObservatoryProbeReactionState;
  intensity: number;
  missionRead: string;
  crewDirective: string;
  affectedStationIds: HuntStationId[];
}

const PROBE_STATION_PROFILES: Record<HuntStationId, ObservatoryProbeStationProfile> = {
  signal: {
    activeRead: "Probe telemetry is opening ingress lanes across the Horizon dishes.",
    cooldownRead: "Horizon crews are holding the opened ingress lanes while telemetry settles.",
    crewDirectiveActive: "Navigators are aligning the dish sweep with the live ingress.",
    crewDirectiveCooldown: "Navigators are holding the dish sweep and confirming the ingress map.",
  },
  targets: {
    activeRead: "Probe telemetry is triangulating the active Subjects cluster from the lattice spine.",
    cooldownRead: "Subjects remains bracketed while the probe cools and the cluster read stabilizes.",
    crewDirectiveActive: "Cluster watchers are collapsing the subject halo around the active node.",
    crewDirectiveCooldown: "Subjects support crews are preserving the triangulated cluster lanes.",
  },
  run: {
    activeRead: "Probe telemetry is staging the Operations scan lane and exposing clean execution routes.",
    cooldownRead: "Operations is keeping the scan lane hot while the probe recharges.",
    crewDirectiveActive: "Technicians are clearing the control deck and aligning the scan rig.",
    crewDirectiveCooldown: "Technicians are holding the scan rig and preserving the warmed route.",
  },
  receipts: {
    activeRead: "Probe telemetry is indexing the latest Evidence arrival and fanning the archive lanes.",
    cooldownRead: "Evidence crews are preserving the surfaced arrival map while telemetry settles.",
    crewDirectiveActive: "Archivists are fanning the vault lanes around the surfaced arrival.",
    crewDirectiveCooldown: "Archivists are locking the surfaced arrival into the archive path.",
  },
  "case-notes": {
    activeRead: "Probe telemetry is staging Judgment seals and exposing the authored finding path.",
    cooldownRead: "Judgment is holding the authored seal path while the probe recharges.",
    crewDirectiveActive: "Judgment aides are staging the seal path across the dais terraces.",
    crewDirectiveCooldown: "Judgment aides are holding the seal path and preserving authored meaning.",
  },
  watch: {
    activeRead: "Probe telemetry is waking the Watchfield perimeter and exposing the outer patrol ring.",
    cooldownRead: "Watchfield sentries are holding the outer patrol ring while telemetry settles.",
    crewDirectiveActive: "Sentries are raising the perimeter watch and aligning the outer beacons.",
    crewDirectiveCooldown: "Sentries are preserving the raised perimeter while the probe recharges.",
  },
};

function toProbeReactionState(
  probeState: ObservatoryProbeState,
): ObservatoryProbeReactionState | null {
  if (probeState.status === "active") return "surveying";
  if (probeState.status === "cooldown") return "stabilizing";
  return null;
}

function buildMissionRead(
  stationId: HuntStationId,
  state: ObservatoryProbeReactionState,
): string {
  const profile = PROBE_STATION_PROFILES[stationId];
  return state === "surveying" ? profile.activeRead : profile.cooldownRead;
}

function buildDistrictProbeReaction(
  stationId: HuntStationId,
  state: ObservatoryProbeReactionState,
  intensity: number,
): ObservatoryDistrictProbeReaction {
  const profile = PROBE_STATION_PROFILES[stationId];
  return {
    state,
    intensity,
    read: buildMissionRead(stationId, state),
    crewDirective:
      state === "surveying" ? profile.crewDirectiveActive : profile.crewDirectiveCooldown,
  };
}

function applyCrewResponse(
  crew: ObservatoryCrewRecipe,
  state: ObservatoryProbeReactionState,
  intensity: number,
): ObservatoryCrewRecipe {
  const focusTarget =
    crew.utilityTarget && Math.abs(crew.utilityTarget[1] - crew.position[1]) <= 1.24
      ? crew.utilityTarget
      : null;
  return {
    ...crew,
    active: true,
    response: {
      state,
      intensity,
      paceMultiplier: state === "surveying" ? 1.65 : 1.24,
      utilityVisible: Boolean(crew.utilityTarget),
      focusTarget,
    },
  };
}

function boostRouteForProbe(
  world: DerivedObservatoryWorld,
  stationId: HuntStationId,
  intensity: number,
): Pick<DerivedObservatoryWorld, "coreLinks" | "transitLinks"> {
  const applyBoost = <TRoute extends DerivedObservatoryWorld["transitLinks"][number]>(
    route: TRoute,
  ): TRoute => {
    if (route.stationId !== stationId) return route;
    return {
      ...route,
      opacity: Math.min(0.96, route.opacity + 0.18 * intensity),
      intensity: Math.min(1.24, route.intensity + 0.34 * intensity),
      showPulse: true,
      convoyCount: route.convoyCount + (intensity >= 0.9 ? 2 : 1),
      corridorOpacity: Math.min(0.92, route.corridorOpacity + 0.16 * intensity),
      glowRadius: route.glowRadius + intensity * 0.12,
    };
  };

  return {
    coreLinks: world.coreLinks.map(applyBoost),
    transitLinks: world.transitLinks.map(applyBoost),
  };
}

export function applyObservatoryProbeConsequences(
  world: DerivedObservatoryWorld,
  probeState: ObservatoryProbeState,
): {
  world: DerivedObservatoryWorld;
  directive: ObservatoryProbeWorldDirective | null;
} {
  const reactionState = toProbeReactionState(probeState);
  const stationId = probeState.targetStationId;
  if (!reactionState || !stationId) {
    return { world, directive: null };
  }

  const intensity = reactionState === "surveying" ? 1 : 0.58;
  const districtReaction = buildDistrictProbeReaction(
    stationId,
    reactionState,
    intensity,
  );
  const boostedRoutes = boostRouteForProbe(world, stationId, intensity);
  const nextDistricts = world.districts.map((district) => {
    if (district.id !== stationId) {
      return district;
    }
    return {
      ...district,
      emphasis: Math.min(1, district.emphasis + 0.18 * intensity),
      lifecycleProgress: Math.min(1, district.lifecycleProgress + 0.16 * intensity),
      pulseAmplitude: district.pulseAmplitude + 0.03 * intensity,
      torusOpacity: Math.min(0.96, district.torusOpacity + 0.14 * intensity),
      localRead: `${district.localRead ?? ""} ${districtReaction.read}`.trim(),
      probeReaction: districtReaction,
      crew: district.crew.map((crew) =>
        applyCrewResponse(crew, reactionState, intensity),
      ),
    };
  });

  return {
    world: {
      ...world,
      districts: nextDistricts,
      coreLinks: boostedRoutes.coreLinks,
      transitLinks: boostedRoutes.transitLinks,
    },
    directive: {
      stationId,
      stationLabel: HUNT_STATION_LABELS[stationId],
      state: reactionState,
      intensity,
      missionRead: districtReaction.read,
      crewDirective: districtReaction.crewDirective,
      affectedStationIds: [stationId],
    },
  };
}
