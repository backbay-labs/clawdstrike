import { useGLTF } from "@react-three/drei";
import {
  OBSERVATORY_ASTRONAUT_OPERATOR_ANIMATION_URLS,
  OBSERVATORY_ASTRONAUT_OPERATOR_ASSET_URL,
  OBSERVATORY_ASTRONAUT_OPERATOR_TEXTURE_SOURCE_URL,
} from "@/features/observatory/character/avatar/assetManifest";
import { OBSERVATORY_HERO_PROP_ASSETS } from "@/features/observatory/world/propAssets";
import type { HuntObservatoryMode } from "@/features/observatory/world/types";
import type { ObservatoryProbeState } from "@/features/observatory/world/probeRuntime";
import type { HuntStationId } from "@/features/observatory/world/types";
import type { ObservatoryWeatherBudget } from "@/features/observatory/world/observatory-weather";

export interface ObservatoryPerformanceProfileInput {
  mode: HuntObservatoryMode;
  flyByActive?: boolean;
  activeHeroInteraction: boolean;
  playerInputEnabled: boolean;
  runtimeQuality?: ObservatoryRuntimeQuality;
  hardwareConcurrency?: number | null;
  prefersReducedMotion?: boolean;
  saveData?: boolean;
  spiritBound?: boolean;
}

export type ObservatoryRuntimeQuality = "low" | "balanced" | "high";
export type ObservatoryLodTier = "focus" | "near" | "far" | "dormant";

export interface ObservatoryRuntimeActivitySources {
  activeHeroInteraction: boolean;
  eruptionCount: number;
  flyByActive: boolean;
  missionTargetStationId: HuntStationId | null;
  playerInputEnabled: boolean;
  probeStatus: ObservatoryProbeState["status"];
  replayScrubbing: boolean;
  selectedStationId: HuntStationId | null;
  shouldInvalidateOnRouteChange: boolean;
  replayFrameIndex?: number;
  routeSignature?: string;
  /** Phase 39: v10.0 invalidation sources */
  annotationDropCount?: number;
  heatmapPulseVersion?: number;
  spiritTrailSegmentCount?: number;
  constellationCount?: number;
  interiorTransitionPhase?: string | null;
}

export interface ObservatoryLodPolicyInput {
  activeStationId: HuntStationId | null;
  likelyStationId: HuntStationId | null;
  missionTargetStationId: HuntStationId | null;
  selectedStationId: HuntStationId | null;
}

export interface ObservatoryLodPolicy {
  focusRadius: number;
  farRadius: number;
  nearRadius: number;
  resolveCrewTier: (input: ObservatoryLodPolicyInput & { distanceToCamera: number; stationId: HuntStationId }) => ObservatoryLodTier;
  resolveDistrictTier: (input: ObservatoryLodPolicyInput & { distanceToCamera: number; stationId: HuntStationId }) => ObservatoryLodTier;
}

export interface ObservatoryPerformanceProfile {
  dpr: [number, number];
  mountFlowSystems: boolean;
  mountVfxPools: boolean;
  enablePhysics: boolean;
  enableParticles: boolean;
  enableBloom: boolean;
  enableAutofocus: boolean;
  enableLut: boolean;
  enableVignette: boolean;
  enableToneMapping: boolean;
  enableSmaa: boolean;
  enableWeather: boolean;
  weatherBudget: ObservatoryWeatherBudget;
}

function resolveObservatoryLodTierFromDistance(
  distanceToCamera: number,
  input: ObservatoryLodPolicyInput & { stationId: HuntStationId; nearRadius: number; farRadius: number; focusRadius: number },
): ObservatoryLodTier {
  if (
    input.stationId === input.activeStationId
    || input.stationId === input.missionTargetStationId
    || input.stationId === input.selectedStationId
  ) {
    return "focus";
  }
  if (distanceToCamera <= input.focusRadius) {
    return "focus";
  }
  if (distanceToCamera <= input.nearRadius || input.stationId === input.likelyStationId) {
    return "near";
  }
  if (distanceToCamera <= input.farRadius) {
    return "far";
  }
  return "dormant";
}

export function createObservatoryLodPolicy(
  input: Partial<Pick<ObservatoryLodPolicy, "focusRadius" | "nearRadius" | "farRadius">> = {},
): ObservatoryLodPolicy {
  const focusRadius = input.focusRadius ?? 12;
  const nearRadius = input.nearRadius ?? 24;
  const farRadius = input.farRadius ?? 40;

  return {
    focusRadius,
    nearRadius,
    farRadius,
    resolveCrewTier: ({ distanceToCamera, ...policyInput }) =>
      resolveObservatoryLodTierFromDistance(distanceToCamera, {
        ...policyInput,
        focusRadius,
        nearRadius,
        farRadius,
      }),
    resolveDistrictTier: ({ distanceToCamera, ...policyInput }) =>
      resolveObservatoryLodTierFromDistance(distanceToCamera, {
        ...policyInput,
        focusRadius,
        nearRadius,
        farRadius,
      }),
  };
}

export function shouldKeepObservatoryRealtimeActive({
  activeHeroInteraction,
  eruptionCount,
  flyByActive,
  missionTargetStationId,
  playerInputEnabled,
  probeStatus,
  replayScrubbing,
}: ObservatoryRuntimeActivitySources): boolean {
  return (
    flyByActive
    || activeHeroInteraction
    || eruptionCount > 0
    || replayScrubbing
    || probeStatus !== "ready"
    || playerInputEnabled
    || missionTargetStationId !== null
  );
}

export function shouldRenderObservatoryPostFx(profile: Pick<
  ObservatoryPerformanceProfile,
  | "enableAutofocus"
  | "enableBloom"
  | "enableLut"
  | "enableSmaa"
  | "enableToneMapping"
  | "enableVignette"
>): boolean {
  return (
    profile.enableAutofocus
    || profile.enableBloom
    || profile.enableLut
    || profile.enableSmaa
    || profile.enableToneMapping
    || profile.enableVignette
  );
}

export const OBSERVATORY_PRELOAD_URLS = Array.from(
  new Set([
    ...Object.values(OBSERVATORY_HERO_PROP_ASSETS).map((asset) => asset.url),
    OBSERVATORY_ASTRONAUT_OPERATOR_ASSET_URL,
    OBSERVATORY_ASTRONAUT_OPERATOR_TEXTURE_SOURCE_URL,
    ...OBSERVATORY_ASTRONAUT_OPERATOR_ANIMATION_URLS,
  ]),
);

let observatoryAssetsPreloaded = false;

export function preloadObservatoryAssets(
  preload: (url: string) => void = useGLTF.preload,
): void {
  if (observatoryAssetsPreloaded) {
    return;
  }
  observatoryAssetsPreloaded = true;
  OBSERVATORY_PRELOAD_URLS.forEach((url) => preload(url));
}

export function resetObservatoryAssetPreloadForTests(): void {
  observatoryAssetsPreloaded = false;
}

export function createObservatoryPerformanceProfile({
  mode,
  flyByActive = false,
  activeHeroInteraction,
  playerInputEnabled,
  runtimeQuality = "high",
  hardwareConcurrency = null,
  prefersReducedMotion = false,
  saveData = false,
  spiritBound = true,
}: ObservatoryPerformanceProfileInput): ObservatoryPerformanceProfile {
  const constrainedDevice =
    prefersReducedMotion
    || saveData
    || (hardwareConcurrency !== null && hardwareConcurrency <= 4);
  const flowMode = mode === "flow";
  const enablePhysics = flowMode && !flyByActive;
  const interactiveFlow = enablePhysics && playerInputEnabled;
  const lowQuality = constrainedDevice || runtimeQuality === "low";
  const balancedQuality = !lowQuality && runtimeQuality === "balanced";
  const weatherBudget: ObservatoryWeatherBudget = lowQuality
    ? "off"
    : flowMode
      ? "full"
      : "reduced";
  const maxDpr = lowQuality
    ? 1.1
    : balancedQuality
      ? interactiveFlow
        ? 1.25
        : flowMode
          ? 1.2
          : spiritBound
            ? 1.2
            : 1.15
      : interactiveFlow
        ? 1.5
        : flowMode
          ? 1.35
          : spiritBound
            ? 1.25
            : 1.2;

  return {
    dpr: [1, maxDpr],
    mountFlowSystems: enablePhysics,
    mountVfxPools: interactiveFlow && !lowQuality && !balancedQuality,
    enablePhysics,
    enableParticles: interactiveFlow && !lowQuality && !balancedQuality,
    enableBloom: flowMode && !lowQuality,
    enableAutofocus: flowMode && activeHeroInteraction && !lowQuality && !balancedQuality,
    enableLut: spiritBound,
    enableVignette: !constrainedDevice || spiritBound,
    enableToneMapping: true,
    enableSmaa: interactiveFlow && !lowQuality && !balancedQuality,
    enableWeather: weatherBudget !== "off",
    weatherBudget,
  };
}
