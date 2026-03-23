import type { RefObject } from "react";
import type { DerivedObservatoryWorld, ObservatoryHeroPropRecipe } from "../../world/deriveObservatoryWorld";
import type { ObservatoryMissionLoopState } from "../../world/missionLoop";
import type { ObservatoryProbeState } from "../../world/probeRuntime";
import type { HuntStationId } from "../../world/types";
import type { ObservatoryLodTier } from "../../utils/observatory-performance";
import type { MissionInteractionSource, ObservatoryPlayerFocusState } from "../flow-runtime/grounding";
import type { ObservatoryGhostTrace } from "../../world/observatory-ghost-memory";
import type { ObservatoryAnalystPresetId } from "../../types";
import type { ObservatoryProbeGuidance } from "../../world/observatory-recommendations";

export interface ObservatoryActiveHeroInteraction {
  assetId: ObservatoryHeroPropRecipe["assetId"];
  expiresAt: number;
  startedAt: number;
  stationId: HuntStationId | "core";
  targetStationId?: HuntStationId | null;
}

export interface ObservatoryTransitLayerProps {
  eruptionStrengthByRouteStation: Partial<Record<HuntStationId, number>>;
  missionTargetStationId: HuntStationId | null;
  world: DerivedObservatoryWorld;
}

export interface ObservatoryDistrictLayerProps {
  activeHeroInteraction: ObservatoryActiveHeroInteraction | null;
  eruptionStrengthByStation: Partial<Record<HuntStationId, number>>;
  missionTargetAssetId: ObservatoryHeroPropRecipe["assetId"] | null;
  missionTargetStationId: HuntStationId | null;
  modeOpacityScale: number;
  onSelectStation?: (stationId: HuntStationId) => void;
  onTriggerHeroProp?: (prop: ObservatoryHeroPropRecipe, meta: MissionInteractionSource) => void;
  playerFocusRef: RefObject<ObservatoryPlayerFocusState | null>;
  playerInteractableAssetId: ObservatoryHeroPropRecipe["assetId"] | null;
  probeStatus: ObservatoryProbeState["status"];
  watchfieldRaised: boolean;
  world: DerivedObservatoryWorld;
  districtLodTiers: Partial<Record<HuntStationId, ObservatoryLodTier>>;
}

export interface ObservatoryWorldSceneProps {
  activeHeroInteraction: ObservatoryActiveHeroInteraction | null;
  cameraResetToken: number;
  eruptionStrengthByRouteStation: Partial<Record<HuntStationId, number>>;
  eruptionStrengthByStation: Partial<Record<HuntStationId, number>>;
  flyByActive: boolean;
  mission: ObservatoryMissionLoopState | null;
  missionTargetAssetId: ObservatoryHeroPropRecipe["assetId"] | null;
  missionTargetStationId: HuntStationId | null;
  onFlyByComplete: () => void;
  onSelectStation?: (stationId: HuntStationId) => void;
  onTriggerHeroProp?: (prop: ObservatoryHeroPropRecipe, meta: MissionInteractionSource) => void;
  playerFocusRef: RefObject<ObservatoryPlayerFocusState | null>;
  playerInteractableAssetId: ObservatoryHeroPropRecipe["assetId"] | null;
  probeLockedTargetStationId: HuntStationId | null;
  probeStatus: ObservatoryProbeState["status"];
  watchfieldRaised: boolean;
  world: DerivedObservatoryWorld;
  ghostTraces?: ObservatoryGhostTrace[];
  /** 1.0 = GHOST preset active (full opacity), 0.2 = inactive (dimmed). Default: 0.2 */
  ghostOpacityScale?: number;
  /** Active analyst preset driving overlay rendering. null = no overlay. */
  analystPresetId?: ObservatoryAnalystPresetId | null;
  /** Phase 40 HEAT: normalized pressure data for heatmap shader (6-element Float32Array) */
  heatmapPressureData?: Float32Array | null;
  /** Phase 40 HEAT-04: gate heatmap rendering based on weatherBudget */
  heatmapVisible?: boolean;
  /** Phase 40 HEAT-05: THREAT preset multiplier (1.0 = normal, 1.5 = THREAT preset) */
  heatmapPresetMultiplier?: number;
  /** Phase 40 PRBI: probe guidance for delta card rendering */
  probeGuidance?: ObservatoryProbeGuidance | null;
}
