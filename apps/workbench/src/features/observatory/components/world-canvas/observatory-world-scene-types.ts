import type { RefObject } from "react";
import type { DerivedObservatoryWorld, ObservatoryHeroPropRecipe } from "../../world/deriveObservatoryWorld";
import type { ObservatoryMissionLoopState } from "../../world/missionLoop";
import type { ObservatoryProbeState } from "../../world/probeRuntime";
import type { HuntStationId } from "../../world/types";
import type { ObservatoryLodTier } from "../../utils/observatory-performance";
import type { MissionInteractionSource, ObservatoryPlayerFocusState } from "../flow-runtime/grounding";
import type { ObservatoryGhostTrace } from "../../world/observatory-ghost-memory";
import type { ConstellationRoute, ObservatoryAnalystPresetId, ObservatoryAnnotationPin } from "../../types";
import type { ObservatoryProbeGuidance } from "../../world/observatory-recommendations";
import type { SpiritMood } from "@/features/spirit/types";

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
  ghostOpacityScale?: number;
  analystPresetId?: ObservatoryAnalystPresetId | null;
  heatmapPressureData?: Float32Array | null;
  heatmapVisible?: boolean;
  heatmapPresetMultiplier?: number;
  probeGuidance?: ObservatoryProbeGuidance | null;
  constellations?: ConstellationRoute[];
  spiritAccentColor?: string | null;
  spiritMood?: SpiritMood | null;
  spiritLevel?: number;
  annotationPins?: ObservatoryAnnotationPin[];
  replayEnabled?: boolean;
  replayFrameIndex?: number;
  replayFrameMs?: number | null;
  onAnnotationDrop?: (worldPosition: [number, number, number]) => void;
  interiorActive?: boolean;
  interiorStationId?: HuntStationId | null;
  interiorTransitionPhase?: "entering" | "inside" | "exiting" | null;
  onInteriorTransitionComplete?: (phase: "inside" | null) => void;
}
