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
  /** Phase 41 CNST: constellation routes from completed missions */
  constellations?: ConstellationRoute[];
  /** Phase 41 CNST: spirit accent color for constellation tint (hex string or null) */
  spiritAccentColor?: string | null;
  /** Phase 41 SPRT: spirit mood for trail rendering */
  spiritMood?: SpiritMood | null;
  /** Phase 41 SPRT: spirit evolution level (1-5) for trail intensity + resonance unlock */
  spiritLevel?: number;
  /** Phase 42 ANNO: annotation pins dropped during replay */
  annotationPins?: ObservatoryAnnotationPin[];
  /** Phase 42 ANNO: whether replay is currently active (gates pin drop) */
  replayEnabled?: boolean;
  /** Phase 42 ANNO: current replay frame index for stamping new pins */
  replayFrameIndex?: number;
  /** Phase 42 ANNO: current replay frame timestamp in ms */
  replayFrameMs?: number | null;
  /** Phase 42 ANNO: callback when analyst clicks empty space to drop a pin */
  onAnnotationDrop?: (worldPosition: [number, number, number]) => void;
  /** Phase 43 INTR: whether interior is currently active */
  interiorActive?: boolean;
  /** Phase 43 INTR: station being viewed in interior mode */
  interiorStationId?: HuntStationId | null;
  /** Phase 43 INTR: current transition phase for camera lerp */
  interiorTransitionPhase?: "entering" | "inside" | "exiting" | null;
  /** Phase 43 INTR: callback when interior camera transition completes */
  onInteriorTransitionComplete?: (phase: "inside" | null) => void;
}
