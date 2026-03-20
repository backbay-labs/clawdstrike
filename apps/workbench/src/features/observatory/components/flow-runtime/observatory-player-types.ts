import type { RefObject } from "react";
import type { HuntStationId } from "../../world/types";
import type {
  DerivedObservatoryWorld,
  ObservatoryHeroPropRecipe,
} from "../../world/deriveObservatoryWorld";
import type {
  MissionInteractionSource,
  ObservatoryPlayerFocusState,
  ObservatoryPlayerWorldState,
} from "./grounding";
import type { FlightState } from "../../character/ship/flight-types";

export type {
  MissionInteractionSource,
  ObservatoryPlayerFocusState,
  ObservatoryPlayerWorldState,
};

export interface ObservatoryFlowRuntimeSceneProps {
  enableCharacterVfx?: boolean;
  heroProps: ObservatoryHeroPropRecipe[];
  inputEnabled?: boolean;
  onInteractProp?: (prop: ObservatoryHeroPropRecipe, meta: MissionInteractionSource) => void;
  onStateChange?: (state: FlightState) => void;
  onWorldStateChange?: (state: ObservatoryPlayerWorldState) => void;
  playerFocusRef: RefObject<ObservatoryPlayerFocusState | null>;
  preferredStationId: HuntStationId | null;
  world: DerivedObservatoryWorld;
}
