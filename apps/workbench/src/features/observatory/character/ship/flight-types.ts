import type { HuntStationId } from "../../world/types";

export type SpeedTier = "cruise" | "boost" | "dock";

export interface FlightConfig {
  /** Cruise speed cap in units/s */
  cruiseSpeed: number;
  /** Boost multiplier relative to cruise (3x) */
  boostMultiplier: number;
  /** Boost duration in ms */
  boostDurationMs: number;
  /** Boost cooldown in ms */
  boostCooldownMs: number;
  /** Dock approach speed cap in units/s */
  dockSpeed: number;
  /** Dock proximity radius in units */
  dockProximityRadius: number;
  /** Thrust acceleration in units/s^2 */
  thrustAcceleration: number;
  /** Velocity damping factor (velocity *= 1 - damping * delta) */
  dampingFactor: number;
  /** Pitch sensitivity (radians per pixel of mouse movement) */
  pitchSensitivity: number;
  /** Yaw sensitivity (radians per pixel of mouse movement) */
  yawSensitivity: number;
  /** Double-tap W window for boost activation in ms */
  boostDoubleTapWindowMs: number;
}

export interface FlightState {
  /** Current velocity as [x, y, z] in world space */
  velocity: [number, number, number];
  /** Ship orientation as quaternion [x, y, z, w] */
  quaternion: [number, number, number, number];
  /** Ship position as [x, y, z] in world space */
  position: [number, number, number];
  /** Active speed tier */
  speedTier: SpeedTier;
  /** Timestamp (ms) when boost was last activated, null if never */
  boostActivatedAtMs: number | null;
  /** Whether boost is currently on cooldown */
  boostOnCooldown: boolean;
  /** Whether pointer lock is currently active */
  pointerLocked: boolean;
  /** Current speed magnitude in units/s */
  currentSpeed: number;
  /** Nearest station id if within dockProximityRadius, null otherwise */
  nearestStationId: HuntStationId | null;
  /** Autopilot target station id — null when not active */
  autopilotTargetStationId: HuntStationId | null;
}

export interface FlightIntent {
  /** Forward/backward thrust: 1 = forward, -1 = brake/reverse, 0 = none */
  thrust: number;
  /** Left/right strafe: -1 = left, 1 = right, 0 = none */
  strafe: number;
  /** Vertical thrust: 1 = up, -1 = down, 0 = none */
  vertical: number;
  /** Mouse delta X (yaw) in pixels since last frame */
  mouseDeltaX: number;
  /** Mouse delta Y (pitch) in pixels since last frame */
  mouseDeltaY: number;
  /** Whether boost was triggered this frame */
  boostTriggered: boolean;
  /** Whether interact (dock) was triggered this frame */
  interactTriggered: boolean;
}

/** Thruster nozzle positions in ship-local space (for VFX anchoring) */
export interface ShipThrusterLayout {
  /** Nozzle positions relative to ship center, each [x, y, z] */
  nozzlePositions: readonly [number, number, number][];
  /** Direction each nozzle points (normalized, ship-local) */
  nozzleDirection: [number, number, number];
}

export const DEFAULT_FLIGHT_CONFIG: FlightConfig = {
  cruiseSpeed: 40,
  boostMultiplier: 3,
  boostDurationMs: 2000,
  boostCooldownMs: 4000,
  dockSpeed: 8,
  dockProximityRadius: 50,
  thrustAcceleration: 60,
  dampingFactor: 1.5,
  pitchSensitivity: 0.003,
  yawSensitivity: 0.003,
  boostDoubleTapWindowMs: 300,
};

export const DEFAULT_FLIGHT_STATE: FlightState = {
  velocity: [0, 0, 0],
  quaternion: [0, 0, 0, 1],
  position: [0, 80, 200],
  speedTier: "cruise",
  boostActivatedAtMs: null,
  boostOnCooldown: false,
  pointerLocked: false,
  currentSpeed: 0,
  nearestStationId: null,
  autopilotTargetStationId: null,
};

/** 4 thruster nozzles on rear of ship, symmetric pattern */
export const SHIP_THRUSTER_LAYOUT: ShipThrusterLayout = {
  nozzlePositions: [
    [-0.4, 0.1, 1.4],
    [0.4, 0.1, 1.4],
    [-0.2, -0.15, 1.4],
    [0.2, -0.15, 1.4],
  ],
  nozzleDirection: [0, 0, 1],
};

export function createEmptyFlightIntent(): FlightIntent {
  return {
    thrust: 0,
    strafe: 0,
    vertical: 0,
    mouseDeltaX: 0,
    mouseDeltaY: 0,
    boostTriggered: false,
    interactTriggered: false,
  };
}
