/**
 * docking-types.ts — Phase 23 DCK-01/02/03/04
 *
 * Types and constants for the three-zone docking system:
 *   approach (50-180 units) → magnet (15-50 units) → dock lock (<15 units at <12 u/s)
 *
 * DOCKING_CONFIG values are fixed by CONTEXT.md must-haves.
 */

import type { HuntStationId } from "../../world/types";

// ---------------------------------------------------------------------------
// Zone type
// ---------------------------------------------------------------------------

/**
 * The docking zone the ship currently occupies relative to the nearest station.
 * - null: no station within approach range
 * - "approach": ship is 50-180 units from station (UI prompt available)
 * - "magnet": ship is 15-50 units; tractor-beam pull bias applied to velocity
 * - "dock": ship is docked (dock lock sequence completed or active)
 */
export type DockingZone = "approach" | "magnet" | "dock" | null;

// ---------------------------------------------------------------------------
// State interface
// ---------------------------------------------------------------------------

export interface DockingState {
  /** Station the ship is docking at / docked to, null when free-flying */
  stationId: HuntStationId | null;
  /** Current docking zone relative to nearest station */
  zone: DockingZone;
  /** Timestamp (ms) when dock lock started, null if not in dock-lock sequence */
  dockLockStartMs: number | null;
  /** Whether the undock grace period is active (prevents immediate re-dock) */
  undockGracePeriodActive: boolean;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const DEFAULT_DOCKING_STATE: DockingState = {
  stationId: null,
  zone: null,
  dockLockStartMs: null,
  undockGracePeriodActive: false,
};

export const DOCKING_CONFIG = {
  /** Outer boundary of approach zone in units (matches dockProximityRadius) */
  approachRadius: 180,
  /** Outer boundary of magnet-pull zone in units */
  magnetRadius: 50,
  /** Inner boundary of magnet zone / dock-lock trigger distance in units */
  dockLockRadius: 15,
  /** Max speed in u/s to allow dock-lock trigger (prevents high-speed slamming) */
  dockLockMaxSpeed: 12,
  /** Magnet pull strength ceiling (0-1 scale applied to addScaledVector bias) */
  magnetPullMaxStrength: 0.3,
  /** Dock lock position lerp duration in ms */
  dockLockDurationMs: 800,
  /** Camera transition duration in ms */
  cameraTransitionDurationMs: 1000,
  /** Undock push distance in units */
  undockPushDistance: 20,
  /** Initial undock push velocity in u/s */
  undockPushVelocity: 15,
  /** Grace period after undock before re-dock is permitted, in ms */
  undockGracePeriodMs: 500,
  /** Docked camera offset from dock point [right, up, back] in world units */
  dockedCameraOffset: [0, 5, 25] as readonly [number, number, number],
} as const;
