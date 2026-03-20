/**
 * hud-constants.ts — Phase 24 HUD-01, HUD-02, HUD-06
 *
 * Shared constants for all Space Flight HUD components.
 * Centralizing here avoids duplication and makes theming easy.
 */

import type { SpeedTier } from "../../character/ship/flight-types";
import type { HuntStationId } from "../../world/types";

// ---------------------------------------------------------------------------
// Speed tier colors
// ---------------------------------------------------------------------------

/**
 * Hex colors for the speed indicator fill bar, keyed by SpeedTier.
 * - cruise: white-ish neutral (calm cruising)
 * - boost: orange (high energy burst)
 * - dock: blue (precise approach mode)
 */
export const SPEED_TIER_COLORS: Record<SpeedTier, string> = {
  cruise: "#e0e6ef",
  boost: "#f4a84b",
  dock: "#5ab4f0",
} as const;

// ---------------------------------------------------------------------------
// Station colors (replicated from observatory-world-template.ts — not exported there)
// ---------------------------------------------------------------------------

/**
 * Hex colors for each Hunt station — used to color station labels in the
 * heading compass and any other HUD elements that reference station identity.
 */
export const STATION_COLORS_HEX: Record<HuntStationId, string> = {
  signal: "#7cc8ff",
  targets: "#9df2dd",
  run: "#f4d982",
  receipts: "#7ee6f2",
  "case-notes": "#f0b87b",
  watch: "#d3b56e",
} as const;

// ---------------------------------------------------------------------------
// General HUD palette
// ---------------------------------------------------------------------------

/**
 * Core HUD color tokens — Elite Dangerous-inspired dark cockpit aesthetic.
 */
export const HUD_COLORS = {
  /** Background of panels/bars */
  hudBg: "#0a0d14",
  /** Panel and element borders */
  hudBorder: "#202531",
  /** Primary text color */
  hudText: "#c8d2e0",
  /** Dim/secondary text color */
  hudTextDim: "#6f7f9a",
} as const;

// ---------------------------------------------------------------------------
// Speed indicator sizing
// ---------------------------------------------------------------------------

/** Height of the vertical speed bar in pixels */
export const HUD_SPEED_BAR_HEIGHT = 120;
/** Width of the vertical speed bar in pixels */
export const HUD_SPEED_BAR_WIDTH = 12;

// ---------------------------------------------------------------------------
// Compass sizing
// ---------------------------------------------------------------------------

/** Width of the visible compass window in pixels */
export const HUD_COMPASS_WIDTH = 400;
/** Total width of the inner scrolling compass strip in pixels (one full revolution) */
export const HUD_COMPASS_INNER_WIDTH = 1200;
