import { useStore } from "@xyflow/react";

// ---------------------------------------------------------------------------
// Zoom tier types and thresholds
// ---------------------------------------------------------------------------

/** Semantic zoom tier controlling node visual detail level. */
export type ZoomTier = "full" | "compact" | "chip" | "dot";

/**
 * Threshold boundaries for zoom tier transitions.
 * - zoom >= compact  -> "full"
 * - zoom >= chip     -> "compact"
 * - zoom >= dot      -> "chip"
 * - zoom < dot       -> "dot"
 */
export const ZOOM_TIER_THRESHOLDS = {
  compact: 0.6,
  chip: 0.35,
  dot: 0.18,
} as const;

// ---------------------------------------------------------------------------
// Pure selector — exported for direct testing
// ---------------------------------------------------------------------------

/**
 * Derives the current zoom tier from React Flow's internal transform state.
 *
 * Returns a string literal so that `useStore(selectZoomTier)` only triggers
 * re-renders when the tier actually changes (Object.is equality on strings),
 * not on every sub-pixel zoom movement.
 */
export function selectZoomTier(state: {
  transform: [number, number, number];
}): ZoomTier {
  const zoom = state.transform[2];
  if (zoom >= ZOOM_TIER_THRESHOLDS.compact) return "full";
  if (zoom >= ZOOM_TIER_THRESHOLDS.chip) return "compact";
  if (zoom >= ZOOM_TIER_THRESHOLDS.dot) return "chip";
  return "dot";
}

// ---------------------------------------------------------------------------
// React hook
// ---------------------------------------------------------------------------

/**
 * Subscribe to the current zoom tier from the React Flow viewport.
 *
 * Because `selectZoomTier` returns a stable string literal, node components
 * using this hook only re-render when the zoom crosses a tier boundary —
 * not on every zoom frame.
 *
 * Must be called inside a `<ReactFlowProvider>`.
 */
export function useZoomTier(): ZoomTier {
  return useStore(selectZoomTier);
}
