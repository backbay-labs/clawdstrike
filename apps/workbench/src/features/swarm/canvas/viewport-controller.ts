import type { Viewport } from "@xyflow/react";

export type SwarmViewportSource =
  | "idle"
  | "pointer"
  | "wheel"
  | "imperative"
  | "snapback";

export interface SwarmViewportPoint {
  x: number;
  y: number;
}

export const SWARM_VIEWPORT_TARGET_MIN_ZOOM = 0.15;
export const SWARM_VIEWPORT_TARGET_MAX_ZOOM = 1.5;
export const SWARM_VIEWPORT_HARD_MIN_ZOOM = 0.08;
export const SWARM_VIEWPORT_HARD_MAX_ZOOM = 2;
export const SWARM_VIEWPORT_ZOOM_SENSITIVITY = 0.6;
export const SWARM_VIEWPORT_RUBBER_BAND_K = 400;
export const SWARM_VIEWPORT_PAN_MULTIPLIER = 1.2;
export const SWARM_VIEWPORT_SNAPBACK_DELAY_MS = 150;
export const SWARM_VIEWPORT_SNAPBACK_LERP = 0.15;
export const SWARM_VIEWPORT_SYNC_EPSILON = 0.0001;

export function shouldZoomCanvasWheel(
  event: { ctrlKey: boolean; metaKey: boolean },
  isMacLike: boolean,
): boolean {
  return event.ctrlKey || (isMacLike && event.metaKey);
}

export function zoomViewportAroundPoint(
  viewport: Viewport,
  targetZoom: number,
  focalPoint: SwarmViewportPoint,
): Viewport {
  const safeTargetZoom = Math.max(0.01, targetZoom);
  const ratio = safeTargetZoom / viewport.zoom - 1;

  return {
    x: viewport.x - (focalPoint.x - viewport.x) * ratio,
    y: viewport.y - (focalPoint.y - viewport.y) * ratio,
    zoom: safeTargetZoom,
  };
}

export function applyViewportWheelZoom(
  viewport: Viewport,
  deltaY: number,
  focalPoint: SwarmViewportPoint,
  minZoom: number = SWARM_VIEWPORT_TARGET_MIN_ZOOM,
  maxZoom: number = SWARM_VIEWPORT_TARGET_MAX_ZOOM,
): Viewport {
  const factorBase = Math.exp((-deltaY * SWARM_VIEWPORT_ZOOM_SENSITIVITY) / 100);
  let factor = factorBase;

  if (viewport.zoom >= maxZoom && factor > 1) {
    const overshoot = viewport.zoom / maxZoom - 1;
    factor = 1 + (factor - 1) / (1 + overshoot * SWARM_VIEWPORT_RUBBER_BAND_K);
  } else if (viewport.zoom <= minZoom && factor < 1) {
    const overshoot = minZoom / viewport.zoom - 1;
    factor = 1 - (1 - factor) / (1 + overshoot * SWARM_VIEWPORT_RUBBER_BAND_K);
  }

  return zoomViewportAroundPoint(
    viewport,
    viewport.zoom * factor,
    focalPoint,
  );
}

export function applyViewportWheelPan(
  viewport: Viewport,
  deltaX: number,
  deltaY: number,
): Viewport {
  return {
    x: viewport.x - deltaX * SWARM_VIEWPORT_PAN_MULTIPLIER,
    y: viewport.y - deltaY * SWARM_VIEWPORT_PAN_MULTIPLIER,
    zoom: viewport.zoom,
  };
}

export function clampViewportZoom(
  viewport: Viewport,
  focalPoint: SwarmViewportPoint,
  minZoom: number = SWARM_VIEWPORT_TARGET_MIN_ZOOM,
  maxZoom: number = SWARM_VIEWPORT_TARGET_MAX_ZOOM,
): Viewport {
  const clampedZoom = Math.min(maxZoom, Math.max(minZoom, viewport.zoom));
  if (Math.abs(clampedZoom - viewport.zoom) <= SWARM_VIEWPORT_SYNC_EPSILON) {
    return viewport;
  }

  return zoomViewportAroundPoint(viewport, clampedZoom, focalPoint);
}

export function stepViewportSnapback(
  viewport: Viewport,
  focalPoint: SwarmViewportPoint,
  minZoom: number = SWARM_VIEWPORT_TARGET_MIN_ZOOM,
  maxZoom: number = SWARM_VIEWPORT_TARGET_MAX_ZOOM,
): Viewport {
  const targetZoom = Math.min(maxZoom, Math.max(minZoom, viewport.zoom));
  if (Math.abs(targetZoom - viewport.zoom) <= SWARM_VIEWPORT_SYNC_EPSILON) {
    return clampViewportZoom(viewport, focalPoint, minZoom, maxZoom);
  }

  const nextZoom = viewport.zoom + (targetZoom - viewport.zoom) * SWARM_VIEWPORT_SNAPBACK_LERP;
  return zoomViewportAroundPoint(viewport, nextZoom, focalPoint);
}

export function viewportNeedsSnapback(
  viewport: Viewport,
  minZoom: number = SWARM_VIEWPORT_TARGET_MIN_ZOOM,
  maxZoom: number = SWARM_VIEWPORT_TARGET_MAX_ZOOM,
): boolean {
  return viewport.zoom < minZoom || viewport.zoom > maxZoom;
}

export function shouldSyncControlledViewport(source: SwarmViewportSource): boolean {
  return source !== "wheel" && source !== "snapback";
}

export function areViewportsEqual(left: Viewport, right: Viewport): boolean {
  return (
    Math.abs(left.x - right.x) <= SWARM_VIEWPORT_SYNC_EPSILON &&
    Math.abs(left.y - right.y) <= SWARM_VIEWPORT_SYNC_EPSILON &&
    Math.abs(left.zoom - right.zoom) <= SWARM_VIEWPORT_SYNC_EPSILON
  );
}

export function getZoomIndicatorLabel(zoom: number): string {
  return `${Math.round(zoom * 100)}%`;
}
