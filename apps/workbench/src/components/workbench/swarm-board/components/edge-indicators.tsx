/**
 * EdgeIndicators -- renders small directional arrows on the canvas edge
 * for each off-screen node, providing at-a-glance awareness of nodes
 * outside the visible viewport.
 */
import React, { useMemo } from "react";
import { useReactFlow, useViewport, Panel } from "@xyflow/react";

// --- Geometry ---

export function rayRectIntersect(
  originX: number,
  originY: number,
  targetX: number,
  targetY: number,
  rectX: number,
  rectY: number,
  rectW: number,
  rectH: number,
): { x: number; y: number } | null {
  const dx = targetX - originX;
  const dy = targetY - originY;
  if (dx === 0 && dy === 0) return null;

  const tLeft = dx !== 0 ? (rectX - originX) / dx : -Infinity;
  const tRight = dx !== 0 ? (rectX + rectW - originX) / dx : Infinity;
  const tTop = dy !== 0 ? (rectY - originY) / dy : -Infinity;
  const tBottom = dy !== 0 ? (rectY + rectH - originY) / dy : Infinity;

  const tMin = Math.max(Math.min(tLeft, tRight), Math.min(tTop, tBottom));
  const tMax = Math.min(Math.max(tLeft, tRight), Math.max(tTop, tBottom));

  if (tMax < 0 || tMin > tMax) return null;

  const t = tMin > 0 ? tMin : tMax;
  return { x: originX + dx * t, y: originY + dy * t };
}

// --- Constants ---

const INDICATOR_SIZE = 20;
const INDICATOR_INSET = 8; // pixels inset from edge to avoid clipping
const MAX_INDICATORS = 12; // cap to avoid clutter on huge boards

// --- Types ---

interface IndicatorData {
  id: string;
  screenX: number;
  screenY: number;
  angleDeg: number;
}

// --- Component ---

export function EdgeIndicators(): React.ReactElement | null {
  const { getNodes } = useReactFlow();
  const viewport = useViewport();
  const nodes = getNodes();

  const indicators = useMemo(() => {
    const results: IndicatorData[] = [];
    const { x: vx, y: vy, zoom } = viewport;

    const containerW =
      typeof window !== "undefined" ? window.innerWidth : 1200;
    const containerH =
      typeof window !== "undefined" ? window.innerHeight : 800;

    const centerX = containerW / 2;
    const centerY = containerH / 2;

    for (const node of nodes) {
      const screenX = node.position.x * zoom + vx;
      const screenY = node.position.y * zoom + vy;
      const nodeW = (node.measured?.width ?? 280) * zoom;
      const nodeH = (node.measured?.height ?? 100) * zoom;

      const isOffScreen =
        screenX + nodeW < 0 ||
        screenX > containerW ||
        screenY + nodeH < 0 ||
        screenY > containerH;

      if (!isOffScreen) continue;

      const nodeCenterX = screenX + nodeW / 2;
      const nodeCenterY = screenY + nodeH / 2;

      const hit = rayRectIntersect(
        centerX,
        centerY,
        nodeCenterX,
        nodeCenterY,
        INDICATOR_INSET,
        INDICATOR_INSET,
        containerW - INDICATOR_INSET * 2,
        containerH - INDICATOR_INSET * 2,
      );

      if (!hit) continue;

      const angleDeg =
        Math.atan2(nodeCenterY - centerY, nodeCenterX - centerX) *
        (180 / Math.PI);

      results.push({
        id: node.id,
        screenX: hit.x,
        screenY: hit.y,
        angleDeg,
      });

      if (results.length >= MAX_INDICATORS) break;
    }

    return results;
  }, [nodes, viewport]);

  if (indicators.length === 0) return null;

  return (
    <Panel
      position="top-left"
      style={{
        margin: 0,
        padding: 0,
        pointerEvents: "none",
        position: "absolute",
        inset: 0,
        zIndex: 15,
        overflow: "hidden",
      }}
    >
      <div style={{ position: "relative", width: "100%", height: "100%" }}>
        {indicators.map((ind) => (
          <div
            key={ind.id}
            data-testid="edge-indicator"
            data-node-id={ind.id}
            style={{
              position: "absolute",
              left: ind.screenX - INDICATOR_SIZE / 2,
              top: ind.screenY - INDICATOR_SIZE / 2,
              width: INDICATOR_SIZE,
              height: INDICATOR_SIZE,
              transform: `rotate(${ind.angleDeg}deg)`,
              pointerEvents: "none",
            }}
          >
            <svg
              width={INDICATOR_SIZE}
              height={INDICATOR_SIZE}
              viewBox="0 0 20 20"
              fill="none"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path
                d="M8 4l6 6-6 6"
                stroke="rgba(212, 168, 75, 0.6)"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </div>
        ))}
      </div>
    </Panel>
  );
}
