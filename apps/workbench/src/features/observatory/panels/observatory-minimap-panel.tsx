import { useEffect, useMemo, useRef, useState } from "react";
import * as THREE from "three";
import { useObservatoryStore } from "@/features/observatory/stores/observatory-store";
import { HUNT_STATION_ORDER, HUNT_STATION_LABELS } from "@/features/observatory/world/stations";
import { OBSERVATORY_STATION_POSITIONS } from "@/features/observatory/world/observatory-world-template";
import { openObservatoryStationRoute } from "../commands/observatory-command-actions";
import { STATION_COLORS_HEX, HUD_COLORS } from "../components/hud/hud-constants";
import type { ConstellationRoute } from "../types";
import type { HuntStationId } from "../world/types";

const LANE_PAIRS: [HuntStationId, HuntStationId][] = [
  ["signal", "targets"],
  ["targets", "run"],
  ["run", "receipts"],
  ["receipts", "case-notes"],
];

const VIEWBOX_SIZE = 200;
const CHART_CENTER_X = 100;
const CHART_CENTER_Y = 100;
const CHART_RADIUS = 85;

function computeWorldBounds() {
  const positions = HUNT_STATION_ORDER.map((id) => OBSERVATORY_STATION_POSITIONS[id]);
  let minX = Infinity, maxX = -Infinity, minZ = Infinity, maxZ = -Infinity;
  for (const pos of positions) {
    if (pos[0] < minX) minX = pos[0];
    if (pos[0] > maxX) maxX = pos[0];
    if (pos[2] < minZ) minZ = pos[2];
    if (pos[2] > maxZ) maxZ = pos[2];
  }
  return { minX, maxX, minZ, maxZ };
}

const WORLD_BOUNDS = computeWorldBounds();
const WORLD_HALF_EXTENT =
  Math.max(
    Math.abs(WORLD_BOUNDS.maxX),
    Math.abs(WORLD_BOUNDS.minX),
    Math.abs(WORLD_BOUNDS.maxZ),
    Math.abs(WORLD_BOUNDS.minZ),
  ) * 1.15;

/** Exported for unit testing. */
export function worldToChart(worldX: number, worldZ: number): { x: number; y: number } {
  const scale = CHART_RADIUS / WORLD_HALF_EXTENT;
  return {
    x: CHART_CENTER_X + worldX * scale,
    y: CHART_CENTER_Y - worldZ * scale,
  };
}

const _q = new THREE.Quaternion();
const _euler = new THREE.Euler();

const MAX_TRAIL_POINTS = 50;
const TRAIL_SAMPLE_INTERVAL_MS = 500;
const trailBuffer: Array<{ x: number; z: number }> = [];
let lastTrailSampleMs = 0;

export function ObservatoryMinimapPanel() {
  const stations = useObservatoryStore.use.stations();
  const artifactCount = useObservatoryStore((state) => state.seamSummary.artifactCount);
  const activeProbes = useObservatoryStore((state) => state.seamSummary.activeProbes);
  const connected = useObservatoryStore.use.connected();
  const selectedStationId = useObservatoryStore.use.selectedStationId();
  const mission = useObservatoryStore((state) => state.mission);
  const dockingState = useObservatoryStore((state) => state.dockingState);
  const discoveredStations = useObservatoryStore((state) => state.discoveredStations);
  const constellations = useObservatoryStore((state) => state.constellations);

  const [tooltipConstellation, setTooltipConstellation] = useState<ConstellationRoute | null>(null);

  const stationChartPositions = useMemo(
    () =>
      HUNT_STATION_ORDER.reduce(
        (acc, id) => {
          const pos = OBSERVATORY_STATION_POSITIONS[id];
          acc[id] = worldToChart(pos[0], pos[2]);
          return acc;
        },
        {} as Record<HuntStationId, { x: number; y: number }>,
      ),
    [],
  );

  const constellationChartPaths = useMemo(() => {
    return constellations.map((c) => ({
      id: c.id,
      route: c,
      points: c.stationPath.map((stationId) => {
        const pos = OBSERVATORY_STATION_POSITIONS[stationId];
        return worldToChart(pos[0], pos[2]);
      }),
    }));
  }, [constellations]);

  const missionStationIds = useMemo(() => {
    if (!mission) return new Set<HuntStationId>();
    const ids = new Set<HuntStationId>();
    for (const obj of mission.objectives) {
      if (!mission.completedObjectiveIds.includes(obj.id)) {
        ids.add(obj.stationId);
      }
    }
    return ids;
  }, [mission]);

  const arrowGroupRef = useRef<SVGGElement | null>(null);
  const trailPolylineRef = useRef<SVGPolylineElement | null>(null);
  const autopilotLineRef = useRef<SVGLineElement | null>(null);

  useEffect(() => {
    let rafId = 0;

    function tick() {
      const storeState = useObservatoryStore.getState();
      const { flightState, autopilotTargetStationId } = storeState;
      const [px, , pz] = flightState.position;
      const [qx, qy, qz, qw] = flightState.quaternion;

      _q.set(qx, qy, qz, qw);
      _euler.setFromQuaternion(_q, "YXZ");
      const yaw = _euler.y;

      const playerChart = worldToChart(px, pz);
      const rotDeg = (-yaw * 180) / Math.PI;

      const group = arrowGroupRef.current;
      if (group) {
        group.setAttribute("transform", `translate(${playerChart.x},${playerChart.y}) rotate(${rotDeg})`);
      }

      const nowMs = Date.now();
      if (nowMs - lastTrailSampleMs >= TRAIL_SAMPLE_INTERVAL_MS) {
        lastTrailSampleMs = nowMs;
        trailBuffer.push({ x: px, z: pz });
        if (trailBuffer.length > MAX_TRAIL_POINTS) {
          trailBuffer.shift();
        }
      }

      const polyline = trailPolylineRef.current;
      if (polyline && trailBuffer.length >= 2) {
        const pts = trailBuffer.map((pt) => {
          const c = worldToChart(pt.x, pt.z);
          return `${c.x},${c.y}`;
        });
        polyline.setAttribute("points", pts.join(" "));
        polyline.style.display = "";
      } else if (polyline) {
        polyline.style.display = "none";
      }

      const apLine = autopilotLineRef.current;
      if (apLine) {
        if (autopilotTargetStationId !== null) {
          const targetPos = stationChartPositions[autopilotTargetStationId];
          if (targetPos) {
            apLine.setAttribute("x1", String(playerChart.x));
            apLine.setAttribute("y1", String(playerChart.y));
            apLine.setAttribute("x2", String(targetPos.x));
            apLine.setAttribute("y2", String(targetPos.y));
            apLine.style.display = "";
          }
        } else {
          apLine.style.display = "none";
        }
      }

      rafId = requestAnimationFrame(tick);
    }

    rafId = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafId);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stationChartPositions]);

  return (
    <div className="flex flex-col h-full bg-[#0b0d13]">
      <div className="px-3 py-2 border-b border-[#1a1d28]/60">
        <span className="text-[11px] font-medium text-[#6f7f9a] uppercase tracking-wider">
          Observatory
        </span>
      </div>

      <div className="flex-1 flex items-center justify-center p-4 relative">
        <svg
          viewBox={`0 0 ${VIEWBOX_SIZE} ${VIEWBOX_SIZE}`}
          width="160"
          height="160"
          aria-label="Observatory station map"
        >
          <circle
            cx={CHART_CENTER_X}
            cy={CHART_CENTER_Y}
            r={CHART_RADIUS * 0.33}
            fill="none"
            stroke="#141720"
            strokeWidth="0.5"
          />
          <circle
            cx={CHART_CENTER_X}
            cy={CHART_CENTER_Y}
            r={CHART_RADIUS * 0.66}
            fill="none"
            stroke="#141720"
            strokeWidth="0.5"
          />
          <circle
            cx={CHART_CENTER_X}
            cy={CHART_CENTER_Y}
            r={CHART_RADIUS}
            fill="none"
            stroke="#1a1d28"
            strokeWidth="1"
          />

          <circle cx={CHART_CENTER_X} cy={CHART_CENTER_Y} r={3} fill="#2d3240" />
          <circle cx={CHART_CENTER_X} cy={CHART_CENTER_Y} r={1.5} fill="#6f7f9a" />

          {LANE_PAIRS.map(([fromId, toId]) => {
            const from = stationChartPositions[fromId];
            const to = stationChartPositions[toId];
            return (
              <line
                key={`lane-${fromId}-${toId}`}
                x1={from.x}
                y1={from.y}
                x2={to.x}
                y2={to.y}
                stroke="#1a1d28"
                strokeWidth="1"
                opacity="0.4"
                data-testid={`lane-${fromId}-${toId}`}
              />
            );
          })}

          {constellationChartPaths.map(({ id, route, points }) => {
            if (points.length < 2) return null;
            const polylinePoints = points.map((p) => `${p.x},${p.y}`).join(" ");
            const isSelected = tooltipConstellation?.id === id;
            return (
              <polyline
                key={`constellation-${id}`}
                points={polylinePoints}
                fill="none"
                stroke={isSelected ? "#e8e4f0" : "#8b7fc7"}
                strokeWidth={isSelected ? "1.5" : "1"}
                opacity={isSelected ? 0.9 : 0.5}
                strokeLinecap="round"
                strokeLinejoin="round"
                style={{ cursor: "pointer" }}
                onClick={(e) => {
                  e.stopPropagation();
                  setTooltipConstellation(isSelected ? null : route);
                }}
                data-testid={`constellation-${id}`}
              />
            );
          })}

          {HUNT_STATION_ORDER.filter((id) => id !== "watch").map((id) => {
            const pos = stationChartPositions[id];
            return (
              <line
                key={`core-link-${id}`}
                x1={CHART_CENTER_X}
                y1={CHART_CENTER_Y}
                x2={pos.x}
                y2={pos.y}
                stroke="#1a1d28"
                strokeWidth="0.5"
                opacity="0.2"
              />
            );
          })}

          <polyline
            ref={trailPolylineRef}
            points=""
            fill="none"
            stroke="rgba(255,255,255,0.5)"
            strokeWidth="1"
            strokeLinecap="round"
            strokeLinejoin="round"
            pointerEvents="none"
            data-testid="flight-trail"
            style={{ display: "none" }}
          />

          <line
            ref={autopilotLineRef}
            x1={CHART_CENTER_X}
            y1={CHART_CENTER_Y}
            x2={CHART_CENTER_X}
            y2={CHART_CENTER_Y}
            stroke="#e0e6ef"
            strokeWidth="1"
            strokeDasharray="4 3"
            opacity={0.6}
            pointerEvents="none"
            data-testid="autopilot-line"
            style={{ display: "none" }}
          />

          {HUNT_STATION_ORDER.map((id) => {
            const { x, y } = stationChartPositions[id];
            const isDiscovered = discoveredStations.has(id);
            const isSelected = selectedStationId === id;
            const isDocked = dockingState.zone === "dock" && dockingState.stationId === id;
            const isMissionTarget = missionStationIds.has(id);
            const isUnvisited = isDiscovered && !isDocked;

            const dotColor = isDiscovered ? STATION_COLORS_HEX[id] : "#2d3a4f";
            const dotRadius = isSelected ? 6 : 5;
            const dotOpacity = isDiscovered ? 0.95 : 0.15;

            return (
              <g key={id}>
                <circle
                  cx={x}
                  cy={y}
                  r={dotRadius}
                  fill={dotColor}
                  opacity={dotOpacity}
                  onClick={() => {
                    openObservatoryStationRoute(id);
                    useObservatoryStore.getState().actions.setAutopilotTarget(id);
                  }}
                  style={{ cursor: "pointer" }}
                  data-station-id={id}
                  data-discovered={isDiscovered ? "true" : "false"}
                />
                <text
                  x={x}
                  y={y + 14}
                  textAnchor="middle"
                  fill={isDiscovered ? HUD_COLORS.hudTextDim : "#2d3240"}
                  fontSize="6"
                  fontFamily="ui-monospace, monospace"
                  pointerEvents="none"
                >
                  {isDiscovered ? HUNT_STATION_LABELS[id] : "?"}
                </text>

                {isDiscovered && isDocked && (
                  <rect
                    x={x + 5 - 3}
                    y={y - 10 - 3}
                    width="6"
                    height="6"
                    fill={dotColor}
                    transform={`rotate(45, ${x + 5}, ${y - 10})`}
                    data-status="docked"
                  />
                )}
                {isDiscovered && !isDocked && isMissionTarget && (
                  <text
                    x={x + 6}
                    y={y - 7}
                    textAnchor="middle"
                    fill={dotColor}
                    fontSize="8"
                    fontWeight="bold"
                    pointerEvents="none"
                    data-status="mission"
                  >
                    *
                  </text>
                )}
                {isDiscovered && !isDocked && !isMissionTarget && isUnvisited && (
                  <circle
                    cx={x + 6}
                    cy={y - 8}
                    r={3}
                    fill="none"
                    stroke={dotColor}
                    strokeWidth="1"
                    opacity={0.7}
                    data-status="unvisited"
                  />
                )}
              </g>
            );
          })}

          <g ref={arrowGroupRef} transform={`translate(${CHART_CENTER_X},${CHART_CENTER_Y}) rotate(0)`}>
            <polygon
              points="0,-6 -3.5,4 3.5,4"
              fill={HUD_COLORS.hudText}
              opacity={0.9}
              pointerEvents="none"
            />
          </g>
        </svg>
        {tooltipConstellation && (
          <div
            className="absolute bg-[#0f1118]/95 border border-[#2a2d3a] rounded px-3 py-2 text-[10px] font-mono pointer-events-auto shadow-lg z-10"
            style={{ bottom: "8px", left: "50%", transform: "translateX(-50%)" }}
            onClick={() => setTooltipConstellation(null)}
            data-testid="constellation-tooltip"
          >
            <div className="text-[#e8e4f0] font-medium">{tooltipConstellation.name}</div>
            <div className="text-[#6f7f9a] mt-0.5">
              {new Date(tooltipConstellation.createdAtMs).toLocaleDateString("en-US", {
                month: "short",
                day: "numeric",
                year: "numeric",
              })}
            </div>
          </div>
        )}
      </div>

      <div className="px-3 py-2 border-t border-[#1a1d28]/60 flex gap-3">
        <span className="text-[10px] text-[#6f7f9a]">
          {artifactCount} artifacts
        </span>
        <span className={connected ? "text-[10px] text-[#3dbf84]" : "text-[10px] text-[#c45c5c]"}>
          {connected ? "live feed" : "offline cache"}
        </span>
        {activeProbes > 0 && (
          <span className="text-[10px] text-[#3dbf84]">probe active</span>
        )}
      </div>
    </div>
  );
}
