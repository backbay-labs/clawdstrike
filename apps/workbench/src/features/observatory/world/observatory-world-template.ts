import * as THREE from "three";
import {
  HUNT_PRIMARY_STATION_ORDER,
  HUNT_STATION_LABELS,
  HUNT_STATION_PLACEMENTS,
} from "./stations";
import type {
  HuntObservatoryMode,
  HuntStationId,
  HuntStationPlacement,
} from "./types";
import {
  OBSERVATORY_HERO_PROP_ASSETS,
  type ObservatoryHeroPropAssetId,
  type ObservatoryHeroPropAvailability,
  type ObservatoryHeroPropFallbackKind,
} from "./propAssets";

export type ObservatoryVec3 = readonly [number, number, number];

interface ObservatoryTransitGeometryCacheEntry {
  points: ObservatoryVec3[];
  waypointPositions: ObservatoryVec3[];
}

interface ObservatoryGrowthAnchorTemplate {
  position: ObservatoryVec3;
  ringInnerRadius: number;
  ringOuterRadius: number;
  nodeRadius: number;
}

interface ObservatoryDistrictTemplate {
  label: string;
  colorHex: string;
  position: ObservatoryVec3;
  baseDiscRadius: number;
  outerRingInnerRadius: number;
  outerRingOuterRadius: number;
  torusRadius: number;
  torusTubeRadius: number;
  floatAmplitude: number;
  pulseSpeed: number;
  microInteraction:
    | "sweep"
    | "expand-cluster"
    | "engage-machinery"
    | "fan-stacks"
    | "seal-scaffold"
    | "sentry-wake";
  growthAnchors: readonly ObservatoryGrowthAnchorTemplate[];
}

interface ObservatoryCoreTemplate {
  haloRadius: number;
  haloOpacity: number;
  outerRingInnerRadius: number;
  outerRingOuterRadius: number;
  outerRingOpacity: number;
  torusRadius: number;
  torusTubeRadius: number;
  torusEmissiveIntensity: number;
  shellRadius: number;
  shellOpacity: number;
  pedestalTopRadius: number;
  pedestalBottomRadius: number;
  pedestalHeight: number;
}

interface ObservatoryWatchfieldTemplate {
  colorHex: string;
  position: ObservatoryVec3;
  ringPoints: readonly ObservatoryVec3[];
  perimeterInnerRadius: number;
  perimeterOuterRadius: number;
  beaconRadius: number;
  secondaryRingInnerRadius: number;
  secondaryRingOuterRadius: number;
}

interface ObservatoryWorldStaticTemplate {
  environmentByMode: Record<
    HuntObservatoryMode,
    {
      backgroundColor: string;
      fogColor: string;
      fogNear: number;
      fogFar: number;
      ambientColor: string;
      ambientIntensity: number;
      directionalLightPosition: ObservatoryVec3;
      directionalLightColor: string;
      directionalLightIntensity: number;
      pointLightPosition: ObservatoryVec3;
      pointLightColor: string;
      pointLightIntensity: number;
      starsRadius: number;
      starsDepth: number;
      starsCount: number;
      starsFactor: number;
      floorRadius: number;
      gridSize: number;
      gridDivisions: number;
      floorOpacity: number;
    }
  >;
  stationPositions: Record<HuntStationId, ObservatoryVec3>;
  heroProps: readonly {
    assetId: ObservatoryHeroPropAssetId;
    assetUrl: string;
    availability: ObservatoryHeroPropAvailability;
    bobAmplitude: number;
    bobSpeed: number;
    fallbackKind: ObservatoryHeroPropFallbackKind;
    glowColor: string;
    importance: number;
    key: string;
    position: ObservatoryVec3;
    rotation: ObservatoryVec3;
    scale: number;
    stationId: HuntStationId | "core";
    wakeThreshold: number;
  }[];
  coreLinksByMode: Record<HuntObservatoryMode, readonly {
    key: string;
    fromStationId: "core";
    stationId: HuntStationId;
    points: ObservatoryVec3[];
    leftEdgePoints: ObservatoryVec3[];
    rightEdgePoints: ObservatoryVec3[];
    waypointPositions: ObservatoryVec3[];
    colorHex: string;
    opacity: number;
    intensity: number;
    active: false;
    convoyCount: number;
    showPulse: false;
    corridorRadius: number;
    corridorOpacity: number;
    glowRadius: number;
  }[]>;
  transitGeometryByMode: Record<HuntObservatoryMode, Record<string, ObservatoryTransitGeometryCacheEntry>>;
  districtTemplates: Record<HuntStationId, ObservatoryDistrictTemplate>;
  coreTemplate: ObservatoryCoreTemplate;
  watchfieldTemplate: ObservatoryWatchfieldTemplate;
}

const WORLD_RADIUS = 300;
export { WORLD_RADIUS };

const STATION_COLORS: Record<HuntStationId, string> = Object.freeze({
  signal: "#7cc8ff",
  targets: "#9df2dd",
  run: "#f4d982",
  receipts: "#7ee6f2",
  "case-notes": "#f0b87b",
  watch: "#d3b56e",
});

function toTuple(vector: THREE.Vector3): ObservatoryVec3 {
  return [vector.x, vector.y, vector.z];
}

function makeStationPosition(placement: HuntStationPlacement): ObservatoryVec3 {
  const radius = placement.radius * WORLD_RADIUS;
  const angle = (placement.angleDeg * Math.PI) / 180;
  return [Math.cos(angle) * radius, placement.elevationY, Math.sin(angle) * radius];
}

export const OBSERVATORY_STATION_POSITIONS: Record<HuntStationId, ObservatoryVec3> = Object.freeze(
  Object.fromEntries(
    HUNT_STATION_PLACEMENTS.map((placement) => [
      placement.id,
      Object.freeze(makeStationPosition(placement)),
    ]),
  ) as Record<HuntStationId, ObservatoryVec3>,
);

export function stationPosition(stationId: HuntStationId): THREE.Vector3 {
  const cached = OBSERVATORY_STATION_POSITIONS[stationId];
  return new THREE.Vector3(cached[0], cached[1], cached[2]);
}

export function stationPositionTuple(stationId: HuntStationId): ObservatoryVec3 {
  return OBSERVATORY_STATION_POSITIONS[stationId];
}

export function buildLanePoints(
  from: ObservatoryVec3,
  to: ObservatoryVec3,
  mode: HuntObservatoryMode,
): ObservatoryVec3[] {
  const midY = (from[1] + to[1]) * 0.5 + (mode === "flow" ? 15 : 10);
  const mid = new THREE.Vector3(
    (from[0] + to[0]) * 0.5,
    midY,
    (from[2] + to[2]) * 0.5,
  );
  return new THREE.CatmullRomCurve3([
    new THREE.Vector3(from[0], from[1], from[2]),
    mid,
    new THREE.Vector3(to[0], to[1], to[2]),
  ]).getPoints(24).map(toTuple);
}

export function buildLocalArcPoints(
  from: ObservatoryVec3,
  to: ObservatoryVec3,
  height: number,
): ObservatoryVec3[] {
  const mid = new THREE.Vector3(
    (from[0] + to[0]) * 0.5,
    ((from[1] + to[1]) * 0.5) + height,
    (from[2] + to[2]) * 0.5,
  );
  return new THREE.CatmullRomCurve3([
    new THREE.Vector3(from[0], from[1], from[2]),
    mid,
    new THREE.Vector3(to[0], to[1], to[2]),
  ]).getPoints(18).map(toTuple);
}

export function offsetPathPoints(points: ObservatoryVec3[], lateralOffset: number): ObservatoryVec3[] {
  return points.map((point, index) => {
    const previous = points[Math.max(0, index - 1)];
    const next = points[Math.min(points.length - 1, index + 1)];
    const tangentX = next[0] - previous[0];
    const tangentZ = next[2] - previous[2];
    const length = Math.hypot(tangentX, tangentZ) || 1;
    const lateralX = (-tangentZ / length) * lateralOffset;
    const lateralZ = (tangentX / length) * lateralOffset;
    return [point[0] + lateralX, point[1], point[2] + lateralZ];
  });
}

function buildPerimeterRing(): ObservatoryVec3[] {
  const perimeterRadius = WORLD_RADIUS * 1.26;
  const points: ObservatoryVec3[] = [];
  for (let index = 0; index <= 64; index += 1) {
    const angle = (index / 64) * Math.PI * 2;
    points.push([
      Math.cos(angle) * perimeterRadius,
      0,
      Math.sin(angle) * perimeterRadius,
    ]);
  }
  return points;
}

function microInteractionForStation(
  stationId: HuntStationId,
): ObservatoryDistrictTemplate["microInteraction"] {
  switch (stationId) {
    case "signal":
      return "sweep";
    case "targets":
      return "expand-cluster";
    case "run":
      return "engage-machinery";
    case "receipts":
      return "fan-stacks";
    case "case-notes":
      return "seal-scaffold";
    case "watch":
      return "sentry-wake";
  }
}

function buildGrowthAnchorTemplates(stationId: HuntStationId): readonly ObservatoryGrowthAnchorTemplate[] {
  switch (stationId) {
    case "signal":
      return Object.freeze([
        { position: [-3.6, -0.1, -0.9], ringInnerRadius: 0.34, ringOuterRadius: 0.48, nodeRadius: 0.07 },
        { position: [0.6, -0.1, -3.3], ringInnerRadius: 0.4, ringOuterRadius: 0.54, nodeRadius: 0.08 },
        { position: [4.2, -0.1, 2.4], ringInnerRadius: 0.46, ringOuterRadius: 0.6, nodeRadius: 0.09 },
      ]);
    case "targets":
      return Object.freeze([
        { position: [4.8, -0.1, 3.6], ringInnerRadius: 0.34, ringOuterRadius: 0.48, nodeRadius: 0.07 },
        { position: [-4.2, -0.1, 3.3], ringInnerRadius: 0.4, ringOuterRadius: 0.54, nodeRadius: 0.08 },
        { position: [2.4, -0.1, -3.6], ringInnerRadius: 0.46, ringOuterRadius: 0.6, nodeRadius: 0.09 },
      ]);
    case "run":
      return Object.freeze([
        { position: [-4.8, -0.1, 2.7], ringInnerRadius: 0.34, ringOuterRadius: 0.48, nodeRadius: 0.07 },
        { position: [-0.6, -0.1, 6.6], ringInnerRadius: 0.4, ringOuterRadius: 0.54, nodeRadius: 0.08 },
        { position: [3.9, -0.1, 3.6], ringInnerRadius: 0.46, ringOuterRadius: 0.6, nodeRadius: 0.09 },
      ]);
    case "receipts":
      return Object.freeze([
        { position: [0.6, -0.1, 6.6], ringInnerRadius: 0.34, ringOuterRadius: 0.48, nodeRadius: 0.07 },
        { position: [4.5, -0.1, 3.6], ringInnerRadius: 0.4, ringOuterRadius: 0.54, nodeRadius: 0.08 },
        { position: [-3.3, -0.1, 4.2], ringInnerRadius: 0.46, ringOuterRadius: 0.6, nodeRadius: 0.09 },
      ]);
    case "case-notes":
      return Object.freeze([
        { position: [-3.6, -0.1, 3.9], ringInnerRadius: 0.34, ringOuterRadius: 0.48, nodeRadius: 0.07 },
        { position: [0.6, -0.1, 6.9], ringInnerRadius: 0.4, ringOuterRadius: 0.54, nodeRadius: 0.08 },
        { position: [4.2, -0.1, 3.45], ringInnerRadius: 0.46, ringOuterRadius: 0.6, nodeRadius: 0.09 },
      ]);
    case "watch":
      return Object.freeze([
        { position: [-4.8, -0.1, 1.8], ringInnerRadius: 0.34, ringOuterRadius: 0.48, nodeRadius: 0.07 },
        { position: [5.1, -0.1, 0.6], ringInnerRadius: 0.4, ringOuterRadius: 0.54, nodeRadius: 0.08 },
        { position: [0.6, -0.1, 5.7], ringInnerRadius: 0.46, ringOuterRadius: 0.6, nodeRadius: 0.09 },
      ]);
  }
}

function createHeroProps() {
  const signalPosition = stationPositionTuple("signal");
  const subjectsPosition = stationPositionTuple("targets");
  const operationsPosition = stationPositionTuple("run");
  const evidencePosition = stationPositionTuple("receipts");
  const judgmentPosition = stationPositionTuple("case-notes");
  const watchfieldPosition = stationPositionTuple("watch");
  const corePosition: ObservatoryVec3 = [0, 3.5, 0];

  return Object.freeze([
    {
      assetId: "signal-dish-tower",
      assetUrl: OBSERVATORY_HERO_PROP_ASSETS["signal-dish-tower"].url,
      availability: OBSERVATORY_HERO_PROP_ASSETS["signal-dish-tower"].availability,
      bobAmplitude: 0.06,
      bobSpeed: 0.24,
      fallbackKind: OBSERVATORY_HERO_PROP_ASSETS["signal-dish-tower"].fallbackKind,
      glowColor: OBSERVATORY_HERO_PROP_ASSETS["signal-dish-tower"].glowColor,
      importance: 0.96,
      key: "hero:signal-dish-tower",
      position: [signalPosition[0] - 10, signalPosition[1] + 0.8, signalPosition[2] - 7] as const,
      rotation: [0, Math.PI * 0.18, 0] as const,
      scale: 3.12,
      stationId: "signal",
      wakeThreshold: 0.22,
    },
    {
      assetId: "subjects-lattice-anchor",
      assetUrl: OBSERVATORY_HERO_PROP_ASSETS["subjects-lattice-anchor"].url,
      availability: OBSERVATORY_HERO_PROP_ASSETS["subjects-lattice-anchor"].availability,
      bobAmplitude: 0.03,
      bobSpeed: 0.16,
      fallbackKind: OBSERVATORY_HERO_PROP_ASSETS["subjects-lattice-anchor"].fallbackKind,
      glowColor: OBSERVATORY_HERO_PROP_ASSETS["subjects-lattice-anchor"].glowColor,
      importance: 0.9,
      key: "hero:subjects-lattice-anchor",
      position: [subjectsPosition[0] + 6.45, subjectsPosition[1] + 0.8, subjectsPosition[2] - 5.1] as const,
      rotation: [0, -Math.PI * 0.26, 0] as const,
      scale: 3.83,
      stationId: "targets",
      wakeThreshold: 0.28,
    },
    {
      assetId: "operations-scan-rig",
      assetUrl: OBSERVATORY_HERO_PROP_ASSETS["operations-scan-rig"].url,
      availability: OBSERVATORY_HERO_PROP_ASSETS["operations-scan-rig"].availability,
      bobAmplitude: 0.02,
      bobSpeed: 0.1,
      fallbackKind: OBSERVATORY_HERO_PROP_ASSETS["operations-scan-rig"].fallbackKind,
      glowColor: OBSERVATORY_HERO_PROP_ASSETS["operations-scan-rig"].glowColor,
      importance: 0.98,
      key: "hero:operations-scan-rig",
      position: [operationsPosition[0] + 3.15, operationsPosition[1] + 0.8, operationsPosition[2] + 4.26] as const,
      rotation: [0, Math.PI * 0.42, 0] as const,
      scale: 3.84,
      stationId: "run",
      wakeThreshold: 0.34,
    },
    {
      assetId: "evidence-vault-rack",
      assetUrl: OBSERVATORY_HERO_PROP_ASSETS["evidence-vault-rack"].url,
      availability: OBSERVATORY_HERO_PROP_ASSETS["evidence-vault-rack"].availability,
      bobAmplitude: 0.01,
      bobSpeed: 0.08,
      fallbackKind: OBSERVATORY_HERO_PROP_ASSETS["evidence-vault-rack"].fallbackKind,
      glowColor: OBSERVATORY_HERO_PROP_ASSETS["evidence-vault-rack"].glowColor,
      importance: 0.92,
      key: "hero:evidence-vault-rack",
      position: [evidencePosition[0] - 5.7, evidencePosition[1] + 0.8, evidencePosition[2] + 5.85] as const,
      rotation: [0, -Math.PI * 0.18, 0] as const,
      scale: 3.3,
      stationId: "receipts",
      wakeThreshold: 0.3,
    },
    {
      assetId: "judgment-dais",
      assetUrl: OBSERVATORY_HERO_PROP_ASSETS["judgment-dais"].url,
      availability: OBSERVATORY_HERO_PROP_ASSETS["judgment-dais"].availability,
      bobAmplitude: 0,
      bobSpeed: 0.05,
      fallbackKind: OBSERVATORY_HERO_PROP_ASSETS["judgment-dais"].fallbackKind,
      glowColor: OBSERVATORY_HERO_PROP_ASSETS["judgment-dais"].glowColor,
      importance: 0.94,
      key: "hero:judgment-dais",
      position: [judgmentPosition[0] + 2.7, judgmentPosition[1] + 0.8, judgmentPosition[2] + 2.76] as const,
      rotation: [0, Math.PI * 0.08, 0] as const,
      scale: 2.73,
      stationId: "case-notes",
      wakeThreshold: 0.42,
    },
    {
      assetId: "watchfield-sentinel-beacon",
      assetUrl: OBSERVATORY_HERO_PROP_ASSETS["watchfield-sentinel-beacon"].url,
      availability: OBSERVATORY_HERO_PROP_ASSETS["watchfield-sentinel-beacon"].availability,
      bobAmplitude: 0.02,
      bobSpeed: 0.12,
      fallbackKind: OBSERVATORY_HERO_PROP_ASSETS["watchfield-sentinel-beacon"].fallbackKind,
      glowColor: OBSERVATORY_HERO_PROP_ASSETS["watchfield-sentinel-beacon"].glowColor,
      importance: 0.88,
      key: "hero:watchfield-sentinel-beacon",
      position: [watchfieldPosition[0] + 2.16, watchfieldPosition[1] + 0.8, watchfieldPosition[2] - 1.86] as const,
      rotation: [0, -Math.PI * 0.18, 0] as const,
      scale: 2.58,
      stationId: "watch",
      wakeThreshold: 0.24,
    },
    {
      assetId: "operator-drone",
      assetUrl: OBSERVATORY_HERO_PROP_ASSETS["operator-drone"].url,
      availability: OBSERVATORY_HERO_PROP_ASSETS["operator-drone"].availability,
      bobAmplitude: 0.16,
      bobSpeed: 0.52,
      fallbackKind: OBSERVATORY_HERO_PROP_ASSETS["operator-drone"].fallbackKind,
      glowColor: OBSERVATORY_HERO_PROP_ASSETS["operator-drone"].glowColor,
      importance: 0.84,
      key: "hero:operator-drone",
      position: [corePosition[0] + 7.35, corePosition[1] + 1.72, corePosition[2] - 5.1] as const,
      rotation: [0, Math.PI * 0.18, 0] as const,
      scale: 0.84,
      stationId: "core",
      wakeThreshold: 0,
    },
  ] as const);
}

function createCoreLinks(mode: HuntObservatoryMode) {
  return Object.freeze(
    HUNT_PRIMARY_STATION_ORDER.map((stationId) => ({
      key: `core-${stationId}`,
      fromStationId: "core" as const,
      stationId,
      points: buildLanePoints([0, 3.5, 0], stationPositionTuple(stationId), mode),
      leftEdgePoints: [] as ObservatoryVec3[],
      rightEdgePoints: [] as ObservatoryVec3[],
      waypointPositions: [] as ObservatoryVec3[],
      colorHex: STATION_COLORS[stationId],
      opacity: mode === "flow" ? 0.22 : 0.12,
      intensity: 0.22,
      active: false as const,
      convoyCount: 0,
      showPulse: false as const,
      corridorRadius: 0.06,
      corridorOpacity: 0.04,
      glowRadius: 0.12,
    })),
  );
}

function getTransitGeometryCacheKey(fromId: HuntStationId, toId: HuntStationId): string {
  return `${fromId}-${toId}`;
}

function createTransitGeometry(
  mode: HuntObservatoryMode,
  fromId: HuntStationId,
  toId: HuntStationId,
): ObservatoryTransitGeometryCacheEntry {
  const points = buildLanePoints(stationPositionTuple(fromId), stationPositionTuple(toId), mode);
  const curve = new THREE.CatmullRomCurve3(points.map((point) => new THREE.Vector3(point[0], point[1], point[2])));
  return {
    points,
    waypointPositions: [0.2, 0.52, 0.82].map((t) => toTuple(curve.getPointAt(t))),
  };
}

function createDistrictTemplate(stationId: HuntStationId): ObservatoryDistrictTemplate {
  const position = stationPositionTuple(stationId);
  const growthAnchors = buildGrowthAnchorTemplates(stationId);
  const microInteraction = microInteractionForStation(stationId);
  return Object.freeze({
    label: HUNT_STATION_LABELS[stationId],
    colorHex: STATION_COLORS[stationId],
    position,
    baseDiscRadius: 8,
    outerRingInnerRadius: 9,
    outerRingOuterRadius: 11,
    torusRadius: 4.5,
    torusTubeRadius: 0.22,
    floatAmplitude: 0.12,
    pulseSpeed: 0.0018,
    microInteraction,
    growthAnchors,
  });
}

function createEnvironmentByMode(): ObservatoryWorldStaticTemplate["environmentByMode"] {
  return {
    atlas: {
      backgroundColor: "#03060d",
      fogColor: "#03060d",
      fogNear: 400,
      fogFar: 1200,
      ambientColor: "#94b8ff",
      ambientIntensity: 0.45,
      directionalLightPosition: [180, 240, 150],
      directionalLightColor: "#f3f7ff",
      directionalLightIntensity: 1.2,
      pointLightPosition: [-240, 150, -120],
      pointLightColor: "#54b7ff",
      pointLightIntensity: 0.8,
      starsRadius: 2400,
      starsDepth: 800,
      starsCount: 2400,
      starsFactor: 6,
      floorRadius: 0,
      gridSize: 0,
      gridDivisions: 0,
      floorOpacity: 0,
    },
    flow: {
      backgroundColor: "#02050c",
      fogColor: "#02050c",
      fogNear: 360,
      fogFar: 1100,
      ambientColor: "#8ab1f0",
      ambientIntensity: 0.42,
      directionalLightPosition: [150, 210, 105],
      directionalLightColor: "#f3f7ff",
      directionalLightIntensity: 1.1,
      pointLightPosition: [-180, 135, -90],
      pointLightColor: "#5ac2ff",
      pointLightIntensity: 1.0,
      starsRadius: 2400,
      starsDepth: 800,
      starsCount: 2400,
      starsFactor: 6,
      floorRadius: 0,
      gridSize: 0,
      gridDivisions: 0,
      floorOpacity: 0,
    },
  };
}

function createWatchfieldTemplate(): ObservatoryWatchfieldTemplate {
  return {
    colorHex: "#d3b56e",
    position: stationPositionTuple("watch"),
    ringPoints: Object.freeze(buildPerimeterRing()),
    perimeterInnerRadius: 360,
    perimeterOuterRadius: 396,
    beaconRadius: 3,
    secondaryRingInnerRadius: 3.5,
    secondaryRingOuterRadius: 4.2,
  };
}

function createCoreTemplate(): ObservatoryCoreTemplate {
  return {
    haloRadius: 12,
    haloOpacity: 0.12,
    outerRingInnerRadius: 15,
    outerRingOuterRadius: 18,
    outerRingOpacity: 0.04,
    torusRadius: 9,
    torusTubeRadius: 0.4,
    torusEmissiveIntensity: 0.42,
    shellRadius: 3.5,
    shellOpacity: 0.96,
    pedestalTopRadius: 0.8,
    pedestalBottomRadius: 1.5,
    pedestalHeight: 5,
  };
}

const coreLinksByMode = {
  atlas: createCoreLinks("atlas"),
  flow: createCoreLinks("flow"),
} as const;

const transitGeometryByMode = {
  atlas: Object.fromEntries(
    [
      ["signal", "targets"],
      ["targets", "run"],
      ["run", "receipts"],
      ["receipts", "case-notes"],
    ].map(([fromId, toId]) => [
      getTransitGeometryCacheKey(fromId as HuntStationId, toId as HuntStationId),
      createTransitGeometry("atlas", fromId as HuntStationId, toId as HuntStationId),
    ]),
  ) as Record<string, ObservatoryTransitGeometryCacheEntry>,
  flow: Object.fromEntries(
    [
      ["signal", "targets"],
      ["targets", "run"],
      ["run", "receipts"],
      ["receipts", "case-notes"],
    ].map(([fromId, toId]) => [
      getTransitGeometryCacheKey(fromId as HuntStationId, toId as HuntStationId),
      createTransitGeometry("flow", fromId as HuntStationId, toId as HuntStationId),
    ]),
  ) as Record<string, ObservatoryTransitGeometryCacheEntry>,
} as const;

const districtTemplates = Object.freeze(
  Object.fromEntries(
    ([
      "signal",
      "targets",
      "run",
      "receipts",
      "case-notes",
      "watch",
    ] as HuntStationId[]).map((stationId) => [stationId, createDistrictTemplate(stationId)]),
  ) as Record<HuntStationId, ObservatoryDistrictTemplate>,
);

export const OBSERVATORY_WORLD_TEMPLATE = Object.freeze({
  environmentByMode: Object.freeze(createEnvironmentByMode()),
  stationPositions: OBSERVATORY_STATION_POSITIONS,
  heroProps: createHeroProps(),
  coreLinksByMode: Object.freeze(coreLinksByMode),
  transitGeometryByMode: Object.freeze(transitGeometryByMode),
  districtTemplates,
  coreTemplate: Object.freeze(createCoreTemplate()),
  watchfieldTemplate: Object.freeze(createWatchfieldTemplate()),
}) as ObservatoryWorldStaticTemplate;
