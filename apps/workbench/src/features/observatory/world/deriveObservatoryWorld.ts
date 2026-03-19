// Ported from huntronomer apps/desktop/src/features/hunt-observatory/world/deriveObservatoryWorld.ts
// Imports remapped from @/features/hunt-observatory → local world/types.ts and world/stations.ts.
import * as THREE from "three";
import {
  HUNT_PERIMETER_STATION_ID,
  HUNT_PRIMARY_STATION_ORDER,
  HUNT_STATION_LABELS,
  HUNT_STATION_PLACEMENTS,
} from "./stations";
import type {
  HuntObservatoryMode,
  HuntObservatoryReceiveState,
  HuntObservatorySceneState,
  HuntStationId,
} from "./types";
import {
  OBSERVATORY_HERO_PROP_ASSETS,
  type ObservatoryHeroPropAssetId,
  type ObservatoryHeroPropAvailability,
  type ObservatoryHeroPropFallbackKind,
} from "./propAssets";

export type ObservatoryVec3 = [number, number, number];

export type ObservatorySpiritVisual = {
  kind: "tracker" | "lantern" | "forge" | "loom" | "ledger";
  accentColor: string;
  likelyStationId?: HuntStationId | null;
  cueKind?: "bind" | "focus" | "transit" | "witness" | "absorb" | null;
} | null;

export interface ObservatoryEnvironmentRecipe {
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

export interface ObservatoryCameraRecipe {
  desiredPosition: ObservatoryVec3;
  desiredTarget: ObservatoryVec3;
  initialPosition: ObservatoryVec3;
  fov: number;
  minDistance: number;
  maxDistance: number;
  dampingFactor: number;
  lerpSpeed: number;
  arrivalDurationMs: number;
  arrivalLift: number;
  settleRadius: number;
  /** CAM-04: How long (ms) to hold on a mission objective station after flight completes. 0 = no dwell. */
  missionFocusDwellMs: number;
}

export interface ObservatoryGrowthAnchorRecipe {
  position: ObservatoryVec3;
  ringInnerRadius: number;
  ringOuterRadius: number;
  nodeRadius: number;
  opacity: number;
}

export interface ObservatoryGrowthStructureRecipe {
  key: string;
  kind: "pylon" | "array" | "halo" | "satellite" | "spire" | "panel" | "dish";
  position: ObservatoryVec3;
  scale: ObservatoryVec3;
  rotation: ObservatoryVec3;
  opacity: number;
  emissiveIntensity: number;
  wakeAmount: number;
}

export interface ObservatoryDistrictGrowthRecipe {
  stationId: HuntStationId;
  growthLevel: number;
  structures: ObservatoryGrowthStructureRecipe[];
  conduitPaths: ObservatoryVec3[][];
}

export interface ObservatoryDistrictSilhouetteRecipe {
  frameLoops: ObservatoryVec3[][];
  nodePositions: ObservatoryVec3[];
}

export type ObservatoryMasterplanFeatureKind =
  | "tower"
  | "dish"
  | "sensor-mast"
  | "orbit-platform"
  | "link-pylon"
  | "gantry"
  | "reactor"
  | "rig"
  | "vault-stack"
  | "archive-lane"
  | "terrace"
  | "scaffold-court"
  | "beacon"
  | "outer-pylon";

export interface ObservatoryMasterplanFeatureRecipe {
  key: string;
  kind: ObservatoryMasterplanFeatureKind;
  position: ObservatoryVec3;
  rotation: ObservatoryVec3;
  scale: ObservatoryVec3;
  opacity: number;
  emissiveIntensity: number;
}

export type ObservatoryTraversalSurfaceKind =
  | "platform"
  | "ramp"
  | "catwalk"
  | "bridge"
  | "jump-pad"
  | "ledge"
  | "observation-platform"
  | "control-deck"
  | "hanging-platform";

export type ObservatoryDistrictLifecycleState =
  | "dormant"
  | "waking"
  | "active"
  | "saturated"
  | "critical";

export interface ObservatoryTraversalSurfaceRecipe {
  key: string;
  kind: ObservatoryTraversalSurfaceKind;
  position: ObservatoryVec3;
  rotation: ObservatoryVec3;
  scale: ObservatoryVec3;
  opacity: number;
  emissiveIntensity: number;
  colliderKind: "box" | "cylinder";
  jumpBoost?: number;
}

export type ObservatoryCrewRole =
  | "navigator"
  | "technician"
  | "archivist"
  | "sentry";

export type ObservatoryCrewLoopKind =
  | "calibrate-horizon"
  | "service-operations"
  | "tend-evidence"
  | "patrol-watch";

export type ObservatoryProbeReactionState = "surveying" | "stabilizing";

export interface ObservatoryDistrictProbeReaction {
  state: ObservatoryProbeReactionState;
  intensity: number;
  read: string;
  crewDirective: string;
}

export interface ObservatoryCrewResponse {
  state: ObservatoryProbeReactionState;
  intensity: number;
  paceMultiplier: number;
  utilityVisible: boolean;
  focusTarget: ObservatoryVec3 | null;
}

export interface ObservatoryCrewRecipe {
  key: string;
  role: ObservatoryCrewRole;
  stationId: HuntStationId;
  position: ObservatoryVec3;
  facingRadians: number;
  accentColor: string;
  scale: number;
  active: boolean;
  loopKind: ObservatoryCrewLoopKind;
  pace: number;
  utilityTarget: ObservatoryVec3 | null;
  waypoints: ObservatoryVec3[];
  response: ObservatoryCrewResponse | null;
}

export interface ObservatoryOccupancyNodeRecipe {
  position: ObservatoryVec3;
  scale: ObservatoryVec3;
  filled: boolean;
  opacity: number;
}

export interface ObservatoryTimeStratumRecipe {
  yOffset: number;
  radius: number;
  opacity: number;
}

export type ObservatoryMicroInteractionKind =
  | "sweep"
  | "expand-cluster"
  | "engage-machinery"
  | "fan-stacks"
  | "seal-scaffold"
  | "sentry-wake";

export interface ObservatoryDistrictRecipe {
  id: HuntStationId;
  label: string;
  colorHex: string;
  position: ObservatoryVec3;
  status: HuntObservatorySceneState["stations"][number]["status"] | "idle";
  active: boolean;
  likely: boolean;
  emphasis: number;
  artifactCount: number;
  lifecycleState: ObservatoryDistrictLifecycleState;
  lifecycleProgress: number;
  baseDiscRadius: number;
  baseDiscOpacity: number;
  outerRingInnerRadius: number;
  outerRingOuterRadius: number;
  outerRingOpacity: number;
  torusRadius: number;
  torusTubeRadius: number;
  torusOpacity: number;
  floatAmplitude: number;
  pulseSpeed: number;
  pulseAmplitude: number;
  growthAnchors: ObservatoryGrowthAnchorRecipe[];
  growth: ObservatoryDistrictGrowthRecipe;
  silhouette: ObservatoryDistrictSilhouetteRecipe;
  masterplanFeatures: ObservatoryMasterplanFeatureRecipe[];
  traversalSurfaces: ObservatoryTraversalSurfaceRecipe[];
  crew: ObservatoryCrewRecipe[];
  occupancyLevel: number;
  occupancyNodes: ObservatoryOccupancyNodeRecipe[];
  timeStrata: ObservatoryTimeStratumRecipe[];
  microInteraction: ObservatoryMicroInteractionKind;
  localRead: string | null;
  probeReaction: ObservatoryDistrictProbeReaction | null;
  verticalSpan: number;
}

export interface ObservatoryTransitRouteRecipe {
  key: string;
  fromStationId: HuntStationId | "core";
  stationId: HuntStationId;
  points: ObservatoryVec3[];
  leftEdgePoints: ObservatoryVec3[];
  rightEdgePoints: ObservatoryVec3[];
  waypointPositions: ObservatoryVec3[];
  colorHex: string;
  opacity: number;
  intensity: number;
  active: boolean;
  convoyCount: number;
  showPulse: boolean;
  corridorRadius: number;
  corridorOpacity: number;
  glowRadius: number;
}

export interface ObservatoryHypothesisNodeRecipe {
  position: ObservatoryVec3;
  radius: number;
  opacity: number;
}

export interface ObservatoryHypothesisScaffoldRecipe {
  key: string;
  primaryStationId: HuntStationId;
  supportingStationIds: HuntStationId[];
  colorHex: string;
  stage: "forming" | "branched" | "stabilizing" | "weakening";
  frameLoops: ObservatoryVec3[][];
  conduitPaths: ObservatoryVec3[][];
  branchPaths: ObservatoryVec3[][];
  nodes: ObservatoryHypothesisNodeRecipe[];
  lockPositions: ObservatoryVec3[];
  panels: Array<{
    position: ObservatoryVec3;
    rotation: ObservatoryVec3;
    scale: ObservatoryVec3;
    opacity: number;
  }>;
  intensity: number;
}

export interface ObservatoryWatchfieldRecipe {
  colorHex: string;
  position: ObservatoryVec3;
  ringPoints: ObservatoryVec3[];
  emphasis: number;
  active: boolean;
  perimeterInnerRadius: number;
  perimeterOuterRadius: number;
  perimeterOpacity: number;
  beaconRadius: number;
  beaconOpacity: number;
  secondaryRingInnerRadius: number;
  secondaryRingOuterRadius: number;
  secondaryRingOpacity: number;
}

export interface ObservatoryHeroPropRecipe {
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
}

export interface ObservatoryCoreRecipe {
  accentColor: string;
  receiveState: HuntObservatoryReceiveState;
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

export interface ObservatoryModeProfile {
  convoyBoost: number;
  label: "ATLAS" | "FLOW";
  layoutOpacityScale: number;
  populationOpacityScale: number;
  routeOpacityScale: number;
  verticalityScale: number;
}

export interface DerivedObservatoryWorld {
  environment: ObservatoryEnvironmentRecipe;
  camera: ObservatoryCameraRecipe;
  likelyStationId: HuntStationId | null;
  receiveState: HuntObservatoryReceiveState;
  modeProfile: ObservatoryModeProfile;
  core: ObservatoryCoreRecipe;
  districts: ObservatoryDistrictRecipe[];
  coreLinks: ObservatoryTransitRouteRecipe[];
  transitLinks: ObservatoryTransitRouteRecipe[];
  hypothesisScaffolds: ObservatoryHypothesisScaffoldRecipe[];
  heroProps: ObservatoryHeroPropRecipe[];
  watchfield: ObservatoryWatchfieldRecipe;
}

const PRIMARY_RADIUS = 13.8;
const WATCHFIELD_RADIUS = 20.5;
const STATION_HEIGHT = 0.72;
const WORLD_GRID_SIZE = 132;

const STATION_COLORS: Record<HuntStationId, string> = {
  signal: "#7cc8ff",
  targets: "#9df2dd",
  run: "#f4d982",
  receipts: "#7ee6f2",
  "case-notes": "#f0b87b",
  watch: "#d3b56e",
};

const LANE_PAIRS: Array<[HuntStationId, HuntStationId]> = [
  ["signal", "targets"],
  ["targets", "run"],
  ["run", "receipts"],
  ["receipts", "case-notes"],
];

const STATION_CAMERA_PROFILES: Record<
  HuntStationId,
  {
    atlas: {
      distance: number;
      height: number;
      lateral: number;
      fov: number;
      targetLift: number;
      settleRadius: number;
    };
    flow: {
      distance: number;
      height: number;
      lateral: number;
      fov: number;
      targetLift: number;
      settleRadius: number;
    };
  }
> = {
  signal: {
    atlas: { distance: 6.9, height: 7.2, lateral: -2.2, fov: 34, targetLift: 2.2, settleRadius: 0.86 },
    flow: { distance: 5.3, height: 5.6, lateral: -1.8, fov: 39, targetLift: 1.9, settleRadius: 0.58 },
  },
  targets: {
    atlas: { distance: 6.8, height: 7.0, lateral: 2.7, fov: 34, targetLift: 2.0, settleRadius: 0.9 },
    flow: { distance: 5.2, height: 5.5, lateral: 2.0, fov: 39, targetLift: 1.7, settleRadius: 0.6 },
  },
  run: {
    atlas: { distance: 5.6, height: 6.2, lateral: -2.7, fov: 33, targetLift: 2.0, settleRadius: 1.02 },
    flow: { distance: 4.4, height: 4.9, lateral: -2.2, fov: 38, targetLift: 1.75, settleRadius: 0.64 },
  },
  receipts: {
    atlas: { distance: 6.4, height: 6.8, lateral: -2.8, fov: 34, targetLift: 1.95, settleRadius: 0.94 },
    flow: { distance: 5.0, height: 5.2, lateral: -2.1, fov: 39, targetLift: 1.72, settleRadius: 0.62 },
  },
  "case-notes": {
    atlas: { distance: 6.8, height: 7.6, lateral: 1.8, fov: 33, targetLift: 2.3, settleRadius: 1.08 },
    flow: { distance: 5.2, height: 5.8, lateral: 1.5, fov: 38, targetLift: 1.92, settleRadius: 0.7 },
  },
  watch: {
    atlas: { distance: 7.5, height: 7.0, lateral: -2.1, fov: 35, targetLift: 1.88, settleRadius: 0.86 },
    flow: { distance: 5.8, height: 5.4, lateral: -1.8, fov: 40, targetLift: 1.62, settleRadius: 0.58 },
  },
};

function toTuple(vector: THREE.Vector3): ObservatoryVec3 {
  return [vector.x, vector.y, vector.z];
}

function growthLevelForDistrict(artifactCount: number, emphasis: number, active: boolean): number {
  const artifactPressure = Math.min(1, artifactCount / 6);
  return Math.min(1, emphasis * 0.5 + artifactPressure * 0.66 + (active ? 0.14 : 0));
}

function stationPosition(stationId: HuntStationId): THREE.Vector3 {
  const placement = HUNT_STATION_PLACEMENTS.find((entry) => entry.id === stationId);
  if (!placement) return new THREE.Vector3();
  const radius = placement.id === HUNT_PERIMETER_STATION_ID ? WATCHFIELD_RADIUS : PRIMARY_RADIUS;
  const angle = (placement.angleDeg * Math.PI) / 180;
  const x = Math.cos(angle) * radius;
  const z = Math.sin(angle) * radius * 0.82;
  return new THREE.Vector3(x, STATION_HEIGHT, z);
}

function buildLanePoints(
  from: THREE.Vector3,
  to: THREE.Vector3,
  mode: HuntObservatoryMode,
): ObservatoryVec3[] {
  const mid = from.clone().lerp(to, 0.5);
  mid.y = mode === "flow" ? 1.8 : 1.2;
  const curve = new THREE.CatmullRomCurve3([from, mid, to]);
  return curve.getPoints(24).map(toTuple);
}

function buildLocalArcPoints(
  from: ObservatoryVec3,
  to: ObservatoryVec3,
  height: number,
): ObservatoryVec3[] {
  const start = new THREE.Vector3(...from);
  const end = new THREE.Vector3(...to);
  const mid = start.clone().lerp(end, 0.5);
  mid.y += height;
  return new THREE.CatmullRomCurve3([start, mid, end]).getPoints(18).map(toTuple);
}

function offsetPathPoints(points: ObservatoryVec3[], lateralOffset: number): ObservatoryVec3[] {
  const vectors = points.map((point) => new THREE.Vector3(...point));
  return vectors.map((point, index) => {
    const previous = vectors[Math.max(0, index - 1)];
    const next = vectors[Math.min(vectors.length - 1, index + 1)];
    const tangent = next.clone().sub(previous);
    const lateral = new THREE.Vector3(-tangent.z, 0, tangent.x)
      .normalize()
      .multiplyScalar(lateralOffset);
    return [point.x + lateral.x, point.y, point.z + lateral.z];
  });
}

function buildPerimeterRing(): ObservatoryVec3[] {
  const points: ObservatoryVec3[] = [];
  for (let index = 0; index <= 64; index += 1) {
    const angle = (index / 64) * Math.PI * 2;
    points.push([
      Math.cos(angle) * WATCHFIELD_RADIUS,
      0.18,
      Math.sin(angle) * WATCHFIELD_RADIUS * 0.82,
    ]);
  }
  return points;
}

function deriveHeroProps(): ObservatoryHeroPropRecipe[] {
  const signalPosition = stationPosition("signal");
  const subjectsPosition = stationPosition("targets");
  const operationsPosition = stationPosition("run");
  const evidencePosition = stationPosition("receipts");
  const judgmentPosition = stationPosition("case-notes");
  const watchfieldPosition = stationPosition("watch");
  const corePosition = new THREE.Vector3(0, 1.14, 0);
  return [
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
      position: [signalPosition.x - 3.4, 0.24, signalPosition.z - 2.4],
      rotation: [0, Math.PI * 0.18, 0],
      scale: 2.08,
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
      position: [subjectsPosition.x + 2.15, 0.22, subjectsPosition.z - 1.7],
      rotation: [0, -Math.PI * 0.26, 0],
      scale: 2.55,
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
      position: [operationsPosition.x + 1.05, 0.18, operationsPosition.z + 1.42],
      rotation: [0, Math.PI * 0.42, 0],
      scale: 2.56,
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
      position: [evidencePosition.x - 1.9, 0.14, evidencePosition.z + 1.95],
      rotation: [0, -Math.PI * 0.18, 0],
      scale: 2.2,
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
      position: [judgmentPosition.x + 0.9, 0.08, judgmentPosition.z + 0.92],
      rotation: [0, Math.PI * 0.08, 0],
      scale: 1.82,
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
      position: [watchfieldPosition.x + 0.72, 0.08, watchfieldPosition.z - 0.62],
      rotation: [0, -Math.PI * 0.18, 0],
      scale: 1.72,
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
      position: [corePosition.x + 2.45, corePosition.y + 1.72, corePosition.z - 1.7],
      rotation: [0, Math.PI * 0.18, 0],
      scale: 0.84,
      stationId: "core",
      wakeThreshold: 0,
    },
  ];
}

function buildGrowthAnchorOffsets(stationId: HuntStationId): ObservatoryVec3[] {
  switch (stationId) {
    case "signal":
      return [
        [1.4, -0.1, 1.1],
        [2.6, -0.1, -0.1],
        [0.6, -0.1, 2.35],
      ];
    case "targets":
      return [
        [-0.5, -0.1, 2.2],
        [-1.8, -0.1, 1.2],
        [1.2, -0.1, 2.6],
      ];
    case "run":
      return [
        [-1.6, -0.1, 0.9],
        [-0.2, -0.1, 2.2],
        [1.3, -0.1, 1.2],
      ];
    case "receipts":
      return [
        [0.2, -0.1, 2.2],
        [1.5, -0.1, 1.2],
        [-1.1, -0.1, 1.4],
      ];
    case "case-notes":
      return [
        [-1.2, -0.1, 1.3],
        [0.2, -0.1, 2.3],
        [1.4, -0.1, 1.15],
      ];
    case "watch":
      return [
        [-1.6, -0.1, 0.6],
        [1.7, -0.1, 0.2],
        [0.2, -0.1, 1.9],
      ];
  }
}

function structureRecipe(
  key: string,
  kind: ObservatoryGrowthStructureRecipe["kind"],
  position: ObservatoryVec3,
  scale: ObservatoryVec3,
  wakeAmount: number,
  rotation: ObservatoryVec3 = [0, 0, 0],
): ObservatoryGrowthStructureRecipe {
  return {
    key,
    kind,
    position,
    scale,
    rotation,
    opacity: 0.08 + wakeAmount * 0.42,
    emissiveIntensity: 0.14 + wakeAmount * 0.5,
    wakeAmount,
  };
}

function buildDistrictSilhouetteRecipe(
  stationId: HuntStationId,
  growthLevel: number,
  emphasis: number,
): ObservatoryDistrictSilhouetteRecipe {
  const level = Math.max(growthLevel, emphasis * 0.6);
  switch (stationId) {
    case "signal":
      return {
        frameLoops: [
          [
            [-1.2, 0.2, -0.3],
            [-0.5, 2.6 + level * 1.1, 0],
            [0.4, 0.4, 0.8],
            [-1.2, 0.2, -0.3],
          ],
          [
            [0.2, 0.2, -1.1],
            [1.1, 2.2 + level * 0.9, -0.2],
            [1.4, 0.3, 0.9],
            [0.2, 0.2, -1.1],
          ],
        ],
        nodePositions: [
          [-0.5, 2.4 + level * 0.9, 0],
          [1.1, 2.1 + level * 0.7, -0.2],
          [0.6, 1.5 + level * 0.5, 1.2],
        ],
      };
    case "targets":
      return {
        frameLoops: [
          Array.from({ length: 9 }, (_, index) => {
            const angle = (index / 8) * Math.PI * 2;
            return [
              Math.cos(angle) * (1.6 + level * 0.3),
              1 + Math.sin(angle * 2) * 0.14,
              Math.sin(angle) * (1.1 + level * 0.2),
            ] as ObservatoryVec3;
          }),
          Array.from({ length: 7 }, (_, index) => {
            const angle = (index / 6) * Math.PI * 2;
            return [
              Math.cos(angle) * 0.9 - 0.5,
              1.7 + Math.sin(angle * 2) * 0.1,
              Math.sin(angle) * 0.7 + 0.4,
            ] as ObservatoryVec3;
          }),
        ],
        nodePositions: [
          [-1.2, 1.6, 0.5],
          [1.2, 1.2, -0.4],
          [0.2, 2.1 + level * 0.4, 1],
        ],
      };
    case "run":
      return {
        frameLoops: [
          [
            [-1.6, 0.3, -1],
            [-1.6, 1.9 + level * 0.7, -1],
            [1.6, 1.9 + level * 0.7, -1],
            [1.6, 0.3, -1],
            [-1.6, 0.3, -1],
          ],
          [
            [-1.1, 0.3, 1.2],
            [-1.1, 1.4 + level * 0.5, 1.2],
            [1.1, 1.4 + level * 0.5, 1.2],
            [1.1, 0.3, 1.2],
            [-1.1, 0.3, 1.2],
          ],
        ],
        nodePositions: [
          [-1.6, 2 + level * 0.7, -1],
          [1.6, 2 + level * 0.7, -1],
          [0, 1.7 + level * 0.6, 1.2],
        ],
      };
    case "receipts":
      return {
        frameLoops: [
          [
            [-1.4, 0.4, -0.8],
            [1.2, 0.75, -0.3],
            [1.4, 1.15 + level * 0.3, 0.8],
            [-1, 0.95 + level * 0.3, 1.1],
            [-1.4, 0.4, -0.8],
          ],
          [
            [-0.9, 0.7, -1.2],
            [0.8, 1.1, -0.7],
            [1.1, 1.5 + level * 0.3, 0.1],
            [-0.6, 1.2 + level * 0.3, -0.1],
            [-0.9, 0.7, -1.2],
          ],
        ],
        nodePositions: [
          [-1, 0.95 + level * 0.3, 1.1],
          [1.4, 1.15 + level * 0.3, 0.8],
          [1.1, 1.5 + level * 0.3, 0.1],
        ],
      };
    case "case-notes":
      return {
        frameLoops: [
          [
            [-1.6, 0.32, -0.9],
            [1.6, 0.32, -0.9],
            [1.2, 0.8 + level * 0.25, 0.3],
            [-1.2, 0.8 + level * 0.25, 0.3],
            [-1.6, 0.32, -0.9],
          ],
          [
            [-1.1, 0.94, -0.1],
            [1.1, 0.94, -0.1],
            [0.8, 1.55 + level * 0.4, 0.9],
            [-0.8, 1.55 + level * 0.4, 0.9],
            [-1.1, 0.94, -0.1],
          ],
        ],
        nodePositions: [
          [-1.2, 0.8 + level * 0.25, 0.3],
          [1.2, 0.8 + level * 0.25, 0.3],
          [0, 1.8 + level * 0.4, 1.1],
        ],
      };
    case "watch":
      return {
        frameLoops: [],
        nodePositions: [],
      };
  }
}

function buildDistrictOccupancyNodes(
  stationId: HuntStationId,
  artifactCount: number,
  growthLevel: number,
  emphasis: number,
): ObservatoryOccupancyNodeRecipe[] {
  const nodeCount = Math.max(3, Math.min(8, artifactCount + 2));
  const baseRadius = 1.8 + growthLevel * 0.9;
  return Array.from({ length: nodeCount }, (_, index) => {
    const angle = (index / Math.max(1, nodeCount)) * Math.PI * 2 + (stationId === "run" ? 0.22 : stationId === "receipts" ? -0.3 : 0);
    const radius = baseRadius + (index % 2 === 0 ? 0.5 : -0.18);
    const filled = index < artifactCount;
    return {
      position: [
        Math.cos(angle) * radius,
        0.1 + Math.floor(index / 3) * 0.03,
        Math.sin(angle) * radius * 0.72,
      ],
      scale: [
        0.16 + (filled ? 0.08 : 0) + emphasis * 0.06,
        0.06,
        0.16 + (filled ? 0.08 : 0) + emphasis * 0.06,
      ],
      filled,
      opacity: (filled ? 0.28 : 0.1) + growthLevel * 0.14,
    };
  });
}

function buildTimeStrata(
  artifactCount: number,
  emphasis: number,
): ObservatoryTimeStratumRecipe[] {
  const strataCount = Math.max(2, Math.min(4, Math.ceil((artifactCount + 1) / 2)));
  return Array.from({ length: strataCount }, (_, index) => ({
    yOffset: -0.14 - index * 0.18,
    radius: 2.8 + index * 0.6 + emphasis * 0.4,
    opacity: 0.12 - index * 0.02 + emphasis * 0.04,
  }));
}

function microInteractionForStation(stationId: HuntStationId): ObservatoryMicroInteractionKind {
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

function deriveDistrictLifecycle(
  status: HuntObservatorySceneState["stations"][number]["status"] | "idle",
  artifactCount: number,
  emphasis: number,
  active: boolean,
  likely: boolean,
): { progress: number; state: ObservatoryDistrictLifecycleState } {
  const progress = Math.min(
    1,
    emphasis * 0.58
      + Math.min(0.42, artifactCount * 0.09)
      + (active ? 0.16 : 0)
      + (likely ? 0.08 : 0)
      + (status === "receiving" ? 0.16 : 0)
      + (status === "blocked" ? 0.22 : 0),
  );

  if (status === "blocked" || (status === "receiving" && progress >= 0.66)) {
    return { progress, state: "critical" };
  }
  if (active && (artifactCount >= 5 || progress >= 0.82)) {
    return { progress, state: "saturated" };
  }
  if (status === "active" || active || progress >= 0.54) {
    return { progress, state: "active" };
  }
  if (status === "warming" || likely || progress >= 0.24) {
    return { progress, state: "waking" };
  }
  return { progress, state: "dormant" };
}

function localReadForStation(
  stationId: HuntStationId,
  artifactCount: number,
  active: boolean,
  likely: boolean,
): string | null {
  const prefix = active ? "Active district." : likely ? "Likely next district." : "Peripheral read.";
  switch (stationId) {
    case "signal":
      return `${prefix} ${artifactCount} signal traces are crossing the horizon.`;
    case "targets":
      return `${prefix} ${artifactCount} subject nodes are clustering under pressure.`;
    case "run":
      return `${prefix} ${artifactCount} operational berths are warming in the machinery lane.`;
    case "receipts":
      return `${prefix} ${artifactCount} evidence objects are stacking into the field.`;
    case "case-notes":
      return `${prefix} ${artifactCount} judgment plates are shaping authored meaning.`;
    case "watch":
      return `${prefix} ${artifactCount} perimeter beacons are holding the watchfield.`;
  }
}

function deriveModeProfile(mode: HuntObservatoryMode): ObservatoryModeProfile {
  return mode === "flow"
    ? {
        convoyBoost: 1.34,
        label: "FLOW",
        layoutOpacityScale: 0.72,
        populationOpacityScale: 0.98,
        routeOpacityScale: 1.42,
        verticalityScale: 1.18,
      }
    : {
        convoyBoost: 0.72,
        label: "ATLAS",
        layoutOpacityScale: 1.12,
        populationOpacityScale: 0.32,
        routeOpacityScale: 0.66,
        verticalityScale: 0.96,
      };
}

function masterplanFeature(
  key: string,
  kind: ObservatoryMasterplanFeatureKind,
  position: ObservatoryVec3,
  scale: ObservatoryVec3,
  opacity: number,
  emissiveIntensity: number,
  rotation: ObservatoryVec3 = [0, 0, 0],
): ObservatoryMasterplanFeatureRecipe {
  return { key, kind, position, rotation, scale, opacity, emissiveIntensity };
}

function traversalSurface(
  key: string,
  kind: ObservatoryTraversalSurfaceKind,
  position: ObservatoryVec3,
  scale: ObservatoryVec3,
  opacity: number,
  emissiveIntensity: number,
  rotation: ObservatoryVec3 = [0, 0, 0],
  colliderKind: "box" | "cylinder" = "box",
  jumpBoost?: number,
): ObservatoryTraversalSurfaceRecipe {
  return {
    key,
    kind,
    position,
    rotation,
    scale,
    opacity,
    emissiveIntensity,
    colliderKind,
    jumpBoost,
  };
}

function buildStairSequence(
  keyPrefix: string,
  start: ObservatoryVec3,
  end: ObservatoryVec3,
  steps: number,
  width: number,
  depth: number,
  opacity: number,
  emissiveIntensity: number,
  yStep: number,
): ObservatoryTraversalSurfaceRecipe[] {
  if (steps <= 0) return [];
  return Array.from({ length: steps }, (_, index) => {
    const t = steps === 1 ? 1 : index / (steps - 1);
    return traversalSurface(
      `${keyPrefix}-step-${index + 1}`,
      "platform",
      [
        start[0] + (end[0] - start[0]) * t,
        start[1] + yStep * index,
        start[2] + (end[2] - start[2]) * t,
      ],
      [
        width,
        0.14,
        Math.max(0.5, depth - index * 0.02),
      ],
      opacity * (0.88 - index * 0.03),
      emissiveIntensity * (0.88 - index * 0.04),
    );
  });
}

function crewRecipe(
  key: string,
  role: ObservatoryCrewRole,
  stationId: HuntStationId,
  position: ObservatoryVec3,
  accentColor: string,
  facingRadians: number,
  loopKind: ObservatoryCrewLoopKind,
  pace: number,
  waypoints: ObservatoryVec3[],
  utilityTarget: ObservatoryVec3 | null,
  scale = 0.62,
  active = false,
): ObservatoryCrewRecipe {
  return {
    key,
    role,
    stationId,
    position,
    accentColor,
    facingRadians,
    loopKind,
    pace,
    utilityTarget,
    waypoints,
    scale,
    active,
    response: null,
  };
}

function buildDistrictMasterplanFeatures(
  stationId: HuntStationId,
  growthLevel: number,
  emphasis: number,
  modeProfile: ObservatoryModeProfile,
): ObservatoryMasterplanFeatureRecipe[] {
  const opacity = (0.16 + growthLevel * 0.24 + emphasis * 0.12) * modeProfile.layoutOpacityScale;
  const liftY = (value: number) => (value <= 0.32 ? value : 0.32 + (value - 0.32) * modeProfile.verticalityScale);
  const stretchY = (value: number) => value * (0.96 + modeProfile.verticalityScale * 0.04);
  const features = (() => {
  switch (stationId) {
    case "signal":
      return [
        masterplanFeature(`${stationId}-tower-a`, "tower", [-2.8, 1.4, -1.4], [0.36, 2.4 + growthLevel * 1.1, 0.36], opacity, 0.34),
        masterplanFeature(`${stationId}-tower-b`, "tower", [-1.2, 1, 1.7], [0.28, 1.8 + growthLevel * 0.9, 0.28], opacity * 0.94, 0.3),
        masterplanFeature(`${stationId}-dish-a`, "dish", [1.4, 1.1, -1.4], [1.2, 0.2, 1.2], opacity, 0.42, [-0.48, 0.26, 0]),
        masterplanFeature(`${stationId}-mast`, "sensor-mast", [2.4, 1.6, 0.9], [0.22, 2.6 + growthLevel * 0.8, 0.22], opacity * 0.92, 0.36),
      ];
    case "targets":
      return [
        masterplanFeature(`${stationId}-orbit-a`, "orbit-platform", [-1.8, 1.1, 1.2], [1.1, 0.14, 1.1], opacity, 0.24),
        masterplanFeature(`${stationId}-orbit-b`, "orbit-platform", [1.4, 1.5, -0.5], [0.9, 0.14, 0.9], opacity * 0.92, 0.22),
        masterplanFeature(`${stationId}-pylon-a`, "link-pylon", [-0.6, 1.2, -1.8], [0.24, 1.9 + growthLevel * 0.7, 0.24], opacity * 0.96, 0.32),
        masterplanFeature(`${stationId}-pylon-b`, "link-pylon", [2.2, 1.2, 1.5], [0.24, 1.5 + growthLevel * 0.6, 0.24], opacity * 0.9, 0.28),
      ];
    case "run":
      return [
        masterplanFeature(`${stationId}-gantry-a`, "gantry", [-2.1, 1.3, 1.4], [1.8, 0.18, 0.34], opacity, 0.28),
        masterplanFeature(`${stationId}-gantry-b`, "gantry", [1.9, 1.7, -1.1], [1.6, 0.18, 0.34], opacity * 0.94, 0.26),
        masterplanFeature(`${stationId}-reactor`, "reactor", [0.8, 1.4, 0.8], [0.8, 1.8 + growthLevel * 0.7, 0.8], opacity, 0.48),
        masterplanFeature(`${stationId}-rig`, "rig", [-0.9, 0.9, -2.1], [0.78, 1.2, 0.56], opacity * 0.88, 0.32, [0, 0.32, 0]),
      ];
    case "receipts":
      return [
        masterplanFeature(`${stationId}-vault-a`, "vault-stack", [-1.8, 0.9, 1.8], [0.64, 1.3 + growthLevel * 0.8, 0.64], opacity, 0.26),
        masterplanFeature(`${stationId}-vault-b`, "vault-stack", [-0.5, 1.2, 2.3], [0.56, 1.7 + growthLevel * 0.9, 0.56], opacity * 0.96, 0.28),
        masterplanFeature(`${stationId}-lane`, "archive-lane", [1.6, 1.4, -0.2], [2.2, 0.12, 0.42], opacity * 0.86, 0.2),
        masterplanFeature(`${stationId}-rack`, "archive-lane", [0.8, 2.2, -1.6], [1.8, 0.12, 0.34], opacity * 0.82, 0.18, [0.18, -0.22, 0]),
      ];
    case "case-notes":
      return [
        masterplanFeature(`${stationId}-terrace-a`, "terrace", [-1.4, 0.6, 1.2], [1.8, 0.16, 1.1], opacity * 0.94, 0.2),
        masterplanFeature(`${stationId}-terrace-b`, "terrace", [0.2, 1.2, 0.4], [1.5, 0.16, 0.96], opacity, 0.22),
        masterplanFeature(`${stationId}-court`, "scaffold-court", [1.9, 1.9, -0.4], [1.6, 0.14, 1.2], opacity * 0.92, 0.26),
        masterplanFeature(`${stationId}-dais-step`, "terrace", [1.1, 0.34, 1.4], [1.4, 0.14, 1.0], opacity * 0.88, 0.18),
      ];
    case "watch":
      return [
        masterplanFeature(`${stationId}-beacon-a`, "beacon", [1.1, 1.3, -0.9], [0.26, 2.0 + growthLevel * 0.6, 0.26], opacity, 0.42),
        masterplanFeature(`${stationId}-beacon-b`, "beacon", [-1.2, 1.2, 0.7], [0.26, 1.7 + growthLevel * 0.5, 0.26], opacity * 0.92, 0.36),
        masterplanFeature(`${stationId}-outer-pylon-a`, "outer-pylon", [2.3, 0.8, 1.9], [0.3, 1.4, 0.3], opacity * 0.82, 0.24),
        masterplanFeature(`${stationId}-outer-pylon-b`, "outer-pylon", [-2.4, 0.8, -1.6], [0.3, 1.5, 0.3], opacity * 0.82, 0.24),
      ];
  }})();

  return features.map((feature) => ({
    ...feature,
    position: [feature.position[0], liftY(feature.position[1]), feature.position[2]],
    scale: [feature.scale[0], stretchY(feature.scale[1]), feature.scale[2]],
  }));
}

function buildDistrictTraversalSurfaces(
  stationId: HuntStationId,
  growthLevel: number,
  emphasis: number,
  modeProfile: ObservatoryModeProfile,
): ObservatoryTraversalSurfaceRecipe[] {
  const opacity = (0.12 + growthLevel * 0.18 + emphasis * 0.08) * modeProfile.layoutOpacityScale;
  const liftY = (value: number) => (value <= 0.24 ? value : 0.24 + (value - 0.24) * modeProfile.verticalityScale);
  const stretchY = (value: number) => value * (0.94 + modeProfile.verticalityScale * 0.06);
  const surfaces = (() => {
    switch (stationId) {
      case "signal":
        return [
          traversalSurface(`${stationId}-observation`, "observation-platform", [-2.5, 0.46, -0.6], [2.4, 0.18, 1.4], opacity, 0.18),
          ...buildStairSequence(`${stationId}-stairs`, [-1.9, 0.28, 0.95], [-0.6, 0.28, 0.2], 4, 1.2, 0.78, opacity * 0.92, 0.16, 0.2),
          traversalSurface(`${stationId}-apron`, "bridge", [-1.18, 0.62, -0.18], [1.48, 0.12, 0.58], opacity * 0.84, 0.16, [0, 0.18, 0]),
          traversalSurface(`${stationId}-ramp`, "ramp", [0.34, 0.78, -0.16], [1.68, 0.18, 0.78], opacity * 0.86, 0.16, [-0.22, 0.28, 0]),
          traversalSurface(`${stationId}-catwalk`, "catwalk", [1.6, 1.36, -0.72], [2.8, 0.12, 0.42], opacity * 0.88, 0.18),
          traversalSurface(`${stationId}-overlook`, "observation-platform", [2.95, 2.06, -1.42], [1.42, 0.16, 1.1], opacity * 0.76, 0.18),
          traversalSurface(`${stationId}-shortcut-bridge`, "bridge", [2.2, 1.66, -0.1], [1.54, 0.12, 0.3], opacity * 0.8, 0.16, [0, 0.48, 0]),
        ];
      case "targets":
        return [
          ...buildStairSequence(`${stationId}-cluster-steps`, [-1.8, 0.34, 1.7], [-0.4, 0.34, 0.9], 3, 1.18, 0.72, opacity * 0.86, 0.16, 0.22),
          traversalSurface(`${stationId}-bridge`, "bridge", [0.1, 1.06, 0.6], [2.8, 0.12, 0.42], opacity, 0.18, [0, 0.34, 0]),
          traversalSurface(`${stationId}-ledge`, "ledge", [-1.6, 0.66, 1.7], [1.6, 0.12, 0.54], opacity * 0.9, 0.16),
          traversalSurface(`${stationId}-orbit-platform`, "platform", [1.6, 1.48, -1.1], [1.4, 0.16, 1.1], opacity * 0.88, 0.18),
          traversalSurface(`${stationId}-hidden-overlook`, "hanging-platform", [2.8, 2.12, 0.34], [1.28, 0.14, 1.02], opacity * 0.7, 0.16),
          traversalSurface(`${stationId}-jump-link`, "jump-pad", [0.96, 0.24, -1.8], [0.82, 0.2, 0.82], opacity * 0.92, 0.22, [0, 0, 0], "cylinder", 7.4),
        ];
      case "run":
        return [
          ...buildStairSequence(`${stationId}-gantry-steps`, [-2.2, 0.32, -1.34], [-1.1, 0.32, -0.3], 5, 1.18, 0.76, opacity * 0.88, 0.16, 0.24),
          traversalSurface(`${stationId}-control-deck`, "control-deck", [1.5, 1.4, 1.4], [2.6, 0.16, 1.5], opacity, 0.24),
          traversalSurface(`${stationId}-catwalk`, "catwalk", [-1.5, 1.02, 0.2], [3.2, 0.12, 0.4], opacity * 0.94, 0.2, [0, -0.12, 0]),
          traversalSurface(`${stationId}-ramp`, "ramp", [-0.2, 0.34, -1.2], [2.4, 0.18, 0.9], opacity * 0.88, 0.16, [-0.22, -0.2, 0]),
          traversalSurface(`${stationId}-upper-bridge`, "bridge", [2.28, 1.96, 0.48], [2.5, 0.12, 0.34], opacity * 0.82, 0.18, [0, -0.22, 0]),
          traversalSurface(`${stationId}-hanger`, "hanging-platform", [3.1, 2.54, 1.06], [1.24, 0.14, 0.9], opacity * 0.74, 0.18),
          traversalSurface(`${stationId}-jump-pad`, "jump-pad", [2.4, 0.22, -0.8], [1.0, 0.22, 1.0], opacity * 0.96, 0.28, [0, 0, 0], "cylinder", 9.8),
          traversalSurface(`${stationId}-jump-route-platform`, "platform", [3.65, 3.06, 0.24], [1.3, 0.16, 0.96], opacity * 0.72, 0.18),
        ];
      case "receipts":
        return [
          ...buildStairSequence(`${stationId}-archive-stairs`, [1.9, 0.38, 1.5], [0.66, 0.38, 0.62], 4, 1.1, 0.66, opacity * 0.84, 0.16, 0.22),
          traversalSurface(`${stationId}-archive-lane`, "bridge", [0.8, 1.12, -0.5], [3.1, 0.12, 0.46], opacity, 0.18),
          traversalSurface(`${stationId}-hang-platform`, "hanging-platform", [-1.3, 1.76, 1.2], [1.8, 0.14, 1.0], opacity * 0.9, 0.18),
          traversalSurface(`${stationId}-ledge`, "ledge", [1.9, 0.74, 1.4], [1.5, 0.12, 0.52], opacity * 0.82, 0.16),
          traversalSurface(`${stationId}-suspended-lane`, "hanging-platform", [0.2, 2.42, -1.34], [1.96, 0.14, 0.8], opacity * 0.74, 0.18),
          traversalSurface(`${stationId}-hidden-overlook`, "observation-platform", [-2.6, 2.3, 1.86], [1.2, 0.16, 1.0], opacity * 0.66, 0.16),
          traversalSurface(`${stationId}-jump-route`, "jump-pad", [-0.1, 0.24, 2.42], [0.82, 0.2, 0.82], opacity * 0.9, 0.22, [0, 0, 0], "cylinder", 7.2),
        ];
      case "case-notes":
        return [
          ...buildStairSequence(`${stationId}-terrace-steps`, [-1.4, 0.34, 1.5], [0.2, 0.34, 0.9], 5, 1.36, 0.9, opacity * 0.88, 0.16, 0.24),
          traversalSurface(`${stationId}-terrace-low`, "platform", [-0.8, 0.42, 1.2], [2.4, 0.16, 1.4], opacity, 0.16),
          traversalSurface(`${stationId}-terrace-mid`, "platform", [0.6, 0.92, 0.6], [2.0, 0.16, 1.2], opacity * 0.94, 0.18),
          traversalSurface(`${stationId}-terrace-high`, "platform", [1.7, 1.48, -0.2], [1.6, 0.16, 1.0], opacity * 0.9, 0.2),
          traversalSurface(`${stationId}-scaffold-bridge`, "bridge", [0.3, 1.42, -1.0], [2.6, 0.12, 0.36], opacity * 0.84, 0.18, [0, 0.22, 0]),
          traversalSurface(`${stationId}-court-overlook`, "control-deck", [2.66, 2.2, -0.42], [1.42, 0.16, 1.02], opacity * 0.74, 0.2),
          traversalSurface(`${stationId}-shortcut-bridge`, "bridge", [2.1, 1.92, 0.78], [1.6, 0.12, 0.28], opacity * 0.72, 0.16, [0, -0.34, 0]),
        ];
      case "watch":
        return [
          ...buildStairSequence(`${stationId}-sentry-steps`, [-1.4, 0.32, 0.7], [-0.2, 0.32, 0.1], 3, 1.12, 0.7, opacity * 0.82, 0.14, 0.22),
          traversalSurface(`${stationId}-perimeter-deck`, "observation-platform", [0.5, 0.52, 0], [2.1, 0.16, 1.4], opacity, 0.18),
          traversalSurface(`${stationId}-bridge`, "bridge", [-1.2, 0.96, 1.1], [2.2, 0.12, 0.34], opacity * 0.9, 0.16, [0, -0.18, 0]),
          traversalSurface(`${stationId}-outer-patrol`, "bridge", [2.1, 1.44, -0.92], [2.4, 0.12, 0.32], opacity * 0.76, 0.16, [0, 0.28, 0]),
          traversalSurface(`${stationId}-watch-overlook`, "observation-platform", [2.96, 1.92, -1.72], [1.28, 0.16, 0.96], opacity * 0.7, 0.16),
          traversalSurface(`${stationId}-jump-pad`, "jump-pad", [1.9, 0.24, -1.4], [0.9, 0.2, 0.9], opacity * 0.96, 0.22, [0, 0, 0], "cylinder", 8.4),
        ];
    }
  })();

  return surfaces.map((surface) => ({
    ...surface,
    position: [surface.position[0], liftY(surface.position[1]), surface.position[2]],
    scale: [surface.scale[0], stretchY(surface.scale[1]), surface.scale[2]],
  }));
}

function buildDistrictCrew(
  stationId: HuntStationId,
  active: boolean,
): ObservatoryCrewRecipe[] {
  switch (stationId) {
    case "signal":
      return [
        crewRecipe(
          "crew:navigator",
          "navigator",
          stationId,
          [-2.2, 0.52, -0.4],
          "#83dcff",
          Math.PI * 0.22,
          "calibrate-horizon",
          0.18,
          [
            [-2.4, 0.52, -0.8],
            [-1.9, 0.62, 0.2],
            [-1.1, 1.08, -0.4],
            [-2.2, 0.52, -0.4],
          ],
          [1.4, 1.6, -1.4],
          0.56,
          active,
        ),
      ];
    case "run":
      return [
        crewRecipe(
          "crew:technician",
          "technician",
          stationId,
          [1.5, 1.58, 1.2],
          "#f2d991",
          Math.PI * 0.8,
          "service-operations",
          0.22,
          [
            [1.5, 1.58, 1.2],
            [0.2, 1.34, 1.1],
            [-0.8, 1.1, 0.3],
            [1.1, 1.46, 0.1],
          ],
          [1.05, 0.18, 1.42],
          0.6,
          active,
        ),
      ];
    case "receipts":
      return [
        crewRecipe(
          "crew:archivist",
          "archivist",
          stationId,
          [-1.2, 1.88, 1.2],
          "#95eff8",
          Math.PI * 0.5,
          "tend-evidence",
          0.16,
          [
            [-1.2, 1.88, 1.2],
            [-0.4, 2.02, 0.7],
            [0.6, 1.24, -0.2],
            [-0.2, 1.76, -0.8],
          ],
          [-1.9, 0.14, 1.95],
          0.58,
          active,
        ),
      ];
    case "watch":
      return [
        crewRecipe(
          "crew:sentry",
          "sentry",
          stationId,
          [0.8, 0.62, -0.2],
          "#d8c27a",
          -Math.PI * 0.2,
          "patrol-watch",
          0.14,
          [
            [0.8, 0.62, -0.2],
            [2.3, 1.12, -1.1],
            [1.1, 1.66, -1.92],
            [-0.8, 0.92, 0.92],
          ],
          [0.72, 0.08, -0.62],
          0.56,
          active,
        ),
      ];
    default:
      return [];
  }
}

function buildDistrictGrowthRecipe(
  stationId: HuntStationId,
  growthAnchors: ObservatoryDistrictRecipe["growthAnchors"],
  growthLevel: number,
  emphasis: number,
): ObservatoryDistrictGrowthRecipe {
  const anchorPositions = growthAnchors.map((anchor) => anchor.position);
  const anchorWake = anchorPositions.map((_, index) => {
    const threshold = 0.12 + index * 0.16;
    return Math.max(0, Math.min(1, (growthLevel - threshold) / 0.4));
  });

  const conduits = [
    ...anchorPositions.map((anchor) => buildLocalArcPoints([0, 0.5, 0], [anchor[0], 0.3, anchor[2]], 0.22)),
    buildLocalArcPoints(anchorPositions[0], anchorPositions[1], 0.16),
    buildLocalArcPoints(anchorPositions[1], anchorPositions[2], 0.16),
  ];

  const structures: ObservatoryGrowthStructureRecipe[] = [];
  switch (stationId) {
    case "signal":
      structures.push(
        structureRecipe(`${stationId}-spire-east`, "spire", anchorPositions[0], [0.22, 1.4 + anchorWake[0] * 1.8, 0.22], anchorWake[0], [0, 0.18, 0]),
        structureRecipe(`${stationId}-spire-west`, "spire", anchorPositions[1], [0.18, 1.1 + anchorWake[1] * 1.4, 0.18], anchorWake[1], [0, -0.12, 0]),
        structureRecipe(`${stationId}-array-north`, "array", anchorPositions[2], [0.3 + anchorWake[2] * 0.14, 0.42 + anchorWake[2] * 0.5, 0.24], anchorWake[2], [0, 0.4, 0]),
        structureRecipe(`${stationId}-dish-core`, "dish", [0, 0.34, 0], [0.6 + growthLevel * 0.18, 0.6, 0.6 + growthLevel * 0.18], growthLevel, [-0.32, 0.5, 0]),
      );
      break;
    case "targets":
      structures.push(
        structureRecipe(`${stationId}-halo-core`, "halo", [0, 0.12, 0], [0.84 + growthLevel * 0.22, 0.84, 0.84 + growthLevel * 0.22], growthLevel),
        structureRecipe(`${stationId}-satellite-east`, "satellite", anchorPositions[0], [0.26 + anchorWake[0] * 0.2, 0.26 + anchorWake[0] * 0.2, 0.26 + anchorWake[0] * 0.2], anchorWake[0]),
        structureRecipe(`${stationId}-satellite-west`, "satellite", anchorPositions[1], [0.22 + anchorWake[1] * 0.16, 0.22 + anchorWake[1] * 0.16, 0.22 + anchorWake[1] * 0.16], anchorWake[1]),
        structureRecipe(`${stationId}-panel-north`, "panel", anchorPositions[2], [0.48 + anchorWake[2] * 0.22, 0.08, 0.7 + anchorWake[2] * 0.28], anchorWake[2], [0.12, 0.3, 0.08]),
      );
      break;
    case "run":
      structures.push(
        structureRecipe(`${stationId}-array-core`, "array", [0, 0.34, 0], [0.44 + growthLevel * 0.18, 0.82 + growthLevel * 0.76, 0.44 + growthLevel * 0.18], growthLevel),
        structureRecipe(`${stationId}-pylon-east`, "pylon", anchorPositions[0], [0.22, 1.0 + anchorWake[0] * 1.5, 0.22], anchorWake[0]),
        structureRecipe(`${stationId}-pylon-west`, "pylon", anchorPositions[1], [0.22, 1.1 + anchorWake[1] * 1.8, 0.22], anchorWake[1]),
        structureRecipe(`${stationId}-spire-north`, "spire", anchorPositions[2], [0.18, 1.2 + anchorWake[2] * 1.7, 0.18], anchorWake[2], [0, 0.22, 0]),
      );
      break;
    case "receipts":
      structures.push(
        structureRecipe(`${stationId}-evidence-bed`, "panel", [0, 0.2, 0], [0.9 + growthLevel * 0.2, 0.08, 0.72 + growthLevel * 0.18], growthLevel, [-0.08, 0.16, -0.12]),
        structureRecipe(`${stationId}-rack-east`, "array", anchorPositions[0], [0.22 + anchorWake[0] * 0.14, 0.58 + anchorWake[0] * 0.6, 0.18], anchorWake[0], [0.04, 0.18, 0]),
        structureRecipe(`${stationId}-rack-west`, "array", anchorPositions[1], [0.22 + anchorWake[1] * 0.14, 0.66 + anchorWake[1] * 0.7, 0.18], anchorWake[1], [0, -0.18, 0]),
        structureRecipe(`${stationId}-beacon-north`, "pylon", anchorPositions[2], [0.16, 0.96 + anchorWake[2] * 1.28, 0.16], anchorWake[2]),
      );
      break;
    case "case-notes":
      structures.push(
        structureRecipe(`${stationId}-terrace-low`, "panel", [0, 0.12, 0.08], [0.9 + growthLevel * 0.12, 0.08, 0.68 + growthLevel * 0.08], growthLevel),
        structureRecipe(`${stationId}-terrace-mid`, "panel", [0, 0.34, 0], [0.72 + growthLevel * 0.12, 0.08, 0.54 + growthLevel * 0.08], growthLevel, [0, 0, 0]),
        structureRecipe(`${stationId}-spire-east`, "spire", anchorPositions[0], [0.16, 0.86 + anchorWake[0] * 1.1, 0.16], anchorWake[0]),
        structureRecipe(`${stationId}-halo-crown`, "halo", anchorPositions[2], [0.42 + anchorWake[2] * 0.18, 0.42, 0.42 + anchorWake[2] * 0.18], anchorWake[2]),
      );
      break;
    case "watch":
      structures.push(
        structureRecipe(`${stationId}-perimeter-halo`, "halo", [0, 0.08, 0], [1, 1, 1], growthLevel),
      );
      break;
  }

  // Add dormant pads even at low growth so each district reads as expandable.
  anchorPositions.forEach((position, index) => {
    structures.push(
      structureRecipe(
        `${stationId}-pad-${index}`,
        "panel",
        [position[0], 0.04, position[2]],
        [0.36 + emphasis * 0.14, 0.04, 0.36 + emphasis * 0.14],
        Math.min(0.42, anchorWake[index] * 0.4 + 0.08),
      ),
    );
  });

  return {
    stationId,
    growthLevel,
    structures,
    conduitPaths: conduits,
  };
}

function deriveCameraRecipe(
  mode: HuntObservatoryMode,
  focusStationId: HuntStationId | null,
  heroProps: ObservatoryHeroPropRecipe[],
): ObservatoryCameraRecipe {
  const base =
    mode === "flow"
      ? {
          initialPosition: [0, 16.4, 31.5] as ObservatoryVec3,
          desiredPosition: [0, 16.4, 31.5] as ObservatoryVec3,
          desiredTarget: [0, 1.1, 0] as ObservatoryVec3,
        }
      : {
          initialPosition: [0, 20.4, 36.8] as ObservatoryVec3,
          desiredPosition: [0, 20.4, 36.8] as ObservatoryVec3,
          desiredTarget: [0, 1.2, 0] as ObservatoryVec3,
        };

  if (!focusStationId) {
    return {
      ...base,
      fov: 42,
      minDistance: 12,
      maxDistance: 42,
      dampingFactor: 0.08,
      lerpSpeed: mode === "flow" ? 3.8 : 3.1,
      arrivalDurationMs: mode === "flow" ? 1100 : 1300,
      arrivalLift: mode === "flow" ? 3.4 : 4.8,
      settleRadius: mode === "flow" ? 0.7 : 1.1,
      missionFocusDwellMs: 0,
    };
  }

  const focus = stationPosition(focusStationId);
  const focusHero =
    heroProps
      .filter((prop) => prop.stationId === focusStationId)
      .sort((left, right) => right.importance - left.importance)[0] ?? null;
  const heroAnchor = focusHero ? new THREE.Vector3(...focusHero.position) : focus.clone();
  const profile = STATION_CAMERA_PROFILES[focusStationId][mode];
  const outward = focus.clone().setY(0).normalize();
  const lateral = new THREE.Vector3(-outward.z, 0, outward.x);
  const targetAnchor = heroAnchor.clone().lerp(focus, mode === "flow" ? 0.08 : 0.02);
  targetAnchor.y = profile.targetLift;
  const desiredPosition = targetAnchor
    .clone()
    .add(outward.multiplyScalar(profile.distance))
    .add(lateral.multiplyScalar(profile.lateral))
    .setY(profile.height);

  return {
    initialPosition: base.initialPosition,
    desiredTarget: toTuple(targetAnchor),
    desiredPosition: toTuple(desiredPosition),
    fov: profile.fov,
    minDistance: 12,
    maxDistance: 42,
    dampingFactor: 0.08,
    lerpSpeed: mode === "flow" ? 4.2 : 3.4,
    arrivalDurationMs: mode === "flow" ? 980 : 1220,
    arrivalLift: mode === "flow" ? 3.1 : 4.3,
    settleRadius: profile.settleRadius,
    // CAM-04: dwell for 1800ms when focused on a specific station in atlas mode.
    // In flow mode, the camera already follows the player — dwell is not meaningful.
    missionFocusDwellMs: mode === "atlas" ? 1800 : 0,
  };
}

function deriveDistrictRecipe(
  stationId: HuntStationId,
  stationState: HuntObservatorySceneState["stations"][number] | null,
  activeStationId: HuntStationId | null,
  likelyStationId: HuntStationId | null,
  mode: HuntObservatoryMode,
  modeProfile: ObservatoryModeProfile,
): ObservatoryDistrictRecipe {
  const emphasis = stationState?.emphasis ?? 0.26;
  const active = activeStationId === stationId;
  const likely = likelyStationId === stationId;
  const artifactCount = stationState?.artifactCount ?? 0;
  const status = stationState?.status ?? "idle";
  const opacity = 0.18 + emphasis * 0.32 + (active ? 0.18 : 0) + (likely ? 0.08 : 0);
  const growthLevel = growthLevelForDistrict(artifactCount, emphasis, active || likely);
  const lifecycle = deriveDistrictLifecycle(status, artifactCount, emphasis, active, likely);
  const growthAnchors = buildGrowthAnchorOffsets(stationId).map((position, index) => ({
    position,
    ringInnerRadius: 0.34 + index * 0.06,
    ringOuterRadius: 0.48 + index * 0.06,
    nodeRadius: 0.07 + index * 0.01,
    opacity: 0.18 + emphasis * 0.1,
  }));
  const growth = buildDistrictGrowthRecipe(stationId, growthAnchors, growthLevel, emphasis);
  const silhouette = buildDistrictSilhouetteRecipe(stationId, growthLevel, emphasis);
  const occupancyLevel = Math.min(1, growthLevel * 0.68 + artifactCount * 0.08 + (active ? 0.1 : 0));
  const occupancyNodes = buildDistrictOccupancyNodes(stationId, artifactCount, growthLevel, emphasis);
  const timeStrata = buildTimeStrata(artifactCount, emphasis);
  const microInteraction = microInteractionForStation(stationId);
  const localRead = localReadForStation(stationId, artifactCount, active, likely);
  const masterplanFeatures = buildDistrictMasterplanFeatures(stationId, growthLevel, emphasis, modeProfile);
  const traversalSurfaces = buildDistrictTraversalSurfaces(stationId, growthLevel, emphasis, modeProfile);
  const crew = buildDistrictCrew(stationId, active || likely);
  const verticalSpan = Math.max(
    2.2,
    ...masterplanFeatures.map((feature) => feature.position[1] + feature.scale[1] * 0.6),
    ...traversalSurfaces.map((surface) => surface.position[1] + surface.scale[1] * 0.8),
  );

  return {
    id: stationId,
    label: HUNT_STATION_LABELS[stationId],
    colorHex: STATION_COLORS[stationId],
    position: toTuple(stationPosition(stationId)),
    status,
    active,
    likely,
    emphasis,
    artifactCount,
    lifecycleState: lifecycle.state,
    lifecycleProgress: lifecycle.progress,
    baseDiscRadius: 2.4,
    baseDiscOpacity: opacity * 0.22,
    outerRingInnerRadius: 2.72,
    outerRingOuterRadius: 3.28,
    outerRingOpacity: opacity * 0.08,
    torusRadius: 1.34,
    torusTubeRadius: 0.07,
    torusOpacity: opacity,
    floatAmplitude: 0.04,
    pulseSpeed: mode === "flow" ? 0.004 : 0.0018,
    pulseAmplitude: active ? 0.06 : 0.03,
    growthAnchors,
    growth,
    silhouette,
    masterplanFeatures,
    traversalSurfaces,
    crew,
    occupancyLevel,
    occupancyNodes,
    timeStrata,
    microInteraction,
    localRead,
    probeReaction: null,
    verticalSpan,
  };
}

function deriveCoreLinks(mode: HuntObservatoryMode): ObservatoryTransitRouteRecipe[] {
  return HUNT_PRIMARY_STATION_ORDER.map((stationId) => ({
    key: `core-${stationId}`,
    fromStationId: "core",
    stationId,
    points: buildLanePoints(new THREE.Vector3(0, 1.1, 0), stationPosition(stationId), mode),
    leftEdgePoints: [],
    rightEdgePoints: [],
    waypointPositions: [],
    colorHex: STATION_COLORS[stationId],
    opacity: mode === "flow" ? 0.22 : 0.12,
    intensity: 0.22,
    active: false,
    convoyCount: 0,
    showPulse: false,
    corridorRadius: 0.06,
    corridorOpacity: 0.04,
    glowRadius: 0.12,
  }));
}

function deriveTransitLinks(
  mode: HuntObservatoryMode,
  activeStationId: HuntStationId | null,
  likelyStationId: HuntStationId | null,
): ObservatoryTransitRouteRecipe[] {
  return LANE_PAIRS.map(([fromId, toId], index) => {
    const points = buildLanePoints(stationPosition(fromId), stationPosition(toId), mode);
    const active = activeStationId === toId || likelyStationId === toId;
    const intensity = active ? 0.92 : mode === "flow" ? 0.58 : 0.34;
    return {
      key: `${fromId}-${toId}`,
      fromStationId: fromId,
      stationId: toId,
      points,
      leftEdgePoints: offsetPathPoints(points, 0.28 + intensity * 0.22),
      rightEdgePoints: offsetPathPoints(points, -0.28 - intensity * 0.22),
      waypointPositions: [0.2, 0.52, 0.82].map((t) => {
        const curve = new THREE.CatmullRomCurve3(points.map((point) => new THREE.Vector3(...point)));
        return toTuple(curve.getPointAt(t));
      }),
      colorHex: STATION_COLORS[toId],
      opacity: mode === "flow" ? 0.16 + intensity * 0.14 : 0.08 + intensity * 0.1,
      intensity,
      active,
      convoyCount: 3 + (active ? 2 : 0),
      showPulse: mode === "flow",
      corridorRadius: mode === "flow" ? 0.26 + intensity * 0.12 : 0.18 + intensity * 0.08,
      corridorOpacity: mode === "flow" ? 0.08 + intensity * 0.08 : 0.04 + intensity * 0.05,
      glowRadius: mode === "flow" ? 0.46 + intensity * 0.12 : 0.32 + intensity * 0.08,
    };
  });
}

function deriveHypothesisScaffolds(
  stations: HuntObservatorySceneState["stations"],
  likelyStationId: HuntStationId | null,
  confidence: number,
  receiveState: HuntObservatoryReceiveState,
): ObservatoryHypothesisScaffoldRecipe[] {
  const ranked = [...stations]
    .filter((station) => station.id !== "watch")
    .sort((left, right) => right.emphasis - left.emphasis);
  const primaryId = likelyStationId ?? ranked[0]?.id ?? null;
  if (!primaryId) return [];
  const primaryState = ranked.find((station) => station.id === primaryId) ?? null;
  const supporting = ranked.filter((station) => station.id !== primaryId).slice(0, 2);
  if (!primaryState || supporting.length === 0) return [];

  const core = new THREE.Vector3(0, 2.2, 0);
  const crown = new THREE.Vector3(0, 5 + confidence * 2.4, 0);
  const primary = stationPosition(primaryId).setY(3 + primaryState.emphasis * 1.5);
  const supportA = stationPosition(supporting[0].id).setY(2.5 + supporting[0].emphasis);
  const supportB =
    supporting[1] != null
      ? stationPosition(supporting[1].id).setY(2.2 + supporting[1].emphasis * 0.8)
      : supportA.clone().lerp(new THREE.Vector3(0, 2.4, 0), 0.45);
  const supportWeight =
    (supporting.reduce((sum, station) => sum + station.emphasis + station.affinity * 0.4, 0) /
      supporting.length) || 0;
  const intensity =
    0.24 + confidence * 0.22 + (receiveState === "receiving" ? 0.08 : receiveState === "aftermath" ? 0.04 : 0);
  const stage: ObservatoryHypothesisScaffoldRecipe["stage"] =
    confidence < 0.34
      ? "weakening"
      : supportWeight > 1.05 || primaryId === "case-notes"
        ? "stabilizing"
        : supportWeight > 0.74
          ? "branched"
          : "forming";
  const branchPaths =
    stage === "branched" || stage === "stabilizing"
      ? [
          buildLanePoints(core.clone().lerp(crown, 0.18), supportA, "atlas"),
          buildLanePoints(crown.clone().lerp(primary, 0.18), supportB, "atlas"),
        ]
      : [];
  const lockPositions =
    stage === "stabilizing"
      ? [toTuple(primary), toTuple(supportA), toTuple(crown)]
      : stage === "weakening"
        ? [toTuple(core)]
        : [];

  return [
    {
      key: `scaffold-${primaryId}`,
      primaryStationId: primaryId,
      supportingStationIds: supporting.map((station) => station.id),
      colorHex: STATION_COLORS[primaryId],
      stage,
      frameLoops: [
        [core, primary, crown, supportA, core].map(toTuple),
        [core.clone().lerp(crown, 0.22), supportB, crown, primary.clone().lerp(crown, 0.24), core.clone().lerp(crown, 0.22)].map(toTuple),
      ],
      conduitPaths: [
        buildLanePoints(core, primary, "atlas"),
        buildLanePoints(primary, supportA, "atlas"),
        buildLanePoints(supportA, supportB, "atlas"),
      ],
      branchPaths,
      nodes: [
        { position: toTuple(core), radius: 0.12, opacity: 0.24 + intensity * 0.18 },
        { position: toTuple(primary), radius: 0.16, opacity: 0.26 + intensity * 0.2 },
        { position: toTuple(supportA), radius: 0.12, opacity: 0.22 + intensity * 0.16 },
        { position: toTuple(supportB), radius: 0.1, opacity: 0.2 + intensity * 0.14 },
        { position: toTuple(crown), radius: 0.18, opacity: 0.28 + intensity * 0.2 },
      ],
      lockPositions,
      panels: [
        {
          position: toTuple(core.clone().lerp(primary, 0.48)),
          rotation: [-0.34, 0.28, 0.12],
          scale: [1.6 + intensity * 0.9, 1.1 + intensity * 0.6, 1],
          opacity: 0.05 + intensity * 0.08,
        },
        {
          position: toTuple(primary.clone().lerp(supportA, 0.46)),
          rotation: [-0.2, -0.32, 0.18],
          scale: [1.2 + intensity * 0.8, 0.9 + intensity * 0.5, 1],
          opacity: 0.04 + intensity * 0.07,
        },
        {
          position: toTuple(crown.clone().lerp(primary, 0.36)),
          rotation: [0.18, 0.14, 0],
          scale: [1 + intensity * 0.7, 0.72 + intensity * 0.42, 1],
          opacity: 0.04 + intensity * 0.06,
        },
      ],
      intensity,
    },
  ];
}

function deriveWatchfieldRecipe(
  watchState: HuntObservatorySceneState["stations"][number] | null,
  active: boolean,
): ObservatoryWatchfieldRecipe {
  const emphasis = watchState?.emphasis ?? 0;
  return {
    colorHex: STATION_COLORS.watch,
    position: toTuple(stationPosition("watch")),
    ringPoints: buildPerimeterRing(),
    emphasis,
    active,
    perimeterInnerRadius: WATCHFIELD_RADIUS - 1.2,
    perimeterOuterRadius: WATCHFIELD_RADIUS + 0.8,
    perimeterOpacity: 0.05 + emphasis * 0.08,
    beaconRadius: 1.02,
    beaconOpacity: active ? 0.92 : 0.58,
    secondaryRingInnerRadius: 1.12,
    secondaryRingOuterRadius: 1.42,
    secondaryRingOpacity: 0.28 + emphasis * 0.24,
  };
}

function deriveCoreRecipe(
  spirit: ObservatorySpiritVisual,
  receiveState: HuntObservatoryReceiveState,
): ObservatoryCoreRecipe {
  return {
    accentColor: spirit?.accentColor ?? "#d8c895",
    receiveState,
    haloRadius: 4.6,
    haloOpacity: 0.12,
    outerRingInnerRadius: 5.4,
    outerRingOuterRadius: 6.2,
    outerRingOpacity: 0.04,
    torusRadius: 3.1,
    torusTubeRadius: 0.12,
    torusEmissiveIntensity: 0.42,
    shellRadius: 1.26,
    shellOpacity: 0.96,
    pedestalTopRadius: 0.3,
    pedestalBottomRadius: 0.54,
    pedestalHeight: 1.8,
  };
}

export function deriveObservatoryWorld(input: {
  mode: HuntObservatoryMode;
  sceneState: HuntObservatorySceneState | null;
  activeStationId: HuntStationId | null;
  spirit?: ObservatorySpiritVisual;
}): DerivedObservatoryWorld {
  const { mode, sceneState, activeStationId, spirit = null } = input;
  const modeProfile = deriveModeProfile(mode);
  const stationStateMap = new Map((sceneState?.stations ?? []).map((station) => [station.id, station] as const));
  const stations = sceneState?.stations ?? [];
  const likelyStationId = sceneState?.likelyStationId ?? spirit?.likelyStationId ?? null;
  const focusStationId = activeStationId ?? likelyStationId;
  const receiveState = sceneState?.roomReceiveState ?? "idle";
  const heroProps = deriveHeroProps();

  return {
    environment: {
      backgroundColor: mode === "flow" ? "#02050c" : "#03060d",
      fogColor: mode === "flow" ? "#02050c" : "#03060d",
      fogNear: mode === "flow" ? 30 : 34,
      fogFar: mode === "flow" ? 78 : 86,
      ambientColor: mode === "flow" ? "#8ab1f0" : "#94b8ff",
      ambientIntensity: mode === "flow" ? 0.34 : 0.38,
      directionalLightPosition: mode === "flow" ? [10, 14, 7] : [12, 16, 10],
      directionalLightColor: "#f3f7ff",
      directionalLightIntensity: mode === "flow" ? 0.92 : 1.04,
      pointLightPosition: mode === "flow" ? [-12, 9, -6] : [-16, 10, -8],
      pointLightColor: mode === "flow" ? "#5ac2ff" : "#54b7ff",
      pointLightIntensity: mode === "flow" ? 0.82 : 0.66,
      starsRadius: 110,
      starsDepth: 56,
      starsCount: 900,
      starsFactor: 4,
      floorRadius: 46,
      gridSize: WORLD_GRID_SIZE,
      gridDivisions: 40,
      floorOpacity: mode === "flow" ? 0.9 : 0.84,
    },
    camera: deriveCameraRecipe(mode, focusStationId, heroProps),
    likelyStationId,
    receiveState,
    modeProfile,
    core: deriveCoreRecipe(spirit, receiveState),
    districts: HUNT_PRIMARY_STATION_ORDER.map((stationId) =>
      deriveDistrictRecipe(
        stationId,
        stationStateMap.get(stationId) ?? null,
        activeStationId,
        likelyStationId,
        mode,
        modeProfile,
      ),
    ),
    coreLinks: deriveCoreLinks(mode),
    transitLinks: deriveTransitLinks(mode, activeStationId, likelyStationId),
    hypothesisScaffolds: deriveHypothesisScaffolds(stations, likelyStationId, sceneState?.confidence ?? 0, receiveState),
    heroProps,
    watchfield: deriveWatchfieldRecipe(stationStateMap.get("watch") ?? null, activeStationId === "watch"),
  };
}
