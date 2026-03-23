// Per-station interior configuration data for station interior zones.
// Defines geometry, accent colors, NPC placements, and hero prop layout for each of the 6 stations.

import type { HuntStationId } from "./types";
import type { ObservatoryHeroPropAssetId } from "./propAssets";

export interface InteriorNpcPlacement {
  position: [number, number, number]; // local offset from room center
  poseLabel: string; // e.g. "typing", "examining", "patrolling" — cosmetic label
}

export interface InteriorPropMesh {
  type: "box" | "cylinder" | "torus" | "cone";
  args: number[]; // geometry constructor args
  position: [number, number, number];
  rotation?: [number, number, number];
  color: string;
  emissive?: string;
  emissiveIntensity?: number;
}

export interface StationInteriorConfig {
  stationId: HuntStationId;
  label: string;
  accentColor: string; // hex color for wall accents + point light
  roomSize: [number, number, number]; // width, height, depth
  wallColor: string; // base wall material color
  props: InteriorPropMesh[]; // 2-3 unique prop meshes per station
  npcs: InteriorNpcPlacement[]; // 3 NPCs per station
  heroPropAssetId: ObservatoryHeroPropAssetId;
  heroPropPosition: [number, number, number]; // local position within room
  lightIntensity: number; // per-station point light intensity
}

export const STATION_INTERIOR_CONFIGS: Record<HuntStationId, StationInteriorConfig> = {
  // Radar Room — blue accent
  signal: {
    stationId: "signal",
    label: "Horizon",
    accentColor: "#1a5fb4",
    roomSize: [20, 8, 20],
    wallColor: "#0d1a2d",
    props: [
      {
        type: "torus",
        args: [1.5, 0.12, 8, 24],
        position: [3, 3, -5],
        color: "#1a5fb4",
        emissive: "#1a5fb4",
        emissiveIntensity: 0.5,
      },
      {
        type: "cylinder",
        args: [0.08, 0.08, 4, 6],
        position: [-4, 2, -6],
        color: "#3a7fd4",
        emissive: "#1a5fb4",
        emissiveIntensity: 0.3,
      },
      {
        type: "cylinder",
        args: [0.08, 0.08, 4, 6],
        position: [5, 2, -7],
        color: "#3a7fd4",
        emissive: "#1a5fb4",
        emissiveIntensity: 0.3,
      },
    ],
    npcs: [
      { position: [2, 0.3, 3], poseLabel: "monitoring" },
      { position: [-3, 0.3, 2], poseLabel: "scanning" },
      { position: [0, 0.3, -3], poseLabel: "patrolling" },
    ],
    heroPropAssetId: "signal-dish-tower",
    heroPropPosition: [0, 0.5, 0],
    lightIntensity: 1.5,
  },

  // Lattice Grid Room — green accent
  targets: {
    stationId: "targets",
    label: "Subjects",
    accentColor: "#3dbf84",
    roomSize: [20, 8, 20],
    wallColor: "#0d2d1a",
    props: [
      {
        type: "box",
        args: [4, 0.1, 4],
        position: [0, 4, -5],
        color: "#3dbf84",
        emissive: "#3dbf84",
        emissiveIntensity: 0.4,
      },
      {
        type: "box",
        args: [1.5, 1.2, 0.8],
        position: [-4, 0.6, -3],
        color: "#2a8a5c",
        emissive: "#3dbf84",
        emissiveIntensity: 0.2,
      },
    ],
    npcs: [
      { position: [3, 0.3, 2], poseLabel: "analyzing" },
      { position: [-2, 0.3, 4], poseLabel: "typing" },
      { position: [1, 0.3, -4], poseLabel: "examining" },
    ],
    heroPropAssetId: "subjects-lattice-anchor",
    heroPropPosition: [0, 0.5, 0],
    lightIntensity: 1.5,
  },

  // Operations Console Room — amber accent
  run: {
    stationId: "run",
    label: "Operations",
    accentColor: "#d4a84b",
    roomSize: [20, 8, 20],
    wallColor: "#2d2210",
    props: [
      {
        type: "torus",
        args: [1.2, 0.1, 8, 24],
        position: [3, 3, 0],
        color: "#d4a84b",
        emissive: "#d4a84b",
        emissiveIntensity: 0.5,
      },
      {
        type: "torus",
        args: [1.0, 0.1, 8, 24],
        position: [-3, 4, 0],
        color: "#d4a84b",
        emissive: "#d4a84b",
        emissiveIntensity: 0.5,
      },
      {
        type: "box",
        args: [2, 1, 1],
        position: [0, 0.5, -6],
        color: "#8a6a2c",
        emissive: "#d4a84b",
        emissiveIntensity: 0.2,
      },
    ],
    npcs: [
      { position: [4, 0.3, 3], poseLabel: "operating" },
      { position: [-3, 0.3, -2], poseLabel: "monitoring" },
      { position: [1, 0.3, 5], poseLabel: "calibrating" },
    ],
    heroPropAssetId: "operations-scan-rig",
    heroPropPosition: [0, 0.5, 0],
    lightIntensity: 1.5,
  },

  // Vault Room — gold accent
  receipts: {
    stationId: "receipts",
    label: "Evidence",
    accentColor: "#c8a22c",
    roomSize: [20, 8, 20],
    wallColor: "#2d2a10",
    props: [
      {
        type: "box",
        args: [3, 4, 0.3],
        position: [0, 2, -9.5],
        color: "#c8a22c",
        emissive: "#c8a22c",
        emissiveIntensity: 0.3,
      },
      {
        type: "box",
        args: [6, 3, 0.4],
        position: [-8, 1.5, 0],
        rotation: [0, Math.PI / 2, 0],
        color: "#8a6a1c",
        emissive: "#c8a22c",
        emissiveIntensity: 0.15,
      },
    ],
    npcs: [
      { position: [3, 0.3, 3], poseLabel: "cataloging" },
      { position: [-5, 0.3, -2], poseLabel: "verifying" },
      { position: [2, 0.3, -5], poseLabel: "archiving" },
    ],
    heroPropAssetId: "evidence-vault-rack",
    heroPropPosition: [0, 0.5, 0],
    lightIntensity: 1.5,
  },

  // Judgment Chamber — purple accent
  "case-notes": {
    stationId: "case-notes",
    label: "Judgment",
    accentColor: "#7b68ee",
    roomSize: [20, 8, 20],
    wallColor: "#1a102d",
    props: [
      {
        type: "cylinder",
        args: [2, 2, 0.3, 16],
        position: [0, 0.15, 0],
        color: "#4a3a8a",
        emissive: "#7b68ee",
        emissiveIntensity: 0.2,
      },
      {
        type: "cylinder",
        args: [0.3, 0.3, 3, 8],
        position: [0, 1.8, 0],
        color: "#7b68ee",
        emissive: "#7b68ee",
        emissiveIntensity: 0.8,
      },
    ],
    npcs: [
      { position: [4, 0.3, 4], poseLabel: "deliberating" },
      { position: [-4, 0.3, -3], poseLabel: "reviewing" },
      { position: [0, 0.3, 6], poseLabel: "presenting" },
    ],
    heroPropAssetId: "judgment-dais",
    heroPropPosition: [0, 0.5, 0],
    lightIntensity: 1.5,
  },

  // Sentinel Beacon Room — red accent
  watch: {
    stationId: "watch",
    label: "Watchfield",
    accentColor: "#c45c5c",
    roomSize: [20, 8, 20],
    wallColor: "#2d1010",
    props: [
      {
        type: "cylinder",
        args: [0.8, 0.8, 5, 12],
        position: [0, 2.5, 0],
        color: "#c45c5c",
        emissive: "#c45c5c",
        emissiveIntensity: 0.7,
      },
      {
        type: "box",
        args: [2, 1.5, 0.1],
        position: [6, 2, -3],
        rotation: [0, -Math.PI / 6, 0],
        color: "#8a3c3c",
        emissive: "#c45c5c",
        emissiveIntensity: 0.3,
      },
      {
        type: "box",
        args: [2, 1.5, 0.1],
        position: [-6, 2, 3],
        rotation: [0, Math.PI / 6, 0],
        color: "#8a3c3c",
        emissive: "#c45c5c",
        emissiveIntensity: 0.3,
      },
    ],
    npcs: [
      { position: [3, 0.3, -4], poseLabel: "monitoring" },
      { position: [-4, 0.3, 3], poseLabel: "alerting" },
      { position: [5, 0.3, 5], poseLabel: "surveilling" },
    ],
    heroPropAssetId: "watchfield-sentinel-beacon",
    heroPropPosition: [0, 0.5, 0],
    lightIntensity: 1.5,
  },
};
