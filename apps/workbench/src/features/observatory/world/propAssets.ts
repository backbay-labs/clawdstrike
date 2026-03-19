// Ported from huntronomer apps/desktop/src/features/hunt-observatory/world/propAssets.ts
// All GLB assets are marked availability: "slot" for Phase 3 — uses fallback procedural geometry only.
// GLB asset loading is deferred (huntronomer assets not available in workbench public folder).

export type ObservatoryHeroPropAssetId =
  | "signal-dish-tower"
  | "subjects-lattice-anchor"
  | "operations-scan-rig"
  | "evidence-vault-rack"
  | "judgment-dais"
  | "watchfield-sentinel-beacon"
  | "operator-drone";

export type ObservatoryHeroPropAvailability = "ready" | "slot";

export type ObservatoryHeroPropFallbackKind =
  | "tower-dish"
  | "lattice-anchor"
  | "scan-rig"
  | "vault-rack"
  | "judgment-dais"
  | "sentinel-beacon"
  | "operator-drone";

export interface ObservatoryHeroPropAssetDefinition {
  availability: ObservatoryHeroPropAvailability;
  fallbackKind: ObservatoryHeroPropFallbackKind;
  glowColor: string;
  url: string;
}

// All assets set to "slot" — fallback procedural geometry will be used (Phase 3 decision).
// Do not change availability to "ready" without adding GLBs to workbench public folder.
export const OBSERVATORY_HERO_PROP_ASSETS: Record<
  ObservatoryHeroPropAssetId,
  ObservatoryHeroPropAssetDefinition
> = {
  "signal-dish-tower": {
    availability: "slot",
    fallbackKind: "tower-dish",
    glowColor: "#7cc8ff",
    url: "/observatory-props/signal-dish-tower/signal-dish-tower.glb",
  },
  "subjects-lattice-anchor": {
    availability: "slot",
    fallbackKind: "lattice-anchor",
    glowColor: "#9df2dd",
    url: "/observatory-props/subjects-lattice-anchor/subjects-lattice-anchor.glb",
  },
  "operations-scan-rig": {
    availability: "slot",
    fallbackKind: "scan-rig",
    glowColor: "#f4d982",
    url: "/observatory-props/operations-scan-rig/operations-scan-rig.glb",
  },
  "evidence-vault-rack": {
    availability: "slot",
    fallbackKind: "vault-rack",
    glowColor: "#7ee6f2",
    url: "/observatory-props/evidence-vault-rack/evidence-vault-rack.glb",
  },
  "judgment-dais": {
    availability: "slot",
    fallbackKind: "judgment-dais",
    glowColor: "#f0b87b",
    url: "/observatory-props/judgment-dais/judgment-dais.glb",
  },
  "watchfield-sentinel-beacon": {
    availability: "slot",
    fallbackKind: "sentinel-beacon",
    glowColor: "#d3b56e",
    url: "/observatory-props/watchfield-sentinel-beacon/watchfield-sentinel-beacon.glb",
  },
  "operator-drone": {
    availability: "slot",
    fallbackKind: "operator-drone",
    glowColor: "#d8c895",
    url: "/observatory-props/operator-drone/operator-drone.glb",
  },
};
