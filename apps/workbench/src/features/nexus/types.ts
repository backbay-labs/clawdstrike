// Ported from huntronomer apps/desktop/src/features/cyber-nexus/types.ts
// Removed: StrikecellSourceSnapshot (glia-three + tauri imports not available in workbench)
// Removed: NexusHudState, NexusSelectionState, NexusOperationMode, NexusEscLayer (full NexusStateContext types)
// Added: DEMO_STRIKECELLS, STRIKECELL_BY_STATION, STRIKECELL_ROUTE_MAP

import type { HuntStationId } from "@/features/observatory/world/types";

export type StrikecellStatus = "healthy" | "warning" | "critical" | "offline";

export type StrikecellDomainId =
  | "security-overview"
  | "threat-radar"
  | "attack-graph"
  | "network-map"
  | "workflows"
  | "marketplace"
  | "events"
  | "policies"
  | "forensics-river";

export interface StrikecellNode {
  id: string;
  strikecellId: StrikecellDomainId;
  label: string;
  kind: "threat" | "technique" | "host" | "workflow" | "policy" | "event" | "metric";
  severity: number;
  activity: number;
  meta?: Record<string, string | number | boolean>;
}

export interface StrikecellConnection {
  id: string;
  sourceId: StrikecellDomainId;
  targetId: StrikecellDomainId;
  kind: "data-flow" | "dependency" | "related";
  strength: number;
}

export interface Strikecell {
  id: StrikecellDomainId;
  name: string;
  routeId: string;
  description: string;
  status: StrikecellStatus;
  activityCount: number;
  nodeCount: number;
  nodes: StrikecellNode[];
  tags: string[];
}

export type NexusLayoutMode = "radial" | "typed-lanes" | "force-directed";
export type NexusViewMode = "galaxy" | "grid";

export interface NexusGraph {
  nodes: StrikecellNode[];
  connections: StrikecellConnection[];
}

// ---------------------------------------------------------------------------
// Demo data — all strikecells offline with no nodes (workbench has no live backend)
// ---------------------------------------------------------------------------

export const DEMO_STRIKECELLS: Strikecell[] = [
  {
    id: "security-overview",
    name: "Security Overview",
    routeId: "/home",
    description: "High-level security posture and key performance indicators",
    status: "offline",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: ["overview", "kpi"],
  },
  {
    id: "threat-radar",
    name: "Threat Radar",
    routeId: "/hunt",
    description: "Active threat detection and intelligence feeds",
    status: "offline",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: ["threats", "intel"],
  },
  {
    id: "attack-graph",
    name: "Attack Graph",
    routeId: "/hunt",
    description: "Visual representation of attack chains and lateral movement",
    status: "offline",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: ["attacks", "graph"],
  },
  {
    id: "network-map",
    name: "Network Map",
    routeId: "/topology",
    description: "Live network topology and asset inventory",
    status: "offline",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: ["network", "topology"],
  },
  {
    id: "workflows",
    name: "Workflows",
    routeId: "/lab",
    description: "Automated response and orchestration workflows",
    status: "offline",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: ["automation", "soar"],
  },
  {
    id: "marketplace",
    name: "Marketplace",
    routeId: "/library",
    description: "Policy templates, detection rules, and integrations",
    status: "offline",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: ["marketplace", "library"],
  },
  {
    id: "events",
    name: "Events",
    routeId: "/audit",
    description: "Security event log and audit trail",
    status: "offline",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: ["events", "audit"],
  },
  {
    id: "policies",
    name: "Policies",
    routeId: "/editor",
    description: "Security policy management and enforcement rules",
    status: "offline",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: ["policies", "rules"],
  },
  {
    id: "forensics-river",
    name: "Forensics River",
    routeId: "/audit",
    description: "Forensic evidence stream and investigation timeline",
    status: "offline",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: ["forensics", "timeline"],
  },
];

// ---------------------------------------------------------------------------
// Routing maps
// ---------------------------------------------------------------------------

/** Maps observatory station → strikecell domain (reverse lookup for onSelectStation). */
export const STRIKECELL_BY_STATION: Record<HuntStationId, StrikecellDomainId> = {
  signal: "security-overview",
  targets: "attack-graph",
  run: "network-map",
  receipts: "forensics-river",
  "case-notes": "policies",
  watch: "threat-radar",
};

/** Maps strikecell domain → workbench route for openApp navigation. */
export const STRIKECELL_ROUTE_MAP: Record<StrikecellDomainId, string> = {
  "security-overview": "/home",
  "threat-radar": "/hunt",
  "attack-graph": "/hunt",
  "network-map": "/topology",
  "forensics-river": "/audit",
  "policies": "/editor",
  "events": "/audit",
  "workflows": "/lab",
  "marketplace": "/library",
};
