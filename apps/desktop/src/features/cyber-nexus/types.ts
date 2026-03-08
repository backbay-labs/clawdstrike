import type {
  AttackChain,
  DashboardAuditEvent,
  DashboardThreat,
  NetworkEdge,
  NetworkNode,
  Threat,
} from "@backbay/glia-three/three";
import type { SecurityKPIs } from "@/services/socDataService";
import type { MarketplacePolicyDto, Workflow } from "@/services/tauri";

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
export type NexusOperationMode = "observe" | "trace" | "contain" | "execute";

export type NexusEscLayer =
  | "search"
  | "context-menu"
  | "layout-dropdown"
  | "drawer"
  | "carousel-focus"
  | "expanded"
  | "selection";

export interface NexusHudState {
  viewMode: NexusViewMode;
  fieldVisible: boolean;
  layoutDropdownOpen: boolean;
  detailPanelOpen: boolean;
}

export interface NexusSelectionState {
  activeStrikecellId: StrikecellDomainId | null;
  selectedNodeIds: string[];
  focusedNodeId: string | null;
  expandedStrikecellIds: StrikecellDomainId[];
}

export interface StrikecellSourceSnapshot {
  connected: boolean;
  threats: Threat[];
  attacks: AttackChain[];
  network: { nodes: NetworkNode[]; edges: NetworkEdge[] };
  overview: {
    threats: DashboardThreat[];
    auditEvents: DashboardAuditEvent[];
    kpis: SecurityKPIs;
  } | null;
  workflows: Workflow[];
  marketplacePolicies: MarketplacePolicyDto[];
}

export interface NexusGraph {
  nodes: StrikecellNode[];
  connections: StrikecellConnection[];
}
