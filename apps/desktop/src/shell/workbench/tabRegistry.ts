/**
 * Tab Registry - Maps TabKind to lazy React components for the workbench tab system.
 *
 * Sources lazy imports from the same React.lazy() calls used in plugins/registry.tsx.
 */
import React from "react";
import type { TabKind, TabState } from "./workbenchState";

export interface TabContentProps {
  tab: TabState;
  isActive: boolean;
  groupId: string;
}

export interface TabRegistryEntry {
  component: React.LazyExoticComponent<React.ComponentType<any>>;
  icon: string;
  defaultTitle: string;
  keepAlive: boolean;
}

// Lazy-loaded components — mirrors plugins/registry.tsx imports
const EventStreamView = React.lazy(() =>
  import("@/features/events/EventStreamView").then((m) => ({ default: m.EventStreamView })),
);
const NexusView = React.lazy(() =>
  import("@/features/forensics-river/ForensicsRiverView").then((m) => ({
    default: m.ForensicsRiverView,
  })),
);
const OperationsHubView = React.lazy(() =>
  import("@/features/operations/OperationsHubView").then((m) => ({ default: m.OperationsHubView })),
);
const PolicyViewerView = React.lazy(() =>
  import("@/features/policies/PolicyViewerView").then((m) => ({ default: m.PolicyViewerView })),
);
const PolicyTesterView = React.lazy(() =>
  import("@/features/policies/PolicyTesterView").then((m) => ({ default: m.PolicyTesterView })),
);
const SwarmMapView = React.lazy(() =>
  import("@/features/swarm/SwarmMapView").then((m) => ({ default: m.SwarmMapView })),
);
const MarketplaceView = React.lazy(() =>
  import("@/features/marketplace/MarketplaceView").then((m) => ({ default: m.MarketplaceView })),
);
const WorkflowsView = React.lazy(() =>
  import("@/features/workflows/WorkflowsView").then((m) => ({ default: m.WorkflowsView })),
);
const ThreatRadarView = React.lazy(() =>
  import("@/features/threat-radar/ThreatRadarView").then((m) => ({ default: m.ThreatRadarView })),
);
const AttackGraphView = React.lazy(() =>
  import("@/features/attack-graph/AttackGraphView").then((m) => ({ default: m.AttackGraphView })),
);
const NetworkMapView = React.lazy(() =>
  import("@/features/network-map/NetworkMapView").then((m) => ({ default: m.NetworkMapView })),
);
const SecurityOverviewView = React.lazy(() =>
  import("@/features/security-overview/SecurityOverviewView").then((m) => ({
    default: m.SecurityOverviewView,
  })),
);
const WorkspaceShellScreen = React.lazy(() =>
  import("@/features/workspace/shell/WorkspaceShellScreen").then((m) => ({
    default: m.WorkspaceShellScreen,
  })),
);
const SpiritChamberTab = React.lazy(() =>
  import("@/shell/workbench/spirit-ritual/SpiritChamberTab").then((m) => ({
    default: m.SpiritChamberTab,
  })),
);

// Placeholder for individual file tabs (Phase 2 workspace integration)
function FileTabPlaceholder() {
  return React.createElement("div", {
    className: "flex items-center justify-center h-full text-sdr-text-muted",
  }, "File editor — coming in workspace integration");
}
const FilePlaceholder = React.lazy(() =>
  Promise.resolve({ default: FileTabPlaceholder as React.ComponentType<any> }),
);

// Welcome/empty state placeholder (rendered by TabContentRenderer for zero-tab state)
function WelcomeTabPlaceholder() {
  return null;
}
const WelcomePlaceholder = React.lazy(() =>
  Promise.resolve({ default: WelcomeTabPlaceholder as React.ComponentType<any> }),
);

export const TAB_REGISTRY: Record<TabKind, TabRegistryEntry> = {
  "signal-thread": {
    component: EventStreamView,
    icon: "activity",
    defaultTitle: "Event Stream",
    keepAlive: true,
  },
  hunt: {
    component: NexusView,
    icon: "nexus",
    defaultTitle: "Hunt Deck",
    keepAlive: true,
  },
  receipt: {
    component: EventStreamView,
    icon: "shield",
    defaultTitle: "Receipt",
    keepAlive: true,
  },
  case: {
    component: NexusView,
    icon: "folder",
    defaultTitle: "Case",
    keepAlive: true,
  },
  sandbox: {
    component: PolicyTesterView,
    icon: "beaker",
    defaultTitle: "Policy Tester",
    keepAlive: true,
  },
  artifact: {
    component: WorkspaceShellScreen,
    icon: "folder",
    defaultTitle: "Workspace",
    keepAlive: true,
  },
  brief: {
    component: SecurityOverviewView,
    icon: "dashboard",
    defaultTitle: "Security Overview",
    keepAlive: true,
  },
  profile: {
    component: SwarmMapView,
    icon: "network",
    defaultTitle: "Swarm Map",
    keepAlive: false,
  },
  policy: {
    component: PolicyViewerView,
    icon: "shield",
    defaultTitle: "Policy Viewer",
    keepAlive: true,
  },
  "threat-radar": {
    component: ThreatRadarView,
    icon: "radar",
    defaultTitle: "Threat Radar",
    keepAlive: false,
  },
  "attack-graph": {
    component: AttackGraphView,
    icon: "graph",
    defaultTitle: "Attack Graph",
    keepAlive: false,
  },
  "network-map": {
    component: NetworkMapView,
    icon: "topology",
    defaultTitle: "Network Map",
    keepAlive: false,
  },
  workflow: {
    component: WorkflowsView,
    icon: "workflow",
    defaultTitle: "Workflows",
    keepAlive: true,
  },
  marketplace: {
    component: MarketplaceView,
    icon: "store",
    defaultTitle: "Marketplace",
    keepAlive: true,
  },
  operations: {
    component: OperationsHubView,
    icon: "dashboard",
    defaultTitle: "Operations",
    keepAlive: true,
  },
  "spirit-chamber": {
    component: SpiritChamberTab,
    icon: "spirit",
    defaultTitle: "Spirit",
    keepAlive: true,
  },
  file: {
    component: FilePlaceholder,
    icon: "folder",
    defaultTitle: "File",
    keepAlive: true,
  },
  note: {
    component: FilePlaceholder,
    icon: "document",
    defaultTitle: "Note",
    keepAlive: true,
  },
  welcome: {
    component: WelcomePlaceholder,
    icon: "nexus",
    defaultTitle: "Welcome",
    keepAlive: false,
  },
};

export function getTabRegistryEntry(kind: TabKind): TabRegistryEntry | undefined {
  return TAB_REGISTRY[kind];
}
