/**
 * Plugin Registry - Huntronomer desktop plugins
 */
import React from "react";
import { getWorkspaceShellRoutes } from "@/features/workspace/shell";
import type { AppId, AppPlugin } from "./types";

// Lazy loaded feature views
const EventStreamView = React.lazy(() =>
  import("@/features/events/EventStreamView").then((m) => ({ default: m.EventStreamView })),
);
const NexusView = React.lazy(() =>
  import("@/features/forensics-river/ForensicsRiverView").then((m) => ({
    default: m.ForensicsRiverView,
  })),
);
const CyberNexusSceneView = React.lazy(() =>
  import("@/features/cyber-nexus/CyberNexusView").then((m) => ({
    default: m.CyberNexusView,
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

function createWorkspacePluginRoutes() {
  return getWorkspaceShellRoutes().map((route) => ({
    index: route.path === "/workspace",
    path: route.path === "/workspace" ? "" : route.path.replace(/^\/workspace\//, ""),
    element: route.element,
  }));
}

// Plugin definitions
const plugins: AppPlugin[] = [
  {
    id: "nexus",
    name: "Hunt Deck",
    icon: "nexus",
    description: "Autonomous threat hunting command surface",
    order: 1,
    tabKind: "hunt",
    singleton: true,
    routes: [
      { path: "", element: <NexusView />, index: true },
      { path: "scene", element: <CyberNexusSceneView /> },
      { path: ":sessionId", element: <NexusView /> },
    ],
  },
  {
    id: "workspace",
    name: "Workspace",
    icon: "folder",
    description: "Trusted roots, editor panes, terminal docks, and local authoring tools",
    order: 2,
    tabKind: "artifact",
    singleton: true,
    routes: createWorkspacePluginRoutes(),
  },
  {
    id: "operations",
    name: "Operations",
    icon: "dashboard",
    description: "Fleet management, daemon connection, and preferences",
    order: 3,
    tabKind: "operations",
    singleton: true,
    routes: [{ path: "", element: <OperationsHubView />, index: true }],
  },
  {
    id: "events",
    name: "Event Stream",
    icon: "activity",
    description: "Real-time policy decisions and audit log",
    order: 4,
    tabKind: "signal-thread",
    singleton: true,
    routes: [{ path: "", element: <EventStreamView />, index: true }],
  },
  {
    id: "policies",
    name: "Policy Viewer",
    icon: "shield",
    description: "Browse and validate policies",
    order: 5,
    tabKind: "policy",
    singleton: true,
    routes: [{ path: "", element: <PolicyViewerView />, index: true }],
  },
  {
    id: "policy-tester",
    name: "Policy Tester",
    icon: "beaker",
    description: "Simulate policy checks",
    order: 6,
    tabKind: "sandbox",
    singleton: true,
    routes: [{ path: "", element: <PolicyTesterView />, index: true }],
  },
  {
    id: "swarm",
    name: "Swarm Map",
    icon: "network",
    description: "3D visualization of agent identities",
    order: 7,
    tabKind: "profile",
    singleton: true,
    routes: [{ path: "", element: <SwarmMapView />, index: true }],
  },
  {
    id: "marketplace",
    name: "Marketplace",
    icon: "store",
    description: "Discover and share community policies",
    order: 8,
    tabKind: "marketplace",
    singleton: true,
    routes: [{ path: "", element: <MarketplaceView />, index: true }],
  },
  {
    id: "workflows",
    name: "Workflows",
    icon: "workflow",
    description: "Automated response chains",
    order: 9,
    tabKind: "workflow",
    singleton: true,
    routes: [{ path: "", element: <WorkflowsView />, index: true }],
  },
  {
    id: "threat-radar",
    name: "Threat Radar",
    icon: "radar",
    description: "Live 3D threat detection radar",
    order: 10,
    tabKind: "threat-radar",
    singleton: true,
    routes: [{ path: "", element: <ThreatRadarView />, index: true }],
  },
  {
    id: "attack-graph",
    name: "Attack Graph",
    icon: "graph",
    description: "MITRE ATT&CK chain visualization",
    order: 11,
    tabKind: "attack-graph",
    singleton: true,
    routes: [{ path: "", element: <AttackGraphView />, index: true }],
  },
  {
    id: "network-map",
    name: "Network Map",
    icon: "topology",
    description: "3D network infrastructure map",
    order: 12,
    tabKind: "network-map",
    singleton: true,
    routes: [{ path: "", element: <NetworkMapView />, index: true }],
  },
  {
    id: "security-overview",
    name: "Security Overview",
    icon: "dashboard",
    description: "Composite security monitoring",
    order: 13,
    tabKind: "brief",
    singleton: true,
    routes: [{ path: "", element: <SecurityOverviewView />, index: true }],
  },
];

// Sort by order
const sortedPlugins = [...plugins].sort((a, b) => a.order - b.order);

export function getPlugins(): AppPlugin[] {
  return sortedPlugins;
}

export function getVisiblePlugins(): AppPlugin[] {
  return sortedPlugins.filter((plugin) => !plugin.hidden);
}

export function getPlugin(id: AppId): AppPlugin | undefined {
  return sortedPlugins.find((p) => p.id === id);
}
