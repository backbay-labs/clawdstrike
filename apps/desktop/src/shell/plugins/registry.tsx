/**
 * Plugin Registry - SDR Desktop plugins
 */
import React from "react";
import type { AppPlugin, AppId } from "./types";

// Lazy loaded feature views
const EventStreamView = React.lazy(() =>
  import("@/features/events/EventStreamView").then((m) => ({ default: m.EventStreamView }))
);
const PolicyViewerView = React.lazy(() =>
  import("@/features/policies/PolicyViewerView").then((m) => ({ default: m.PolicyViewerView }))
);
const PolicyTesterView = React.lazy(() =>
  import("@/features/policies/PolicyTesterView").then((m) => ({ default: m.PolicyTesterView }))
);
const SwarmMapView = React.lazy(() =>
  import("@/features/swarm/SwarmMapView").then((m) => ({ default: m.SwarmMapView }))
);
const MarketplaceView = React.lazy(() =>
  import("@/features/marketplace/MarketplaceView").then((m) => ({ default: m.MarketplaceView }))
);
const WorkflowsView = React.lazy(() =>
  import("@/features/workflows/WorkflowsView").then((m) => ({ default: m.WorkflowsView }))
);
const SettingsView = React.lazy(() =>
  import("@/features/settings/SettingsView").then((m) => ({ default: m.SettingsView }))
);

// Plugin definitions
const plugins: AppPlugin[] = [
  {
    id: "events",
    name: "Event Stream",
    icon: "activity",
    description: "Real-time policy decisions and audit log",
    order: 1,
    routes: [{ path: "", element: <EventStreamView />, index: true }],
  },
  {
    id: "policies",
    name: "Policy Viewer",
    icon: "shield",
    description: "Browse and validate policies",
    order: 2,
    routes: [{ path: "", element: <PolicyViewerView />, index: true }],
  },
  {
    id: "policy-tester",
    name: "Policy Tester",
    icon: "beaker",
    description: "Simulate policy checks",
    order: 3,
    routes: [{ path: "", element: <PolicyTesterView />, index: true }],
  },
  {
    id: "swarm",
    name: "Swarm Map",
    icon: "network",
    description: "3D visualization of agent identities",
    order: 4,
    routes: [{ path: "", element: <SwarmMapView />, index: true }],
  },
  {
    id: "marketplace",
    name: "Marketplace",
    icon: "store",
    description: "Discover and share community policies",
    order: 5,
    routes: [{ path: "", element: <MarketplaceView />, index: true }],
  },
  {
    id: "workflows",
    name: "Workflows",
    icon: "workflow",
    description: "Automated response chains",
    order: 6,
    routes: [{ path: "", element: <WorkflowsView />, index: true }],
  },
  {
    id: "settings",
    name: "Settings",
    icon: "settings",
    description: "Daemon connection and preferences",
    order: 7,
    routes: [{ path: "", element: <SettingsView />, index: true }],
  },
];

// Sort by order
const sortedPlugins = [...plugins].sort((a, b) => a.order - b.order);

export function getPlugins(): AppPlugin[] {
  return sortedPlugins;
}

export function getPlugin(id: AppId): AppPlugin | undefined {
  return sortedPlugins.find((p) => p.id === id);
}
