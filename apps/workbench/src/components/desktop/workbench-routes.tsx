import { lazy, Suspense } from "react";
import { Navigate, type RouteObject } from "react-router-dom";

const PolicyEditor = lazy(() =>
  import("@/components/workbench/editor/policy-editor").then((m) => ({
    default: m.PolicyEditor,
  })),
);

const LabLayout = lazy(() =>
  import("@/components/workbench/lab/lab-layout").then((m) => ({
    default: m.LabLayout,
  })),
);

const HuntLayout = lazy(() =>
  import("@/components/workbench/hunt/hunt-layout").then((m) => ({
    default: m.HuntLayout,
  })),
);

const SimulatorLayout = lazy(() =>
  import("@/components/workbench/simulator/simulator-layout").then((m) => ({
    default: m.SimulatorLayout,
  })),
);

const SwarmBoardPage = lazy(() =>
  import("@/components/workbench/swarm-board/swarm-board-page"),
);

const TopologyLayout = lazy(() =>
  import("@/components/workbench/topology/topology-layout").then((m) => ({
    default: m.TopologyLayout,
  })),
);

const ComplianceDashboard = lazy(() =>
  import("@/components/workbench/compliance/compliance-dashboard").then(
    (m) => ({ default: m.ComplianceDashboard }),
  ),
);

const ReceiptInspector = lazy(() =>
  import("@/components/workbench/receipts/receipt-inspector").then((m) => ({
    default: m.ReceiptInspector,
  })),
);

const LibraryGallery = lazy(() =>
  import("@/components/workbench/library/library-gallery").then((m) => ({
    default: m.LibraryGallery,
  })),
);

const SettingsPage = lazy(() =>
  import("@/components/workbench/settings/settings-page").then((m) => ({
    default: m.SettingsPage,
  })),
);

const ApprovalQueue = lazy(() =>
  import("@/components/workbench/approvals/approval-queue").then((m) => ({
    default: m.ApprovalQueue,
  })),
);

const FleetDashboard = lazy(() =>
  import("@/components/workbench/fleet/fleet-dashboard").then((m) => ({
    default: m.FleetDashboard,
  })),
);

const AuditLog = lazy(() =>
  import("@/components/workbench/audit/audit-log").then((m) => ({
    default: m.AuditLog,
  })),
);

const HomePage = lazy(() =>
  import("@/components/workbench/home/home-page").then((m) => ({
    default: m.HomePage,
  })),
);

const SentinelsPage = lazy(() =>
  import("@/components/workbench/sentinel-swarm-pages").then((m) => ({
    default: m.SentinelsPage,
  })),
);

const SentinelCreatePage = lazy(() =>
  import("@/components/workbench/sentinel-swarm-pages").then((m) => ({
    default: m.SentinelCreatePage,
  })),
);

const SentinelDetailPage = lazy(() =>
  import("@/components/workbench/sentinel-swarm-pages").then((m) => ({
    default: m.SentinelDetailPage,
  })),
);

const FindingsPage = lazy(() =>
  import("@/components/workbench/sentinel-swarm-pages").then((m) => ({
    default: m.FindingsPage,
  })),
);

const FindingDetailPage = lazy(() =>
  import("@/components/workbench/sentinel-swarm-pages").then((m) => ({
    default: m.FindingDetailPage,
  })),
);

const IntelDetailPage = lazy(() =>
  import("@/components/workbench/sentinel-swarm-pages").then((m) => ({
    default: m.IntelDetailPage,
  })),
);

const SwarmPage = lazy(() =>
  import("@/components/workbench/swarms/swarm-page").then((m) => ({
    default: m.SwarmPage,
  })),
);

const SwarmDetail = lazy(() =>
  import("@/components/workbench/swarms/swarm-detail").then((m) => ({
    default: m.SwarmDetail,
  })),
);

const MissionControlPage = lazy(() =>
  import("@/components/workbench/missions/mission-control-page").then((m) => ({
    default: m.MissionControlPage,
  })),
);

const SpiritChamberTab = lazy(() =>
  import("@/features/spirit/components/spirit-chamber-tab").then((m) => ({
    default: m.SpiritChamberTab,
  })),
);

const ObservatoryTab = lazy(() =>
  import("@/features/observatory/components/ObservatoryTab").then((m) => ({
    default: m.ObservatoryTab,
  })),
);

const NexusTab = lazy(() =>
  import("@/features/nexus/components/NexusTab").then((m) => ({
    default: m.NexusTab,
  })),
);

function PlaceholderPane({ label }: { label: string }) {
  return (
    <div className="flex flex-1 items-center justify-center text-[#6f7f9a] text-sm font-mono">
      {label} — coming in a later phase
    </div>
  );
}

function parseRoute(route: string): URL {
  const normalized = route.startsWith("/") ? route : `/${route}`;
  return new URL(normalized, "https://clawdstrike.local");
}

export function normalizeWorkbenchRoute(route: string): string {
  const url = parseRoute(route);

  switch (url.pathname) {
    case "/":
    case "/overview":
      return "/home";
    case "/intel":
      return "/findings?tab=intel";
    case "/guards":
      return "/editor?panel=guards";
    case "/compare":
      return "/editor?panel=compare";
    case "/delegation":
      return "/topology?tab=delegation";
    case "/hierarchy":
      return "/topology?tab=hierarchy";
    default:
      return `${url.pathname}${url.search}` || "/home";
  }
}

export function getWorkbenchRouteLabel(route: string): string {
  const url = parseRoute(normalizeWorkbenchRoute(route));

  if (url.pathname === "/home") return "Home";
  if (url.pathname === "/editor") {
    const panel = url.searchParams.get("panel");
    if (panel === "guards") return "Guards";
    if (panel === "compare") return "Compare";
    return "Editor";
  }
  if (url.pathname === "/swarm-board") return "Swarm Board";
  if (url.pathname === "/hunt") return "Hunt";
  if (url.pathname === "/simulator") return "Simulator";
  if (url.pathname === "/lab") {
    const tab = url.searchParams.get("tab");
    if (tab === "hunt") return "Hunt";
    if (tab === "simulate") return "Simulator";
    return "Lab";
  }
  if (url.pathname === "/topology") {
    const tab = url.searchParams.get("tab");
    if (tab === "delegation") return "Delegation";
    if (tab === "hierarchy") return "Hierarchy";
    return "Topology";
  }
  if (url.pathname === "/sentinels/create") return "New Sentinel";
  if (url.pathname.startsWith("/sentinels/")) return "Sentinel";
  if (url.pathname === "/sentinels") return "Sentinels";
  if (url.pathname.startsWith("/findings/")) return "Finding";
  if (url.pathname === "/findings") return "Findings";
  if (url.pathname.startsWith("/intel/")) return "Intel";
  if (url.pathname.startsWith("/swarms/")) return "Swarm";
  if (url.pathname === "/swarms") return "Swarms";
  if (url.pathname === "/missions") return "Mission Control";
  if (url.pathname === "/compliance") return "Compliance";
  if (url.pathname === "/receipts") return "Receipts";
  if (url.pathname === "/library") return "Library";
  if (url.pathname === "/settings") return "Settings";
  if (url.pathname === "/approvals") return "Approvals";
  if (url.pathname === "/fleet") return "Fleet";
  if (url.pathname === "/audit") return "Audit";
  if (url.pathname === "/observatory") return "Observatory";
  if (url.pathname === "/spirit-chamber") return "Spirit Chamber";
  if (url.pathname === "/nexus") return "Nexus";
  return "Workbench";
}

export const WORKBENCH_ROUTE_OBJECTS: RouteObject[] = [
  { index: true, element: <Navigate to="/home" replace /> },
  { path: "home", element: <HomePage /> },
  { path: "editor", element: <PolicyEditor /> },
  { path: "compliance", element: <ComplianceDashboard /> },
  { path: "receipts", element: <ReceiptInspector /> },
  { path: "library", element: <LibraryGallery /> },
  { path: "settings", element: <SettingsPage /> },
  { path: "approvals", element: <ApprovalQueue /> },
  { path: "fleet", element: <FleetDashboard /> },
  { path: "audit", element: <AuditLog /> },
  { path: "sentinels", element: <SentinelsPage /> },
  { path: "sentinels/create", element: <SentinelCreatePage /> },
  { path: "sentinels/:id", element: <SentinelDetailPage /> },
  { path: "findings", element: <FindingsPage /> },
  { path: "findings/:id", element: <FindingDetailPage /> },
  { path: "intel/:id", element: <IntelDetailPage /> },
  { path: "missions", element: <MissionControlPage /> },
  { path: "swarms", element: <SwarmPage /> },
  { path: "swarms/:id", element: <SwarmDetail /> },
  { path: "swarm-board", element: <Suspense fallback={<div className="flex-1" />}><SwarmBoardPage /></Suspense> },
  { path: "lab", element: <LabLayout /> },
  { path: "topology", element: <TopologyLayout /> },
  {
    path: "intel",
    element: (
      <Navigate
        to={{ pathname: "/findings", search: "?tab=intel" }}
        replace
      />
    ),
  },
  { path: "hunt", element: <Suspense fallback={<div className="flex-1" />}><HuntLayout /></Suspense> },
  { path: "simulator", element: <Suspense fallback={<div className="flex-1" />}><SimulatorLayout /></Suspense> },
  {
    path: "guards",
    element: (
      <Navigate
        to={{ pathname: "/editor", search: "?panel=guards" }}
        replace
      />
    ),
  },
  {
    path: "compare",
    element: (
      <Navigate
        to={{ pathname: "/editor", search: "?panel=compare" }}
        replace
      />
    ),
  },
  {
    path: "delegation",
    element: (
      <Navigate
        to={{ pathname: "/topology", search: "?tab=delegation" }}
        replace
      />
    ),
  },
  {
    path: "hierarchy",
    element: (
      <Navigate
        to={{ pathname: "/topology", search: "?tab=hierarchy" }}
        replace
      />
    ),
  },
  { path: "overview", element: <Navigate to="/home" replace /> },
  { path: "observatory", element: <Suspense fallback={<div className="flex-1" />}><ObservatoryTab /></Suspense> },
  { path: "spirit-chamber", element: <Suspense fallback={<div className="flex-1" />}><SpiritChamberTab /></Suspense> },
  { path: "nexus", element: <Suspense fallback={<div className="flex-1" />}><NexusTab /></Suspense> },
  { path: "*", element: <Navigate to="/home" replace /> },
];
