import { lazy, Suspense } from "react";
import { Navigate, type RouteObject } from "react-router-dom";
import { FeatureErrorBoundary } from "@/components/ui/feature-error-boundary";

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

const ReceiptDetailPage = lazy(() =>
  import("@/components/workbench/swarm-board/receipt-detail-page").then((m) => ({
    default: m.ReceiptDetailPage,
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

const FleetAgentDetail = lazy(() =>
  import("@/components/workbench/fleet/fleet-agent-detail").then((m) => ({
    default: m.FleetAgentDetail,
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

const GuardsPage = lazy(() =>
  import("@/components/workbench/guards/guards-page").then((m) => ({
    default: m.GuardsPage,
  })),
);

const CompareLayout = lazy(() =>
  import("@/components/workbench/compare/compare-layout").then((m) => ({
    default: m.CompareLayout,
  })),
);

const LiveAgentTab = lazy(() =>
  import("@/components/workbench/editor/live-agent-tab").then((m) => ({
    default: m.LiveAgentTab,
  })),
);

const SdkIntegrationTab = lazy(() =>
  import("@/components/workbench/editor/sdk-integration-tab").then((m) => ({
    default: m.SdkIntegrationTab,
  })),
);

const MitreHeatmap = lazy(() =>
  import("@/components/workbench/coverage/mitre-heatmap").then((m) => ({
    default: m.MitreHeatmap,
  })),
);

const SigmaBuilderPage = lazy(() =>
  import("@/components/workbench/editor/visual-builder-pages").then((m) => ({
    default: m.SigmaBuilderPage,
  })),
);
const YaraBuilderPage = lazy(() =>
  import("@/components/workbench/editor/visual-builder-pages").then((m) => ({
    default: m.YaraBuilderPage,
  })),
);
const OcsfBuilderPage = lazy(() =>
  import("@/components/workbench/editor/visual-builder-pages").then((m) => ({
    default: m.OcsfBuilderPage,
  })),
);
const TrustprintPatternsPage = lazy(() =>
  import("@/components/workbench/editor/trustprint-pages").then((m) => ({
    default: m.TrustprintPatternsPage,
  })),
);
const TrustprintProvidersPage = lazy(() =>
  import("@/components/workbench/editor/trustprint-pages").then((m) => ({
    default: m.TrustprintProvidersPage,
  })),
);
const TrustprintThresholdsPage = lazy(() =>
  import("@/components/workbench/editor/trustprint-pages").then((m) => ({
    default: m.TrustprintThresholdsPage,
  })),
);

const FileEditorShell = lazy(() =>
  import("@/features/editor/file-editor-shell").then((m) => ({
    default: m.FileEditorShell,
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

const ReceiptPreviewTab = lazy(() =>
  import("@/features/evidence/components/ReceiptPreviewTab").then((m) => ({
    default: m.ReceiptPreviewTab,
  })),
);

function parseRoute(route: string): URL {
  const normalized = route.startsWith("/") ? route : `/${route}`;
  return new URL(normalized, "https://clawdstrike.local");
}

export function normalizeWorkbenchRoute(route: string): string {
  const url = parseRoute(route);

  // File routes pass through unchanged (they contain the actual file path)
  if (url.pathname.startsWith("/file/")) {
    return `${url.pathname}${url.search}` || "/home";
  }

  // Swarm board routes pass through unchanged (they contain the bundle path)
  if (url.pathname.startsWith("/swarm-board/")) {
    return `${url.pathname}${url.search}` || "/swarm-board";
  }

  // Redirect /editor?panel=guards and /editor?panel=compare to standalone routes
  // FLAT-08: /editor redirects to /home
  if (url.pathname === "/editor") {
    const panel = url.searchParams.get("panel");
    if (panel === "guards") return "/guards";
    if (panel === "compare") return "/compare";
    return "/home";
  }

  switch (url.pathname) {
    case "/":
    case "/overview":
      return "/home";
    case "/intel":
      return "/findings?tab=intel";
    case "/guards":
      return "/guards";
    case "/compare":
      return "/compare";
    case "/live-agent":
      return "/live-agent";
    case "/sdk-integration":
      return "/sdk-integration";
    case "/coverage":
      return "/coverage";
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
  if (url.pathname === "/guards") return "Guards";
  if (url.pathname === "/compare") return "Compare";
  if (url.pathname === "/live-agent") return "Live Agent";
  if (url.pathname === "/sdk-integration") return "SDK Integration";
  if (url.pathname === "/coverage") return "Coverage";
  if (url.pathname.startsWith("/swarm-board/")) {
    const segments = url.pathname.split("/").filter(Boolean);
    const last = segments[segments.length - 1];
    try {
      const decoded = decodeURIComponent(last);
      return decoded.replace(/\.swarm$/, "").split("/").pop() || "Swarm Board";
    } catch {
      return "Swarm Board";
    }
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
  if (url.pathname.startsWith("/receipt/")) return "Receipt " + (url.pathname.split("/").pop()?.slice(0, 8) ?? "");
  if (url.pathname === "/receipts") return "Receipts";
  if (url.pathname === "/library") return "Library";
  if (url.pathname === "/settings") return "Settings";
  if (url.pathname === "/approvals") return "Approvals";
  if (url.pathname.startsWith("/fleet/")) return url.pathname.split("/").pop() ?? "Agent";
  if (url.pathname === "/fleet") return "Fleet";
  if (url.pathname === "/audit") return "Audit";
  if (url.pathname === "/visual-builder/sigma") return "Sigma Builder";
  if (url.pathname === "/visual-builder/yara") return "YARA Builder";
  if (url.pathname === "/visual-builder/ocsf") return "OCSF Builder";
  if (url.pathname === "/trustprint/patterns") return "TrustPrint Patterns";
  if (url.pathname === "/trustprint/providers") return "TrustPrint Providers";
  if (url.pathname === "/trustprint/thresholds") return "TrustPrint Thresholds";
  if (url.pathname === "/observatory") return "Observatory";
  if (url.pathname === "/spirit-chamber") return "Spirit Chamber";
  if (url.pathname === "/nexus") return "Nexus";
  if (url.pathname === "/receipt-preview") return "Receipt Preview";
  if (url.pathname.startsWith("/file/")) {
    const segments = url.pathname.split("/").filter(Boolean);
    return segments[segments.length - 1] ?? "File";
  }
  return "Workbench";
}

export const WORKBENCH_ROUTE_OBJECTS: RouteObject[] = [
  { index: true, element: <Navigate to="/home" replace /> },
  { path: "home", element: <HomePage /> },
  { path: "editor", element: <Navigate to="/home" replace /> },
  { path: "compliance", element: <ComplianceDashboard /> },
  { path: "receipt/:id", element: <ReceiptDetailPage /> },
  { path: "receipts", element: <ReceiptInspector /> },
  { path: "library", element: <LibraryGallery /> },
  { path: "settings", element: <SettingsPage /> },
  { path: "approvals", element: <ApprovalQueue /> },
  { path: "fleet/:id", element: <FeatureErrorBoundary feature="Fleet Agent"><FleetAgentDetail /></FeatureErrorBoundary> },
  { path: "fleet", element: <FeatureErrorBoundary feature="Fleet Dashboard"><FleetDashboard /></FeatureErrorBoundary> },
  { path: "audit", element: <AuditLog /> },
  { path: "sentinels", element: <SentinelsPage /> },
  { path: "sentinels/create", element: <SentinelCreatePage /> },
  { path: "sentinels/:id", element: <SentinelDetailPage /> },
  { path: "findings", element: <FeatureErrorBoundary feature="Findings"><FindingsPage /></FeatureErrorBoundary> },
  { path: "findings/:id", element: <FeatureErrorBoundary feature="Finding Detail"><FindingDetailPage /></FeatureErrorBoundary> },
  { path: "intel/:id", element: <FeatureErrorBoundary feature="Intel Detail"><IntelDetailPage /></FeatureErrorBoundary> },
  { path: "missions", element: <MissionControlPage /> },
  { path: "swarms", element: <SwarmPage /> },
  { path: "swarms/:id", element: <SwarmDetail /> },
  { path: "swarm-board/*", element: <FeatureErrorBoundary feature="Swarm Board"><Suspense fallback={<div className="flex-1" />}><SwarmBoardPage /></Suspense></FeatureErrorBoundary> },
  { path: "swarm-board", element: <FeatureErrorBoundary feature="Swarm Board"><Suspense fallback={<div className="flex-1" />}><SwarmBoardPage /></Suspense></FeatureErrorBoundary> },
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
  { path: "guards", element: <GuardsPage /> },
  { path: "compare", element: <CompareLayout /> },
  { path: "live-agent", element: <LiveAgentTab /> },
  { path: "sdk-integration", element: <SdkIntegrationTab /> },
  { path: "coverage", element: <MitreHeatmap tabs={[]} /> },
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
  { path: "visual-builder/sigma", element: <SigmaBuilderPage /> },
  { path: "visual-builder/yara", element: <YaraBuilderPage /> },
  { path: "visual-builder/ocsf", element: <OcsfBuilderPage /> },
  { path: "trustprint/patterns", element: <TrustprintPatternsPage /> },
  { path: "trustprint/providers", element: <TrustprintProvidersPage /> },
  { path: "trustprint/thresholds", element: <TrustprintThresholdsPage /> },
  { path: "overview", element: <Navigate to="/home" replace /> },
  { path: "observatory", element: <Suspense fallback={<div className="flex-1" />}><ObservatoryTab /></Suspense> },
  { path: "spirit-chamber", element: <Suspense fallback={<div className="flex-1" />}><SpiritChamberTab /></Suspense> },
  { path: "nexus", element: <Suspense fallback={<div className="flex-1" />}><NexusTab /></Suspense> },
  { path: "receipt-preview", element: <Suspense fallback={<div className="flex-1" />}><ReceiptPreviewTab /></Suspense> },
  { path: "file/*", element: <FeatureErrorBoundary feature="Editor"><FileEditorShell /></FeatureErrorBoundary> },
  { path: "*", element: <Navigate to="/home" replace /> },
];
