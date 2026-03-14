import type { ProcessDefinition } from "@backbay/glia-desktop";
import { lazy } from "react";

const Dashboard = lazy(() => import("../pages/Dashboard").then((m) => ({ default: m.Dashboard })));
const Events = lazy(() => import("../pages/Events").then((m) => ({ default: m.Events })));
const AuditLog = lazy(() => import("../pages/AuditLog").then((m) => ({ default: m.AuditLog })));
const Policies = lazy(() => import("../pages/Policies").then((m) => ({ default: m.Policies })));
const Settings = lazy(() => import("../pages/Settings").then((m) => ({ default: m.Settings })));
const AgentExplorer = lazy(() =>
  import("../pages/AgentExplorer").then((m) => ({ default: m.AgentExplorer })),
);
const ReceiptVerifier = lazy(() =>
  import("../pages/ReceiptVerifier").then((m) => ({ default: m.ReceiptVerifier })),
);
const PolicyEditor = lazy(() =>
  import("../pages/PolicyEditor").then((m) => ({ default: m.PolicyEditor })),
);
const GuardPlayground = lazy(() =>
  import("../pages/GuardPlayground").then((m) => ({ default: m.GuardPlayground })),
);
const PostureMap = lazy(() =>
  import("../pages/PostureMap").then((m) => ({ default: m.PostureMap })),
);
const ComplianceReport = lazy(() =>
  import("../pages/ComplianceReport").then((m) => ({ default: m.ComplianceReport })),
);
const ReplayMode = lazy(() =>
  import("../pages/ReplayMode").then((m) => ({ default: m.ReplayMode })),
);
const AgentChat = lazy(() => import("../pages/AgentChat").then((m) => ({ default: m.AgentChat })));
const BrokerMissionControl = lazy(() =>
  import("../pages/BrokerMissionControl").then((m) => ({ default: m.BrokerMissionControl })),
);
const BrokerWallet = lazy(() =>
  import("../pages/BrokerWallet").then((m) => ({ default: m.BrokerWallet })),
);
const BrokerTheater = lazy(() =>
  import("../pages/BrokerTheater").then((m) => ({ default: m.BrokerTheater })),
);

/* ── Artifact OS SVG Sigils ── */

function MonitorSigil() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={20}
      height={20}
      fill="none"
      stroke="var(--gold)"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 2L3 7v10l9 5 9-5V7l-9-5z" />
      <path d="M12 12l9-5M12 12v10M12 12L3 7" opacity={0.4} />
      <circle cx={12} cy={12} r={2.5} fill="var(--gold)" stroke="none" opacity={0.6} />
    </svg>
  );
}

function EventStreamSigil() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={20}
      height={20}
      fill="none"
      stroke="var(--teal)"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M13 2L4.09 12.96h6.36L9.55 22l8.91-10.96h-6.36L13 2z" />
    </svg>
  );
}

function AuditSigil() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={20}
      height={20}
      fill="none"
      stroke="var(--gold)"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8l-6-6z" />
      <path d="M14 2v6h6" opacity={0.4} />
      <line x1={8} y1={13} x2={16} y2={13} opacity={0.5} />
      <line x1={8} y1={17} x2={13} y2={17} opacity={0.5} />
    </svg>
  );
}

function PoliciesSigil() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={20}
      height={20}
      fill="none"
      stroke="var(--gold)"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="M9 12l2 2 4-4" stroke="var(--stamp-allowed)" opacity={0.7} />
    </svg>
  );
}

function SettingsSigil() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={20}
      height={20}
      fill="none"
      stroke="var(--muted)"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx={12} cy={12} r={3} />
      <path
        d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"
        opacity={0.5}
      />
    </svg>
  );
}

function AgentExplorerSigil() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={20}
      height={20}
      fill="none"
      stroke="var(--teal)"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx={6} cy={6} r={2.5} />
      <circle cx={18} cy={6} r={2.5} />
      <circle cx={12} cy={18} r={2.5} />
      <path d="M8 7.5l3 7M16 7.5l-3 7M8.5 6h7" opacity={0.5} />
    </svg>
  );
}

function ReceiptVerifierSigil() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={20}
      height={20}
      fill="none"
      stroke="var(--gold)"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx={12} cy={12} r={8} />
      <circle cx={12} cy={12} r={4} opacity={0.4} />
      <path d="M9.5 12l1.5 2 3.5-4" stroke="var(--stamp-allowed)" opacity={0.7} />
    </svg>
  );
}

function PolicyEditorSigil() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={20}
      height={20}
      fill="none"
      stroke="var(--gold)"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="M15.5 8.5l-5 5L8 11" opacity={0.4} />
      <path d="M14 3l2 2-6 6-2-2 6-6z" stroke="var(--teal)" opacity={0.6} />
    </svg>
  );
}

function GuardPlaygroundSigil() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={20}
      height={20}
      fill="none"
      stroke="var(--teal)"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M9 3h6l2 6H7l2-6z" />
      <path d="M7 9c0 0-1 3-1 6s2 6 6 6 6-3 6-6-1-6-1-6" />
      <line x1={12} y1={9} x2={12} y2={15} opacity={0.4} />
    </svg>
  );
}

function PostureMapSigil() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={20}
      height={20}
      fill="none"
      stroke="var(--teal)"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx={5} cy={12} r={2} />
      <circle cx={12} cy={5} r={2} />
      <circle cx={19} cy={12} r={2} />
      <circle cx={12} cy={19} r={2} />
      <path d="M7 11l3-4M15 7l2 3M17 13l-3 4M9 17l-2-3" opacity={0.4} />
      <circle cx={12} cy={12} r={1.5} fill="var(--teal)" stroke="none" opacity={0.5} />
    </svg>
  );
}

function ComplianceSigil() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={20}
      height={20}
      fill="none"
      stroke="var(--gold)"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M15 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V7l-5-5z" />
      <path d="M15 2v5h5" opacity={0.4} />
      <path d="M9 15l2 2 4-4" stroke="var(--stamp-allowed)" opacity={0.7} />
    </svg>
  );
}

function ReplaySigil() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={20}
      height={20}
      fill="none"
      stroke="var(--gold)"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx={12} cy={12} r={9} />
      <polygon points="10,8 16,12 10,16" fill="var(--gold)" stroke="none" opacity={0.5} />
    </svg>
  );
}

function AgentChatSigil() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={20}
      height={20}
      fill="none"
      stroke="var(--teal)"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />
      <path d="M8 9h8M8 13h5" opacity={0.4} />
    </svg>
  );
}

function BrokerWalletSigil() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={20}
      height={20}
      fill="none"
      stroke="var(--gold)"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x={3} y={6} width={18} height={12} rx={2} />
      <path d="M16 12h3" opacity={0.5} />
      <circle cx={8} cy={12} r={1.5} fill="var(--gold)" stroke="none" opacity={0.6} />
    </svg>
  );
}

function BrokerMissionControlSigil() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={20}
      height={20}
      fill="none"
      stroke="var(--gold)"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx={12} cy={12} r={8} />
      <path d="M12 4v4M12 16v4M4 12h4M16 12h4" opacity={0.35} />
      <path d="M12 12l4-3" stroke="var(--teal)" />
      <circle cx={12} cy={12} r={1.5} fill="var(--gold)" stroke="none" opacity={0.65} />
    </svg>
  );
}

function BrokerTheaterSigil() {
  return (
    <svg
      viewBox="0 0 24 24"
      width={20}
      height={20}
      fill="none"
      stroke="var(--teal)"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M4 6h16" opacity={0.35} />
      <path d="M4 12h10" />
      <path d="M4 18h16" opacity={0.35} />
      <circle cx={17} cy={12} r={3} fill="none" />
    </svg>
  );
}

/** Map processId → sigil component for use in taskbar & desktop */
export const PROCESS_ICONS: Record<string, React.ReactNode> = {
  monitor: <MonitorSigil />,
  "event-stream": <EventStreamSigil />,
  audit: <AuditSigil />,
  policy: <PoliciesSigil />,
  settings: <SettingsSigil />,
  "agent-explorer": <AgentExplorerSigil />,
  "receipt-verifier": <ReceiptVerifierSigil />,
  "policy-editor": <PolicyEditorSigil />,
  "guard-playground": <GuardPlaygroundSigil />,
  "posture-map": <PostureMapSigil />,
  "compliance-report": <ComplianceSigil />,
  "replay-mode": <ReplaySigil />,
  "agent-chat": <AgentChatSigil />,
  "broker-mission-control": <BrokerMissionControlSigil />,
  "broker-wallet": <BrokerWalletSigil />,
  "broker-theater": <BrokerTheaterSigil />,
};

export const processes: ProcessDefinition[] = [
  {
    id: "monitor",
    name: "Monitor",
    icon: <MonitorSigil />,
    component: Dashboard,
    defaultSize: { width: 920, height: 680 },
    minSize: { width: 720, height: 540 },
    singleton: true,
    category: "security",
    description: "Health, metrics & live event feed",
  },
  {
    id: "event-stream",
    name: "Event Stream",
    icon: <EventStreamSigil />,
    component: Events,
    defaultSize: { width: 860, height: 600 },
    minSize: { width: 640, height: 480 },
    singleton: true,
    category: "security",
    description: "Real-time SSE event table",
  },
  {
    id: "audit",
    name: "Audit Log",
    icon: <AuditSigil />,
    component: AuditLog,
    defaultSize: { width: 920, height: 640 },
    minSize: { width: 720, height: 500 },
    singleton: true,
    category: "security",
    description: "Historical event audit trail",
  },
  {
    id: "policy",
    name: "Policies",
    icon: <PoliciesSigil />,
    component: Policies,
    defaultSize: { width: 720, height: 560 },
    minSize: { width: 560, height: 440 },
    singleton: true,
    category: "security",
    description: "Active policy viewer",
  },
  {
    id: "settings",
    name: "Settings",
    icon: <SettingsSigil />,
    component: Settings,
    defaultSize: { width: 660, height: 540 },
    minSize: { width: 520, height: 420 },
    singleton: true,
    category: "system",
    description: "Connection, SIEM & webhook config",
  },
  {
    id: "agent-explorer",
    name: "Agent Explorer",
    icon: <AgentExplorerSigil />,
    component: AgentExplorer,
    defaultSize: { width: 880, height: 640 },
    minSize: { width: 680, height: 500 },
    singleton: true,
    category: "security",
    description: "Browse agents, sessions & posture",
  },
  {
    id: "receipt-verifier",
    name: "Receipt Verifier",
    icon: <ReceiptVerifierSigil />,
    component: ReceiptVerifier,
    defaultSize: { width: 720, height: 560 },
    minSize: { width: 560, height: 440 },
    singleton: true,
    category: "security",
    description: "Verify Ed25519 receipt signatures",
  },
  {
    id: "policy-editor",
    name: "Policy Editor",
    icon: <PolicyEditorSigil />,
    component: PolicyEditor,
    defaultSize: { width: 960, height: 680 },
    minSize: { width: 760, height: 540 },
    singleton: true,
    category: "security",
    description: "Edit & validate security policies",
  },
  {
    id: "guard-playground",
    name: "Guard Playground",
    icon: <GuardPlaygroundSigil />,
    component: GuardPlayground,
    defaultSize: { width: 800, height: 600 },
    minSize: { width: 640, height: 480 },
    singleton: true,
    category: "security",
    description: "Test guards with mock inputs",
  },
  {
    id: "posture-map",
    name: "Posture Map",
    icon: <PostureMapSigil />,
    component: PostureMap,
    defaultSize: { width: 960, height: 700 },
    minSize: { width: 760, height: 540 },
    singleton: true,
    category: "advanced",
    description: "Live force-directed agent posture graph",
  },
  {
    id: "compliance-report",
    name: "Compliance",
    icon: <ComplianceSigil />,
    component: ComplianceReport,
    defaultSize: { width: 800, height: 640 },
    minSize: { width: 640, height: 500 },
    singleton: true,
    category: "advanced",
    description: "Generate compliance reports",
  },
  {
    id: "broker-mission-control",
    name: "Broker Mission Control",
    icon: <BrokerMissionControlSigil />,
    component: BrokerMissionControl,
    defaultSize: { width: 1180, height: 760 },
    minSize: { width: 900, height: 620 },
    singleton: true,
    category: "security",
    description: "Wave 5 operator surface for previews, lineage, and bundles",
  },
  {
    id: "broker-wallet",
    name: "Broker Wallet",
    icon: <BrokerWalletSigil />,
    component: BrokerWallet,
    defaultSize: { width: 1080, height: 720 },
    minSize: { width: 820, height: 560 },
    singleton: true,
    category: "security",
    description: "Inspect and control live broker capabilities",
  },
  {
    id: "broker-theater",
    name: "Broker Theater",
    icon: <BrokerTheaterSigil />,
    component: BrokerTheater,
    defaultSize: { width: 980, height: 700 },
    minSize: { width: 760, height: 540 },
    singleton: true,
    category: "security",
    description: "Watch live broker timeline and freeze state",
  },
  {
    id: "replay-mode",
    name: "Replay",
    icon: <ReplaySigil />,
    component: ReplayMode,
    defaultSize: { width: 920, height: 640 },
    minSize: { width: 720, height: 500 },
    singleton: true,
    category: "advanced",
    description: "Replay historical events with timeline",
  },
  {
    id: "agent-chat",
    name: "Agent Chat",
    icon: <AgentChatSigil />,
    component: AgentChat,
    defaultSize: { width: 800, height: 640 },
    minSize: { width: 640, height: 500 },
    singleton: true,
    category: "advanced",
    description: "Multi-agent action feed as chat",
  },
];

export type DesktopIconGroupId = "core" | "policy-ops" | "advanced";

export interface DesktopIconConfig {
  id: string;
  processId: string;
  label: string;
  group: DesktopIconGroupId;
}

export interface DesktopIconGroup {
  id: DesktopIconGroupId;
  label: string;
  icons: DesktopIconConfig[];
}

export const desktopIcons: DesktopIconConfig[] = [
  { id: "monitor", processId: "monitor", label: "Monitor", group: "core" },
  { id: "agent-explorer", processId: "agent-explorer", label: "Agent Explorer", group: "core" },
  { id: "event-stream", processId: "event-stream", label: "Event Stream", group: "core" },
  { id: "audit", processId: "audit", label: "Audit Log", group: "core" },
  {
    id: "broker-mission-control",
    processId: "broker-mission-control",
    label: "Mission Control",
    group: "core",
  },
  { id: "broker-wallet", processId: "broker-wallet", label: "Broker Wallet", group: "core" },
  { id: "broker-theater", processId: "broker-theater", label: "Broker Theater", group: "core" },
  { id: "policy", processId: "policy", label: "Policies", group: "policy-ops" },
  { id: "policy-editor", processId: "policy-editor", label: "Policy Editor", group: "policy-ops" },
  { id: "guard-playground", processId: "guard-playground", label: "Guard Lab", group: "policy-ops" },
  { id: "posture-map", processId: "posture-map", label: "Posture Map", group: "policy-ops" },
  { id: "agent-chat", processId: "agent-chat", label: "Agent Chat", group: "policy-ops" },
  { id: "receipt-verifier", processId: "receipt-verifier", label: "Receipts", group: "advanced" },
  { id: "settings", processId: "settings", label: "Settings", group: "advanced" },
  { id: "compliance-report", processId: "compliance-report", label: "Compliance", group: "advanced" },
  { id: "replay-mode", processId: "replay-mode", label: "Replay", group: "advanced" },
];

const GROUP_LABELS: Record<DesktopIconGroupId, string> = {
  core: "Operations",
  "policy-ops": "Policy + Runtime",
  advanced: "Tools",
};

export const desktopIconGroups: DesktopIconGroup[] = (
  ["core", "policy-ops", "advanced"] as const
).map((groupId) => ({
  id: groupId,
  label: GROUP_LABELS[groupId],
  icons: desktopIcons.filter((icon) => icon.group === groupId),
}));

export const allApps = desktopIcons;

export const startMenuDefaultPinnedIds = [
  "monitor",
  "broker-mission-control",
  "broker-wallet",
  "agent-explorer",
  "audit",
  "event-stream",
  "settings",
];

export const pinnedAppIds = [
  "monitor",
  "broker-mission-control",
  "broker-wallet",
  "agent-explorer",
  "audit",
  "event-stream",
  "settings",
];
