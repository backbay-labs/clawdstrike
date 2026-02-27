import { lazy } from "react";
import type { ProcessDefinition } from "@backbay/glia-desktop";

const Dashboard = lazy(() => import("../pages/Dashboard").then(m => ({ default: m.Dashboard })));
const Events = lazy(() => import("../pages/Events").then(m => ({ default: m.Events })));
const AuditLog = lazy(() => import("../pages/AuditLog").then(m => ({ default: m.AuditLog })));
const Policies = lazy(() => import("../pages/Policies").then(m => ({ default: m.Policies })));
const Settings = lazy(() => import("../pages/Settings").then(m => ({ default: m.Settings })));
const AgentExplorer = lazy(() => import("../pages/AgentExplorer").then(m => ({ default: m.AgentExplorer })));
const ReceiptVerifier = lazy(() => import("../pages/ReceiptVerifier").then(m => ({ default: m.ReceiptVerifier })));
const PolicyEditor = lazy(() => import("../pages/PolicyEditor").then(m => ({ default: m.PolicyEditor })));
const GuardPlayground = lazy(() => import("../pages/GuardPlayground").then(m => ({ default: m.GuardPlayground })));
const PostureMap = lazy(() => import("../pages/PostureMap").then(m => ({ default: m.PostureMap })));
const ComplianceReport = lazy(() => import("../pages/ComplianceReport").then(m => ({ default: m.ComplianceReport })));
const ReplayMode = lazy(() => import("../pages/ReplayMode").then(m => ({ default: m.ReplayMode })));
const AgentChat = lazy(() => import("../pages/AgentChat").then(m => ({ default: m.AgentChat })));

/* ── Artifact OS SVG Sigils ── */

function MonitorSigil() {
  return (
    <svg viewBox="0 0 24 24" width={20} height={20} fill="none" stroke="var(--gold)" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2L3 7v10l9 5 9-5V7l-9-5z" />
      <path d="M12 12l9-5M12 12v10M12 12L3 7" opacity={0.4} />
      <circle cx={12} cy={12} r={2.5} fill="var(--gold)" stroke="none" opacity={0.6} />
    </svg>
  );
}

function EventStreamSigil() {
  return (
    <svg viewBox="0 0 24 24" width={20} height={20} fill="none" stroke="var(--teal)" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M13 2L4.09 12.96h6.36L9.55 22l8.91-10.96h-6.36L13 2z" />
    </svg>
  );
}

function AuditSigil() {
  return (
    <svg viewBox="0 0 24 24" width={20} height={20} fill="none" stroke="var(--gold)" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8l-6-6z" />
      <path d="M14 2v6h6" opacity={0.4} />
      <line x1={8} y1={13} x2={16} y2={13} opacity={0.5} />
      <line x1={8} y1={17} x2={13} y2={17} opacity={0.5} />
    </svg>
  );
}

function PoliciesSigil() {
  return (
    <svg viewBox="0 0 24 24" width={20} height={20} fill="none" stroke="var(--gold)" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="M9 12l2 2 4-4" stroke="var(--stamp-allowed)" opacity={0.7} />
    </svg>
  );
}

function SettingsSigil() {
  return (
    <svg viewBox="0 0 24 24" width={20} height={20} fill="none" stroke="var(--muted)" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <circle cx={12} cy={12} r={3} />
      <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" opacity={0.5} />
    </svg>
  );
}

function AgentExplorerSigil() {
  return (
    <svg viewBox="0 0 24 24" width={20} height={20} fill="none" stroke="var(--teal)" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <circle cx={6} cy={6} r={2.5} />
      <circle cx={18} cy={6} r={2.5} />
      <circle cx={12} cy={18} r={2.5} />
      <path d="M8 7.5l3 7M16 7.5l-3 7M8.5 6h7" opacity={0.5} />
    </svg>
  );
}

function ReceiptVerifierSigil() {
  return (
    <svg viewBox="0 0 24 24" width={20} height={20} fill="none" stroke="var(--gold)" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <circle cx={12} cy={12} r={8} />
      <circle cx={12} cy={12} r={4} opacity={0.4} />
      <path d="M9.5 12l1.5 2 3.5-4" stroke="var(--stamp-allowed)" opacity={0.7} />
    </svg>
  );
}

function PolicyEditorSigil() {
  return (
    <svg viewBox="0 0 24 24" width={20} height={20} fill="none" stroke="var(--gold)" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="M15.5 8.5l-5 5L8 11" opacity={0.4} />
      <path d="M14 3l2 2-6 6-2-2 6-6z" stroke="var(--teal)" opacity={0.6} />
    </svg>
  );
}

function GuardPlaygroundSigil() {
  return (
    <svg viewBox="0 0 24 24" width={20} height={20} fill="none" stroke="var(--teal)" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 3h6l2 6H7l2-6z" />
      <path d="M7 9c0 0-1 3-1 6s2 6 6 6 6-3 6-6-1-6-1-6" />
      <line x1={12} y1={9} x2={12} y2={15} opacity={0.4} />
    </svg>
  );
}

function PostureMapSigil() {
  return (
    <svg viewBox="0 0 24 24" width={20} height={20} fill="none" stroke="var(--teal)" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
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
    <svg viewBox="0 0 24 24" width={20} height={20} fill="none" stroke="var(--gold)" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M15 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V7l-5-5z" />
      <path d="M15 2v5h5" opacity={0.4} />
      <path d="M9 15l2 2 4-4" stroke="var(--stamp-allowed)" opacity={0.7} />
    </svg>
  );
}

function ReplaySigil() {
  return (
    <svg viewBox="0 0 24 24" width={20} height={20} fill="none" stroke="var(--gold)" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <circle cx={12} cy={12} r={9} />
      <polygon points="10,8 16,12 10,16" fill="var(--gold)" stroke="none" opacity={0.5} />
    </svg>
  );
}

function AgentChatSigil() {
  return (
    <svg viewBox="0 0 24 24" width={20} height={20} fill="none" stroke="var(--teal)" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" />
      <path d="M8 9h8M8 13h5" opacity={0.4} />
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

export const desktopIcons = [
  { id: "monitor", processId: "monitor", label: "Monitor" },
  { id: "event-stream", processId: "event-stream", label: "Event Stream" },
  { id: "audit", processId: "audit", label: "Audit Log" },
  { id: "policy", processId: "policy", label: "Policies" },
  { id: "agent-explorer", processId: "agent-explorer", label: "Agents" },
  { id: "policy-editor", processId: "policy-editor", label: "Policy Editor" },
  { id: "settings", processId: "settings", label: "Settings" },
  { id: "receipt-verifier", processId: "receipt-verifier", label: "Receipts" },
  { id: "guard-playground", processId: "guard-playground", label: "Guard Lab" },
  { id: "posture-map", processId: "posture-map", label: "Posture Map" },
  { id: "compliance-report", processId: "compliance-report", label: "Compliance" },
  { id: "replay-mode", processId: "replay-mode", label: "Replay" },
  { id: "agent-chat", processId: "agent-chat", label: "Agent Chat" },
];

export const pinnedAppIds = ["monitor", "event-stream", "audit", "agent-explorer", "settings"];
