import type { ProcessDefinition } from "@backbay/glia-desktop";
import { Dashboard } from "../pages/Dashboard";
import { Events } from "../pages/Events";
import { AuditLog } from "../pages/AuditLog";
import { Policies } from "../pages/Policies";
import { Settings } from "../pages/Settings";

export const processes: ProcessDefinition[] = [
  {
    id: "monitor",
    name: "Monitor",
    icon: "🛡",
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
    icon: "⚡",
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
    icon: "📜",
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
    icon: "📋",
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
    icon: "⚙",
    component: Settings,
    defaultSize: { width: 660, height: 540 },
    minSize: { width: 520, height: 420 },
    singleton: true,
    category: "system",
    description: "Connection, SIEM & webhook config",
  },
];

export const desktopIcons = [
  { id: "monitor", processId: "monitor", label: "Monitor" },
  { id: "event-stream", processId: "event-stream", label: "Event Stream" },
  { id: "audit", processId: "audit", label: "Audit Log" },
  { id: "policy", processId: "policy", label: "Policies" },
  { id: "settings", processId: "settings", label: "Settings" },
];

export const pinnedAppIds = ["monitor", "event-stream", "audit", "settings"];
