/**
 * Dock System Types
 *
 * Ported from Origin desktop dock system.
 * Capsules can hold: output logs, events feed, artifact preview, inspectors.
 */

export type CapsuleKind =
  | "output" // Job/run output
  | "events" // Kernel/events feed
  | "artifact" // Artifact preview
  | "inspector" // Workcell/issue inspector
  | "terminal" // Terminal session popup
  | "action" // Agent decision/question requiring user input
  | "chat" // Chat/messaging capsule
  | "social" // Social/connections capsule
  | "season_pass" // Optional: future
  | "kernel_agent"; // Optional: future

export type ActionPriority = "critical" | "high" | "normal" | "low";
export type ActionType = "decision" | "question" | "approval" | "input" | "review";

export interface AgentAction {
  id: string;
  type: ActionType;
  priority: ActionPriority;
  title: string;
  description: string;
  agentId: string;
  agentName: string;
  options?: ActionOption[];
  inputSchema?: Record<string, unknown>;
  timeout?: number;
  createdAt: string;
  context?: Record<string, unknown>;
}

export interface ActionOption {
  id: string;
  label: string;
  description?: string;
  icon?: string;
  variant?: "default" | "primary" | "destructive";
}

export interface ChatMessage {
  id: string;
  role: "user" | "agent" | "system";
  content: string;
  timestamp: string;
  agentId?: string;
  agentName?: string;
}

export interface ChatChannel {
  id: string;
  name: string;
  type: "direct" | "group" | "broadcast";
  unreadCount: number;
  lastMessage?: ChatMessage;
  participants?: string[];
}

export type CapsuleViewMode = "compact" | "expanded" | "fullView" | "collapsed";

export interface DockCapsuleState {
  id: string;
  kind: CapsuleKind;
  title: string;
  subtitle?: string;
  badgeCount?: number;

  sourceId?: string;
  sourceData?: unknown;

  viewMode: CapsuleViewMode;
  isMinimized: boolean;
  isPinned: boolean;

  position?: { x: number; y: number };
}

export interface CapsuleTabState {
  id: string;
  capsuleId: string;
  kind: CapsuleKind;
  title: string;
  badgeCount?: number;
  isMinimized: boolean;
}

export interface SessionItem {
  id: string;
  kind: "run" | "terminal" | "build";
  title: string;
  status?: "idle" | "running" | "success" | "error";
  progress?: number;
  route?: string;
}

export type ShelfMode = "events" | "output" | "artifacts";

export interface ShelfState {
  isOpen: boolean;
  mode: ShelfMode | null;
}

export interface CapsuleContentProps {
  capsule: DockCapsuleState;
  isExpanded: boolean;
}

