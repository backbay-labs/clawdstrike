/**
 * Dock System - Pluggable Agentic UI Dock & Capsule System
 *
 * Provides floating capsule windows for:
 * - Job/run output
 * - Kernel events feed
 * - Artifact preview
 * - Workcell/issue inspector
 * - Terminal sessions
 * - Agent actions/decisions (NEW)
 * - Chat/messaging (NEW)
 * - Social/connections (NEW)
 */

export { Capsule, CapsuleTab } from "./Capsule";
export { DockProvider, useCapsule, useCapsulesByKind, useDock } from "./DockContext";
export { DockSystem, default } from "./DockSystem";
export { SessionRail } from "./SessionRail";
export type {
  ActionOption,
  // New agentic types
  ActionPriority,
  ActionType,
  AgentAction,
  CapsuleContentProps,
  CapsuleKind,
  CapsuleTabState,
  CapsuleViewMode,
  ChatChannel,
  ChatMessage,
  DockCapsuleState,
  SessionItem,
  ShelfMode,
  ShelfState,
} from "./types";
export {
  // Legacy exports
  sampleActions,
  sampleChat,
  sampleChronicle,
  sampleCoven,
  // New mystical naming
  sampleOracle,
  sampleSessions,
  sampleSocial,
  sampleWhisper,
  useDockDemo,
} from "./useDockDemo";
