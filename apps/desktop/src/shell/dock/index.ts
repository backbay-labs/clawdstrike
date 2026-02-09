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

export { DockSystem, default } from "./DockSystem";
export { DockProvider, useDock, useCapsule, useCapsulesByKind } from "./DockContext";
export { Capsule, CapsuleTab } from "./Capsule";
export { SessionRail } from "./SessionRail";
export {
  useDockDemo,
  // New mystical naming
  sampleOracle,
  sampleWhisper,
  sampleCoven,
  sampleChronicle,
  sampleSessions,
  // Legacy exports
  sampleActions,
  sampleChat,
  sampleSocial,
} from "./useDockDemo";
export type {
  CapsuleKind,
  CapsuleViewMode,
  DockCapsuleState,
  CapsuleTabState,
  SessionItem,
  ShelfMode,
  ShelfState,
  CapsuleContentProps,
  // New agentic types
  ActionPriority,
  ActionType,
  AgentAction,
  ActionOption,
  ChatMessage,
  ChatChannel,
} from "./types";
