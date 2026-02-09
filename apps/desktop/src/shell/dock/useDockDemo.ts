/**
 * useDockDemo - Demo hook to populate dock with sample data
 *
 * Use this to demonstrate the agentic UI dock features:
 * - Oracle capsules for agent decisions/prophecies
 * - Whisper capsules for agent communication
 * - Coven capsules for agent collective connections
 * - Sessions for active invocations
 */

import { useEffect } from "react";
import { useDock } from "./DockContext";
import type { DockCapsuleState, SessionItem } from "./types";

// =============================================================================
// Oracle Data - Agent Decisions & Prophecies
// =============================================================================

const ORACLE_VISIONS: Omit<DockCapsuleState, "viewMode" | "isMinimized" | "isPinned">[] = [
  {
    id: "oracle-ritual-approval",
    kind: "action",
    title: "Ritual Approval",
    subtitle: "Production deployment",
    badgeCount: 1,
    sourceData: {
      type: "approval",
      priority: "critical",
      description: "The kernel has completed its preparations. 3 new enchantments and 2 ward repairs await release to the production realm. Shall we proceed with the ritual?",
      agentName: "Architect",
      options: [
        { id: "approve", label: "Begin Ritual", description: "Deploy to production now", variant: "primary" },
        { id: "staging", label: "Test in Sanctum", description: "Validate in staging first" },
        { id: "reject", label: "Abort", description: "Cancel the deployment", variant: "destructive" },
      ],
      timeout: 300000,
      createdAt: new Date().toISOString(),
    },
  },
  {
    id: "oracle-path-choice",
    kind: "action",
    title: "Path Divergence",
    subtitle: "Bead #42",
    sourceData: {
      type: "decision",
      priority: "high",
      description: "Multiple paths reveal themselves for this task. Which vessel shall carry the work?",
      agentName: "Dispatcher",
      options: [
        { id: "claude", label: "Opus Vessel", description: "Deep reasoning, complex tasks" },
        { id: "codex", label: "Codex Vessel", description: "Swift incantations", variant: "primary" },
        { id: "speculate", label: "Parallel Paths", description: "Run both, divine the best" },
      ],
      createdAt: new Date().toISOString(),
    },
  },
  {
    id: "oracle-clarification",
    kind: "action",
    title: "Seeking Clarity",
    subtitle: "Bead #58",
    sourceData: {
      type: "question",
      priority: "normal",
      description: "The scrolls speak of 'updating the auth flow' but the runes are unclear. Should the ward use OAuth2 sigils or JWT tokens?",
      agentName: "Claude",
      options: [
        { id: "oauth", label: "OAuth2 Sigils" },
        { id: "jwt", label: "JWT Tokens", variant: "primary" },
        { id: "both", label: "Dual Wards" },
      ],
      createdAt: new Date().toISOString(),
    },
  },
  {
    id: "oracle-review",
    kind: "action",
    title: "Proof Awaits",
    subtitle: "PR #127",
    sourceData: {
      type: "review",
      priority: "normal",
      description: "The enchantment is complete. The proof awaits your inspection before the merge ritual.",
      agentName: "Claude",
      options: [
        { id: "approve", label: "Seal & Merge", variant: "primary" },
        { id: "changes", label: "Request Revisions" },
        { id: "comment", label: "Add Inscription" },
      ],
      createdAt: new Date().toISOString(),
    },
  },
  {
    id: "oracle-secret-needed",
    kind: "action",
    title: "Secret Required",
    subtitle: "Integration binding",
    sourceData: {
      type: "input",
      priority: "high",
      description: "The payment binding requires your Stripe secret key to complete the ritual.",
      agentName: "Binder",
      inputPlaceholder: "sk_live_...",
      createdAt: new Date().toISOString(),
    },
  },
  {
    id: "oracle-world-gen",
    kind: "action",
    title: "World Genesis",
    subtitle: "dark_dungeon",
    sourceData: {
      type: "approval",
      priority: "normal",
      description: "The Forge has manifested a new realm: Dark Dungeon. 47 assets crafted, all gates passed. Ready for integration.",
      agentName: "Forge Master",
      options: [
        { id: "integrate", label: "Integrate Realm", variant: "primary" },
        { id: "preview", label: "Preview First" },
        { id: "regenerate", label: "Regenerate" },
      ],
      createdAt: new Date().toISOString(),
    },
  },
];

// =============================================================================
// Whisper Data - Agent Communication Channels
// =============================================================================

const WHISPER_CHANNELS: Omit<DockCapsuleState, "viewMode" | "isMinimized" | "isPinned">[] = [
  {
    id: "whisper-claude",
    kind: "chat",
    title: "Claude Opus",
    subtitle: "Working on #42",
    badgeCount: 2,
    sourceData: {
      channelName: "Claude Opus",
      isTyping: true,
      messages: [
        {
          id: "msg-1",
          role: "agent",
          agentName: "Claude",
          content: "I have begun the authentication refactor. Analyzing the existing ward structures...",
          timestamp: new Date(Date.now() - 300000).toISOString(),
        },
        {
          id: "msg-2",
          role: "agent",
          agentName: "Claude",
          content: "Three scrolls require updates. Manifesting workcell now.",
          timestamp: new Date(Date.now() - 240000).toISOString(),
        },
        {
          id: "msg-3",
          role: "user",
          content: "Include tests for the new auth middleware",
          timestamp: new Date(Date.now() - 180000).toISOString(),
        },
        {
          id: "msg-4",
          role: "agent",
          agentName: "Claude",
          content: "Understood. Unit tests and integration trials shall be woven into the enchantment.",
          timestamp: new Date(Date.now() - 120000).toISOString(),
        },
        {
          id: "msg-5",
          role: "system",
          content: "Workcell wc-8a3f manifested",
          timestamp: new Date(Date.now() - 60000).toISOString(),
        },
      ],
    },
  },
  {
    id: "whisper-forge",
    kind: "chat",
    title: "Forge Master",
    subtitle: "Asset generation",
    badgeCount: 1,
    sourceData: {
      channelName: "Forge Master",
      isTyping: false,
      messages: [
        {
          id: "forge-1",
          role: "agent",
          agentName: "Forge",
          content: "Commencing world generation for 'enchanted_forest'...",
          timestamp: new Date(Date.now() - 600000).toISOString(),
        },
        {
          id: "forge-2",
          role: "system",
          content: "Stage 1/4: Terrain sculpting",
          timestamp: new Date(Date.now() - 540000).toISOString(),
        },
        {
          id: "forge-3",
          role: "agent",
          agentName: "Forge",
          content: "Terrain complete. 12 height variations generated. Proceeding to flora placement.",
          timestamp: new Date(Date.now() - 420000).toISOString(),
        },
        {
          id: "forge-4",
          role: "system",
          content: "Stage 2/4: Flora placement",
          timestamp: new Date(Date.now() - 360000).toISOString(),
        },
        {
          id: "forge-5",
          role: "agent",
          agentName: "Forge",
          content: "238 trees, 1,247 shrubs, 3,891 grass clusters manifested. Quality gate: PASSED",
          timestamp: new Date(Date.now() - 180000).toISOString(),
        },
      ],
    },
  },
  {
    id: "whisper-kernel",
    kind: "chat",
    title: "Kernel",
    subtitle: "System channel",
    sourceData: {
      channelName: "Kernel Overseer",
      isTyping: false,
      messages: [
        {
          id: "kern-1",
          role: "system",
          content: "Kernel awakened. 4 workcells available.",
          timestamp: new Date(Date.now() - 900000).toISOString(),
        },
        {
          id: "kern-2",
          role: "agent",
          agentName: "Kernel",
          content: "Scanning beads graph... 3 pending issues detected.",
          timestamp: new Date(Date.now() - 840000).toISOString(),
        },
        {
          id: "kern-3",
          role: "agent",
          agentName: "Kernel",
          content: "Issue #42 routed to Claude Opus (high complexity). Issue #43 routed to Codex (quick fix).",
          timestamp: new Date(Date.now() - 720000).toISOString(),
        },
        {
          id: "kern-4",
          role: "system",
          content: "Run run-auth-42 initiated",
          timestamp: new Date(Date.now() - 600000).toISOString(),
        },
      ],
    },
  },
];

// =============================================================================
// Coven Data - Agent Collective Connections
// =============================================================================

const COVEN_DATA: Omit<DockCapsuleState, "viewMode" | "isMinimized" | "isPinned"> = {
  id: "coven-collective",
  kind: "social",
  title: "The Coven",
  badgeCount: 3,
  sourceData: {
    pendingRequests: 2,
    connections: [
      { id: "agent-claude", name: "Claude Opus", status: "online" },
      { id: "agent-codex", name: "Codex", status: "online" },
      { id: "agent-forge", name: "Forge Master", status: "online" },
      { id: "agent-crusher", name: "Crusher", status: "away" },
      { id: "agent-dispatcher", name: "Dispatcher", status: "online" },
      { id: "agent-architect", name: "Architect", status: "online" },
      { id: "agent-verifier", name: "Verifier", status: "away" },
      { id: "user-connor", name: "Connor (Summoner)", status: "online", lastSeen: "Active now" },
    ],
  },
};

// =============================================================================
// Session Data - Active Invocations
// =============================================================================

const ACTIVE_SESSIONS: SessionItem[] = [
  // Running - these will be prominently shown expanded
  { id: "run-auth-42", kind: "run", title: "Auth Refactor", status: "running", progress: 0.65, route: "/kernel" },
  { id: "build-main", kind: "build", title: "Build", status: "running", progress: 0.45, route: "/kernel" },
  // Error - shown expanded in error group
  { id: "run-migration", kind: "run", title: "DB Migration", status: "error", route: "/kernel" },
  // Idle/Success - these will be grouped/collapsed
  { id: "run-quick-43", kind: "run", title: "Quick Fix #43", status: "success", route: "/kernel" },
  { id: "run-api-tests", kind: "run", title: "API Tests", status: "success", route: "/kernel" },
  { id: "run-lint", kind: "run", title: "Lint Check", status: "success", route: "/kernel" },
  { id: "terminal-1", kind: "terminal", title: "Terminal 1", status: "idle", route: "/terminals" },
  { id: "terminal-2", kind: "terminal", title: "Terminal 2", status: "idle", route: "/terminals" },
];

// =============================================================================
// Events Data - Chronicle Entries
// =============================================================================

const CHRONICLE_EVENTS = [
  { type: "kernel", message: "Kernel awakened, scanning beads graph", timestamp: new Date(Date.now() - 900000).toISOString() },
  { type: "dispatch", message: "Issue #42 routed to Claude Opus", timestamp: new Date(Date.now() - 840000).toISOString() },
  { type: "workcell", message: "Workcell wc-8a3f manifested for #42", timestamp: new Date(Date.now() - 720000).toISOString() },
  { type: "dispatch", message: "Issue #43 routed to Codex", timestamp: new Date(Date.now() - 660000).toISOString() },
  { type: "forge", message: "World generation started: enchanted_forest", timestamp: new Date(Date.now() - 600000).toISOString() },
  { type: "gate", message: "Gate passed: terrain_quality for enchanted_forest", timestamp: new Date(Date.now() - 480000).toISOString() },
  { type: "gate", message: "Gate passed: flora_density for enchanted_forest", timestamp: new Date(Date.now() - 300000).toISOString() },
  { type: "proof", message: "Proof submitted for #43 - awaiting verification", timestamp: new Date(Date.now() - 180000).toISOString() },
  { type: "verify", message: "Verification passed for #43", timestamp: new Date(Date.now() - 120000).toISOString() },
  { type: "merge", message: "PR #126 merged to main", timestamp: new Date(Date.now() - 60000).toISOString() },
];

// =============================================================================
// Demo Hook
// =============================================================================

interface UseDockDemoOptions {
  /** Show oracle (action) capsules */
  showOracle?: boolean;
  /** Show whisper (chat) capsules */
  showWhisper?: boolean;
  /** Show coven (social) capsule */
  showCoven?: boolean;
  /** Show session items */
  showSessions?: boolean;
  /** Number of oracle visions to show (1-6) */
  oracleCount?: number;
  /** Number of whisper channels to show (1-3) */
  whisperCount?: number;
  /** Open shelf with events */
  showChronicle?: boolean;
}

/**
 * Hook to populate dock with sample data for demonstration
 *
 * @example
 * ```tsx
 * // In your component - full demo
 * useDockDemo({ showOracle: true, showWhisper: true, showCoven: true, oracleCount: 3 });
 *
 * // Minimal demo - just sessions
 * useDockDemo({ showSessions: true });
 * ```
 */
export function useDockDemo(options: UseDockDemoOptions = {}) {
  const {
    showOracle = true,
    showWhisper = true,
    showCoven = true,
    showSessions = true,
    oracleCount = 3,
    whisperCount = 2,
    showChronicle = false,
  } = options;

  const { openCapsule, setSessions, capsules, toggleShelf } = useDock();

  useEffect(() => {
    // Only run once when no capsules exist
    if (capsules.length > 0) return;

    // Add sessions
    if (showSessions) {
      setSessions(ACTIVE_SESSIONS);
    }

    // Add oracle (action) capsules - start minimized
    if (showOracle) {
      const visions = ORACLE_VISIONS.slice(0, Math.min(oracleCount, ORACLE_VISIONS.length));
      visions.forEach((vision, index) => {
        setTimeout(() => {
          openCapsule(vision, true); // Start minimized
        }, (index + 1) * 100);
      });
    }

    // Add whisper (chat) capsules - start minimized
    if (showWhisper) {
      const channels = WHISPER_CHANNELS.slice(0, Math.min(whisperCount, WHISPER_CHANNELS.length));
      const baseDelay = showOracle ? (oracleCount + 1) * 100 : 100;
      channels.forEach((channel, index) => {
        setTimeout(() => {
          openCapsule(channel, true); // Start minimized
        }, baseDelay + (index * 100));
      });
    }

    // Add coven (social) capsule - start minimized
    if (showCoven) {
      const covenDelay = (showOracle ? oracleCount : 0) * 100 + (showWhisper ? whisperCount : 0) * 100 + 200;
      setTimeout(() => {
        openCapsule(COVEN_DATA, true); // Start minimized
      }, covenDelay);
    }

    // Open chronicle (events shelf)
    if (showChronicle) {
      setTimeout(() => {
        toggleShelf("events");
      }, 1000);
    }
  }, [showOracle, showWhisper, showCoven, showSessions, oracleCount, whisperCount, showChronicle, openCapsule, setSessions, capsules.length, toggleShelf]);
}

/**
 * Sample data exports for direct use
 */
export const sampleOracle = ORACLE_VISIONS;
export const sampleWhisper = WHISPER_CHANNELS;
export const sampleCoven = COVEN_DATA;
export const sampleSessions = ACTIVE_SESSIONS;
export const sampleChronicle = CHRONICLE_EVENTS;

// Legacy exports for backwards compatibility
export const sampleActions = ORACLE_VISIONS;
export const sampleChat = WHISPER_CHANNELS[0];
export const sampleSocial = COVEN_DATA;

export default useDockDemo;
