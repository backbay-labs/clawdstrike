/**
 * ForensicsRiverView - Live/replay 3D river for OpenClaw telemetry.
 *
 * Wave 3:
 * - Polls OpenClaw `sessions.preview` to materialize tool calls + policy outcomes as RiverActions.
 * - Augments with live exec approvals from gateway events.
 * - Keeps a sliding live window so actions "flow" as time advances.
 */

import { RiverView as River } from "@backbay/glia-three/three";
import { clsx } from "clsx";
import * as React from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useConnection } from "@/context/ConnectionContext";
import { type OpenClawGatewayRuntime, useOpenClaw } from "@/context/OpenClawContext";
import { NexusAppRail } from "@/features/cyber-nexus/components/NexusAppRail";
import { NexusControlStrip } from "@/features/cyber-nexus/components/NexusControlStrip";
import type { NexusLayoutMode, Strikecell, StrikecellDomainId } from "@/features/cyber-nexus/types";
import { AgentGlyphOverlay } from "@/features/forensics/components/AgentGlyphOverlay";
import { AgentOrbHud } from "@/features/forensics/components/AgentOrbHud";
import { useAgentCognitionState } from "@/features/forensics/hooks/useAgentCognitionState";
import { isTauri, openclawGatewayProbe } from "@/services/tauri";
import {
  dispatchShellOpenCommandPalette,
  SHELL_FOCUS_AGENT_SESSION_EVENT,
  type ShellFocusAgentSessionDetail,
} from "@/shell/events";
import { useActiveSession, useSessionActions, useSessions } from "@/shell/sessions";

type Agent = { id: string; label: string; color?: string };
type RiverAction = River.RiverAction;
type CausalLink = River.CausalLink;
type DetectorData = River.DetectorData;
type IncidentData = River.IncidentData;
type PolicySegment = River.PolicySegment;
type SignalData = River.SignalData;

type RiverDataset = {
  actions: RiverAction[];
  agents: Agent[];
  policies: PolicySegment[];
  signals: SignalData[];
  incidents: IncidentData[];
  detectors: DetectorData[];
  causalLinks: CausalLink[];
  timeRange: [number, number];
  initialTime?: number;
};

type SessionListResponse = {
  sessions?: Array<{ key?: string; updatedAt?: number; displayName?: string }>;
};

type SessionPreviewResponse = {
  previews?: Array<{
    key: string;
    status: string;
    items?: Array<{ role?: string; text?: string }>;
  }>;
};

type ProbeSessionRow = {
  key: string;
  label: string;
  updatedAt?: number;
  agentId?: string;
  percentUsed?: number;
  inputTokens?: number;
  outputTokens?: number;
};

// RiverView's live-stream heuristic starts playback at `end - 5000ms`.
// Keep `end` slightly in the future so "now" events appear immediately.
const LIVE_TIME_RANGE_LEAD_MS = 5500;

const NEXUS_RAIL_STRIKECELLS: Strikecell[] = [
  {
    id: "security-overview",
    name: "Security",
    routeId: "nexus",
    description: "",
    status: "healthy",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: [],
  },
  {
    id: "attack-graph",
    name: "Attack",
    routeId: "nexus",
    description: "",
    status: "healthy",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: [],
  },
  {
    id: "threat-radar",
    name: "Threat",
    routeId: "nexus",
    description: "",
    status: "healthy",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: [],
  },
  {
    id: "network-map",
    name: "Arena",
    routeId: "nexus",
    description: "",
    status: "healthy",
    activityCount: 0,
    nodeCount: 0,
    nodes: [],
    tags: [],
  },
];

type NexusSceneMode = "security" | "attack" | "threat" | "arena";

const SCENE_BY_STRIKECELL: Record<StrikecellDomainId, NexusSceneMode> = {
  "security-overview": "security",
  "attack-graph": "attack",
  "threat-radar": "threat",
  "network-map": "arena",
  "forensics-river": "security",
  events: "security",
  marketplace: "security",
  policies: "security",
  workflows: "security",
};

const SCENE_META: Record<NexusSceneMode, { title: string; subtitle: string }> = {
  security: {
    title: "Security Scene",
    subtitle: "Live policy posture, detector telemetry, and guarded flow lanes.",
  },
  attack: {
    title: "Attack Builder Lab",
    subtitle: "Construct and inspect operator attack paths before execution.",
  },
  threat: {
    title: "Threat Scene",
    subtitle: "Signal and anomaly focus across active agents and approvals.",
  },
  arena: {
    title: "Arena Network View",
    subtitle: "Topology-style operational lanes for connected session traffic.",
  },
};

const RUNTIME_SESSION_KEYS = {
  nodes: "__runtime_nodes",
  presence: "__runtime_presence",
  approvals: "__runtime_approvals",
} as const;

const RUNTIME_SESSION_FALLBACK_KEYS = [
  RUNTIME_SESSION_KEYS.nodes,
  RUNTIME_SESSION_KEYS.presence,
  RUNTIME_SESSION_KEYS.approvals,
] as const;
const RUNTIME_SESSION_FALLBACK_KEY_SET = new Set<string>(RUNTIME_SESSION_FALLBACK_KEYS);

function isRuntimeFallbackKey(
  value: string,
): value is (typeof RUNTIME_SESSION_FALLBACK_KEYS)[number] {
  return RUNTIME_SESSION_FALLBACK_KEY_SET.has(value);
}

function resolveRuntimeFallbackSelection(
  selectedSessionKey: string,
): Array<(typeof RUNTIME_SESSION_FALLBACK_KEYS)[number]> {
  if (selectedSessionKey === "__all__") return [...RUNTIME_SESSION_FALLBACK_KEYS];
  if (isRuntimeFallbackKey(selectedSessionKey)) return [selectedSessionKey];
  return [...RUNTIME_SESSION_FALLBACK_KEYS];
}

function demoPolicies(): PolicySegment[] {
  return [
    {
      id: "pol-1",
      label: "Network Egress",
      startT: 0,
      endT: 0.25,
      side: "both",
      type: "hard-deny",
    },
    { id: "pol-2", label: "FS Read-Only", startT: 0.2, endT: 0.5, side: "left", type: "soft" },
    {
      id: "pol-3",
      label: "Exec Sandbox",
      startT: 0.45,
      endT: 0.75,
      side: "right",
      type: "hard-deny",
    },
    { id: "pol-4", label: "Audit Zone", startT: 0.7, endT: 0.9, side: "both", type: "record-only" },
    {
      id: "pol-gap",
      label: "UNCOVERED",
      startT: 0.9,
      endT: 1,
      side: "both",
      type: "soft",
      coverageGap: true,
    },
  ];
}

function demoDetectors(): DetectorData[] {
  return [
    {
      id: "detector-0",
      label: "Heuristic Scanner",
      type: "heuristic",
      position: [-5, 0, 2.5],
      active: true,
      signalCount: 3,
    },
    {
      id: "detector-1",
      label: "ML Anomaly Model",
      type: "model",
      position: [-1, 0, -2.5],
      active: true,
      signalCount: 5,
    },
    {
      id: "detector-2",
      label: "Signature DB",
      type: "signature",
      position: [3, 0, 2.5],
      active: false,
      signalCount: 0,
    },
    {
      id: "detector-3",
      label: "Behavior Monitor",
      type: "behavioral",
      position: [6, 0, -2.5],
      active: true,
      signalCount: 2,
    },
  ];
}

function hashToIndex(input: string, mod: number): number {
  let h = 0;
  for (let i = 0; i < input.length; i++) h = (h * 31 + input.charCodeAt(i)) >>> 0;
  return mod > 0 ? h % mod : 0;
}

function clamp01(v: number): number {
  if (!Number.isFinite(v)) return 0;
  return Math.max(0, Math.min(1, v));
}

function parseAgentIdFromSessionKey(sessionKey: string): string {
  const m = /^agent:([^:]+):/.exec(sessionKey);
  return m?.[1] ?? sessionKey;
}

function normalizeAgentIdentity(value: string): string {
  return value
    .trim()
    .replace(/^agent\s+/i, "")
    .toLowerCase();
}

function matchesFocusedAgent(agentId: string, focusedAgentId: string | null): boolean {
  if (!focusedAgentId) return true;
  return normalizeAgentIdentity(agentId) === normalizeAgentIdentity(focusedAgentId);
}

function parseMessageId(text: string | undefined): string | null {
  if (!text) return null;
  const m = /\[message_id:\s*([^\]]+)\]/i.exec(text);
  if (!m) return null;
  const id = m[1]?.trim();
  return id ? id : null;
}

function summarizeText(text: string, max = 52): string {
  const trimmed = text.trim().replace(/\s+/g, " ");
  if (trimmed.length <= max) return trimmed;
  return `${trimmed.slice(0, max - 1)}…`;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object") return null;
  return value as Record<string, unknown>;
}

function asNumber(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string") {
    const parsed = Number.parseFloat(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function normalizeSessionLabel(sessionKey: string, fallback?: string, agentHint?: string): string {
  if (fallback && fallback.trim()) return fallback.trim();
  const parsedAgent = parseAgentIdFromSessionKey(sessionKey);
  const agentId = parsedAgent || (agentHint && agentHint.trim() ? agentHint.trim() : null);
  if (agentId) return `Agent ${agentId}`;
  return sessionKey.replace(/^agent:/, "");
}

function parseProbeSessionRows(payload: unknown): ProbeSessionRow[] {
  const root = asRecord(payload);
  if (!root) return [];

  const rowsByKey = new Map<string, ProbeSessionRow>();

  const upsertRow = (row: Record<string, unknown>, agentHint?: string) => {
    const rowAgentId =
      typeof row.agentId === "string"
        ? row.agentId
        : typeof row.agent_id === "string"
          ? row.agent_id
          : undefined;
    const fallbackAgentId = (rowAgentId ?? agentHint ?? "unknown").trim() || "unknown";
    const sessionId =
      typeof row.sessionId === "string"
        ? row.sessionId
        : typeof row.session_id === "string"
          ? row.session_id
          : undefined;
    const key =
      typeof row.key === "string"
        ? row.key
        : typeof row.sessionKey === "string"
          ? row.sessionKey
          : typeof row.session_key === "string"
            ? row.session_key
            : sessionId
              ? `agent:${fallbackAgentId}:session:${sessionId}`
              : "";
    if (!key) return;

    let updatedAt = asNumber(row.updatedAt) ?? asNumber(row.updated_at) ?? asNumber(row.ts) ?? null;
    if (updatedAt === null) {
      const ageMs = asNumber(row.age);
      if (ageMs !== null) updatedAt = Date.now() - Math.max(0, ageMs);
    }
    if (updatedAt === null) updatedAt = Date.now();

    const displayName =
      typeof row.displayName === "string"
        ? row.displayName
        : typeof row.title === "string"
          ? row.title
          : undefined;
    const agentId = rowAgentId ?? agentHint ?? parseAgentIdFromSessionKey(key);
    const next: ProbeSessionRow = {
      key,
      label: normalizeSessionLabel(key, displayName, agentId),
      updatedAt,
      agentId: agentId ?? undefined,
      percentUsed: asNumber(row.percentUsed) ?? asNumber(row.percent_used) ?? undefined,
      inputTokens: asNumber(row.inputTokens) ?? asNumber(row.input_tokens) ?? undefined,
      outputTokens: asNumber(row.outputTokens) ?? asNumber(row.output_tokens) ?? undefined,
    };

    const previous = rowsByKey.get(key);
    if (!previous || (next.updatedAt ?? 0) >= (previous.updatedAt ?? 0)) {
      rowsByKey.set(key, next);
    }
  };

  const ingestRecentRows = (value: unknown, agentHint?: string) => {
    const rows = Array.isArray(value) ? value : [];
    rows.forEach((row) => {
      const rec = asRecord(row);
      if (!rec) return;
      upsertRow(rec, agentHint);
    });
  };

  const ingestByAgent = (value: unknown) => {
    const rows = Array.isArray(value) ? value : [];
    rows.forEach((entry) => {
      const rec = asRecord(entry);
      if (!rec) return;
      const agentId =
        typeof rec.agentId === "string"
          ? rec.agentId
          : typeof rec.name === "string"
            ? rec.name
            : undefined;
      ingestRecentRows(rec.recent, agentId);
    });
  };

  const ingestScope = (scope: Record<string, unknown>) => {
    const sessions = asRecord(scope.sessions);
    ingestRecentRows(sessions?.recent);
    ingestByAgent(sessions?.byAgent);

    const summary = asRecord(scope.summary);
    const summarySessions = asRecord(summary?.sessions);
    ingestRecentRows(summarySessions?.recent);
    ingestByAgent(summarySessions?.byAgent);

    const agents = Array.isArray(scope.agents) ? scope.agents : [];
    agents.forEach((agent) => {
      const rec = asRecord(agent);
      if (!rec) return;
      const agentId =
        typeof rec.agentId === "string"
          ? rec.agentId
          : typeof rec.name === "string"
            ? rec.name
            : undefined;
      const agentSessions = asRecord(rec.sessions);
      ingestRecentRows(agentSessions?.recent, agentId);
    });
  };

  const targets = Array.isArray(root.targets) ? root.targets : [];
  targets.forEach((target) => {
    const rec = asRecord(target);
    if (!rec) return;
    const health = asRecord(rec.health);
    const summary = asRecord(rec.summary);
    if (health) ingestScope(health);
    if (summary) ingestScope(summary);
  });

  const rootHealth = asRecord(root.health);
  const rootSummary = asRecord(root.summary);
  if (rootHealth) ingestScope(rootHealth);
  if (rootSummary) ingestScope(rootSummary);

  return Array.from(rowsByKey.values())
    .sort((a, b) => (b.updatedAt ?? 0) - (a.updatedAt ?? 0))
    .slice(0, 32);
}

function deriveActionsFromProbeRows(args: {
  rows: ProbeSessionRow[];
  selectedSessionKey: string;
  nowMs: number;
  windowStartMs: number;
  clock: Map<string, number>;
}): { actions: RiverAction[]; causalLinks: CausalLink[] } {
  if (args.rows.length === 0) return { actions: [], causalLinks: [] };

  const rowByKey = new Map(args.rows.map((row) => [row.key, row] as const));
  const selectedKeys =
    args.selectedSessionKey === "__all__"
      ? args.rows.slice(0, 3).map((row) => row.key)
      : [args.selectedSessionKey];
  const selectedRows = selectedKeys
    .map((key) => rowByKey.get(key))
    .filter((row): row is ProbeSessionRow => Boolean(row));
  const sourceRows = selectedRows.length > 0 ? selectedRows : args.rows.slice(0, 3);

  const actions: RiverAction[] = [];
  sourceRows.forEach((row, index) => {
    const id = `probe:session:${row.key}`;
    const fallbackTimestamp = Math.max(
      args.windowStartMs,
      (row.updatedAt ?? args.nowMs) - index * 420,
    );
    const timestamp = args.clock.get(id) ?? fallbackTimestamp;
    args.clock.set(id, timestamp);
    if (timestamp < args.windowStartMs) return;

    const percentUsed = row.percentUsed ?? null;
    const riskScore = percentUsed !== null ? clamp01((percentUsed / 100) * 0.88 + 0.08) : 0.26;
    const noveltyScore =
      row.outputTokens !== undefined
        ? clamp01(Math.log10(Math.max(1, row.outputTokens) + 10) / 4)
        : 0.18;
    const blastRadius =
      row.inputTokens !== undefined
        ? clamp01(Math.log10(Math.max(1, row.inputTokens) + 10) / 4)
        : 0.14;
    const policyStatus: RiverAction["policyStatus"] =
      percentUsed !== null && percentUsed >= 90 ? "approval-required" : "allowed";
    const agentId = row.agentId ?? parseAgentIdFromSessionKey(row.key) ?? row.label;

    actions.push({
      id,
      kind: "message",
      label: `Session · ${summarizeText(row.label, 62)}`,
      agentId,
      timestamp,
      policyStatus,
      riskScore,
      noveltyScore,
      blastRadius,
      consequence:
        percentUsed !== null
          ? `${Math.round(percentUsed)}% context usage`
          : "OpenClaw probe session",
    });
  });

  return { actions, causalLinks: [] };
}

function isMethodUnavailableError(error: unknown): boolean {
  const message =
    error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
  return (
    message.includes("unknown method") ||
    message.includes("method not found") ||
    message.includes("not implemented")
  );
}

function runtimeSessionRows(
  runtime: OpenClawGatewayRuntime | undefined,
): Array<{ key: string; label: string; updatedAt?: number }> {
  const rows: Array<{ key: string; label: string; updatedAt?: number }> = [];
  const updatedAt = runtime?.lastMessageAtMs ?? runtime?.connectedAtMs ?? Date.now();
  const connectedNodes = (runtime?.nodes ?? []).filter((node) => node.connected !== false);
  const presenceRows = Array.isArray(runtime?.presence) ? runtime.presence : [];
  const approvals = runtime?.execApprovalQueue ?? [];

  if (connectedNodes.length > 0) {
    rows.push({
      key: RUNTIME_SESSION_KEYS.nodes,
      label: `NODES (${connectedNodes.length})`,
      updatedAt,
    });
  }
  if (presenceRows.length > 0) {
    rows.push({
      key: RUNTIME_SESSION_KEYS.presence,
      label: `PRESENCE (${presenceRows.length})`,
      updatedAt,
    });
  }
  if (approvals.length > 0) {
    rows.push({
      key: RUNTIME_SESSION_KEYS.approvals,
      label: `APPROVALS (${approvals.length})`,
      updatedAt,
    });
  }
  return rows;
}

function normalizeRuntimeLabel(value: unknown, fallback: string): string {
  if (typeof value !== "string") return fallback;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : fallback;
}

function deriveActionsFromRuntimeState(args: {
  runtime: OpenClawGatewayRuntime | undefined;
  selectedSessionKey: string;
  nowMs: number;
  windowStartMs: number;
  clock: Map<string, number>;
}): { actions: RiverAction[]; causalLinks: CausalLink[] } {
  const runtime = args.runtime;
  if (!runtime) return { actions: [], causalLinks: [] };

  const actions: RiverAction[] = [];
  const causalLinks: CausalLink[] = [];
  const selected = resolveRuntimeFallbackSelection(args.selectedSessionKey);
  const includeNodes = selected.includes(RUNTIME_SESSION_KEYS.nodes);
  const includePresence = selected.includes(RUNTIME_SESSION_KEYS.presence);
  const includeApprovals = selected.includes(RUNTIME_SESSION_KEYS.approvals);
  const baseTimestamp = runtime.lastMessageAtMs ?? runtime.connectedAtMs ?? args.nowMs;

  function stamp(id: string, fallbackTimestamp: number): number {
    const existing = args.clock.get(id);
    if (typeof existing === "number") return existing;
    args.clock.set(id, fallbackTimestamp);
    return fallbackTimestamp;
  }

  if (includeNodes) {
    const connectedNodes = (runtime.nodes ?? [])
      .filter((node) => node.connected !== false)
      .slice(0, 18);
    connectedNodes.forEach((node, index) => {
      const nodeId = normalizeRuntimeLabel(node.nodeId, `node-${index + 1}`);
      const label = normalizeRuntimeLabel(node.displayName ?? node.nodeId, `Node ${index + 1}`);
      const consequenceParts = [node.platform, node.version].filter(
        (value): value is string => typeof value === "string" && value.trim().length > 0,
      );
      const id = `runtime:node:${nodeId}`;
      const fallbackTimestamp = Math.max(
        args.windowStartMs,
        (typeof node.connectedAtMs === "number" ? node.connectedAtMs : baseTimestamp) - index * 280,
      );
      const timestamp = stamp(id, fallbackTimestamp);
      if (timestamp < args.windowStartMs) return;

      actions.push({
        id,
        kind: "query",
        label: `Node · ${label}`,
        agentId: label,
        timestamp,
        policyStatus: "allowed",
        riskScore: 0.14,
        noveltyScore: 0.1,
        blastRadius: 0.16,
        consequence: consequenceParts.length > 0 ? consequenceParts.join(" · ") : "Connected node",
      });
    });
  }

  if (includePresence) {
    const rows = Array.isArray(runtime.presence) ? runtime.presence : [];
    rows.slice(0, 20).forEach((row, index) => {
      const rec = asRecord(row);
      const source = rec?.client ?? rec?.id ?? rec?.session_key ?? rec?.sessionKey;
      const label = normalizeRuntimeLabel(source, `Presence ${index + 1}`);
      const id = `runtime:presence:${label}:${index}`;
      const fallbackTimestamp = Math.max(args.windowStartMs, baseTimestamp - 1800 - index * 180);
      const timestamp = stamp(id, fallbackTimestamp);
      if (timestamp < args.windowStartMs) return;

      actions.push({
        id,
        kind: "message",
        label: `Presence · ${label}`,
        agentId: label,
        timestamp,
        policyStatus: "allowed",
        riskScore: 0.16,
        noveltyScore: 0.12,
        blastRadius: 0.1,
        consequence: "Gateway heartbeat",
      });
    });
  }

  if (includeApprovals) {
    const approvals = runtime.execApprovalQueue ?? [];
    approvals.slice(0, 24).forEach((approval, index) => {
      const id = `runtime:approval:${approval.id}`;
      const command = normalizeRuntimeLabel(approval.request.command, "pending command");
      const agentId = normalizeRuntimeLabel(approval.request.agentId, "operator");
      const fallbackTimestamp = Math.max(args.windowStartMs, baseTimestamp - 900 - index * 140);
      const timestamp = stamp(id, fallbackTimestamp);
      if (timestamp < args.windowStartMs) return;

      actions.push({
        id,
        kind: "exec",
        label: `Approval · ${summarizeText(command, 62)}`,
        agentId,
        timestamp,
        policyStatus: "approval-required",
        riskScore: 0.88,
        noveltyScore: 0.3,
        blastRadius: 0.58,
        consequence: approval.request.ask ?? approval.request.security ?? undefined,
      });
    });
  }

  return { actions, causalLinks };
}

function derivePolicyStatusFromPolicyCheck(outputText: string | null): {
  status: RiverAction["policyStatus"];
  riskScore: number;
  consequence?: string;
} {
  if (!outputText) return { status: "uncovered", riskScore: 0.4 };

  try {
    const parsed = JSON.parse(outputText) as unknown;
    if (typeof parsed !== "object" || !parsed) return { status: "uncovered", riskScore: 0.4 };
    const rec = parsed as Record<string, unknown>;
    const allowed = rec.allowed === true;
    const denied = rec.denied === true;
    const warn = rec.warn === true;
    const guard = typeof rec.guard === "string" ? rec.guard : null;
    const reason = typeof rec.reason === "string" ? rec.reason : null;
    const message = typeof rec.message === "string" ? rec.message : null;

    if (denied || (!allowed && guard)) {
      return { status: "denied", riskScore: 0.92, consequence: reason ?? message ?? undefined };
    }
    if (warn) {
      return { status: "exception", riskScore: 0.65, consequence: reason ?? message ?? undefined };
    }
    if (allowed) {
      return { status: "allowed", riskScore: 0.18, consequence: message ?? undefined };
    }
  } catch {
    // ignore
  }

  return { status: "uncovered", riskScore: 0.45 };
}

function deriveActionsFromPreview(args: {
  sessionKey: string;
  items: Array<{ role?: string; text?: string }>;
  nowMs: number;
  clock: Map<string, number>;
  windowStartMs: number;
}): { actions: RiverAction[]; causalLinks: CausalLink[] } {
  const agentId = parseAgentIdFromSessionKey(args.sessionKey);
  const actions: RiverAction[] = [];
  const causalLinks: CausalLink[] = [];

  let currentMessageId: string | null = null;
  let chainTailId: string | null = null;
  let toolIndex = 0;
  let cachedPolicyStatus: RiverAction["policyStatus"] | null = null;
  let cachedPolicyRisk = 0.25;

  function suggestTimestamp(itemIndex: number): number {
    // Sessions don't expose per-message timestamps in preview yet, so we infer a
    // stable order-based timeline within the live window.
    const remaining = Math.max(0, args.items.length - 1 - itemIndex);
    const approx = args.nowMs - remaining * 420;
    return Math.max(args.windowStartMs, approx);
  }

  function stamp(id: string, fallbackTimestamp: number): number {
    const existing = args.clock.get(id);
    if (typeof existing === "number") return existing;
    args.clock.set(id, fallbackTimestamp);
    return fallbackTimestamp;
  }

  function pushAction(action: RiverAction) {
    if (action.timestamp < args.windowStartMs) return;
    actions.push(action);
  }

  for (let i = 0; i < args.items.length; i++) {
    const item = args.items[i];
    const role = typeof item.role === "string" ? item.role : "unknown";
    const text = typeof item.text === "string" ? item.text : "";

    if (role === "user") {
      const messageId = parseMessageId(text) ?? `user:${hashToIndex(text, 1_000_000)}`;
      currentMessageId = messageId;
      toolIndex = 0;
      cachedPolicyStatus = null;
      cachedPolicyRisk = 0.25;

      const id = `${args.sessionKey}:user:${messageId}`;
      const timestamp = stamp(id, suggestTimestamp(i));
      pushAction({
        id,
        kind: "message",
        label: `User · ${summarizeText(text.replace(/\[message_id:[^\]]+\]/gi, ""))}`,
        agentId,
        timestamp,
        policyStatus: "allowed",
        riskScore: 0.12,
        noveltyScore: 0.15,
        blastRadius: 0.08,
      });
      chainTailId = id;
      continue;
    }

    if (role === "tool" && text.trim().toLowerCase().startsWith("call ")) {
      const tool = text.trim().slice(5).trim();
      const msgId = currentMessageId ?? `tool:${tool}`;
      const id = `${args.sessionKey}:tool:${msgId}:${tool}:${toolIndex++}`;
      const timestamp = stamp(id, suggestTimestamp(i));

      const next = args.items[i + 1];
      const nextRole = typeof next?.role === "string" ? next.role : null;
      const nextText = typeof next?.text === "string" ? next.text : null;
      const outputText =
        nextRole === "tool" && nextText && !nextText.trim().toLowerCase().startsWith("call ")
          ? nextText
          : null;
      if (outputText) i += 1;

      let kind: RiverAction["kind"] =
        tool === "exec" ? "exec" : tool.includes("policy") ? "query" : "message";
      let policyStatus: RiverAction["policyStatus"] = cachedPolicyStatus ?? "allowed";
      let riskScore = cachedPolicyRisk;
      let consequence: string | undefined;

      if (tool === "policy_check") {
        const derived = derivePolicyStatusFromPolicyCheck(outputText);
        policyStatus = derived.status;
        riskScore = derived.riskScore;
        consequence = derived.consequence;
        cachedPolicyStatus = derived.status;
        cachedPolicyRisk = derived.riskScore;
      } else if (tool === "exec") {
        policyStatus = cachedPolicyStatus ?? "allowed";
        riskScore = Math.max(0.15, cachedPolicyRisk * 0.6);
        consequence = outputText ? summarizeText(outputText, 80) : undefined;
      }

      const predecessors = chainTailId ? [chainTailId] : undefined;
      pushAction({
        id,
        kind,
        label:
          tool === "policy_check" ? "Policy Check" : tool === "exec" ? "Exec" : `Tool · ${tool}`,
        agentId,
        timestamp,
        policyStatus,
        riskScore: clamp01(riskScore),
        noveltyScore: tool === "exec" ? 0.22 : tool === "policy_check" ? 0.35 : 0.18,
        blastRadius: tool === "exec" ? 0.35 : tool === "policy_check" ? 0.2 : 0.15,
        consequence,
        predecessors,
      });
      if (chainTailId) {
        causalLinks.push({ fromId: chainTailId, toId: id, strength: 0.9, type: "direct" });
      }
      chainTailId = id;
      continue;
    }

    if (role === "assistant") {
      const msgId = currentMessageId ?? `assistant:${hashToIndex(text, 1_000_000)}`;
      const id = `${args.sessionKey}:assistant:${msgId}:${hashToIndex(text, 10_000)}`;
      const timestamp = stamp(id, suggestTimestamp(i));
      const predecessors = chainTailId ? [chainTailId] : undefined;
      pushAction({
        id,
        kind: "message",
        label: `Assistant · ${summarizeText(text)}`,
        agentId,
        timestamp,
        policyStatus: cachedPolicyStatus ?? "allowed",
        riskScore: clamp01((cachedPolicyRisk ?? 0.2) * 0.4),
        noveltyScore: 0.15,
        blastRadius: 0.12,
        predecessors,
      });
      if (chainTailId) {
        causalLinks.push({ fromId: chainTailId, toId: id, strength: 0.7, type: "temporal" });
      }
      chainTailId = id;
      continue;
    }
  }

  return { actions, causalLinks };
}

export function ForensicsRiverView() {
  const navigate = useNavigate();
  const { sessionId } = useParams<{ sessionId?: string }>();
  const oc = useOpenClaw();
  const { status: daemonStatus } = useConnection();
  const nexusSessions = useSessions({ appId: "nexus", archived: false });
  const activeSession = useActiveSession();
  const { setActiveSession } = useSessionActions();
  const rt = oc.runtimeByGatewayId[oc.activeGatewayId];

  const [mode, setMode] = React.useState<"live" | "replay">("live");
  const [windowMs, setWindowMs] = React.useState(120_000);
  const [sessions, setSessions] = React.useState<
    Array<{ key: string; label: string; updatedAt?: number }>
  >([]);
  const [selectedSessionKey, setSelectedSessionKey] = React.useState<string>("__all__");
  const [sessionMenuOpen, setSessionMenuOpen] = React.useState(false);
  const [windowMenuOpen, setWindowMenuOpen] = React.useState(false);
  const [layoutMode, setLayoutMode] = React.useState<NexusLayoutMode>("radial");
  const [layoutDropdownOpen, setLayoutDropdownOpen] = React.useState(false);
  const [commandQuery, setCommandQuery] = React.useState("");
  const [openAppId, setOpenAppId] = React.useState<StrikecellDomainId | null>("security-overview");
  const [sceneMode, setSceneMode] = React.useState<NexusSceneMode>("security");
  const [sceneRevision, setSceneRevision] = React.useState(0);
  const [sceneTransition, setSceneTransition] = React.useState<{
    from: NexusSceneMode;
    to: NexusSceneMode;
  } | null>(null);
  const [focusedAgentId, setFocusedAgentId] = React.useState<string | null>(null);
  const [probeSessionRows, setProbeSessionRows] = React.useState<ProbeSessionRow[]>([]);
  const tauriAvailable = React.useMemo(() => isTauri(), []);

  const clockByGatewayRef = React.useRef<Record<string, Map<string, number>>>({});
  const sessionsListUnavailableRef = React.useRef(false);
  const sessionPreviewUnavailableRef = React.useRef(false);
  const sceneTransitionTimerRef = React.useRef<number | null>(null);

  React.useEffect(() => {
    return () => {
      if (sceneTransitionTimerRef.current !== null) {
        window.clearTimeout(sceneTransitionTimerRef.current);
      }
    };
  }, []);

  React.useEffect(() => {
    if (!tauriAvailable) {
      setProbeSessionRows([]);
      return;
    }

    let cancelled = false;
    let inFlight = false;

    async function tick() {
      if (inFlight) return;
      inFlight = true;
      try {
        const payload = await openclawGatewayProbe(2400);
        const rows = parseProbeSessionRows(payload);
        if (!cancelled) setProbeSessionRows(rows);
      } catch {
        if (!cancelled) setProbeSessionRows([]);
      } finally {
        inFlight = false;
      }
    }

    void tick();
    const interval = window.setInterval(() => void tick(), 18_000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [tauriAvailable]);

  React.useEffect(() => {
    const onFocusAgentSession = (event: Event) => {
      const custom = event as CustomEvent<ShellFocusAgentSessionDetail>;
      const detail = custom.detail;
      if (!detail) return;
      if (typeof detail.sessionKey === "string" && detail.sessionKey.trim().length > 0) {
        setSelectedSessionKey(detail.sessionKey);
      }
      if (typeof detail.agentId === "string" && detail.agentId.trim().length > 0) {
        setFocusedAgentId(detail.agentId.trim());
      }
    };

    window.addEventListener(SHELL_FOCUS_AGENT_SESSION_EVENT, onFocusAgentSession as EventListener);
    return () =>
      window.removeEventListener(
        SHELL_FOCUS_AGENT_SESSION_EVENT,
        onFocusAgentSession as EventListener,
      );
  }, []);

  const getClock = React.useCallback((gatewayId: string) => {
    const existing = clockByGatewayRef.current[gatewayId];
    if (existing) return existing;
    const next = new Map<string, number>();
    clockByGatewayRef.current[gatewayId] = next;
    return next;
  }, []);

  const [datasetByGatewayId, setDatasetByGatewayId] = React.useState<Record<string, RiverDataset>>(
    {},
  );

  const statusLabel =
    rt?.status === "connected"
      ? "OPENCLAW LIVE"
      : rt?.status === "error"
        ? "OFFLINE (ERROR)"
        : "OFFLINE";

  const telemetryDataset = React.useMemo<RiverDataset>(() => {
    const activeDataset = datasetByGatewayId[oc.activeGatewayId] ?? {
      actions: [],
      agents: [],
      policies: demoPolicies(),
      signals: [],
      incidents: [],
      detectors: demoDetectors(),
      causalLinks: [],
      timeRange: [Date.now() - windowMs, Date.now()] as [number, number],
    };

    if (activeDataset.actions.length > 0) return activeDataset;
    if (probeSessionRows.length === 0) return activeDataset;

    const nowMs = Date.now();
    const windowStartMs = nowMs - windowMs;
    const clock = getClock(oc.activeGatewayId);
    const probeDerived = deriveActionsFromProbeRows({
      rows: probeSessionRows,
      selectedSessionKey,
      nowMs,
      windowStartMs,
      clock,
    });
    if (probeDerived.actions.length === 0) return activeDataset;

    const dedupedActions = Array.from(
      new Map(probeDerived.actions.map((action) => [action.id, action])).values(),
    ).sort((a, b) => a.timestamp - b.timestamp);
    const agents: Agent[] = Array.from(new Set(dedupedActions.map((action) => action.agentId))).map(
      (id) => ({
        id,
        label: id,
        color: River.AGENT_COLORS[hashToIndex(id, River.AGENT_COLORS.length)],
      }),
    );
    const signals: SignalData[] = dedupedActions.map((action) => ({
      id: `signal:${action.id}`,
      type: action.policyStatus === "approval-required" ? "anomaly" : "behavioral",
      score: clamp01(Math.max(action.riskScore, 0.24)),
      label:
        action.policyStatus === "approval-required"
          ? `ANOMALY · ${action.label}`
          : `BEHAVIORAL · ${action.label}`,
      actionId: action.id,
      detectorId: "detector-0",
    }));

    return {
      ...activeDataset,
      actions: dedupedActions,
      agents,
      policies: demoPolicies(),
      signals,
      incidents: [],
      detectors: demoDetectors(),
      causalLinks: probeDerived.causalLinks,
      timeRange: [windowStartMs, nowMs + LIVE_TIME_RANGE_LEAD_MS],
    };
  }, [
    datasetByGatewayId,
    getClock,
    oc.activeGatewayId,
    probeSessionRows,
    selectedSessionKey,
    windowMs,
  ]);
  const activeStrikecell = React.useMemo(
    () => NEXUS_RAIL_STRIKECELLS.find((strikecell) => strikecell.id === openAppId) ?? null,
    [openAppId],
  );
  const sessionRows = React.useMemo(() => {
    if (sessions.length > 0) return sessions;
    if (probeSessionRows.length > 0) {
      return probeSessionRows.map((row) => ({
        key: row.key,
        label: row.label,
        updatedAt: row.updatedAt,
      }));
    }
    return runtimeSessionRows(rt);
  }, [probeSessionRows, rt, sessions]);
  const sessionOptions = React.useMemo(
    () => [
      { value: "__all__", label: "ALL (top 3)" },
      ...sessionRows.map((session) => ({ value: session.key, label: session.label })),
    ],
    [sessionRows],
  );
  const windowOptions = React.useMemo(
    () => [
      { value: "60000", label: "60s" },
      { value: "120000", label: "2m" },
      { value: "300000", label: "5m" },
    ],
    [],
  );
  const sceneMeta = SCENE_META[sceneMode];

  const sceneDataset = React.useMemo<RiverDataset>(() => {
    if (sceneMode === "attack") {
      const focusActions = telemetryDataset.actions.filter(
        (action) =>
          action.kind === "exec" ||
          action.policyStatus === "approval-required" ||
          action.policyStatus === "denied" ||
          action.policyStatus === "exception",
      );
      const attackSeed = focusActions.length > 0 ? focusActions : telemetryDataset.actions;
      return {
        ...telemetryDataset,
        actions: attackSeed.slice(-48).map((action) =>
          action.kind === "exec"
            ? {
                ...action,
                label: action.label.startsWith("Lab ·") ? action.label : `Lab · ${action.label}`,
                blastRadius: clamp01(action.blastRadius + 0.16),
                riskScore: clamp01(action.riskScore + 0.08),
              }
            : action,
        ),
      };
    }

    if (sceneMode === "threat") {
      const threatActions = telemetryDataset.actions
        .filter((action) => action.policyStatus !== "allowed" || action.riskScore >= 0.45)
        .slice(-54);
      const threatSignals = telemetryDataset.signals
        .filter(
          (signal) => signal.score >= 0.45 || signal.type === "anomaly" || signal.type === "risk",
        )
        .slice(-60);
      return {
        ...telemetryDataset,
        actions: threatActions.length > 0 ? threatActions : telemetryDataset.actions.slice(-40),
        signals: threatSignals.length > 0 ? threatSignals : telemetryDataset.signals.slice(-24),
      };
    }

    if (sceneMode === "arena") {
      return {
        ...telemetryDataset,
        policies: telemetryDataset.policies.map((policy) => ({
          ...policy,
          type: policy.type === "hard-deny" ? "soft" : policy.type,
          coverageGap: false,
        })),
      };
    }

    return telemetryDataset;
  }, [sceneMode, telemetryDataset]);

  const focusedSceneDataset = React.useMemo<RiverDataset>(() => {
    if (!focusedAgentId) return sceneDataset;

    const boostedActions = sceneDataset.actions.map((action) => {
      if (matchesFocusedAgent(action.agentId, focusedAgentId)) {
        return {
          ...action,
          riskScore: clamp01(Math.max(action.riskScore, 0.52)),
          noveltyScore: clamp01(Math.max(action.noveltyScore, 0.34)),
          blastRadius: clamp01(Math.max(action.blastRadius, 0.24)),
        };
      }
      return {
        ...action,
        riskScore: clamp01(action.riskScore * 0.55),
        noveltyScore: clamp01(action.noveltyScore * 0.68),
        blastRadius: clamp01(action.blastRadius * 0.72),
      };
    });

    const focusSignals: SignalData[] = boostedActions
      .filter((action) => matchesFocusedAgent(action.agentId, focusedAgentId))
      .slice(-22)
      .map((action) => ({
        id: `focus:${focusedAgentId}:${action.id}`,
        type: "anomaly",
        score: clamp01(Math.max(action.riskScore, 0.45)),
        label: `FOCUS · ${action.label}`,
        actionId: action.id,
        detectorId: "detector-0",
      }));

    const signalMap = new Map<string, SignalData>();
    for (const signal of sceneDataset.signals) signalMap.set(signal.id, signal);
    for (const signal of focusSignals) signalMap.set(signal.id, signal);

    return {
      ...sceneDataset,
      actions: boostedActions,
      signals: Array.from(signalMap.values()),
    };
  }, [focusedAgentId, sceneDataset]);

  React.useEffect(() => {
    if (selectedSessionKey === "__all__") {
      setFocusedAgentId(null);
      return;
    }
    if (!selectedSessionKey.startsWith("agent:")) return;
    const nextFocusedAgent = parseAgentIdFromSessionKey(selectedSessionKey);
    setFocusedAgentId((current) => {
      if (current && matchesFocusedAgent(current, nextFocusedAgent)) return current;
      return nextFocusedAgent;
    });
  }, [selectedSessionKey]);

  const agentGlyphs = useAgentCognitionState({
    actions: telemetryDataset.actions,
    sessionRows,
    focusedAgentId,
  });

  const focusedGlyph = React.useMemo(
    () => agentGlyphs.find((glyph) => glyph.isFocused) ?? null,
    [agentGlyphs],
  );

  const handleClearFocus = React.useCallback(() => {
    setSelectedSessionKey("__all__");
    setFocusedAgentId(null);
  }, [setFocusedAgentId, setSelectedSessionKey]);

  const sceneFeatureFlags = React.useMemo(
    () => ({
      showPolicyRails: sceneMode !== "arena",
      showCausalThreads: true,
      showSignals: sceneMode !== "arena",
      showDetectors: sceneMode !== "attack",
      showIncidents: sceneMode === "threat" ? true : sceneDataset.incidents.length > 0,
    }),
    [sceneDataset.incidents.length, sceneMode],
  );

  React.useEffect(() => {
    if (!sessionId) return;
    const matched = nexusSessions.find((session) => session.id === sessionId);
    if (matched) {
      if (activeSession?.id !== sessionId) setActiveSession(sessionId);
      return;
    }
    navigate("/nexus", { replace: true });
  }, [activeSession?.id, navigate, nexusSessions, sessionId, setActiveSession]);

  React.useEffect(() => {
    if (rt?.status !== "connected") return;

    async function refreshRuntimeSlices() {
      await Promise.allSettled([
        oc.refreshNodes(oc.activeGatewayId),
        oc.refreshPresence(oc.activeGatewayId),
      ]);
    }

    void refreshRuntimeSlices();
    const interval = window.setInterval(() => {
      void refreshRuntimeSlices();
    }, 9000);
    return () => {
      window.clearInterval(interval);
    };
  }, [oc, oc.activeGatewayId, rt?.status]);

  // Poll session inventory.
  React.useEffect(() => {
    if (rt?.status !== "connected") {
      setSessions([]);
      sessionsListUnavailableRef.current = false;
      return;
    }

    let cancelled = false;
    let inFlight = false;

    async function tick() {
      if (inFlight) return;
      inFlight = true;
      const runtimeRows = runtimeSessionRows(rt);
      try {
        if (sessionsListUnavailableRef.current) {
          if (!cancelled) setSessions(runtimeRows);
          if (
            !cancelled &&
            selectedSessionKey !== "__all__" &&
            !runtimeRows.some((s) => s.key === selectedSessionKey)
          ) {
            setSelectedSessionKey(runtimeRows[0]?.key ?? "__all__");
          }
          return;
        }

        const res = await oc.request<SessionListResponse>("sessions.list");
        const rows = Array.isArray(res.sessions) ? res.sessions : [];
        const normalized = rows
          .map((s) => ({
            key: String(s.key ?? ""),
            label: String(s.displayName ?? s.key ?? ""),
            updatedAt: typeof s.updatedAt === "number" ? s.updatedAt : undefined,
          }))
          .filter((s) => s.key);
        normalized.sort((a, b) => (b.updatedAt ?? 0) - (a.updatedAt ?? 0));
        const nextRows = normalized.length > 0 ? normalized : runtimeRows;
        if (!cancelled) setSessions(nextRows);
        if (
          !cancelled &&
          selectedSessionKey !== "__all__" &&
          !nextRows.some((s) => s.key === selectedSessionKey)
        ) {
          setSelectedSessionKey(nextRows[0]?.key ?? "__all__");
        }
      } catch (error) {
        if (isMethodUnavailableError(error)) {
          sessionsListUnavailableRef.current = true;
        }
        if (!cancelled) setSessions(runtimeRows);
        if (
          !cancelled &&
          selectedSessionKey !== "__all__" &&
          !runtimeRows.some((s) => s.key === selectedSessionKey)
        ) {
          setSelectedSessionKey(runtimeRows[0]?.key ?? "__all__");
        }
      } finally {
        inFlight = false;
      }
    }

    tick().catch(() => {});
    const interval = window.setInterval(() => tick().catch(() => {}), 7000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [oc, rt, rt?.status, selectedSessionKey]);

  // Poll session preview + build river dataset.
  React.useEffect(() => {
    if (mode !== "live") return;
    if (rt?.status !== "connected") {
      sessionPreviewUnavailableRef.current = false;
      return;
    }

    const gatewayId = oc.activeGatewayId;
    const clock = getClock(gatewayId);

    let cancelled = false;
    let inFlight = false;
    let cycle = 0;

    async function tick() {
      if (inFlight) return;
      inFlight = true;
      try {
        const nowMs = Date.now();
        const windowStartMs = nowMs - windowMs;

        // Refresh sessions periodically; previews update fast.
        cycle = (cycle + 1) % 5;
        if (cycle === 1 && sessionRows.length === 0 && !sessionsListUnavailableRef.current) {
          // Best-effort warm-up when sessions list hasn't arrived yet.
          await oc.request("sessions.list").catch(() => {});
        }

        const rawKeys =
          selectedSessionKey === "__all__"
            ? sessionRows.slice(0, 3).map((s) => s.key)
            : [selectedSessionKey];
        const keys = rawKeys.length > 0 ? rawKeys : [selectedSessionKey];
        const previewKeys = keys.filter((key) => !isRuntimeFallbackKey(key));

        const actions: RiverAction[] = [];
        const causalLinks: CausalLink[] = [];
        let previewActionsCount = 0;

        if (!sessionPreviewUnavailableRef.current && previewKeys.length > 0) {
          try {
            const previewRes = await oc.request<SessionPreviewResponse>("sessions.preview", {
              keys: previewKeys,
            });
            const previews = Array.isArray(previewRes.previews) ? previewRes.previews : [];

            for (const preview of previews) {
              if (preview.status !== "ok") continue;
              const items = Array.isArray(preview.items) ? preview.items : [];
              const derived = deriveActionsFromPreview({
                sessionKey: preview.key,
                items,
                nowMs,
                clock,
                windowStartMs,
              });
              actions.push(...derived.actions);
              causalLinks.push(...derived.causalLinks);
            }

            previewActionsCount = actions.length;
          } catch (error) {
            if (isMethodUnavailableError(error)) {
              sessionPreviewUnavailableRef.current = true;
            } else {
              throw error;
            }
          }
        }

        const includeFullRuntime =
          selectedSessionKey === "__all__" ||
          keys.some((key) => isRuntimeFallbackKey(key)) ||
          sessionPreviewUnavailableRef.current ||
          previewActionsCount === 0;
        const runtimeDerived = deriveActionsFromRuntimeState({
          runtime: rt,
          selectedSessionKey: includeFullRuntime
            ? selectedSessionKey
            : RUNTIME_SESSION_KEYS.approvals,
          nowMs,
          windowStartMs,
          clock,
        });
        actions.push(...runtimeDerived.actions);
        causalLinks.push(...runtimeDerived.causalLinks);

        const dedupedActions = Array.from(
          new Map(actions.map((action) => [action.id, action])).values(),
        );
        const dedupedCausalLinks = Array.from(
          new Map(
            causalLinks.map((link) => [`${link.fromId}:${link.toId}:${link.type}`, link]),
          ).values(),
        );
        dedupedActions.sort((a, b) => a.timestamp - b.timestamp);

        // Build agents list from action agentIds.
        const agentIds = Array.from(new Set(dedupedActions.map((a) => a.agentId)));
        const agents: Agent[] = agentIds.map((id) => ({
          id,
          label: id,
          color: River.AGENT_COLORS[hashToIndex(id, River.AGENT_COLORS.length)],
        }));

        const signals: SignalData[] = dedupedActions
          .filter((a) => a.policyStatus !== "allowed" || a.riskScore > 0.55)
          .slice(-30)
          .map((a) => {
            const type =
              a.policyStatus === "uncovered"
                ? "coverage-gap"
                : a.policyStatus === "approval-required"
                  ? "anomaly"
                  : a.policyStatus === "denied"
                    ? "risk"
                    : "behavioral";
            return {
              id: `signal:${a.id}`,
              type,
              score: clamp01(Math.max(a.riskScore, 0.3)),
              label: `${type.toUpperCase()} · ${a.label}`,
              actionId: a.id,
              detectorId: "detector-0",
            };
          });

        const nextDataset: RiverDataset = {
          actions: dedupedActions,
          agents,
          policies: demoPolicies(),
          signals,
          incidents: [] as IncidentData[],
          detectors: demoDetectors(),
          causalLinks: dedupedCausalLinks,
          timeRange: [windowStartMs, nowMs + LIVE_TIME_RANGE_LEAD_MS],
        };

        if (!cancelled) {
          setDatasetByGatewayId((prev) => ({ ...prev, [gatewayId]: nextDataset }));
        }
      } catch {
        // keep last
      } finally {
        inFlight = false;
      }
    }

    tick().catch(() => {});
    const interval = window.setInterval(() => tick().catch(() => {}), 1200);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [
    getClock,
    mode,
    oc,
    oc.activeGatewayId,
    rt,
    rt?.status,
    selectedSessionKey,
    sessionRows,
    windowMs,
  ]);

  const handleOpenRailStrikecell = (id: StrikecellDomainId) => {
    const nextScene = SCENE_BY_STRIKECELL[id] ?? "security";
    if (openAppId === id && sceneMode === nextScene) {
      if (sceneTransitionTimerRef.current !== null) {
        window.clearTimeout(sceneTransitionTimerRef.current);
      }
      setSceneTransition({ from: sceneMode, to: nextScene });
      setSceneRevision((value) => value + 1);
      sceneTransitionTimerRef.current = window.setTimeout(() => {
        setSceneTransition(null);
        sceneTransitionTimerRef.current = null;
      }, 420);
      return;
    }

    if (sceneTransitionTimerRef.current !== null) {
      window.clearTimeout(sceneTransitionTimerRef.current);
    }
    setSceneTransition({ from: sceneMode, to: nextScene });
    setOpenAppId(id);
    setSceneMode(nextScene);
    setSceneRevision((value) => value + 1);
    sceneTransitionTimerRef.current = window.setTimeout(() => {
      setSceneTransition(null);
      sceneTransitionTimerRef.current = null;
    }, 560);
  };

  return (
    <div className="flex h-full w-full" style={{ background: "#050510" }}>
      <div className="relative min-w-0 flex-1">
        <NexusControlStrip
          connectionStatus={daemonStatus}
          layoutMode={layoutMode}
          activeStrikecell={activeStrikecell}
          brandSubline="Huntronomer"
          commandQuery={commandQuery}
          layoutDropdownOpen={layoutDropdownOpen}
          onOpenSearch={() => {}}
          onCommandQueryChange={setCommandQuery}
          onOpenCommandPalette={dispatchShellOpenCommandPalette}
          onToggleLayoutDropdown={() => setLayoutDropdownOpen((open) => !open)}
          onCloseLayoutDropdown={() => setLayoutDropdownOpen(false)}
          onSelectLayout={(mode) => {
            setLayoutMode(mode);
            setLayoutDropdownOpen(false);
          }}
          onOpenOperations={() => navigate("/operations?tab=fleet")}
          onOpenConnectionSettings={() => navigate("/operations?tab=connection")}
        />

        <div className="absolute top-[72px] left-0 right-0 z-20 px-4 py-2 pointer-events-none">
          <div className="pointer-events-auto flex items-center gap-2">
            <button onClick={() => setMode("live")} className={cls(mode === "live")}>
              LIVE
            </button>
            <button onClick={() => setMode("replay")} className={cls(mode === "replay")}>
              REPLAY
            </button>
            <div className="ml-2 text-xs font-mono text-white/35">{statusLabel}</div>
            <InlineMenuSelect
              value={selectedSessionKey}
              options={sessionOptions}
              open={sessionMenuOpen}
              onToggle={() => setSessionMenuOpen((prev) => !prev)}
              onClose={() => setSessionMenuOpen(false)}
              onSelect={(value) => {
                setSelectedSessionKey(value);
                setSessionMenuOpen(false);
              }}
              title="Session"
              className="ml-3"
            />
            <InlineMenuSelect
              value={String(windowMs)}
              options={windowOptions}
              open={windowMenuOpen}
              onToggle={() => setWindowMenuOpen((prev) => !prev)}
              onClose={() => setWindowMenuOpen(false)}
              onSelect={(value) => {
                setWindowMs(Number(value) || 120_000);
                setWindowMenuOpen(false);
              }}
              title="Live window"
            />
            <div className="ml-3 text-sm text-white/50">
              {focusedSceneDataset.actions.length} actions ·{" "}
              {Math.max(focusedSceneDataset.agents.length, agentGlyphs.length)} agents ·{" "}
              {focusedSceneDataset.signals.length} signals · {focusedSceneDataset.incidents.length}{" "}
              incidents
            </div>
          </div>

          <div className="pointer-events-auto mt-2 inline-flex max-w-[720px] items-start gap-3 rounded-lg border border-[rgba(213,173,87,0.26)] bg-[linear-gradient(180deg,rgba(10,13,20,0.92)_0%,rgba(6,9,15,0.95)_100%)] px-3 py-2 shadow-[0_12px_28px_rgba(0,0,0,0.45)]">
            <div className="text-[10px] font-mono uppercase tracking-[0.14em] text-[rgba(213,173,87,0.9)]">
              Scene
            </div>
            <div className="min-w-0">
              <div className="text-xs font-mono uppercase tracking-[0.1em] text-sdr-text-primary">
                {sceneMeta.title}
              </div>
              <div className="mt-0.5 text-xs text-sdr-text-secondary">{sceneMeta.subtitle}</div>
            </div>
          </div>
        </div>

        {sceneTransition ? (
          <div className="pointer-events-none absolute inset-0 z-20 flex items-center justify-center">
            <div className="rounded-xl border border-[rgba(213,173,87,0.36)] bg-[linear-gradient(180deg,rgba(10,13,20,0.92)_0%,rgba(6,9,14,0.94)_100%)] px-4 py-3 shadow-[0_18px_44px_rgba(0,0,0,0.52)]">
              <div className="text-[10px] font-mono uppercase tracking-[0.16em] text-[rgba(213,173,87,0.92)]">
                Station transfer
              </div>
              <div className="mt-1 text-sm font-mono uppercase tracking-[0.1em] text-sdr-text-primary">
                {SCENE_META[sceneTransition.to].title}
              </div>
              <div className="mt-1 text-xs text-sdr-text-secondary">
                Calibrating scene vectors and guard overlays.
              </div>
            </div>
          </div>
        ) : null}

        <River.RiverView
          key={`station:${sceneMode}:${sceneRevision}`}
          actions={focusedSceneDataset.actions}
          agents={focusedSceneDataset.agents}
          policies={focusedSceneDataset.policies}
          signals={focusedSceneDataset.signals}
          incidents={focusedSceneDataset.incidents}
          detectors={focusedSceneDataset.detectors}
          causalLinks={focusedSceneDataset.causalLinks}
          timeRange={focusedSceneDataset.timeRange}
          autoPlay={mode === "live"}
          showPolicyRails={sceneFeatureFlags.showPolicyRails}
          showCausalThreads={sceneFeatureFlags.showCausalThreads}
          showSignals={sceneFeatureFlags.showSignals}
          showDetectors={sceneFeatureFlags.showDetectors}
          showIncidents={sceneFeatureFlags.showIncidents}
        />

        <AgentGlyphOverlay glyphs={agentGlyphs} />
        <AgentOrbHud
          focusedGlyph={focusedGlyph}
          focusedSessionKey={focusedGlyph?.sessionKey ?? null}
          onClearFocus={handleClearFocus}
        />

        <NexusAppRail
          strikecells={NEXUS_RAIL_STRIKECELLS}
          openAppId={openAppId}
          onToggleApp={handleOpenRailStrikecell}
          mode="station"
          title="Stations"
          transitioningId={sceneTransition ? openAppId : null}
        />
      </div>
    </div>
  );
}

function cls(active: boolean) {
  return `text-xs font-mono px-2 py-1 border rounded ${
    active
      ? "border-white/30 text-white/80 bg-white/5"
      : "border-white/10 text-white/40 hover:text-white/70"
  }`;
}

type InlineMenuSelectProps = {
  value: string;
  options: Array<{ value: string; label: string }>;
  open: boolean;
  onToggle: () => void;
  onClose: () => void;
  onSelect: (value: string) => void;
  title: string;
  className?: string;
};

function InlineMenuSelect({
  value,
  options,
  open,
  onToggle,
  onClose,
  onSelect,
  title,
  className,
}: InlineMenuSelectProps) {
  const rootRef = React.useRef<HTMLDivElement | null>(null);

  React.useEffect(() => {
    if (!open) return;

    const onPointer = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) onClose();
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };

    window.addEventListener("mousedown", onPointer);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onPointer);
      window.removeEventListener("keydown", onKey);
    };
  }, [onClose, open]);

  const activeOption = options.find((option) => option.value === value);

  return (
    <div ref={rootRef} className={clsx("relative", className)}>
      <button
        type="button"
        onClick={onToggle}
        className={clsx(
          "origin-focus-ring premium-chip premium-chip--control flex items-center gap-2 px-2 py-1 text-xs font-mono",
          open ? "text-[color:var(--origin-gold)]" : "text-sdr-text-secondary",
        )}
        title={title}
        aria-label={title}
        aria-expanded={open}
      >
        <span>{activeOption?.label ?? value}</span>
        <span className="text-[10px] text-sdr-text-muted">{open ? "▲" : "▼"}</span>
      </button>

      {open ? (
        <div className="premium-panel premium-panel--dropdown absolute left-0 top-[calc(100%+8px)] z-[88] min-w-[180px] rounded-lg p-1.5">
          {options.map((option) => (
            <button
              key={option.value}
              type="button"
              onClick={() => onSelect(option.value)}
              className={clsx(
                "origin-focus-ring flex w-full items-center justify-between rounded px-2 py-1.5 text-left text-[11px] font-mono transition",
                option.value === value
                  ? "bg-[rgba(213,173,87,0.15)] text-[color:var(--origin-gold)]"
                  : "text-sdr-text-secondary hover:bg-[rgba(213,173,87,0.08)] hover:text-sdr-text-primary",
              )}
            >
              <span>{option.label}</span>
              {option.value === value ? <span>●</span> : null}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}
