/**
 * ForensicsRiverView - Live/replay 3D river for OpenClaw telemetry.
 *
 * Wave 3:
 * - Polls OpenClaw `sessions.preview` to materialize tool calls + policy outcomes as RiverActions.
 * - Augments with live exec approvals from gateway events.
 * - Keeps a sliding live window so actions "flow" as time advances.
 */
import * as React from "react";
import { RiverView as River } from "@backbay/glia-three/three";
import { useOpenClaw } from "@/context/OpenClawContext";

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

// RiverView's live-stream heuristic starts playback at `end - 5000ms`.
// Keep `end` slightly in the future so "now" events appear immediately.
const LIVE_TIME_RANGE_LEAD_MS = 5500;

function demoPolicies(): PolicySegment[] {
  return [
    { id: "pol-1", label: "Network Egress", startT: 0, endT: 0.25, side: "both", type: "hard-deny" },
    { id: "pol-2", label: "FS Read-Only", startT: 0.2, endT: 0.5, side: "left", type: "soft" },
    { id: "pol-3", label: "Exec Sandbox", startT: 0.45, endT: 0.75, side: "right", type: "hard-deny" },
    { id: "pol-4", label: "Audit Zone", startT: 0.7, endT: 0.9, side: "both", type: "record-only" },
    { id: "pol-gap", label: "UNCOVERED", startT: 0.9, endT: 1, side: "both", type: "soft", coverageGap: true },
  ];
}

function demoDetectors(): DetectorData[] {
  return [
    { id: "detector-0", label: "Heuristic Scanner", type: "heuristic", position: [-5, 0, 2.5], active: true, signalCount: 3 },
    { id: "detector-1", label: "ML Anomaly Model", type: "model", position: [-1, 0, -2.5], active: true, signalCount: 5 },
    { id: "detector-2", label: "Signature DB", type: "signature", position: [3, 0, 2.5], active: false, signalCount: 0 },
    { id: "detector-3", label: "Behavior Monitor", type: "behavioral", position: [6, 0, -2.5], active: true, signalCount: 2 },
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
      const outputText = nextRole === "tool" && nextText && !nextText.trim().toLowerCase().startsWith("call ")
        ? nextText
        : null;
      if (outputText) i += 1;

      let kind: RiverAction["kind"] = tool === "exec" ? "exec" : tool.includes("policy") ? "query" : "message";
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
        label: tool === "policy_check" ? "Policy Check" : tool === "exec" ? "Exec" : `Tool · ${tool}`,
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
  const oc = useOpenClaw();
  const rt = oc.runtimeByGatewayId[oc.activeGatewayId];

  const [mode, setMode] = React.useState<"live" | "replay">("live");
  const [windowMs, setWindowMs] = React.useState(120_000);
  const [sessions, setSessions] = React.useState<Array<{ key: string; label: string; updatedAt?: number }>>([]);
  const [selectedSessionKey, setSelectedSessionKey] = React.useState<string>("agent:main:main");

  const clockByGatewayRef = React.useRef<Record<string, Map<string, number>>>({});
  const getClock = React.useCallback((gatewayId: string) => {
    const existing = clockByGatewayRef.current[gatewayId];
    if (existing) return existing;
    const next = new Map<string, number>();
    clockByGatewayRef.current[gatewayId] = next;
    return next;
  }, []);

  const [datasetByGatewayId, setDatasetByGatewayId] = React.useState<Record<string, RiverDataset>>({});

  const statusLabel = rt?.status === "connected" ? "OPENCLAW LIVE" : rt?.status === "error" ? "OFFLINE (ERROR)" : "OFFLINE";

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

  // Poll session inventory.
  React.useEffect(() => {
    if (rt?.status !== "connected") return;

    let cancelled = false;
    let inFlight = false;

    async function tick() {
      if (inFlight) return;
      inFlight = true;
      try {
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
        if (!cancelled) setSessions(normalized);
        if (!cancelled && !normalized.some((s) => s.key === selectedSessionKey)) {
          setSelectedSessionKey(normalized[0]?.key ?? "agent:main:main");
        }
      } catch {
        // keep last
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
  }, [oc, rt?.status, selectedSessionKey]);

  // Poll session preview + build river dataset.
  React.useEffect(() => {
    if (mode !== "live") return;
    if (rt?.status !== "connected") return;

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
        if (cycle === 1 && sessions.length === 0) {
          // Best-effort warm-up when sessions list hasn't arrived yet.
          await oc.request("sessions.list").catch(() => {});
        }

        const keys =
          selectedSessionKey === "__all__"
            ? sessions.slice(0, 3).map((s) => s.key)
            : [selectedSessionKey];

        const previewRes = await oc.request<SessionPreviewResponse>("sessions.preview", { keys });
        const previews = Array.isArray(previewRes.previews) ? previewRes.previews : [];

        const actions: RiverAction[] = [];
        const causalLinks: CausalLink[] = [];

        for (const preview of previews) {
          if (preview.status !== "ok") continue;
          const items = Array.isArray(preview.items) ? preview.items : [];
          const derived = deriveActionsFromPreview({ sessionKey: preview.key, items, nowMs, clock, windowStartMs });
          actions.push(...derived.actions);
          causalLinks.push(...derived.causalLinks);
        }

        // Surface exec approvals as live action nodes.
        const approvals = rt.execApprovalQueue ?? [];
        for (const approval of approvals) {
          const id = `approval:${approval.id}`;
          const agentId = approval.request.agentId ? String(approval.request.agentId) : "operator";
          const timestamp = clock.get(id) ?? nowMs;
          if (!clock.has(id)) clock.set(id, timestamp);
          if (timestamp < windowStartMs) continue;

          actions.push({
            id,
            kind: "exec",
            label: `Approval · ${summarizeText(approval.request.command, 60)}`,
            agentId,
            timestamp,
            policyStatus: "approval-required",
            riskScore: 0.85,
            noveltyScore: 0.25,
            blastRadius: 0.55,
            consequence: approval.request.ask ?? approval.request.security ?? undefined,
          });
        }

        actions.sort((a, b) => a.timestamp - b.timestamp);

        // Build agents list from action agentIds.
        const agentIds = Array.from(new Set(actions.map((a) => a.agentId)));
        const agents: Agent[] = agentIds.map((id) => ({
          id,
          label: id,
          color: River.AGENT_COLORS[hashToIndex(id, River.AGENT_COLORS.length)],
        }));

        const signals: SignalData[] = actions
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
          actions,
          agents,
          policies: demoPolicies(),
          signals,
          incidents: [] as IncidentData[],
          detectors: demoDetectors(),
          causalLinks,
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
  }, [getClock, mode, oc, oc.activeGatewayId, rt?.status, rt?.execApprovalQueue, selectedSessionKey, sessions, windowMs]);

  return (
    <div className="relative h-full w-full" style={{ background: "#050510" }}>
      <div className="absolute top-0 left-0 right-0 z-10 flex items-center justify-between px-4 py-3 bg-gradient-to-b from-[#0a0a0f] to-transparent pointer-events-none">
        <div>
          <h1 className="text-lg font-semibold text-white">Forensics River</h1>
          <p className="text-sm text-white/50">
            {activeDataset.actions.length} actions · {activeDataset.agents.length} agents · {activeDataset.signals.length} signals · {activeDataset.incidents.length} incidents
          </p>
        </div>

        <div className="pointer-events-auto flex items-center gap-2">
          <button
            onClick={() => setMode("live")}
            className={cls("LIVE", mode === "live")}
          >
            LIVE
          </button>
          <button
            onClick={() => setMode("replay")}
            className={cls("REPLAY", mode === "replay")}
          >
            REPLAY
          </button>
          <div className="ml-2 text-xs font-mono text-white/35">{statusLabel}</div>
          <select
            value={selectedSessionKey}
            onChange={(e) => setSelectedSessionKey(e.target.value)}
            className="ml-3 px-2 py-1 text-xs font-mono rounded border border-white/10 bg-black/30 text-white/70 outline-none"
            title="Session"
          >
            <option value="__all__">ALL (top 3)</option>
            {sessions.map((s) => (
              <option key={s.key} value={s.key}>
                {s.label}
              </option>
            ))}
          </select>
          <select
            value={String(windowMs)}
            onChange={(e) => setWindowMs(Number(e.target.value) || 120_000)}
            className="px-2 py-1 text-xs font-mono rounded border border-white/10 bg-black/30 text-white/70 outline-none"
            title="Live window"
          >
            <option value="60000">60s</option>
            <option value="120000">2m</option>
            <option value="300000">5m</option>
          </select>
        </div>
      </div>

      <River.RiverView
        actions={activeDataset.actions}
        agents={activeDataset.agents}
        policies={activeDataset.policies}
        signals={activeDataset.signals}
        incidents={activeDataset.incidents}
        detectors={activeDataset.detectors}
        causalLinks={activeDataset.causalLinks}
        timeRange={activeDataset.timeRange}
        autoPlay={mode === "live"}
        showPolicyRails
        showCausalThreads
        showSignals
        showDetectors
        showIncidents={activeDataset.incidents.length > 0}
      />
    </div>
  );
}

function cls(label: string, active: boolean) {
  return `text-xs font-mono px-2 py-1 border rounded ${
    active ? "border-white/30 text-white/80 bg-white/5" : "border-white/10 text-white/40 hover:text-white/70"
  }`;
}
