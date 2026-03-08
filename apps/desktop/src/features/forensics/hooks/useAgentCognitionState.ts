import { CognitionController } from "@backbay/glia-agent/cognition";
import type { AVO } from "@backbay/glia-agent/emotion";
import * as React from "react";

type OrganismState =
  | "idle"
  | "listening"
  | "thinking"
  | "responding"
  | "success"
  | "error"
  | "sleep"
  | "busy";
type OrganismPower = "minimal" | "standard" | "elevated" | "intense";

export type AgentActionTelemetry = {
  id: string;
  kind: string;
  label: string;
  agentId: string;
  timestamp: number;
  policyStatus: string;
  riskScore: number;
  noveltyScore: number;
  blastRadius: number;
};

type SessionRow = {
  key: string;
  label: string;
  updatedAt?: number;
};

export type AgentGlyphState = {
  id: string;
  label: string;
  sessionKey: string | null;
  latestAt: number;
  actionCount: number;
  dimensions: AVO;
  state: OrganismState;
  power: OrganismPower;
  position: [number, number, number];
  isFocused: boolean;
  history: AgentActionTelemetry[];
};

type AgentAccumulator = {
  id: string;
  label: string;
  sessionKey: string | null;
  actions: AgentActionTelemetry[];
  latestAt: number;
};

type UseAgentCognitionStateInput = {
  actions: AgentActionTelemetry[];
  sessionRows: SessionRow[];
  focusedAgentId: string | null;
};

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  if (value < 0) return 0;
  if (value > 1) return 1;
  return value;
}

function normalizeAgentId(value: string): string {
  return value
    .trim()
    .replace(/^agent\s+/i, "")
    .toLowerCase();
}

function extractAgentIdFromSessionKey(sessionKey: string): string | null {
  const match = /^agent:([^:]+):/i.exec(sessionKey);
  return match?.[1] ?? null;
}

function average(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

function toOrganismState(
  status: string | undefined,
  latestAt: number,
  actionCount: number,
  nowMs: number,
): OrganismState {
  const ageMs = Math.max(0, nowMs - latestAt);
  if (actionCount === 0) return "idle";
  if (status === "denied" || status === "exception") return "error";
  if (status === "approval-required") return "thinking";
  if (status === "uncovered") return "busy";
  if (ageMs <= 9_000) return "responding";
  if (ageMs <= 35_000) return "listening";
  if (ageMs <= 120_000) return "idle";
  return "sleep";
}

function toPower(risk: number, intensity: number, focused: boolean): OrganismPower {
  const score = clamp01(risk * 0.72 + intensity * 0.56 + (focused ? 0.2 : 0));
  if (score >= 0.84) return "intense";
  if (score >= 0.56) return "elevated";
  if (score >= 0.26) return "standard";
  return "minimal";
}

function toLayoutPosition(index: number, total: number): [number, number, number] {
  const safeTotal = Math.max(total, 1);
  if (safeTotal === 1) return [0, 0.7, -1.2];
  const span = Math.min(Math.PI * 0.74, Math.PI * (0.24 + safeTotal * 0.07));
  const t = safeTotal <= 1 ? 0.5 : index / (safeTotal - 1);
  const angle = -span / 2 + span * t;
  const radius = 8.2;
  const x = Math.sin(angle) * radius;
  const z = -1.7 + Math.cos(angle) * 1.7;
  return [x, 0.7, z];
}

function ensureController(
  registry: Map<string, CognitionController>,
  id: string,
): CognitionController {
  const existing = registry.get(id);
  if (existing) return existing;
  const created = new CognitionController();
  registry.set(id, created);
  return created;
}

export function useAgentCognitionState({
  actions,
  sessionRows,
  focusedAgentId,
}: UseAgentCognitionStateInput): AgentGlyphState[] {
  const controllersRef = React.useRef<Map<string, CognitionController>>(new Map());
  const lastProcessedRunRef = React.useRef<Map<string, string>>(new Map());
  const [glyphs, setGlyphs] = React.useState<AgentGlyphState[]>([]);

  React.useEffect(() => {
    const controllers = controllersRef.current;
    const lastProcessedRun = lastProcessedRunRef.current;
    return () => {
      controllers.forEach((controller) => controller.dispose());
      controllers.clear();
      lastProcessedRun.clear();
    };
  }, []);

  React.useEffect(() => {
    const nowMs = Date.now();
    const byAgent = new Map<string, AgentAccumulator>();

    for (const action of actions) {
      const normalized = normalizeAgentId(action.agentId);
      const existing = byAgent.get(normalized);
      if (!existing) {
        byAgent.set(normalized, {
          id: action.agentId,
          label: action.agentId,
          sessionKey: null,
          actions: [action],
          latestAt: action.timestamp,
        });
        continue;
      }
      existing.actions.push(action);
      existing.latestAt = Math.max(existing.latestAt, action.timestamp);
    }

    for (const session of sessionRows) {
      if (!session.key.startsWith("agent:")) continue;
      const parsedAgentId = extractAgentIdFromSessionKey(session.key);
      if (!parsedAgentId) continue;
      const normalized = normalizeAgentId(parsedAgentId);
      const existing = byAgent.get(normalized);
      if (existing) {
        if (!existing.sessionKey) existing.sessionKey = session.key;
        if (typeof session.updatedAt === "number") {
          existing.latestAt = Math.max(existing.latestAt, session.updatedAt);
        }
        continue;
      }
      byAgent.set(normalized, {
        id: parsedAgentId,
        label: parsedAgentId,
        sessionKey: session.key,
        actions: [],
        latestAt: session.updatedAt ?? nowMs,
      });
    }

    const normalizedFocus = focusedAgentId ? normalizeAgentId(focusedAgentId) : null;

    const entries = Array.from(byAgent.entries())
      .map(([normalizedId, accumulator]) => ({
        normalizedId,
        ...accumulator,
      }))
      .sort((a, b) => b.latestAt - a.latestAt)
      .slice(0, 24);

    const nextGlyphs = entries.map((entry, index) => {
      const controller = ensureController(controllersRef.current, entry.normalizedId);
      const sortedActions = [...entry.actions].sort((a, b) => b.timestamp - a.timestamp);
      const latestAction = sortedActions[0];
      const riskSamples = sortedActions.slice(0, 16).map((action) => clamp01(action.riskScore));
      const noveltySamples = sortedActions
        .slice(0, 16)
        .map((action) => clamp01(action.noveltyScore));
      const blastSamples = sortedActions.slice(0, 16).map((action) => clamp01(action.blastRadius));

      const density =
        sortedActions.filter((action) => nowMs - action.timestamp <= 120_000).length / 12;
      const deniedCount = sortedActions.filter(
        (action) => action.policyStatus === "denied" || action.policyStatus === "exception",
      ).length;
      const pendingApprovals = sortedActions.filter(
        (action) => action.policyStatus === "approval-required",
      ).length;

      const risk = average(riskSamples);
      const workload = clamp01(density);
      const uncertainty = average(noveltySamples);
      const errorStress = clamp01(
        (deniedCount + pendingApprovals * 0.35) / Math.max(sortedActions.length, 1),
      );
      const confidence = clamp01(1 - uncertainty * 0.55 - errorStress * 0.65);
      const timePressure = clamp01(workload * 0.74 + average(blastSamples) * 0.3);
      const planDrift = clamp01(uncertainty * 0.68 + (pendingApprovals > 0 ? 0.16 : 0));
      const costPressure = clamp01(average(blastSamples) * 0.6 + risk * 0.24);
      const attention = clamp01(workload * 0.66 + (latestAction ? 0.24 : 0.08));

      controller.handleEvent({
        type: "signals.update",
        signals: {
          attention,
          workload,
          timePressure,
          planDrift,
          costPressure,
          risk,
          uncertainty,
          confidence,
          errorStress,
        },
      });

      if (latestAction) {
        const previousRun = lastProcessedRunRef.current.get(entry.normalizedId);
        if (previousRun !== latestAction.id) {
          controller.handleEvent({ type: "run.started", runId: latestAction.id });
          controller.handleEvent({
            type: "run.event",
            runId: latestAction.id,
            status: latestAction.policyStatus,
            progress: clamp01(0.2 + latestAction.noveltyScore * 0.6),
          });
          controller.handleEvent({
            type: "run.completed",
            runId: latestAction.id,
            success:
              latestAction.policyStatus !== "denied" && latestAction.policyStatus !== "exception",
          });
          lastProcessedRunRef.current.set(entry.normalizedId, latestAction.id);
        } else {
          controller.handleEvent({
            type: "run.event",
            runId: latestAction.id,
            status: latestAction.policyStatus,
            progress: clamp01(0.2 + latestAction.noveltyScore * 0.6),
          });
        }
      } else {
        controller.handleEvent({ type: "ui.user_idle" });
      }

      controller.tick(950);
      const emotion = controller.getEmotionTarget();

      const focused = normalizedFocus === entry.normalizedId;
      return {
        id: entry.id,
        label: entry.label,
        sessionKey: entry.sessionKey,
        latestAt: entry.latestAt,
        actionCount: sortedActions.length,
        dimensions: emotion.avo,
        state: toOrganismState(
          latestAction?.policyStatus,
          entry.latestAt,
          sortedActions.length,
          nowMs,
        ),
        power: toPower(risk, workload, focused),
        position: toLayoutPosition(index, entries.length),
        isFocused: focused,
        history: sortedActions.slice(0, 200),
      } satisfies AgentGlyphState;
    });

    setGlyphs(nextGlyphs);
  }, [actions, focusedAgentId, sessionRows]);

  return glyphs;
}
