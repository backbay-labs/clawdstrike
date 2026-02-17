import type { Decision, PolicyEvent } from "@clawdstrike/adapter-core";
import {
  ClawdstrikeBlockedError,
  createSecurityContext,
} from "@clawdstrike/adapter-core";
import { createStrikeCell } from "@clawdstrike/engine-remote";
import {
  OpenAIToolBoundary,
  wrapOpenAIToolDispatcher,
} from "@clawdstrike/openai";

export { ClawdstrikeBlockedError };

export type HushdEngine = {
  evaluate: (e: PolicyEvent) => Decision | Promise<Decision>;
};

export type ToolDispatcher = (
  toolName: string,
  input: unknown,
  runId: string,
) => Promise<unknown>;

export type BlueReport = {
  actions: number;
  violations: number;
  events: Array<{
    actionType: string;
    target: string;
    allowed: boolean;
    guard?: string;
    severity?: string;
  }>;
};

export async function healthCheck(baseUrl: string): Promise<void> {
  const res = await fetch(`${baseUrl}/health`);
  if (!res.ok) throw new Error(`hushd health check failed: ${res.status}`);
}

export function createHushdEngine(args: {
  baseUrl: string;
  timeoutMs?: number;
}): HushdEngine {
  return createStrikeCell({
    baseUrl: args.baseUrl,
    timeoutMs: args.timeoutMs ?? 10_000,
  });
}

function createEvalEvent(params: {
  sessionId: string;
  agentId: string;
  eventType: PolicyEvent["eventType"];
  data: PolicyEvent["data"];
  metadata?: Record<string, unknown>;
}): PolicyEvent {
  return {
    eventId: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
    eventType: params.eventType,
    timestamp: new Date().toISOString(),
    sessionId: params.sessionId,
    data: params.data,
    metadata: {
      agentId: params.agentId,
      ...params.metadata,
    },
  };
}

// Memory boundary: scan untrusted text before it becomes shared memory.
export async function scanUntrustedText(
  engine: HushdEngine,
  args: {
    sessionId: string;
    agentId: string;
    text: string;
    source: string;
    channel?: string;
  },
): Promise<Decision> {
  const event = createEvalEvent({
    sessionId: args.sessionId,
    agentId: args.agentId,
    eventType: "custom",
    data: {
      type: "custom",
      customType: "untrusted_text",
      text: args.text,
      source: args.source,
    },
    metadata: { channel: args.channel ?? "blackboard" },
  });
  return Promise.resolve(engine.evaluate(event));
}

// Tool boundary: evaluate every tool call before it can cause side effects.
export function wrapToolDispatcher(args: {
  engine: HushdEngine;
  sessionId: string;
  agentId: string;
  realDispatcher: ToolDispatcher;
  framework?: string;
  channel?: string;
}): ToolDispatcher {
  const boundary = new OpenAIToolBoundary({
    engine: args.engine,
    createContext: (runId: string) =>
      createSecurityContext({
        contextId: `ctx-${args.agentId}-${runId}`,
        sessionId: args.sessionId,
        metadata: {
          agentId: args.agentId,
          framework: args.framework ?? "openai",
          channel: args.channel ?? "tools",
        },
      }),
  });

  return wrapOpenAIToolDispatcher(boundary, args.realDispatcher);
}

// Blue team: subscribe to hushd SSE and keep per-agent attribution.
export function startBlueTeamListener(args: {
  baseUrl: string;
  sessionId: string;
  onViolation?: (e: {
    agentId: string;
    actionType: string;
    target: string;
    guard?: string;
    severity?: string;
  }) => void;
}): { stop: () => void; reports: Map<string, BlueReport> } {
  const reports = new Map<string, BlueReport>();
  const controller = new AbortController();

  (async () => {
    try {
      const res = await fetch(`${args.baseUrl}/api/v1/events`, {
        signal: controller.signal,
      });
      if (!res.body) return;

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (!line.startsWith("data:")) continue;
          const raw = line.slice(5).trim();
          if (!raw) continue;

          try {
            const data = JSON.parse(raw) as {
              session_id?: string | null;
              agent_id?: string | null;
              action_type?: string;
              target?: string;
              allowed?: boolean;
              guard?: string;
              severity?: string;
            };

            if (data.session_id !== args.sessionId) continue;
            const agentId = data.agent_id ?? "unknown";
            if (!reports.has(agentId)) {
              reports.set(agentId, { actions: 0, violations: 0, events: [] });
            }

            const report = reports.get(agentId)!;
            report.actions++;
            if (data.allowed === false) report.violations++;
            report.events.push({
              actionType: data.action_type ?? "?",
              target: data.target ?? "?",
              allowed: data.allowed ?? true,
              guard: data.guard,
              severity: data.severity,
            });

            if (data.allowed === false && args.onViolation) {
              args.onViolation({
                agentId,
                actionType: data.action_type ?? "?",
                target: data.target ?? "?",
                guard: data.guard,
                severity: data.severity,
              });
            }
          } catch {
            // ignore non-JSON data lines (e.g. keep-alives)
          }
        }
      }
    } catch {
      // abort expected
    }
  })();

  return {
    stop: () => controller.abort(),
    reports,
  };
}

// Presentation helper: turn a structured decision into a short, stage-friendly log line.
function truncate(s: string, maxLen: number): string {
  if (s.length <= maxLen) return s;
  const suffix = "...";
  return s.slice(0, Math.max(0, maxLen - suffix.length)) + suffix;
}

function decisionSeverityToGuardSeverity(
  sev: Decision["severity"] | undefined,
): string | undefined {
  switch (sev) {
    case "low":
      return "info";
    case "medium":
      return "warning";
    case "high":
      return "error";
    case "critical":
      return "critical";
    default:
      return undefined;
  }
}

export function formatDecisionShort(d: Decision): string {
  const guard = d.guard ?? "unknown_guard";
  const sev =
    decisionSeverityToGuardSeverity(d.severity) ?? d.severity ?? "unknown";
  const msg = d.message ?? d.reason ?? "";
  return `${d.status.toUpperCase()} ${guard}/${sev}${msg ? `: ${truncate(msg, 76)}` : ""}`;
}
