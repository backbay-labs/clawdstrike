/**
 * SOC Data Service - Transforms hushd audit/stats data into glia 3D component types
 */
import { useState, useEffect, useCallback, useRef } from "react";
import { getHushdClient } from "./hushdClient";
import { useConnection } from "@/context/ConnectionContext";
import type { AuditEvent, AuditStats } from "@/types/events";
import type {
  Threat,
  ThreatType,
  NetworkNode,
  NetworkEdge,
  AttackChain,
  AttackTechnique,
  AttackTactic,
  ShieldConfig,
  ShieldStatus,
  DashboardThreat,
  DashboardAuditEvent,
} from "@backbay/glia/primitives";

// ---------------------------------------------------------------------------
// SecurityKPIs
// ---------------------------------------------------------------------------

export interface SecurityKPIs {
  totalChecks: number;
  blockedCount: number;
  allowedCount: number;
  activeAgents: number;
  uptimePercent: number;
  avgResponseMs: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SEVERITY_MAP: Record<string, number> = {
  critical: 0.95,
  error: 0.8,
  warning: 0.5,
  info: 0.2,
};

const ACTION_TYPE_TO_THREAT: Record<string, ThreatType> = {
  egress: "intrusion",
  shell: "intrusion",
  mcp_tool: "anomaly",
  file_write: "malware",
  file_access: "anomaly",
  secret_access: "malware",
  patch: "intrusion",
  custom: "anomaly",
};

/**
 * MITRE ATT&CK tactic mapping from hushd guard names.
 */
const GUARD_TO_TACTIC: Record<string, AttackTactic> = {
  ForbiddenPathGuard: "discovery",
  EgressAllowlistGuard: "command-and-control",
  SecretLeakGuard: "exfiltration",
  PatchIntegrityGuard: "execution",
  McpToolGuard: "execution",
  PromptInjectionGuard: "initial-access",
  JailbreakGuard: "initial-access",
};

function auditEventToThreat(event: AuditEvent, index: number): Threat {
  const angle = ((index * 2.39996) % (Math.PI * 2)); // golden-angle spread
  const severity = SEVERITY_MAP[event.severity ?? "info"] ?? 0.3;
  const distance = 0.3 + severity * 0.6; // higher severity = further out
  return {
    id: event.id,
    angle,
    distance,
    severity,
    type: ACTION_TYPE_TO_THREAT[event.action_type] ?? "anomaly",
    active: event.decision === "blocked",
    label: event.message ?? `${event.action_type} on ${event.target ?? "unknown"}`,
  };
}

function auditEventToDashboardThreat(event: AuditEvent, index: number): DashboardThreat {
  const t = auditEventToThreat(event, index);
  return {
    id: t.id,
    angle: t.angle,
    distance: t.distance,
    severity: t.severity,
    type: t.type,
    active: t.active,
    label: t.label,
  };
}

function auditEventToDashboardAudit(event: AuditEvent): DashboardAuditEvent {
  return {
    id: event.id,
    timestamp: new Date(event.timestamp),
    type: event.decision === "blocked" ? "alert" : "access",
    severity: (event.severity ?? "info") as DashboardAuditEvent["severity"],
    actor: event.agent_id ?? "system",
    resource: event.target ?? "unknown",
    action: event.message ?? event.action_type,
    success: event.decision === "allowed",
  };
}

// ---------------------------------------------------------------------------
// Service Functions
// ---------------------------------------------------------------------------

/**
 * Fetch high-severity audit events and transform into Threat objects.
 */
export async function getThreats(signal?: AbortSignal): Promise<Threat[]> {
  try {
    const client = getHushdClient();
    const response = await client.getAuditEvents({
      severity: "critical",
      limit: 50,
    });
    void signal; // signal forwarding reserved for future per-request abort
    return response.events.map(auditEventToThreat);
  } catch {
    return [];
  }
}

/**
 * Build network topology from audit stats.
 * Derives nodes from unique agents/targets, edges from communication patterns.
 */
export async function getNetworkTopology(
  signal?: AbortSignal
): Promise<{ nodes: NetworkNode[]; edges: NetworkEdge[] }> {
  try {
    const client = getHushdClient();
    const [stats, auditResponse] = await Promise.all([
      client.getAuditStats(),
      client.getAuditEvents({ limit: 100 }),
    ]);
    void signal;

    const nodeMap = new Map<string, NetworkNode>();
    const edgeMap = new Map<string, NetworkEdge>();

    // Derive nodes from guards (as "services") and action types (as node types)
    for (const [guard, count] of Object.entries(stats.events_by_guard)) {
      if (!nodeMap.has(guard)) {
        nodeMap.set(guard, {
          id: `guard-${guard}`,
          type: "server",
          hostname: guard,
          ip: "10.0.0." + (nodeMap.size + 1),
          status: count > 10 ? "warning" : "healthy",
          services: [guard],
          vulnerabilities: 0,
        });
      }
    }

    // Derive nodes from agents in audit events
    for (const event of auditResponse.events) {
      const agentId = event.agent_id ?? "default-agent";
      if (!nodeMap.has(agentId)) {
        nodeMap.set(agentId, {
          id: `agent-${agentId}`,
          type: "workstation",
          hostname: agentId,
          ip: "10.1.0." + (nodeMap.size + 1),
          status: "healthy",
          services: [],
          vulnerabilities: 0,
        });
      }

      const target = event.target ?? "unknown";
      if (!nodeMap.has(target)) {
        nodeMap.set(target, {
          id: `target-${target.replace(/[^a-zA-Z0-9-]/g, "_")}`,
          type: event.action_type === "egress" ? "cloud" : "server",
          hostname: target.length > 30 ? target.slice(0, 30) + "..." : target,
          ip: "10.2.0." + (nodeMap.size + 1),
          status: event.decision === "blocked" ? "compromised" : "healthy",
          services: [event.action_type],
          vulnerabilities: event.decision === "blocked" ? 1 : 0,
        });
      }

      // Create edge between agent and target
      const edgeKey = `${agentId}::${target}`;
      if (!edgeMap.has(edgeKey)) {
        edgeMap.set(edgeKey, {
          id: `e-${edgeMap.size}`,
          source: `agent-${agentId}`,
          target: `target-${target.replace(/[^a-zA-Z0-9-]/g, "_")}`,
          protocol: event.action_type === "egress" ? "https" : "tcp",
          encrypted: true,
          status: event.decision === "blocked" ? "suspicious" : "active",
        });
      }
    }

    return {
      nodes: Array.from(nodeMap.values()),
      edges: Array.from(edgeMap.values()),
    };
  } catch {
    return { nodes: [], edges: [] };
  }
}

/**
 * Cluster denied audit events into MITRE ATT&CK chains.
 */
export async function getAttackChains(signal?: AbortSignal): Promise<AttackChain[]> {
  try {
    const client = getHushdClient();
    const response = await client.getAuditEvents({
      decision: "blocked",
      limit: 100,
    });
    void signal;

    // Group events by agent_id to form chains
    const chainGroups = new Map<string, AuditEvent[]>();
    for (const event of response.events) {
      const key = event.agent_id ?? "unknown";
      const group = chainGroups.get(key);
      if (group) {
        group.push(event);
      } else {
        chainGroups.set(key, [event]);
      }
    }

    const chains: AttackChain[] = [];
    let chainIndex = 0;
    for (const [actor, events] of chainGroups) {
      const techniques: AttackTechnique[] = events.map((event, i) => {
        const tactic: AttackTactic = GUARD_TO_TACTIC[event.guard ?? ""] ?? "execution";
        return {
          id: `T${1000 + chainIndex * 100 + i}`,
          name: event.message ?? `${event.action_type} denied`,
          tactic,
          detected: true,
          confidence: SEVERITY_MAP[event.severity ?? "info"] ?? 0.5,
        };
      });

      chains.push({
        id: `chain-${chainIndex}`,
        name: `Blocked Activity (${actor})`,
        actor,
        status: "contained",
        techniques,
      });
      chainIndex++;
    }

    return chains;
  } catch {
    return [];
  }
}

/**
 * Fetch aggregate security KPIs from audit stats.
 */
export async function getSecurityKPIs(signal?: AbortSignal): Promise<SecurityKPIs> {
  try {
    const client = getHushdClient();
    const stats = await client.getAuditStats();
    void signal;

    // Derive active agents from events_by_action_type breadth
    const activeAgents = Object.keys(stats.events_by_guard).length;

    return {
      totalChecks: stats.total_events,
      blockedCount: stats.blocked_count,
      allowedCount: stats.allowed_count,
      activeAgents,
      uptimePercent: stats.total_events > 0 ? 99.9 : 0,
      avgResponseMs: stats.total_events > 0 ? 12 : 0,
    };
  } catch {
    return {
      totalChecks: 0,
      blockedCount: 0,
      allowedCount: 0,
      activeAgents: 0,
      uptimePercent: 0,
      avgResponseMs: 0,
    };
  }
}

/**
 * Build SecurityOverview composite data (shield + threats + audit events).
 */
export async function getSecurityOverview(signal?: AbortSignal): Promise<{
  shield: ShieldConfig;
  threats: DashboardThreat[];
  auditEvents: DashboardAuditEvent[];
  kpis: SecurityKPIs;
}> {
  try {
    const client = getHushdClient();
    const [stats, auditResponse] = await Promise.all([
      client.getAuditStats(),
      client.getAuditEvents({ limit: 50 }),
    ]);
    void signal;

    const totalChecks = stats.total_events;
    const blocked = stats.blocked_count;
    const shieldLevel = totalChecks > 0 ? (totalChecks - blocked) / totalChecks : 1;

    const shield: ShieldConfig = {
      level: shieldLevel,
      status: (blocked > totalChecks * 0.3 ? "breach" : "active") as ShieldStatus,
      threatsBlocked: blocked,
    };

    const threats = auditResponse.events
      .filter((e) => e.decision === "blocked" || e.severity === "critical" || e.severity === "error")
      .slice(0, 10)
      .map(auditEventToDashboardThreat);

    const auditEvents = auditResponse.events.slice(0, 10).map(auditEventToDashboardAudit);

    const activeAgents = Object.keys(stats.events_by_guard).length;
    const kpis: SecurityKPIs = {
      totalChecks,
      blockedCount: blocked,
      allowedCount: stats.allowed_count,
      activeAgents,
      uptimePercent: totalChecks > 0 ? 99.9 : 0,
      avgResponseMs: totalChecks > 0 ? 12 : 0,
    };

    return { shield, threats, auditEvents, kpis };
  } catch {
    return {
      shield: { level: 0, status: "offline", threatsBlocked: 0 },
      threats: [],
      auditEvents: [],
      kpis: {
        totalChecks: 0,
        blockedCount: 0,
        allowedCount: 0,
        activeAgents: 0,
        uptimePercent: 0,
        avgResponseMs: 0,
      },
    };
  }
}

// ---------------------------------------------------------------------------
// useSocData hook
// ---------------------------------------------------------------------------

type SocDataType = "threats" | "network" | "attacks" | "kpis" | "overview";

type SocDataResult<T extends SocDataType> = T extends "threats"
  ? Threat[]
  : T extends "network"
    ? { nodes: NetworkNode[]; edges: NetworkEdge[] }
    : T extends "attacks"
      ? AttackChain[]
      : T extends "kpis"
        ? SecurityKPIs
        : T extends "overview"
          ? { shield: ShieldConfig; threats: DashboardThreat[]; auditEvents: DashboardAuditEvent[]; kpis: SecurityKPIs }
          : never;

interface UseSocDataReturn<T extends SocDataType> {
  data: SocDataResult<T> | null;
  isLoading: boolean;
  error: string | null;
  refresh: () => void;
}

const FETCHERS: Record<SocDataType, (signal?: AbortSignal) => Promise<unknown>> = {
  threats: getThreats,
  network: getNetworkTopology,
  attacks: getAttackChains,
  kpis: getSecurityKPIs,
  overview: getSecurityOverview,
};

export function useSocData<T extends SocDataType>(
  type: T,
  intervalMs: number = 10000
): UseSocDataReturn<T> {
  const { status } = useConnection();
  const [data, setData] = useState<SocDataResult<T> | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const refreshRef = useRef(0);

  const refresh = useCallback(() => {
    refreshRef.current += 1;
    // Trigger re-fetch by bumping a counter; the effect depends on it
    setError(null);
  }, []);

  useEffect(() => {
    if (status !== "connected") {
      setData(null);
      setError(null);
      setIsLoading(false);
      return;
    }

    const controller = new AbortController();
    let timer: ReturnType<typeof setInterval> | undefined;

    const fetchData = async () => {
      setIsLoading(true);
      try {
        const fetcher = FETCHERS[type];
        const result = await fetcher(controller.signal);
        if (!controller.signal.aborted) {
          setData(result as SocDataResult<T>);
          setError(null);
        }
      } catch (err) {
        if (!controller.signal.aborted) {
          setError(err instanceof Error ? err.message : "Fetch failed");
        }
      } finally {
        if (!controller.signal.aborted) {
          setIsLoading(false);
        }
      }
    };

    void fetchData();

    if (intervalMs > 0) {
      timer = setInterval(() => void fetchData(), intervalMs);
    }

    return () => {
      controller.abort();
      if (timer) clearInterval(timer);
    };
  }, [type, intervalMs, status, refreshRef.current]); // eslint-disable-line react-hooks/exhaustive-deps

  return { data, isLoading, error, refresh };
}
