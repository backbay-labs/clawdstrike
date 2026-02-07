/**
 * useSpineEvents - React hook for consuming normalized SDR events from spine
 *
 * Manages a SpineEventSource instance and provides reactive state for
 * events, connection status, and derived data (threats, chains, topology).
 */

import { useEffect, useRef, useState, useCallback, useMemo } from "react";
import { SpineEventSource } from "@/services/spineEventSource";
import type {
  SDREvent,
  SpineConnectionStatus,
  LiveAttackChain,
  LiveTechnique,
} from "@/types/spine";
import type { Threat, ThreatType } from "@backbay/glia/primitives";
import type { AttackChain, AttackTechnique, AttackTactic } from "@backbay/glia/primitives";
import type { NetworkNode, NetworkEdge, NetworkEdgeProtocol } from "@backbay/glia/primitives";

// ---------------------------------------------------------------------------
// Hook options
// ---------------------------------------------------------------------------

export interface UseSpineEventsOptions {
  natsUrl?: string;
  forceDemo?: boolean;
  enabled?: boolean;
  maxEvents?: number;
  demoInterval?: number;
}

export interface UseSpineEventsResult {
  /** All normalized events (newest first) */
  events: SDREvent[];
  /** Connection status */
  status: SpineConnectionStatus;
  /** Map SDR events -> glia Threat objects for ThreatRadar */
  threats: Threat[];
  /** Map SDR events -> glia AttackChain objects for AttackGraph */
  chains: AttackChain[];
  /** Network nodes derived from events */
  networkNodes: NetworkNode[];
  /** Network edges derived from events */
  networkEdges: NetworkEdge[];
  /** Live attack chains with full event lineage */
  liveChains: LiveAttackChain[];
  /** Clear all events */
  clearEvents: () => void;
}

// ---------------------------------------------------------------------------
// Hook implementation
// ---------------------------------------------------------------------------

export function useSpineEvents(options: UseSpineEventsOptions = {}): UseSpineEventsResult {
  const { natsUrl, forceDemo = false, enabled = true, maxEvents = 500, demoInterval } = options;

  const [events, setEvents] = useState<SDREvent[]>([]);
  const [status, setStatus] = useState<SpineConnectionStatus>("disconnected");
  const sourceRef = useRef<SpineEventSource | null>(null);

  const handleEvent = useCallback(
    (event: SDREvent) => {
      setEvents((prev) => {
        const next = [event, ...prev];
        return next.length > maxEvents ? next.slice(0, maxEvents) : next;
      });
    },
    [maxEvents],
  );

  const handleStatus = useCallback((s: SpineConnectionStatus) => {
    setStatus(s);
  }, []);

  useEffect(() => {
    if (!enabled) {
      sourceRef.current?.disconnect();
      sourceRef.current = null;
      setStatus("disconnected");
      return;
    }

    const source = new SpineEventSource({
      onEvent: handleEvent,
      onStatus: handleStatus,
      natsUrl,
      forceDemo,
      demoInterval,
    });

    sourceRef.current = source;
    source.connect();

    return () => {
      source.disconnect();
    };
  }, [enabled, natsUrl, forceDemo, demoInterval, handleEvent, handleStatus]);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  // -----------------------------------------------------------------------
  // Derived: Threats for ThreatRadar
  // -----------------------------------------------------------------------
  const threats = useMemo(() => mapEventsToThreats(events), [events]);

  // -----------------------------------------------------------------------
  // Derived: Attack chains for AttackGraph
  // -----------------------------------------------------------------------
  const { chains, liveChains } = useMemo(() => buildAttackChains(events), [events]);

  // -----------------------------------------------------------------------
  // Derived: Network topology
  // -----------------------------------------------------------------------
  const { networkNodes, networkEdges } = useMemo(() => buildNetworkTopology(events), [events]);

  return { events, status, threats, chains, networkNodes, networkEdges, liveChains, clearEvents };
}

// ---------------------------------------------------------------------------
// Threat mapping: SDREvent -> glia Threat (for ThreatRadar)
// ---------------------------------------------------------------------------

const CATEGORY_TO_THREAT_TYPE: Record<string, ThreatType> = {
  process_exec: "malware",
  process_exit: "anomaly",
  file_access: "anomaly",
  file_write: "intrusion",
  network_connect: "intrusion",
  network_flow: "ddos",
  dns_query: "phishing",
  policy_violation: "malware",
  secret_leak: "intrusion",
  privilege_escalation: "malware",
};

function mapEventsToThreats(events: SDREvent[]): Threat[] {
  // Only show medium+ severity as radar blips
  const significant = events.filter((e) => e.severity >= 0.3);

  return significant.slice(0, 50).map((event, i) => ({
    id: event.id,
    angle: (i / Math.max(significant.length, 1)) * Math.PI * 2,
    distance: 1 - event.severity, // higher severity = closer to center
    severity: event.severity,
    type: CATEGORY_TO_THREAT_TYPE[event.category] ?? "anomaly",
    active: event.severity >= 0.6,
    label: event.summary,
  }));
}

// ---------------------------------------------------------------------------
// Attack chain building: group events by process tree into chains
// ---------------------------------------------------------------------------

const CATEGORY_TO_MITRE: Record<string, { id: string; name: string; tactic: AttackTactic }> = {
  process_exec: { id: "T1059", name: "Command and Scripting Interpreter", tactic: "execution" },
  file_write: { id: "T1565", name: "Data Manipulation", tactic: "impact" },
  network_connect: { id: "T1071", name: "Application Layer Protocol", tactic: "command-and-control" },
  privilege_escalation: { id: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "privilege-escalation" },
  secret_leak: { id: "T1552", name: "Unsecured Credentials", tactic: "credential-access" },
  policy_violation: { id: "T1562", name: "Impair Defenses", tactic: "defense-evasion" },
  dns_query: { id: "T1071.004", name: "DNS", tactic: "command-and-control" },
};

function buildAttackChains(events: SDREvent[]): { chains: AttackChain[]; liveChains: LiveAttackChain[] } {
  // Group by root exec_id or by origin pod (fallback)
  const groups = new Map<string, SDREvent[]>();

  for (const event of events) {
    if (event.severity < 0.4) continue; // skip low-severity noise

    const key = event.origin?.execId?.split("-")[0] ?? event.origin?.pod ?? event.id;
    const group = groups.get(key) ?? [];
    group.push(event);
    groups.set(key, group);
  }

  const liveChains: LiveAttackChain[] = [];

  for (const [key, groupEvents] of groups) {
    if (groupEvents.length < 2) continue; // need at least 2 events for a chain

    const sorted = [...groupEvents].sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    const maxSeverity = Math.max(...sorted.map((e) => e.severity));
    const chainStatus = maxSeverity >= 0.8 ? "active" : maxSeverity >= 0.5 ? "contained" : "remediated";

    const techniques: LiveTechnique[] = [];
    const seenTechniques = new Set<string>();

    for (const event of sorted) {
      const mitre = event.mitre;
      const fallback = CATEGORY_TO_MITRE[event.category];
      const techId = mitre?.techniqueId ?? fallback?.id;
      const techName = mitre?.techniqueName ?? fallback?.name;
      const tactic = (mitre?.tactic ?? fallback?.tactic) as AttackTactic | undefined;
      if (!techId || !techName || !tactic) continue;

      if (!seenTechniques.has(techId)) {
        seenTechniques.add(techId);
        techniques.push({
          id: techId,
          name: techName,
          tactic,
          detected: true,
          confidence: event.severity,
          eventIds: [event.id],
        });
      } else {
        const existing = techniques.find((t) => t.id === techId);
        if (existing) {
          existing.eventIds.push(event.id);
          existing.confidence = Math.max(existing.confidence, event.severity);
        }
      }
    }

    if (techniques.length < 1) continue;

    const podName = sorted[0].origin?.pod ?? key;

    liveChains.push({
      id: `chain-${key}`,
      name: `${podName} intrusion`,
      rootExecId: key,
      status: chainStatus as LiveAttackChain["status"],
      firstSeen: sorted[0].timestamp,
      lastSeen: sorted[sorted.length - 1].timestamp,
      events: sorted,
      techniques,
    });
  }

  // Convert to glia AttackChain format
  const chains: AttackChain[] = liveChains.map((lc) => ({
    id: lc.id,
    name: lc.name,
    actor: "Unknown",
    status: lc.status,
    techniques: lc.techniques.map<AttackTechnique>((t) => ({
      id: t.id,
      name: t.name,
      tactic: t.tactic as AttackTactic,
      detected: t.detected,
      confidence: t.confidence,
    })),
  }));

  return { chains, liveChains };
}

// ---------------------------------------------------------------------------
// Network topology: build nodes and edges from network events
// ---------------------------------------------------------------------------

function buildNetworkTopology(events: SDREvent[]): { networkNodes: NetworkNode[]; networkEdges: NetworkEdge[] } {
  const nodeMap = new Map<string, NetworkNode>();
  const edgeMap = new Map<string, NetworkEdge>();

  for (const event of events) {
    if (!event.network) continue;

    const { srcIp, dstIp, srcPort, dstPort, protocol, bytes, verdict } = event.network;
    if (!srcIp && !dstIp) continue;

    // Create/update source node
    if (srcIp) {
      const existing = nodeMap.get(srcIp);
      if (!existing) {
        nodeMap.set(srcIp, {
          id: srcIp,
          type: guessNodeType(srcIp, event.origin?.pod),
          hostname: event.origin?.pod ?? srcIp,
          ip: srcIp,
          status: "healthy",
          services: [],
          vulnerabilities: 0,
        });
      }
    }

    // Create/update destination node
    if (dstIp) {
      const existing = nodeMap.get(dstIp);
      if (!existing) {
        const isExternal = !dstIp.startsWith("10.") && !dstIp.startsWith("172.") && !dstIp.startsWith("192.168.");
        nodeMap.set(dstIp, {
          id: dstIp,
          type: isExternal ? "cloud" : "server",
          hostname: dstIp,
          ip: dstIp,
          status: verdict === "dropped" ? "warning" : "healthy",
          services: dstPort ? [portToService(dstPort)] : [],
          vulnerabilities: 0,
        });
      } else if (verdict === "dropped") {
        existing.status = "warning";
      }
    }

    // Create/update edge
    if (srcIp && dstIp) {
      const edgeKey = `${srcIp}->${dstIp}:${dstPort ?? 0}`;
      const existing = edgeMap.get(edgeKey);
      if (!existing) {
        edgeMap.set(edgeKey, {
          id: edgeKey,
          source: srcIp,
          target: dstIp,
          protocol: toEdgeProtocol(protocol, dstPort),
          port: dstPort,
          bandwidth: bytes ?? 100,
          encrypted: dstPort === 443 || dstPort === 8443,
          status: verdict === "dropped" ? "suspicious" : verdict === "error" ? "suspicious" : "active",
        });
      } else {
        existing.bandwidth = (existing.bandwidth ?? 0) + (bytes ?? 100);
        if (verdict === "dropped" || verdict === "error") {
          existing.status = "suspicious";
        }
      }
    }
  }

  return {
    networkNodes: Array.from(nodeMap.values()),
    networkEdges: Array.from(edgeMap.values()),
  };
}

const VALID_EDGE_PROTOCOLS = new Set<NetworkEdgeProtocol>(["tcp", "udp", "icmp", "http", "https", "ssh", "rdp", "smb"]);

function toEdgeProtocol(raw?: string, port?: number): NetworkEdgeProtocol {
  if (raw && VALID_EDGE_PROTOCOLS.has(raw as NetworkEdgeProtocol)) {
    return raw as NetworkEdgeProtocol;
  }
  // Infer from port
  if (port === 443 || port === 8443) return "https";
  if (port === 80 || port === 8080) return "http";
  if (port === 22) return "ssh";
  if (port === 3389) return "rdp";
  if (port === 445) return "smb";
  return "tcp";
}

function guessNodeType(ip: string, pod?: string): NetworkNode["type"] {
  if (pod?.includes("fw") || pod?.includes("firewall")) return "firewall";
  if (pod?.includes("rtr") || pod?.includes("router")) return "router";
  if (pod?.includes("ws-") || pod?.includes("workstation")) return "workstation";
  if (pod?.includes("iot") || pod?.includes("sensor")) return "iot";
  if (ip.startsWith("172.") || pod?.includes("cloud") || pod?.includes("aws")) return "cloud";
  return "server";
}

function portToService(port: number): string {
  const map: Record<number, string> = {
    22: "ssh", 53: "dns", 80: "http", 443: "https", 3306: "mysql",
    5432: "postgres", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9090: "prometheus", 9200: "elasticsearch", 4444: "unknown",
  };
  return map[port] ?? `port-${port}`;
}
