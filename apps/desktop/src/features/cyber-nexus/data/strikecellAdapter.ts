import type {
  NexusGraph,
  Strikecell,
  StrikecellConnection,
  StrikecellDomainId,
  StrikecellNode,
  StrikecellSourceSnapshot,
  StrikecellStatus,
} from "../types";

// Canonical deterministic strikecell order.
// Keeping this constant stable avoids UI jitter and test nondeterminism.
const STRIKECELL_ORDER: StrikecellDomainId[] = [
  "security-overview",
  "threat-radar",
  "attack-graph",
  "network-map",
  "forensics-river",
  "workflows",
  "marketplace",
  "events",
  "policies",
];

const STRIKECELL_META: Record<
  StrikecellDomainId,
  { name: string; routeId: string; description: string; tags: string[] }
> = {
  "security-overview": {
    name: "Security Overview",
    routeId: "security-overview",
    description: "Composite posture and defensive health.",
    tags: ["posture", "kpi", "shield"],
  },
  "threat-radar": {
    name: "Threat Radar",
    routeId: "threat-radar",
    description: "Live active threat telemetry and severity.",
    tags: ["threats", "live", "triage"],
  },
  "attack-graph": {
    name: "Attack Graph",
    routeId: "attack-graph",
    description: "MITRE ATT&CK chains and techniques.",
    tags: ["mitre", "chains", "techniques"],
  },
  "network-map": {
    name: "Network Map",
    routeId: "network-map",
    description: "Topology, hosts, and suspicious paths.",
    tags: ["network", "hosts", "topology"],
  },
  workflows: {
    name: "Workflows",
    routeId: "workflows",
    description: "Automation pipelines and trigger health.",
    tags: ["automation", "response", "playbooks"],
  },
  marketplace: {
    name: "Marketplace",
    routeId: "marketplace",
    description: "Policy bundles and attestation trust surface.",
    tags: ["policy", "supply-chain", "trust"],
  },
  events: {
    name: "Event Stream",
    routeId: "events",
    description: "Recent audit and policy decision stream.",
    tags: ["audit", "stream", "timeline"],
  },
  policies: {
    name: "Policies",
    routeId: "policies",
    description: "Policy posture and enforcement coverage.",
    tags: ["rules", "enforcement", "coverage"],
  },
  "forensics-river": {
    name: "Nexus",
    routeId: "nexus",
    description: "Forensic action-river timeline replay.",
    tags: ["forensics", "timeline", "audit", "replay"],
  },
};

interface HealthInputs {
  connected: boolean;
  severityScore: number;
  blockedRate: number;
  activityCount: number;
}

function clamp01(value: number): number {
  return Math.max(0, Math.min(1, value));
}

function ratio(value: number, total: number): number {
  if (total <= 0) return 0;
  return clamp01(value / total);
}

export function deriveStrikecellHealth({
  connected,
  severityScore,
  blockedRate,
  activityCount,
}: HealthInputs): StrikecellStatus {
  if (!connected) return "offline";

  const normalizedActivity = clamp01(activityCount / 25);
  const risk = clamp01(severityScore * 0.55 + blockedRate * 0.35 + normalizedActivity * 0.1);

  if (risk >= 0.72) return "critical";
  if (risk >= 0.34) return "warning";
  return "healthy";
}

function metricNode(
  strikecellId: StrikecellDomainId,
  id: string,
  label: string,
  activity: number,
  severity: number,
  meta?: Record<string, string | number | boolean>,
): StrikecellNode {
  return {
    id,
    strikecellId,
    label,
    kind: "metric",
    activity: clamp01(activity),
    severity: clamp01(severity),
    meta,
  };
}

function buildCell(
  id: StrikecellDomainId,
  status: StrikecellStatus,
  activityCount: number,
  nodes: StrikecellNode[],
): Strikecell {
  const meta = STRIKECELL_META[id];
  return {
    id,
    name: meta.name,
    routeId: meta.routeId,
    description: meta.description,
    status,
    activityCount,
    nodeCount: nodes.length,
    nodes,
    tags: meta.tags,
  };
}

function buildThreatNodes(snapshot: StrikecellSourceSnapshot): StrikecellNode[] {
  return snapshot.threats.slice(0, 10).map((threat) => ({
    id: `threat:${threat.id}`,
    strikecellId: "threat-radar",
    label: threat.label ?? threat.id,
    kind: "threat",
    severity: clamp01(threat.severity),
    activity: threat.active ? 1 : 0.35,
    meta: { type: threat.type, active: threat.active },
  }));
}

function buildAttackNodes(snapshot: StrikecellSourceSnapshot): StrikecellNode[] {
  return snapshot.attacks
    .flatMap((chain) => chain.techniques.map((technique) => ({ chain, technique })))
    .slice(0, 12)
    .map(({ chain, technique }) => ({
      id: `attack:${chain.id}:${technique.id}`,
      strikecellId: "attack-graph",
      label: technique.name,
      kind: "technique",
      severity: clamp01(technique.confidence),
      activity: technique.detected ? 0.8 : 0.4,
      meta: {
        chain: chain.name,
        tactic: technique.tactic,
        detected: technique.detected,
      },
    }));
}

function buildNetworkNodes(snapshot: StrikecellSourceSnapshot): StrikecellNode[] {
  return snapshot.network.nodes.slice(0, 12).map((node) => ({
    id: `network:${node.id}`,
    strikecellId: "network-map",
    label: node.hostname,
    kind: "host",
    severity: node.status === "compromised" ? 0.95 : node.status === "warning" ? 0.55 : 0.2,
    activity: clamp01((node.vulnerabilities ?? 0) / 5 + 0.2),
    meta: {
      type: node.type,
      ip: node.ip,
      vulnerabilities: node.vulnerabilities ?? 0,
      status: node.status,
    },
  }));
}

function buildWorkflowNodes(snapshot: StrikecellSourceSnapshot): StrikecellNode[] {
  return snapshot.workflows.slice(0, 10).map((workflow) => ({
    id: `workflow:${workflow.id}`,
    strikecellId: "workflows",
    label: workflow.name,
    kind: "workflow",
    severity: workflow.enabled ? 0.25 : 0.45,
    activity: clamp01(workflow.run_count / 40),
    meta: {
      enabled: workflow.enabled,
      runs: workflow.run_count,
    },
  }));
}

function buildMarketplaceNodes(snapshot: StrikecellSourceSnapshot): StrikecellNode[] {
  return snapshot.marketplacePolicies.slice(0, 10).map((policy) => ({
    id: `marketplace:${policy.entry_id}`,
    strikecellId: "marketplace",
    label: policy.title,
    kind: "policy",
    severity: policy.attestation_uid ? 0.2 : 0.5,
    activity: clamp01(policy.tags.length / 8 + 0.2),
    meta: {
      category: policy.category ?? "uncategorized",
      hasAttestation: Boolean(policy.attestation_uid),
    },
  }));
}

function buildEventNodes(snapshot: StrikecellSourceSnapshot): StrikecellNode[] {
  const events = snapshot.overview?.auditEvents ?? [];
  return events.slice(0, 12).map((event) => ({
    id: `event:${event.id}`,
    strikecellId: "events",
    label: `${event.action} @ ${event.resource}`,
    kind: "event",
    severity:
      event.severity === "critical"
        ? 0.95
        : event.severity === "error"
          ? 0.82
          : event.severity === "warning"
            ? 0.58
            : 0.2,
    activity: event.success ? 0.3 : 0.9,
    meta: {
      actor: event.actor,
      type: event.type,
      success: event.success,
    },
  }));
}

function buildPolicyNodes(snapshot: StrikecellSourceSnapshot): StrikecellNode[] {
  const kpis = snapshot.overview?.kpis;
  if (!kpis) return [];

  return [
    metricNode(
      "policies",
      "policy:block-rate",
      "Block Rate",
      ratio(kpis.blockedCount, kpis.totalChecks),
      ratio(kpis.blockedCount, kpis.totalChecks),
      {
        blocked: kpis.blockedCount,
        total: kpis.totalChecks,
      },
    ),
    metricNode(
      "policies",
      "policy:allow-rate",
      "Allow Rate",
      ratio(kpis.allowedCount, kpis.totalChecks),
      1 - ratio(kpis.allowedCount, kpis.totalChecks),
      {
        allowed: kpis.allowedCount,
        total: kpis.totalChecks,
      },
    ),
    metricNode(
      "policies",
      "policy:active-agents",
      "Active Agents",
      clamp01(kpis.activeAgents / 12),
      kpis.activeAgents > 0 ? 0.15 : 0.8,
      { agents: kpis.activeAgents },
    ),
  ];
}

function buildForensicsNodes(snapshot: StrikecellSourceSnapshot): StrikecellNode[] {
  const events = snapshot.overview?.auditEvents ?? [];
  return events
    .filter((e) => !e.success || e.severity === "critical" || e.severity === "error")
    .slice(0, 10)
    .map((event) => ({
      id: `forensics:${event.id}`,
      strikecellId: "forensics-river" as StrikecellDomainId,
      label: `${event.action} @ ${event.resource}`,
      kind: "event" as const,
      severity:
        event.severity === "critical"
          ? 0.95
          : event.severity === "error"
            ? 0.82
            : event.severity === "warning"
              ? 0.58
              : 0.2,
      activity: event.success ? 0.4 : 0.9,
      meta: {
        actor: event.actor,
        type: event.type,
        success: event.success,
      },
    }));
}

function buildOverviewNodes(snapshot: StrikecellSourceSnapshot): StrikecellNode[] {
  const kpis = snapshot.overview?.kpis;
  if (!kpis) return [];

  return [
    metricNode(
      "security-overview",
      "overview:checks",
      "Total Checks",
      clamp01(kpis.totalChecks / 500),
      ratio(kpis.blockedCount, Math.max(kpis.totalChecks, 1)),
      { checks: kpis.totalChecks },
    ),
    metricNode(
      "security-overview",
      "overview:blocked",
      "Blocked",
      clamp01(kpis.blockedCount / 200),
      ratio(kpis.blockedCount, Math.max(kpis.totalChecks, 1)),
      { blocked: kpis.blockedCount },
    ),
    metricNode(
      "security-overview",
      "overview:uptime",
      "Uptime",
      clamp01(kpis.uptimePercent / 100),
      kpis.uptimePercent >= 99 ? 0.1 : 0.45,
      { uptime: kpis.uptimePercent },
    ),
  ];
}

function computeConnections(strikecells: Strikecell[]): StrikecellConnection[] {
  const byId = new Map(strikecells.map((strikecell) => [strikecell.id, strikecell]));

  const weighted = (
    sourceId: StrikecellDomainId,
    targetId: StrikecellDomainId,
    kind: StrikecellConnection["kind"],
    baseStrength: number,
  ): StrikecellConnection => {
    const source = byId.get(sourceId);
    const target = byId.get(targetId);
    const sourceFactor = clamp01((source?.activityCount ?? 0) / 40);
    const targetFactor = clamp01((target?.activityCount ?? 0) / 40);
    const strength = clamp01(baseStrength + sourceFactor * 0.2 + targetFactor * 0.2);

    return {
      id: `${sourceId}->${targetId}`,
      sourceId,
      targetId,
      kind,
      strength,
    };
  };

  // Explicit deterministic ordering is intentional; tests rely on this sequence.
  return [
    weighted("security-overview", "threat-radar", "data-flow", 0.75),
    weighted("security-overview", "events", "data-flow", 0.7),
    weighted("threat-radar", "attack-graph", "dependency", 0.82),
    weighted("attack-graph", "network-map", "dependency", 0.68),
    weighted("network-map", "events", "related", 0.62),
    weighted("workflows", "events", "dependency", 0.58),
    weighted("workflows", "policies", "related", 0.52),
    weighted("marketplace", "policies", "dependency", 0.72),
    weighted("policies", "security-overview", "related", 0.66),
    weighted("events", "forensics-river", "data-flow", 0.78),
    weighted("forensics-river", "attack-graph", "related", 0.6),
    weighted("forensics-river", "security-overview", "related", 0.55),
  ];
}

export function buildStrikecellsFromSocData(snapshot: StrikecellSourceSnapshot): Strikecell[] {
  const threatNodes = buildThreatNodes(snapshot);
  const attackNodes = buildAttackNodes(snapshot);
  const networkNodes = buildNetworkNodes(snapshot);
  const workflowNodes = buildWorkflowNodes(snapshot);
  const marketplaceNodes = buildMarketplaceNodes(snapshot);
  const eventNodes = buildEventNodes(snapshot);
  const policyNodes = buildPolicyNodes(snapshot);
  const overviewNodes = buildOverviewNodes(snapshot);
  const forensicsNodes = buildForensicsNodes(snapshot);

  const kpis = snapshot.overview?.kpis;
  const totalChecks = kpis?.totalChecks ?? 0;
  const blockedCount = kpis?.blockedCount ?? 0;
  const blockedRate = ratio(blockedCount, Math.max(totalChecks, 1));

  const strikecells = [
    buildCell(
      "security-overview",
      deriveStrikecellHealth({
        connected: snapshot.connected,
        severityScore: blockedRate,
        blockedRate,
        activityCount: overviewNodes.reduce((acc, node) => acc + node.activity, 0) * 10,
      }),
      totalChecks,
      overviewNodes,
    ),
    buildCell(
      "threat-radar",
      deriveStrikecellHealth({
        connected: snapshot.connected,
        severityScore:
          threatNodes.length === 0
            ? 0
            : threatNodes.reduce((acc, node) => acc + node.severity, 0) / threatNodes.length,
        blockedRate,
        activityCount: snapshot.threats.filter((threat) => threat.active).length,
      }),
      snapshot.threats.filter((threat) => threat.active).length,
      threatNodes,
    ),
    buildCell(
      "attack-graph",
      deriveStrikecellHealth({
        connected: snapshot.connected,
        severityScore:
          attackNodes.length === 0
            ? 0
            : attackNodes.reduce((acc, node) => acc + node.severity, 0) / attackNodes.length,
        blockedRate,
        activityCount: snapshot.attacks.reduce((acc, chain) => acc + chain.techniques.length, 0),
      }),
      snapshot.attacks.reduce((acc, chain) => acc + chain.techniques.length, 0),
      attackNodes,
    ),
    buildCell(
      "network-map",
      deriveStrikecellHealth({
        connected: snapshot.connected,
        severityScore:
          networkNodes.length === 0
            ? 0
            : networkNodes.reduce((acc, node) => acc + node.severity, 0) / networkNodes.length,
        blockedRate,
        activityCount: snapshot.network.nodes.length + snapshot.network.edges.length,
      }),
      snapshot.network.nodes.length + snapshot.network.edges.length,
      networkNodes,
    ),
    buildCell(
      "workflows",
      deriveStrikecellHealth({
        connected: snapshot.connected,
        severityScore:
          workflowNodes.length === 0
            ? 0
            : workflowNodes.reduce((acc, node) => acc + node.severity, 0) / workflowNodes.length,
        blockedRate,
        activityCount: snapshot.workflows.filter((workflow) => workflow.enabled).length,
      }),
      snapshot.workflows.reduce((acc, workflow) => acc + workflow.run_count, 0),
      workflowNodes,
    ),
    buildCell(
      "marketplace",
      deriveStrikecellHealth({
        connected: snapshot.connected,
        severityScore:
          marketplaceNodes.length === 0
            ? 0.2
            : marketplaceNodes.reduce((acc, node) => acc + node.severity, 0) /
              marketplaceNodes.length,
        blockedRate,
        activityCount: snapshot.marketplacePolicies.length,
      }),
      snapshot.marketplacePolicies.length,
      marketplaceNodes,
    ),
    buildCell(
      "events",
      deriveStrikecellHealth({
        connected: snapshot.connected,
        severityScore:
          eventNodes.length === 0
            ? blockedRate
            : eventNodes.reduce((acc, node) => acc + node.severity, 0) / eventNodes.length,
        blockedRate,
        activityCount: eventNodes.length,
      }),
      eventNodes.length,
      eventNodes,
    ),
    buildCell(
      "forensics-river",
      deriveStrikecellHealth({
        connected: snapshot.connected,
        severityScore:
          forensicsNodes.length === 0
            ? blockedRate
            : forensicsNodes.reduce((acc, n) => acc + n.severity, 0) / forensicsNodes.length,
        blockedRate,
        activityCount: forensicsNodes.length,
      }),
      forensicsNodes.length,
      forensicsNodes,
    ),
    buildCell(
      "policies",
      deriveStrikecellHealth({
        connected: snapshot.connected,
        severityScore: blockedRate,
        blockedRate,
        activityCount: kpis?.activeAgents ?? 0,
      }),
      kpis?.activeAgents ?? 0,
      policyNodes,
    ),
  ];

  const ordered = STRIKECELL_ORDER.map((id) =>
    strikecells.find((strikecell) => strikecell.id === id),
  ).filter((strikecell): strikecell is Strikecell => Boolean(strikecell));

  if (!snapshot.connected) {
    return ordered.map((strikecell) => ({
      ...strikecell,
      status: "offline",
      activityCount: 0,
      nodes: [],
      nodeCount: 0,
    }));
  }

  return ordered;
}

export function buildNexusNodesAndConnections(strikecells: Strikecell[]): NexusGraph {
  const nodes = strikecells.flatMap((strikecell) => strikecell.nodes);
  const connections = computeConnections(strikecells);
  return { nodes, connections };
}
