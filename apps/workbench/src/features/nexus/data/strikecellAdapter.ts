import type {
  NexusGraph,
  Strikecell,
  StrikecellConnection,
  StrikecellDomainId,
  StrikecellStatus,
} from "../types";

// ---------------------------------------------------------------------------
// Graph builder -- used by CyberNexusInner to derive connections from strikecells
// ---------------------------------------------------------------------------

function clamp01(value: number): number {
  return Math.max(0, Math.min(1, value));
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

export function buildNexusNodesAndConnections(strikecells: Strikecell[]): NexusGraph {
  const nodes = strikecells.flatMap((strikecell) => strikecell.nodes);
  const connections = computeConnections(strikecells);
  return { nodes, connections };
}

export function deriveStrikecellHealth(input: {
  connected: boolean;
  severityScore: number;
  blockedRate: number;
  activityCount: number;
}): StrikecellStatus {
  if (!input.connected) return "offline";

  const normalizedActivity = clamp01(input.activityCount / 25);
  const risk = clamp01(
    input.severityScore * 0.55 + input.blockedRate * 0.35 + normalizedActivity * 0.1,
  );

  if (risk >= 0.72) return "critical";
  if (risk >= 0.34) return "warning";
  return "healthy";
}
