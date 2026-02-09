import { describe, expect, it } from "vitest";
import {
  buildNexusNodesAndConnections,
  buildStrikecellsFromSocData,
  deriveStrikecellHealth,
} from "./strikecellAdapter";
import type { StrikecellSourceSnapshot } from "../types";

const baseSnapshot: StrikecellSourceSnapshot = {
  connected: true,
  threats: [
    {
      id: "t1",
      angle: 0,
      distance: 0.5,
      severity: 0.9,
      type: "intrusion",
      active: true,
      label: "High-risk egress",
    },
  ],
  attacks: [
    {
      id: "chain-1",
      name: "Chain 1",
      actor: "agent-x",
      status: "active",
      techniques: [
        {
          id: "T1001",
          name: "Technique A",
          tactic: "execution",
          detected: true,
          confidence: 0.8,
        },
      ],
    },
  ],
  network: {
    nodes: [
      {
        id: "n1",
        type: "server",
        hostname: "srv-1",
        ip: "10.0.0.1",
        status: "warning",
        services: ["https"],
        vulnerabilities: 1,
      },
    ],
    edges: [
      {
        id: "e1",
        source: "n1",
        target: "n2",
        protocol: "https",
        encrypted: true,
        status: "active",
      },
    ],
  },
  overview: {
    threats: [],
    auditEvents: [
      {
        id: "evt-1",
        timestamp: new Date(),
        type: "alert",
        severity: "critical",
        actor: "agent-x",
        resource: "db",
        action: "blocked write",
        success: false,
      },
    ],
    kpis: {
      totalChecks: 100,
      blockedCount: 30,
      allowedCount: 70,
      activeAgents: 4,
      uptimePercent: 99.9,
      avgResponseMs: 12,
    },
  },
  workflows: [
    {
      id: "wf-1",
      name: "Critical alert",
      enabled: true,
      trigger: { type: "event_match", conditions: [] },
      actions: [],
      run_count: 8,
      created_at: new Date().toISOString(),
    },
  ],
  marketplacePolicies: [
    {
      entry_id: "p-1",
      bundle_uri: "bundle://one",
      title: "Enterprise policy",
      description: "Enterprise defaults",
      category: "enterprise",
      tags: ["enterprise", "strict"],
      signed_bundle: {
        bundle: {
          version: "1",
          bundle_id: "b-1",
          compiled_at: new Date().toISOString(),
          policy: { version: "1", name: "enterprise", description: "strict" },
          policy_hash: "abc",
        },
        signature: "sig",
      },
    },
  ],
};

describe("deriveStrikecellHealth", () => {
  it("returns offline when disconnected", () => {
    expect(
      deriveStrikecellHealth({
        connected: false,
        severityScore: 0.9,
        blockedRate: 0.9,
        activityCount: 100,
      })
    ).toBe("offline");
  });

  it("returns healthy for low-risk profiles", () => {
    expect(
      deriveStrikecellHealth({
        connected: true,
        severityScore: 0.1,
        blockedRate: 0.1,
        activityCount: 2,
      })
    ).toBe("healthy");
  });

  it("returns critical for high-risk profiles", () => {
    expect(
      deriveStrikecellHealth({
        connected: true,
        severityScore: 0.95,
        blockedRate: 0.8,
        activityCount: 40,
      })
    ).toBe("critical");
  });
});

describe("buildStrikecellsFromSocData", () => {
  it("maps all domain strikecells with deterministic ordering", () => {
    const strikecells = buildStrikecellsFromSocData(baseSnapshot);
    expect(strikecells.map((strikecell) => strikecell.id)).toEqual([
      "security-overview",
      "threat-radar",
      "attack-graph",
      "network-map",
      "forensics-river",
      "workflows",
      "marketplace",
      "events",
      "policies",
    ]);
    expect(strikecells.every((strikecell) => typeof strikecell.activityCount === "number")).toBe(true);
  });

  it("returns offline strikecells when disconnected", () => {
    const strikecells = buildStrikecellsFromSocData({ ...baseSnapshot, connected: false });
    expect(strikecells.every((strikecell) => strikecell.status === "offline")).toBe(true);
    expect(strikecells.every((strikecell) => strikecell.activityCount === 0)).toBe(true);
    expect(strikecells.every((strikecell) => strikecell.nodeCount === 0)).toBe(true);
  });
});

describe("buildNexusNodesAndConnections", () => {
  it("creates flattened nodes with graph connections", () => {
    const strikecells = buildStrikecellsFromSocData(baseSnapshot);
    const graph = buildNexusNodesAndConnections(strikecells);
    expect(graph.nodes.length).toBeGreaterThan(0);
    expect(graph.connections.length).toBeGreaterThan(0);
    expect(graph.connections.some((connection) => connection.sourceId === "marketplace" && connection.targetId === "policies")).toBe(true);
  });

  it("is deterministic across repeated runs", () => {
    const strikecellsA = buildStrikecellsFromSocData(baseSnapshot);
    const strikecellsB = buildStrikecellsFromSocData(baseSnapshot);
    const graphA = buildNexusNodesAndConnections(strikecellsA);
    const graphB = buildNexusNodesAndConnections(strikecellsB);

    expect(graphA.nodes.map((node) => node.id)).toEqual(graphB.nodes.map((node) => node.id));
    expect(graphA.connections.map((connection) => connection.id)).toEqual(
      graphB.connections.map((connection) => connection.id)
    );
    expect(graphA.connections.map((connection) => connection.strength)).toEqual(
      graphB.connections.map((connection) => connection.strength)
    );
  });
});
