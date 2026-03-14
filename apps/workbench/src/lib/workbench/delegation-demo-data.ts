/**
 * Rich demo delegation graph for visualization when the control-api is
 * unavailable.  Tells a realistic story of a multi-agent deployment pipeline.
 *
 * Scenario:
 *   A System-level Orchestrator delegates to a Planner, Coder and Tester.
 *   The Planner spawns two low-trust research sub-agents.  The Coder issues
 *   a narrower grant to a Code Reviewer.  A Deployer awaits Approval.
 *   One research agent is compromised and its grants are revoked.  Session
 *   and Event nodes capture runtime activity.
 */

import type { DelegationGraph, DelegationNode, DelegationEdge } from "./delegation-types";


function isoRelative(daysFromNow: number, hours = 0): string {
  const d = new Date();
  d.setDate(d.getDate() + daysFromNow);
  d.setHours(hours, 0, 0, 0);
  return d.toISOString();
}


const nodes: DelegationNode[] = [
  // --- Principals ---
  {
    id: "p-orchestrator",
    kind: "Principal",
    label: "Orchestrator",
    role: "Custom",
    trustLevel: "System",
    capabilities: [
      "FileRead", "FileWrite", "NetworkEgress", "CommandExec",
      "SecretAccess", "McpTool", "DeployApproval", "AgentAdmin",
    ],
    metadata: { description: "Root system orchestrator" },
  },
  {
    id: "p-planner",
    kind: "Principal",
    label: "Planner",
    role: "Planner",
    trustLevel: "High",
    capabilities: ["FileRead", "NetworkEgress", "McpTool", "AgentAdmin"],
    metadata: { description: "Strategic task planner" },
  },
  {
    id: "p-coder",
    kind: "Principal",
    label: "Coder",
    role: "Coder",
    trustLevel: "High",
    capabilities: ["FileRead", "FileWrite", "CommandExec", "McpTool"],
    metadata: { description: "Primary code authoring agent" },
  },
  {
    id: "p-tester",
    kind: "Principal",
    label: "Tester",
    role: "Tester",
    trustLevel: "Medium",
    capabilities: ["FileRead", "CommandExec"],
    metadata: { description: "Test execution and reporting" },
  },
  {
    id: "p-reviewer",
    kind: "Principal",
    label: "Code Reviewer",
    role: "Reviewer",
    trustLevel: "Medium",
    capabilities: ["FileRead"],
    metadata: { description: "Reviews code changes before merge" },
  },
  {
    id: "p-deployer",
    kind: "Principal",
    label: "Deployer",
    role: "Deployer",
    trustLevel: "High",
    capabilities: ["FileRead", "CommandExec", "DeployApproval", "NetworkEgress"],
    metadata: { description: "Handles production deployments" },
  },
  {
    id: "p-monitor",
    kind: "Principal",
    label: "Monitor",
    role: "Monitor",
    trustLevel: "Medium",
    capabilities: ["FileRead", "NetworkEgress"],
    metadata: { description: "Runtime monitoring and alerting" },
  },
  {
    id: "p-research-a",
    kind: "Principal",
    label: "Research Agent A",
    role: "Custom",
    trustLevel: "Low",
    capabilities: ["FileRead", "NetworkEgress"],
    metadata: { description: "Web research sub-agent" },
  },
  {
    id: "p-research-b",
    kind: "Principal",
    label: "Research Agent B",
    role: "Custom",
    trustLevel: "Low",
    capabilities: ["FileRead", "NetworkEgress"],
    metadata: { description: "Documentation lookup sub-agent (COMPROMISED)" },
  },

  // --- Grants ---
  {
    id: "g-planner-grant",
    kind: "Grant",
    label: "Planner Delegation",
    capabilities: ["FileRead", "NetworkEgress", "McpTool", "AgentAdmin"],
    metadata: { expires: isoRelative(1) },
  },
  {
    id: "g-coder-grant",
    kind: "Grant",
    label: "Coder Delegation",
    capabilities: ["FileRead", "FileWrite", "CommandExec", "McpTool"],
    metadata: { expires: isoRelative(1) },
  },
  {
    id: "g-reviewer-grant",
    kind: "Grant",
    label: "Review Grant",
    capabilities: ["FileRead"],
    metadata: { expires: isoRelative(0, 12), scope: "PR #42 only" },
  },
  {
    id: "g-research-grant",
    kind: "Grant",
    label: "Research Grant",
    capabilities: ["FileRead", "NetworkEgress"],
    metadata: { expires: isoRelative(-1, 6) },
  },

  // --- Approval ---
  {
    id: "a-deploy-approval",
    kind: "Approval",
    label: "Deploy Approval v2.1.0",
    metadata: { approver: "ops-team", timestamp: isoRelative(0, 8) },
  },

  // --- Sessions ---
  {
    id: "s-coder-session",
    kind: "Session",
    label: "Coder Session #7a3f",
    metadata: { startedAt: isoRelative(0, 7), status: "active" },
  },
  {
    id: "s-tester-session",
    kind: "Session",
    label: "Tester Session #b2c1",
    metadata: { startedAt: isoRelative(0, 7), status: "active" },
  },

  // --- Events ---
  {
    id: "e-secret-leak",
    kind: "Event",
    label: "SecretLeak Blocked",
    metadata: {
      guard: "SecretLeakGuard",
      action: "file_write",
      path: "/app/config/.env",
      timestamp: isoRelative(0, 7),
    },
  },
  {
    id: "e-revocation",
    kind: "Event",
    label: "Grant Revoked",
    metadata: {
      reason: "Anomalous egress detected",
      target: "Research Agent B",
      timestamp: isoRelative(0, 8),
    },
  },

  // --- Response Action ---
  {
    id: "ra-quarantine",
    kind: "ResponseAction",
    label: "Quarantine Agent B",
    metadata: {
      action: "isolate_principal",
      triggered_by: "e-revocation",
      timestamp: isoRelative(0, 8),
    },
  },
];


const edges: DelegationEdge[] = [
  // Orchestrator issues grants
  {
    id: "e1",
    from: "p-orchestrator",
    to: "g-planner-grant",
    kind: "IssuedGrant",
    capabilities: ["FileRead", "NetworkEgress", "McpTool", "AgentAdmin"],
  },
  {
    id: "e2",
    from: "g-planner-grant",
    to: "p-planner",
    kind: "ReceivedGrant",
    capabilities: ["FileRead", "NetworkEgress", "McpTool", "AgentAdmin"],
  },
  {
    id: "e3",
    from: "p-orchestrator",
    to: "g-coder-grant",
    kind: "IssuedGrant",
    capabilities: ["FileRead", "FileWrite", "CommandExec", "McpTool"],
  },
  {
    id: "e4",
    from: "g-coder-grant",
    to: "p-coder",
    kind: "ReceivedGrant",
    capabilities: ["FileRead", "FileWrite", "CommandExec", "McpTool"],
  },

  // Orchestrator spawns tester, deployer, monitor directly
  {
    id: "e5",
    from: "p-orchestrator",
    to: "p-tester",
    kind: "SpawnedPrincipal",
    capabilities: ["FileRead", "CommandExec"],
  },
  {
    id: "e6",
    from: "p-orchestrator",
    to: "p-deployer",
    kind: "SpawnedPrincipal",
    capabilities: ["FileRead", "CommandExec", "DeployApproval", "NetworkEgress"],
  },
  {
    id: "e7",
    from: "p-orchestrator",
    to: "p-monitor",
    kind: "SpawnedPrincipal",
    capabilities: ["FileRead", "NetworkEgress"],
  },

  // Planner spawns research agents
  {
    id: "e8",
    from: "p-planner",
    to: "p-research-a",
    kind: "SpawnedPrincipal",
    capabilities: ["FileRead", "NetworkEgress"],
  },
  {
    id: "e9",
    from: "p-planner",
    to: "p-research-b",
    kind: "SpawnedPrincipal",
    capabilities: ["FileRead", "NetworkEgress"],
  },

  // Planner issues research grant (derived from its own)
  {
    id: "e10",
    from: "g-planner-grant",
    to: "g-research-grant",
    kind: "DerivedFromGrant",
    capabilities: ["FileRead", "NetworkEgress"],
  },
  {
    id: "e11",
    from: "g-research-grant",
    to: "p-research-a",
    kind: "ReceivedGrant",
    capabilities: ["FileRead", "NetworkEgress"],
  },
  {
    id: "e12",
    from: "g-research-grant",
    to: "p-research-b",
    kind: "ReceivedGrant",
    capabilities: ["FileRead", "NetworkEgress"],
  },

  // Coder issues narrower grant to reviewer (derived from coder grant)
  {
    id: "e13",
    from: "g-coder-grant",
    to: "g-reviewer-grant",
    kind: "DerivedFromGrant",
    capabilities: ["FileRead"],
  },
  {
    id: "e14",
    from: "g-reviewer-grant",
    to: "p-reviewer",
    kind: "ReceivedGrant",
    capabilities: ["FileRead"],
  },

  // Deploy approval
  {
    id: "e15",
    from: "a-deploy-approval",
    to: "p-deployer",
    kind: "ApprovedBy",
  },

  // Revocation: Research Agent B compromised
  {
    id: "e16",
    from: "e-revocation",
    to: "p-research-b",
    kind: "RevokedBy",
    metadata: { reason: "Anomalous egress to unknown C2 domain" },
  },

  // Sessions exercised
  {
    id: "e17",
    from: "p-coder",
    to: "s-coder-session",
    kind: "ExercisedInSession",
  },
  {
    id: "e18",
    from: "p-tester",
    to: "s-tester-session",
    kind: "ExercisedInSession",
  },

  // Events
  {
    id: "e19",
    from: "s-coder-session",
    to: "e-secret-leak",
    kind: "ExercisedInEvent",
    metadata: { guard: "SecretLeakGuard", verdict: "Deny" },
  },

  // Monitor detects anomaly leading to revocation
  {
    id: "e20",
    from: "p-monitor",
    to: "e-revocation",
    kind: "ExercisedInEvent",
    metadata: { detection: "egress_anomaly" },
  },

  // Response action triggered by revocation event
  {
    id: "e21",
    from: "e-revocation",
    to: "ra-quarantine",
    kind: "TriggeredResponseAction",
  },

  // Deployer session (post-approval)
  {
    id: "e22",
    from: "p-deployer",
    to: "a-deploy-approval",
    kind: "ExercisedInEvent",
    metadata: { action: "request_approval" },
  },

  // Reviewer reads coder session artifacts
  {
    id: "e23",
    from: "p-reviewer",
    to: "s-coder-session",
    kind: "ExercisedInSession",
    metadata: { action: "review_diff" },
  },

  // Research A reports back to planner
  {
    id: "e24",
    from: "p-research-a",
    to: "p-planner",
    kind: "ExercisedInEvent",
    metadata: { action: "research_complete", findings: 12 },
  },
];


export const DEMO_DELEGATION_GRAPH: DelegationGraph = { nodes, edges };
