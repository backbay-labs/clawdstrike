/**
 * Demo approval requests for the Approval Queue when the control-api
 * is unavailable.
 *
 * Covers a range of providers, risk levels, statuses, and expiry windows
 * to exercise every visual state in the UI.
 */

import type { ApprovalRequest, ApprovalDecision } from "./approval-types";

// ---------------------------------------------------------------------------
// Helpers — timestamps relative to "now" so countdown timers work in demo
// ---------------------------------------------------------------------------

function minutesFromNow(m: number): string {
  return new Date(Date.now() + m * 60_000).toISOString();
}

function minutesAgo(m: number): string {
  return new Date(Date.now() - m * 60_000).toISOString();
}

// ---------------------------------------------------------------------------
// Requests (10)
// ---------------------------------------------------------------------------

export const DEMO_APPROVAL_REQUESTS: ApprovalRequest[] = [
  {
    id: "apr-001",
    originContext: {
      provider: "slack",
      tenant_id: "T-ACME-CORP",
      space_id: "C-engineering",
      space_type: "channel",
      actor_id: "U-bot-infra",
      actor_name: "infra-bot",
      visibility: "internal",
    },
    enclaveId: "enc-prod-01",
    toolName: "shell_command",
    reason: "Needs to run `kubectl rollout restart` to recover a degraded pod in the production cluster.",
    requestedBy: "infra-bot",
    requestedAt: minutesAgo(12),
    expiresAt: minutesFromNow(18),
    status: "pending",
    agentId: "agent-infra-001",
    agentName: "Infra Remediation Bot",
    capability: "CommandExec",
    riskLevel: "high",
  },
  {
    id: "apr-002",
    originContext: {
      provider: "github",
      tenant_id: "backbay-labs",
      space_id: "clawdstrike-policy-builder",
      space_type: "repository",
      actor_id: "github-actions[bot]",
      actor_name: "CI Pipeline",
      visibility: "internal",
    },
    enclaveId: "enc-ci-01",
    toolName: "network_egress",
    reason: "Publish step requires egress to registry.npmjs.org to push @clawdstrike/sdk v0.12.0.",
    requestedBy: "CI Pipeline",
    requestedAt: minutesAgo(3),
    expiresAt: minutesFromNow(27),
    status: "pending",
    agentId: "agent-ci-npm",
    agentName: "NPM Publish Agent",
    capability: "NetworkEgress",
    riskLevel: "medium",
  },
  {
    id: "apr-003",
    originContext: {
      provider: "teams",
      tenant_id: "T-CONTOSO",
      space_id: "team-helpdesk",
      space_type: "channel",
      actor_id: "U-support-bot",
      actor_name: "support-agent",
      visibility: "internal",
    },
    toolName: "file_write",
    reason: "Write diagnostic bundle to /tmp/diag-20260309.tar.gz for support ticket #8891.",
    requestedBy: "support-agent",
    requestedAt: minutesAgo(45),
    expiresAt: minutesFromNow(75),
    status: "pending",
    agentId: "agent-support-01",
    agentName: "Customer Support Bot",
    capability: "FileWrite",
    riskLevel: "low",
  },
  {
    id: "apr-004",
    originContext: {
      provider: "slack",
      tenant_id: "T-ACME-CORP",
      space_id: "C-research",
      space_type: "channel",
      actor_id: "U-researcher",
      actor_name: "alex-research",
      visibility: "internal",
    },
    enclaveId: "enc-research-02",
    toolName: "mcp_tool:arxiv-search",
    reason: "Research agent wants to invoke the arxiv-search MCP tool to fetch papers on adversarial prompt detection.",
    requestedBy: "alex-research",
    requestedAt: minutesAgo(8),
    expiresAt: minutesFromNow(52),
    status: "pending",
    agentId: "agent-research-alpha",
    agentName: "Research Agent Alpha",
    capability: "McpTool",
    riskLevel: "medium",
  },
  {
    id: "apr-005",
    originContext: {
      provider: "github",
      tenant_id: "backbay-labs",
      space_id: "infrastructure",
      space_type: "repository",
      actor_id: "deploy-bot",
      actor_name: "Deploy Bot",
      visibility: "internal",
    },
    enclaveId: "enc-prod-01",
    toolName: "deploy_approval",
    reason: "Production release v2.1.0 — all tests passing, 3 reviewers approved. Requesting final deploy gate.",
    requestedBy: "Deploy Bot",
    requestedAt: minutesAgo(2),
    expiresAt: minutesFromNow(3),
    status: "pending",
    agentId: "agent-deploy-prod",
    agentName: "Production Deployer",
    capability: "DeployApproval",
    riskLevel: "critical",
  },
  {
    id: "apr-006",
    originContext: {
      provider: "slack",
      tenant_id: "T-ACME-CORP",
      space_id: "C-security",
      space_type: "channel",
      actor_id: "U-sec-scanner",
      actor_name: "sec-scanner",
      visibility: "restricted",
    },
    enclaveId: "enc-security-01",
    toolName: "secret_access",
    reason: "Rotation workflow needs to read current API keys from vault to generate replacements.",
    requestedBy: "sec-scanner",
    requestedAt: minutesAgo(20),
    expiresAt: minutesFromNow(10),
    status: "pending",
    agentId: "agent-sec-rotate",
    agentName: "Secret Rotation Agent",
    capability: "SecretAccess",
    riskLevel: "high",
  },
  // --- Already resolved ---
  {
    id: "apr-007",
    originContext: {
      provider: "jira",
      tenant_id: "T-ACME-CORP",
      space_id: "PROJ-CLOUD",
      space_type: "project",
      actor_id: "U-auto-triage",
      actor_name: "auto-triage",
      visibility: "internal",
    },
    toolName: "file_read",
    reason: "Triage bot reading stack traces from /var/log/app/*.log for automatic bug classification.",
    requestedBy: "auto-triage",
    requestedAt: minutesAgo(120),
    expiresAt: minutesAgo(60),
    status: "approved",
    agentId: "agent-triage-01",
    agentName: "Auto-Triage Bot",
    capability: "FileRead",
    riskLevel: "low",
  },
  {
    id: "apr-008",
    originContext: {
      provider: "github",
      tenant_id: "backbay-labs",
      space_id: "clawdstrike",
      space_type: "repository",
      actor_id: "dependabot[bot]",
      actor_name: "Dependabot",
      visibility: "public",
    },
    toolName: "network_egress",
    reason: "Fetch updated advisory database from github.com/advisories for vulnerability scan.",
    requestedBy: "Dependabot",
    requestedAt: minutesAgo(90),
    expiresAt: minutesAgo(30),
    status: "denied",
    agentId: "agent-dependabot",
    agentName: "Dependabot Scanner",
    capability: "NetworkEgress",
    riskLevel: "medium",
  },
  // --- Expired ---
  {
    id: "apr-009",
    originContext: {
      provider: "cli",
      tenant_id: "local",
      space_id: "terminal",
      space_type: "session",
      actor_id: "U-dev-local",
      actor_name: "dev-local",
      visibility: "private",
    },
    toolName: "shell_command",
    reason: "Local dev agent requested `rm -rf node_modules` to clear cache during troubleshooting.",
    requestedBy: "dev-local",
    requestedAt: minutesAgo(180),
    expiresAt: minutesAgo(150),
    status: "expired",
    agentId: "agent-local-dev",
    agentName: "Local Dev Agent",
    capability: "CommandExec",
    riskLevel: "high",
  },
  {
    id: "apr-010",
    originContext: {
      provider: "api",
      tenant_id: "T-PARTNER",
      space_id: "integration-test",
      space_type: "environment",
      actor_id: "U-partner-bot",
      actor_name: "partner-bot",
      visibility: "external",
    },
    enclaveId: "enc-partner-sandbox",
    toolName: "mcp_tool:database-query",
    reason: "Partner integration agent requesting database read access for data reconciliation job.",
    requestedBy: "partner-bot",
    requestedAt: minutesAgo(60),
    expiresAt: minutesAgo(5),
    status: "expired",
    agentId: "agent-partner-int",
    agentName: "Partner Integration Bot",
    capability: "McpTool",
    riskLevel: "medium",
  },
];

// ---------------------------------------------------------------------------
// Resolved decisions (for the already-resolved items above)
// ---------------------------------------------------------------------------

export const DEMO_APPROVAL_DECISIONS: ApprovalDecision[] = [
  {
    requestId: "apr-007",
    decision: "approved",
    scope: { ttlSeconds: 3600, threadOnly: false, toolOnly: true },
    reason: "Low-risk read-only access, scoped to file_read only.",
    decidedBy: "ops-admin@acme.corp",
    decidedAt: minutesAgo(115),
  },
  {
    requestId: "apr-008",
    decision: "denied",
    reason: "Public visibility repo — egress to external advisory DB not permitted under strict policy.",
    decidedBy: "sec-lead@backbay.io",
    decidedAt: minutesAgo(85),
  },
];
