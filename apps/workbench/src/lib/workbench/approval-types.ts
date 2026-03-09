export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export type OriginProvider = "slack" | "teams" | "github" | "jira" | "cli" | "api";

export interface OriginContext {
  provider: OriginProvider;
  tenant_id?: string;
  space_id?: string;
  space_type?: string;
  actor_id?: string;
  actor_name?: string;
  visibility?: string;
}

export interface ApprovalRequest {
  id: string;
  originContext: OriginContext;
  enclaveId?: string;
  toolName: string;
  reason: string;
  requestedBy: string;
  requestedAt: string;
  expiresAt: string;
  status: ApprovalStatus;
  agentId?: string;
  agentName?: string;
  capability?: string;
  riskLevel?: RiskLevel;
}

export interface ApprovalScope {
  ttlSeconds?: number;
  threadOnly?: boolean;
  toolOnly?: boolean;
}

export interface ApprovalDecision {
  requestId: string;
  decision: "approved" | "denied";
  scope?: ApprovalScope;
  reason?: string;
  decidedBy: string;
  decidedAt: string;
}
