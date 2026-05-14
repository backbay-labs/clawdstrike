import type {
  OriginProvider as CanonicalOriginProvider,
  OriginContext as CanonicalOriginContext,
} from "./types";

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export type OriginProvider = CanonicalOriginProvider;

/**
 * Extends the canonical OriginContext with approval-specific fields.
 * - `actor_name` is an approval-specific display name for the actor.
 */
export interface OriginContext extends Omit<CanonicalOriginContext, "provider"> {
  provider: OriginProvider;
  actor_name?: string;
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
