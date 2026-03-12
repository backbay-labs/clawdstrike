import type {
  OriginProvider as CanonicalOriginProvider,
  OriginContext as CanonicalOriginContext,
} from "./types";

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";

export type RiskLevel = "low" | "medium" | "high" | "critical";

/**
 * Extends the canonical OriginProvider with backend-specific providers
 * ("cli" and "api") that are used in approval workflows but not part
 * of the external origin provider set.
 */
export type OriginProvider = CanonicalOriginProvider | "cli" | "api";

/**
 * Extends the canonical OriginContext with approval-specific fields.
 * - `provider` is widened to include backend-specific providers ("cli", "api").
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
