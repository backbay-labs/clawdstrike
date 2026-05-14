import type { SecurityContext } from "./context.js";
import type { Decision, PolicyEvent } from "./types.js";

export interface BrokerExecutionContext {
  toolName: string;
  rawInput: unknown;
  dispatchInput: unknown;
  parameters: Record<string, unknown>;
  policyEvent: PolicyEvent;
  decision: Decision;
  securityContext: SecurityContext;
}

export interface BrokerExecutionResult {
  replacementResult: unknown;
  metadata?: Record<string, unknown>;
}

export interface BrokerExecutor {
  execute(context: BrokerExecutionContext): Promise<BrokerExecutionResult | null>;
}

export interface BrokerConfig {
  executor: BrokerExecutor;
}
