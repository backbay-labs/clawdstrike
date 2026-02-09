import type { AuditEvent, AuditEventType, AuditLogger } from './audit.js';
import type { SecurityContext } from './context.js';
import type { PolicyEngineLike } from './engine.js';
import type { InterceptResult, ProcessedOutput } from './interceptor.js';
import type { ClawdstrikeConfig, Decision } from './types.js';

export interface FrameworkAdapter<TContext = unknown> {
  readonly name: string;
  readonly version: string;

  initialize(config: AdapterConfig): Promise<void>;
  createContext(metadata?: Record<string, unknown>): SecurityContext;

  interceptToolCall(
    context: SecurityContext,
    toolCall: GenericToolCall,
  ): Promise<InterceptResult>;

  processOutput(
    context: SecurityContext,
    toolCall: GenericToolCall,
    output: unknown,
  ): Promise<ProcessedOutput>;

  finalizeContext(context: SecurityContext): Promise<SessionSummary>;
  getEngine(): PolicyEngineLike;
  getHooks(): FrameworkHooks<TContext>;
}

export interface AdapterConfig extends ClawdstrikeConfig {
  blockOnViolation?: boolean;
  sanitizeOutputs?: boolean;
  injectSecurityPrompt?: boolean;
  normalizeToolName?: (name: string) => string;
  excludedTools?: string[];
  audit?: AuditConfig;
  handlers?: EventHandlers;
}

export interface AuditConfig {
  enabled?: boolean;
  logger?: AuditLogger;
  events?: AuditEventType[];
  logParameters?: boolean;
  logOutputs?: boolean;
  redactPII?: boolean;
}

export interface EventHandlers {
  onBeforeEvaluate?: (toolCall: GenericToolCall) => void;
  onAfterEvaluate?: (toolCall: GenericToolCall, decision: Decision) => void;
  onBlocked?: (toolCall: GenericToolCall, decision: Decision) => void;
  onWarning?: (toolCall: GenericToolCall, decision: Decision) => void;
  onError?: (error: Error, toolCall?: GenericToolCall) => void;
}

export interface FrameworkHooks<TContext = unknown> {
  createCallbackHandler?(): unknown;
  wrapTool?<T>(tool: T): T;
  injectIntoContext?(context: TContext): TContext;
  extractFromContext?(context: TContext): Record<string, unknown>;
}

export interface GenericToolCall {
  id: string;
  name: string;
  parameters: Record<string, unknown>;
  rawParameters?: unknown;
  timestamp: Date;
  source: string;
  metadata?: Record<string, unknown>;
}

export interface SessionSummary {
  sessionId: string;
  startTime: Date;
  endTime: Date;
  duration: number;
  totalToolCalls: number;
  blockedToolCalls: number;
  warningsIssued: number;
  toolsUsed: string[];
  toolsBlocked: string[];
  auditEvents: AuditEvent[];
  policy: string;
  mode: string;
}

