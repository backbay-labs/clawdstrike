/**
 * @clawdstrike/adapter-core
 *
 * Core adapter infrastructure for Clawdstrike security integrations.
 */

export type { PolicyEngineLike } from './engine.js';

export type {
  ClawdstrikeConfig,
  CuaEventData,
  Decision,
  DecisionStatus,
  EvaluationMode,
  EventData,
  EventType,
  GuardToggles,
  LogLevel,
  Policy,
  PolicyEvent,
  Severity,
} from './types.js';

export {
  allowDecision,
  createDecision,
  denyDecision,
  warnDecision,
} from './types.js';

export type { ContextSummary, SecurityContext } from './context.js';
export { DefaultSecurityContext, createSecurityContext } from './context.js';

export type {
  AdapterConfig,
  AuditConfig,
  EventHandlers,
  FrameworkAdapter,
  FrameworkHooks,
  GenericToolCall,
  SessionSummary,
  ToolCallTranslationInput,
  ToolCallTranslator,
} from './adapter.js';

export type { AuditEvent, AuditEventType, AuditLogger } from './audit.js';
export { InMemoryAuditLogger } from './audit.js';

export type { OutputSanitizer, RedactionInfo } from './sanitizer.js';
export { DefaultOutputSanitizer } from './default-output-sanitizer.js';

export type {
  InterceptResult,
  ProcessedOutput,
  ToolInterceptor,
} from './interceptor.js';

export { BaseToolInterceptor } from './base-tool-interceptor.js';
export { PolicyEventFactory } from './policy-event-factory.js';
export type {
  ParseNetworkTargetOptions,
  ParsedNetworkTarget,
} from './network-target.js';
export { parseNetworkTarget } from './network-target.js';

export type {
  GenericToolBoundaryOptions,
  GenericToolDispatcher,
} from './generic-tool-runner.js';
export {
  GenericToolBoundary,
  GenericToolCallBlockedError,
  wrapGenericToolDispatcher,
} from './generic-tool-runner.js';

export { ClawdstrikeBlockedError } from './errors.js';

export type {
  FrameworkToolBoundaryOptions,
  FrameworkToolDispatcher,
} from './framework-tool-boundary.js';
export {
  FrameworkToolBoundary,
  wrapFrameworkToolDispatcher,
} from './framework-tool-boundary.js';

export { createSessionSummary } from './finalize-context.js';

export { createFrameworkAdapter } from './framework-adapter.js';

export type { PolicyEvalResponseV1 } from './engine-response.js';
export {
  failClosed,
  isRecord,
  parseDecision,
  parsePolicyEvalResponse,
} from './engine-response.js';
