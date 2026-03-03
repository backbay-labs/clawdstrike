/**
 * @clawdstrike/adapter-core
 *
 * Core adapter infrastructure for Clawdstrike security integrations.
 */

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
} from "./adapter.js";
export type { AuditEvent, AuditEventType, AuditLogger } from "./audit.js";
export { InMemoryAuditLogger } from "./audit.js";
export { BaseToolInterceptor } from "./base-tool-interceptor.js";
export type { ContextSummary, SecurityContext } from "./context.js";
export { createSecurityContext, DefaultSecurityContext } from "./context.js";
export { DefaultOutputSanitizer } from "./default-output-sanitizer.js";
export type { PolicyEngineLike } from "./engine.js";
export type { PolicyEvalResponseV1 } from "./engine-response.js";
export {
  failClosed,
  isRecord,
  parseDecision,
  parsePolicyEvalResponse,
} from "./engine-response.js";
export { ClawdstrikeBlockedError } from "./errors.js";
export { createSessionSummary } from "./finalize-context.js";
export { createFrameworkAdapter } from "./framework-adapter.js";
export type {
  FrameworkToolBoundaryOptions,
  FrameworkToolDispatcher,
} from "./framework-tool-boundary.js";
export {
  FrameworkToolBoundary,
  wrapFrameworkToolDispatcher,
} from "./framework-tool-boundary.js";

export type {
  GenericToolBoundaryOptions,
  GenericToolDispatcher,
} from "./generic-tool-runner.js";
export {
  GenericToolBoundary,
  GenericToolCallBlockedError,
  wrapGenericToolDispatcher,
} from "./generic-tool-runner.js";
export type {
  InterceptResult,
  ProcessedOutput,
  ToolInterceptor,
} from "./interceptor.js";
export type {
  ParsedNetworkTarget,
  ParseNetworkTargetOptions,
} from "./network-target.js";
export { parseNetworkTarget } from "./network-target.js";
export { PolicyEventFactory } from "./policy-event-factory.js";
export type { OutputSanitizer, RedactionInfo } from "./sanitizer.js";
export type {
  ClawdstrikeConfig,
  CommandEventData,
  CuaEventData,
  Decision,
  DecisionReasonCode,
  DecisionStatus,
  EvaluationMode,
  EventData,
  EventType,
  FileEventData,
  GuardToggles,
  LogLevel,
  NetworkEventData,
  PatchEventData,
  Policy,
  PolicyEvent,
  SecretEventData,
  Severity,
  ToolEventData,
} from "./types.js";
export {
  allowDecision,
  createDecision,
  denyDecision,
  sanitizeDecision,
  warnDecision,
} from "./types.js";

export type { CuaTranslatorConfig } from "./cua/cua-translator-base.js";
export { createCuaTranslator } from "./cua/cua-translator-base.js";
export type { ClawdstrikeLike, SecuritySource } from "./resolve-interceptor.js";
export {
  isClawdstrikeLike,
  isToolInterceptor,
  resolveInterceptor,
} from "./resolve-interceptor.js";
export type { ExecuteOrCallToolLike, SecureToolSetOptions } from "./secure-tool-wrapper.js";
export { secureToolSet, wrapExecuteWithInterceptor } from "./secure-tool-wrapper.js";
