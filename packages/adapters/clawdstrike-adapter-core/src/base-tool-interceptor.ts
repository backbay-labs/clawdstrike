import type { AdapterConfig, GenericToolCall } from './adapter.js';
import type { AuditEvent } from './audit.js';
import type { SecurityContext } from './context.js';
import type { PolicyEngineLike } from './engine.js';
import type { InterceptResult, ProcessedOutput, ToolInterceptor } from './interceptor.js';
import type { OutputSanitizer, RedactionInfo } from './sanitizer.js';
import { DefaultOutputSanitizer } from './default-output-sanitizer.js';
import { PolicyEventFactory } from './policy-event-factory.js';
import { allowDecision, type Decision, type PolicyEvent } from './types.js';

type SanitizeExecutionOverrides = {
  modifiedInput?: unknown;
  modifiedParameters?: Record<string, unknown>;
  replacementResult?: unknown;
  mode: 'advisory' | 'enforced';
  strategy: string;
};

export class BaseToolInterceptor implements ToolInterceptor {
  protected readonly engine: PolicyEngineLike;
  protected readonly config: AdapterConfig;
  protected readonly sanitizer: OutputSanitizer;
  protected readonly eventFactory: PolicyEventFactory;

  constructor(engine: PolicyEngineLike, config: AdapterConfig, sanitizer?: OutputSanitizer) {
    this.engine = engine;
    this.config = config;
    this.sanitizer = sanitizer ?? new DefaultOutputSanitizer(engine);
    this.eventFactory = new PolicyEventFactory();
  }

  async beforeExecute(
    toolName: string,
    input: unknown,
    context: SecurityContext,
  ): Promise<InterceptResult> {
    const startTime = Date.now();

    if (this.config.excludedTools?.includes(toolName)) {
      return {
        proceed: true,
        decision: allowDecision({ guard: 'excluded' }),
        duration: Date.now() - startTime,
      };
    }

    const normalizedName = this.config.normalizeToolName?.(toolName) ?? toolName;
    const params = this.normalizeParams(input);

    const toolCall: GenericToolCall = {
      id: `${context.id}-${Date.now()}`,
      name: normalizedName,
      parameters: params,
      timestamp: new Date(),
      source: 'generic',
    };

    let event: PolicyEvent;
    try {
      event = this.createPolicyEvent(normalizedName, params, input, context);
      toolCall.id = event.eventId;
    } catch (error) {
      const translationError = error instanceof Error ? error : new Error(String(error));
      const decision: Decision = {
        status: 'deny',
        reason_code: 'ADC_GUARD_ERROR',
        guard: 'provider_translator',
        severity: 'high',
        reason: `Policy event translation failed: ${translationError.message}`,
        message: `Policy event translation failed: ${translationError.message}`,
      };

      context.checkCount++;
      context.violationCount++;
      context.recordBlocked(normalizedName, decision);
      this.config.handlers?.onError?.(translationError, toolCall);
      this.config.handlers?.onAfterEvaluate?.(toolCall, decision);
      this.config.handlers?.onBlocked?.(toolCall, decision);

      await this.emitAuditEvent(context, {
        id: `${toolCall.id}-translation-error`,
        type: 'tool_call_blocked',
        timestamp: new Date(),
        contextId: context.id,
        sessionId: context.sessionId,
        toolName: normalizedName,
        parameters: this.config.audit?.logParameters
          ? (this.sanitizeForAudit(params) as Record<string, unknown>)
          : undefined,
        decision,
        details: { error: translationError.message, phase: 'translation' },
      });

      if (this.config.blockOnViolation !== false) {
        return {
          proceed: false,
          decision,
          duration: Date.now() - startTime,
        };
      }

      return {
        proceed: true,
        decision: {
          ...decision,
          status: 'warn',
          severity: 'medium',
        },
        warning: decision.message,
        duration: Date.now() - startTime,
      };
    }

    this.config.handlers?.onBeforeEvaluate?.(toolCall);

    const decision = await this.engine.evaluate(event);
    context.checkCount++;
    let sanitizeOverrides: SanitizeExecutionOverrides | undefined;

    this.config.handlers?.onAfterEvaluate?.(toolCall, decision);

    if (decision.status === 'deny') {
      context.violationCount++;
      context.recordBlocked(normalizedName, decision);
      this.config.handlers?.onBlocked?.(toolCall, decision);

      await this.emitAuditEvent(context, {
        id: `${event.eventId}-blocked`,
        type: 'tool_call_blocked',
        timestamp: new Date(),
        contextId: context.id,
        sessionId: context.sessionId,
        toolName: normalizedName,
        parameters: this.config.audit?.logParameters
          ? (this.sanitizeForAudit(params) as Record<string, unknown>)
          : undefined,
        decision,
      });

      if (this.config.blockOnViolation !== false) {
        return {
          proceed: false,
          decision,
          duration: Date.now() - startTime,
        };
      }
    }

    if (decision.status === 'sanitize') {
      sanitizeOverrides = this.deriveSanitizeExecutionOverrides(input, params, decision);
      this.config.handlers?.onWarning?.(toolCall, decision);

      await this.emitAuditEvent(context, {
        id: `${event.eventId}-sanitized`,
        type: 'output_sanitized',
        timestamp: new Date(),
        contextId: context.id,
        sessionId: context.sessionId,
        toolName: normalizedName,
        decision,
        details: {
          original: 'original' in decision ? decision.original : undefined,
          sanitized: 'sanitized' in decision ? decision.sanitized : undefined,
          execution: {
            mode: sanitizeOverrides.mode,
            strategy: sanitizeOverrides.strategy,
            hasReplacementResult: sanitizeOverrides.replacementResult !== undefined,
          },
        },
      });
    }

    const dispatchInput = sanitizeOverrides?.modifiedInput
      ?? sanitizeOverrides?.modifiedParameters
      ?? input;
    const dispatchParams = BaseToolInterceptor.asRecord(dispatchInput) ?? this.normalizeParams(dispatchInput);

    if (decision.status === 'warn') {
      this.config.handlers?.onWarning?.(toolCall, decision);

      await this.emitAuditEvent(context, {
        id: `${event.eventId}-warning`,
        type: 'tool_call_warning',
        timestamp: new Date(),
        contextId: context.id,
        sessionId: context.sessionId,
        toolName: normalizedName,
        decision,
      });
    }

    await this.emitAuditEvent(context, {
      id: `${event.eventId}-start`,
      type: 'tool_call_start',
      timestamp: new Date(),
      contextId: context.id,
      sessionId: context.sessionId,
      toolName: normalizedName,
      parameters: this.config.audit?.logParameters
        ? (this.sanitizeForAudit(dispatchParams) as Record<string, unknown>)
        : undefined,
      decision,
    });

    return {
      proceed: true,
      decision,
      modifiedInput: sanitizeOverrides?.modifiedInput,
      modifiedParameters: sanitizeOverrides?.modifiedParameters,
      replacementResult: sanitizeOverrides?.replacementResult,
      warning:
        decision.status === 'warn' || decision.status === 'sanitize'
          ? decision.message
          : undefined,
      duration: Date.now() - startTime,
    };
  }

  private createPolicyEvent(
    toolName: string,
    parameters: Record<string, unknown>,
    rawInput: unknown,
    context: SecurityContext,
  ): PolicyEvent {
    const translated = this.config.translateToolCall?.({
      framework: String(context.metadata?.framework ?? 'generic'),
      toolName,
      parameters,
      rawInput,
      sessionId: context.sessionId,
      contextMetadata: context.metadata,
    });

    const event = translated ?? this.eventFactory.create(toolName, parameters, context.sessionId);
    event.metadata = {
      ...(context.metadata ?? {}),
      ...(event.metadata ?? {}),
    };
    return event;
  }

  async afterExecute(
    toolName: string,
    _input: unknown,
    output: unknown,
    context: SecurityContext,
  ): Promise<ProcessedOutput> {
    const normalizedName = this.config.normalizeToolName?.(toolName) ?? toolName;

    let processedOutput = output;
    let modified = false;
    let redactions: RedactionInfo[] = [];

    if (this.config.sanitizeOutputs !== false) {
      const sanitized = this.sanitizer.sanitize(output, context);
      if (sanitized !== output) {
        processedOutput = sanitized;
        modified = true;
        redactions = this.sanitizer.getRedactions(output);
      }
    }

    await this.emitAuditEvent(context, {
      id: `${context.id}-${Date.now()}-end`,
      type: 'tool_call_end',
      timestamp: new Date(),
      contextId: context.id,
      sessionId: context.sessionId,
      toolName: normalizedName,
      output: this.config.audit?.logOutputs ? this.sanitizeForAudit(processedOutput) : undefined,
      details: modified ? { redactions } : undefined,
    });

    return {
      output: processedOutput,
      modified,
      redactions,
    };
  }

  async onError(
    toolName: string,
    input: unknown,
    error: Error,
    context: SecurityContext,
  ): Promise<void> {
    const normalizedName = this.config.normalizeToolName?.(toolName) ?? toolName;

    this.config.handlers?.onError?.(error, {
      id: `${context.id}-${Date.now()}`,
      name: normalizedName,
      parameters: this.normalizeParams(input),
      timestamp: new Date(),
      source: 'generic',
    });

    await this.emitAuditEvent(context, {
      id: `${context.id}-${Date.now()}-error`,
      type: 'tool_call_error',
      timestamp: new Date(),
      contextId: context.id,
      sessionId: context.sessionId,
      toolName: normalizedName,
      details: { error: error.message },
    });
  }

  protected normalizeParams(input: unknown): Record<string, unknown> {
    if (typeof input === 'object' && input !== null) {
      return input as Record<string, unknown>;
    }
    if (typeof input === 'string') {
      try {
        return JSON.parse(input) as Record<string, unknown>;
      } catch {
        return { raw: input };
      }
    }
    return { value: input };
  }

  private deriveSanitizeExecutionOverrides(
    input: unknown,
    params: Record<string, unknown>,
    decision: Extract<Decision, { status: 'sanitize' }>,
  ): SanitizeExecutionOverrides {
    const details = BaseToolInterceptor.asRecord(decision.details);

    if (details && 'replacement_result' in details) {
      return {
        replacementResult: details.replacement_result,
        mode: 'enforced',
        strategy: 'details.replacement_result',
      };
    }

    const sanitizedParameters = BaseToolInterceptor.asRecord(details?.sanitized_parameters);
    if (sanitizedParameters) {
      return {
        modifiedParameters: sanitizedParameters,
        mode: 'enforced',
        strategy: 'details.sanitized_parameters',
      };
    }

    if (typeof decision.sanitized === 'string') {
      if (typeof input === 'string') {
        return {
          modifiedInput: decision.sanitized,
          mode: 'enforced',
          strategy: 'decision.sanitized_string_input',
        };
      }

      const textKey = this.findTextParameterKey(params);
      if (textKey) {
        return {
          modifiedParameters: {
            ...params,
            [textKey]: decision.sanitized,
          },
          mode: 'enforced',
          strategy: `decision.sanitized_field:${textKey}`,
        };
      }
    }

    return {
      mode: 'advisory',
      strategy: 'no_applicable_override',
    };
  }

  private findTextParameterKey(params: Record<string, unknown>): string | undefined {
    for (const key of ['text', 'input', 'prompt', 'query', 'command', 'content']) {
      if (typeof params[key] === 'string') {
        return key;
      }
    }
    return undefined;
  }

  private static asRecord(value: unknown): Record<string, unknown> | null {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return null;
    }
    return value as Record<string, unknown>;
  }

  protected sanitizeForAudit(value: unknown): unknown {
    if (!this.engine.redactSecrets && !this.config.audit?.redactPII) {
      return value;
    }

    return this.sanitizeForAuditInternal(value, new WeakMap());
  }

  private sanitizeForAuditInternal(value: unknown, seen: WeakMap<object, unknown>): unknown {
    if (value === null || value === undefined) {
      return value;
    }

    if (typeof value === 'string') {
      const secretRedacted = this.engine.redactSecrets ? this.engine.redactSecrets(value) : value;
      return this.config.audit?.redactPII ? redactPII(secretRedacted) : secretRedacted;
    }

    if (typeof value !== 'object') {
      return value;
    }

    if (value instanceof Date) {
      return value;
    }

    const existing = seen.get(value);
    if (existing) {
      return existing;
    }

    if (Array.isArray(value)) {
      const arr: unknown[] = [];
      seen.set(value, arr);
      for (const item of value) {
        arr.push(this.sanitizeForAuditInternal(item, seen));
      }
      return arr;
    }

    const redacted: Record<string, unknown> = {};
    seen.set(value, redacted);
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      redacted[key] = this.sanitizeForAuditInternal(val, seen);
    }
    return redacted;
  }

  private async emitAuditEvent(context: SecurityContext, event: AuditEvent): Promise<void> {
    if (this.config.audit?.enabled === false) {
      return;
    }

    const allowedEvents = this.config.audit?.events;
    if (allowedEvents && !allowedEvents.includes(event.type)) {
      return;
    }

    context.addAuditEvent(event);

    const logger = this.config.audit?.logger;
    if (!logger) {
      return;
    }

    try {
      await logger.log(event);
    } catch (error) {
      this.config.handlers?.onError?.(error as Error);
    }
  }
}

function redactPII(value: string): string {
  let redacted = value;

  redacted = redacted.replace(
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    '[REDACTED_EMAIL]',
  );

  redacted = redacted.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]');

  redacted = redacted.replace(/\+?\d[\d\s().-]{8,}\d/g, '[REDACTED_PHONE]');

  return redacted;
}
