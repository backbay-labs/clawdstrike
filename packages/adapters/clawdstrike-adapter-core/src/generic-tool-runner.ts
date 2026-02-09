import type { AdapterConfig } from './adapter.js';
import type { AuditEvent } from './audit.js';
import { BaseToolInterceptor } from './base-tool-interceptor.js';
import { createSecurityContext, type SecurityContext } from './context.js';
import type { PolicyEngineLike } from './engine.js';
import type { InterceptResult, ToolInterceptor } from './interceptor.js';
import type { Decision } from './types.js';

export type GenericToolDispatcher<TInput = unknown, TOutput = unknown, TRunId = string> = (
  toolName: string,
  input: TInput,
  runId: TRunId,
) => Promise<TOutput>;

export interface GenericToolBoundaryOptions<
  TInput = unknown,
  TOutput = unknown,
  TRunId = string,
> {
  engine?: PolicyEngineLike;
  interceptor?: ToolInterceptor<TInput, TOutput>;
  config?: AdapterConfig;
  createContext?: (runId: TRunId) => SecurityContext;
  keyFromRunId?: (runId: TRunId) => string;
}

type PendingRun<TInput> = {
  toolName: string;
  input: TInput;
  context: SecurityContext;
};

export class GenericToolCallBlockedError extends Error {
  readonly toolName: string;
  readonly decision: Decision;

  constructor(toolName: string, decision: Decision) {
    super(`Tool call blocked by policy: ${toolName}`);
    this.name = 'GenericToolCallBlockedError';
    this.toolName = toolName;
    this.decision = decision;
  }
}

export class GenericToolBoundary<TInput = unknown, TOutput = unknown, TRunId = string> {
  private readonly interceptor: ToolInterceptor<TInput, TOutput>;
  private readonly config: AdapterConfig;
  private readonly createContextForRun: (runId: TRunId) => SecurityContext;
  private readonly keyFromRunId: (runId: TRunId) => string;

  private readonly contexts = new Map<string, SecurityContext>();
  private readonly pending = new Map<string, PendingRun<TInput>>();

  constructor(options: GenericToolBoundaryOptions<TInput, TOutput, TRunId> = {}) {
    this.config = options.config ?? {};
    this.keyFromRunId = options.keyFromRunId ?? ((runId: TRunId) => String(runId));

    if (options.interceptor) {
      this.interceptor = options.interceptor;
    } else if (options.engine) {
      this.interceptor = new BaseToolInterceptor(options.engine, this.config) as ToolInterceptor<
        TInput,
        TOutput
      >;
    } else {
      throw new Error('GenericToolBoundary requires { interceptor } or { engine }');
    }

    this.createContextForRun =
      options.createContext
      ?? ((runId: TRunId) =>
        createSecurityContext({
          sessionId: this.keyFromRunId(runId),
          metadata: { framework: 'generic' },
        }));
  }

  async handleToolStart(
    toolName: string,
    input: TInput,
    runId: TRunId,
  ): Promise<InterceptResult> {
    const context = this.getContext(runId);
    const result = await this.interceptor.beforeExecute(toolName, input, context);
    if (!result.proceed) {
      throw new GenericToolCallBlockedError(toolName, result.decision);
    }

    this.pending.set(this.keyFromRunId(runId), { toolName, input, context });
    return result;
  }

  async handleToolEnd(output: TOutput, runId: TRunId): Promise<TOutput> {
    const key = this.keyFromRunId(runId);
    const pending = this.pending.get(key);
    if (!pending) {
      return output;
    }

    const processed = await this.interceptor.afterExecute(
      pending.toolName,
      pending.input,
      output,
      pending.context,
    );

    this.pending.delete(key);
    return processed.output as TOutput;
  }

  async handleToolError(error: Error, runId: TRunId): Promise<void> {
    const key = this.keyFromRunId(runId);
    const pending = this.pending.get(key);
    if (!pending) {
      return;
    }

    await this.interceptor.onError(pending.toolName, pending.input, error, pending.context);
    this.pending.delete(key);
  }

  getContext(runId: TRunId): SecurityContext {
    const key = this.keyFromRunId(runId);
    const existing = this.contexts.get(key);
    if (existing) {
      return existing;
    }

    const context = this.createContextForRun(runId);
    this.contexts.set(key, context);
    return context;
  }

  getContextIfAny(runId: TRunId): SecurityContext | undefined {
    return this.contexts.get(this.keyFromRunId(runId));
  }

  clearRun(runId: TRunId): void {
    const key = this.keyFromRunId(runId);
    this.pending.delete(key);
    this.contexts.delete(key);
  }

  clearAll(): void {
    this.pending.clear();
    this.contexts.clear();
  }

  getAuditEvents(): AuditEvent[] {
    return Array.from(this.contexts.values()).flatMap(context => context.auditEvents);
  }
}

export function wrapGenericToolDispatcher<TInput = unknown, TOutput = unknown, TRunId = string>(
  boundary: GenericToolBoundary<TInput, TOutput, TRunId>,
  dispatch: GenericToolDispatcher<TInput, TOutput, TRunId>,
): GenericToolDispatcher<TInput, TOutput, TRunId> {
  return async (toolName, input, runId) => {
    await boundary.handleToolStart(toolName, input, runId);
    try {
      const output = await dispatch(toolName, input, runId);
      return await boundary.handleToolEnd(output, runId);
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      await boundary.handleToolError(err, runId);
      throw error;
    }
  };
}

