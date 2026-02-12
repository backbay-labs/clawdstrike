import { BaseToolInterceptor, createSecurityContext } from '@clawdstrike/adapter-core';
import type {
  AdapterConfig,
  AuditEvent,
  PolicyEngineLike,
  SecurityContext,
  ToolInterceptor,
} from '@clawdstrike/adapter-core';

import { ClawdstrikeBlockedError } from './errors.js';

export interface OpenCodeToolBoundaryOptions {
  engine?: PolicyEngineLike;
  interceptor?: ToolInterceptor;
  config?: AdapterConfig;
  createContext?: (runId: string) => SecurityContext;
}

export type OpenCodeToolDispatcher<TOutput = unknown> = (
  toolName: string,
  input: unknown,
  runId: string,
) => Promise<TOutput>;

type PendingRun = {
  toolName: string;
  input: unknown;
  context: SecurityContext;
};

export class OpenCodeToolBoundary {
  private readonly interceptor: ToolInterceptor;
  private readonly config: AdapterConfig;
  private readonly createContext: (runId: string) => SecurityContext;

  private readonly contexts = new Map<string, SecurityContext>();
  private readonly pending = new Map<string, PendingRun>();

  constructor(options: OpenCodeToolBoundaryOptions = {}) {
    this.config = options.config ?? {};

    if (options.interceptor) {
      this.interceptor = options.interceptor;
    } else if (options.engine) {
      this.interceptor = new BaseToolInterceptor(options.engine, this.config);
    } else {
      throw new Error('OpenCodeToolBoundary requires { interceptor } or { engine }');
    }

    this.createContext =
      options.createContext
      ?? ((runId: string) =>
        createSecurityContext({
          sessionId: runId,
          metadata: { framework: 'opencode' },
        }));
  }

  async handleToolStart(toolName: string, input: unknown, runId: string): Promise<void> {
    const context = this.getContext(runId);
    const result = await this.interceptor.beforeExecute(toolName, input, context);
    if (!result.proceed) {
      throw new ClawdstrikeBlockedError(toolName, result.decision);
    }

    this.pending.set(runId, { toolName, input, context });
  }

  async handleToolEnd(output: unknown, runId: string): Promise<unknown> {
    const pending = this.pending.get(runId);
    if (!pending) {
      return output;
    }

    const processed = await this.interceptor.afterExecute(
      pending.toolName,
      pending.input,
      output,
      pending.context,
    );

    this.pending.delete(runId);
    return processed.output;
  }

  async handleToolError(error: Error, runId: string): Promise<void> {
    const pending = this.pending.get(runId);
    if (!pending) {
      return;
    }

    await this.interceptor.onError(pending.toolName, pending.input, error, pending.context);
    this.pending.delete(runId);
  }

  getAuditEvents(): AuditEvent[] {
    return Array.from(this.contexts.values()).flatMap(ctx => ctx.auditEvents);
  }

  private getContext(runId: string): SecurityContext {
    const existing = this.contexts.get(runId);
    if (existing) {
      return existing;
    }

    const ctx = this.createContext(runId);
    this.contexts.set(runId, ctx);
    return ctx;
  }
}

export function wrapOpenCodeToolDispatcher<TOutput = unknown>(
  boundary: OpenCodeToolBoundary,
  dispatch: OpenCodeToolDispatcher<TOutput>,
): OpenCodeToolDispatcher<TOutput> {
  return async (toolName, input, runId) => {
    await boundary.handleToolStart(toolName, input, runId);
    try {
      const output = await dispatch(toolName, input, runId);
      return (await boundary.handleToolEnd(output, runId)) as TOutput;
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      await boundary.handleToolError(error, runId);
      throw err;
    }
  };
}
