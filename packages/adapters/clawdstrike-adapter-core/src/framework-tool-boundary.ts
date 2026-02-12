import type { AdapterConfig } from './adapter.js';
import type { AuditEvent } from './audit.js';
import { BaseToolInterceptor } from './base-tool-interceptor.js';
import { createSecurityContext, type SecurityContext } from './context.js';
import type { PolicyEngineLike } from './engine.js';
import type { ToolInterceptor } from './interceptor.js';
import { ClawdstrikeBlockedError } from './errors.js';

export interface FrameworkToolBoundaryOptions {
  engine?: PolicyEngineLike;
  interceptor?: ToolInterceptor;
  config?: AdapterConfig;
  createContext?: (runId: string) => SecurityContext;
}

export type FrameworkToolDispatcher<TOutput = unknown> = (
  toolName: string,
  input: unknown,
  runId: string,
) => Promise<TOutput>;

type PendingRun = {
  toolName: string;
  input: unknown;
  context: SecurityContext;
};

export class FrameworkToolBoundary {
  private readonly interceptor: ToolInterceptor;
  private readonly config: AdapterConfig;
  private readonly createContextFn: (runId: string) => SecurityContext;
  private readonly framework: string;

  private readonly contexts = new Map<string, SecurityContext>();
  private readonly pending = new Map<string, PendingRun>();

  constructor(framework: string, options: FrameworkToolBoundaryOptions = {}) {
    this.framework = framework;
    this.config = options.config ?? {};

    if (options.interceptor) {
      this.interceptor = options.interceptor;
    } else if (options.engine) {
      this.interceptor = new BaseToolInterceptor(options.engine, this.config);
    } else {
      throw new Error(`${this.constructor.name} requires { interceptor } or { engine }`);
    }

    this.createContextFn =
      options.createContext
      ?? ((runId: string) =>
        createSecurityContext({
          sessionId: runId,
          metadata: { framework: this.framework },
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

  clearRun(runId: string): void {
    this.pending.delete(runId);
    this.contexts.delete(runId);
  }

  clearAll(): void {
    this.pending.clear();
    this.contexts.clear();
  }

  private getContext(runId: string): SecurityContext {
    const existing = this.contexts.get(runId);
    if (existing) {
      return existing;
    }

    const ctx = this.createContextFn(runId);
    this.contexts.set(runId, ctx);
    return ctx;
  }
}

export function wrapFrameworkToolDispatcher<TOutput = unknown>(
  boundary: FrameworkToolBoundary,
  dispatch: FrameworkToolDispatcher<TOutput>,
): FrameworkToolDispatcher<TOutput> {
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
