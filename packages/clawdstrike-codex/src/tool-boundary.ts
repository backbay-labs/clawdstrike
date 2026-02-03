import { BaseToolInterceptor, createSecurityContext } from '@clawdstrike/adapter-core';
import type {
  AdapterConfig,
  AuditEvent,
  PolicyEngineLike,
  SecurityContext,
  ToolInterceptor,
} from '@clawdstrike/adapter-core';

import { ClawdstrikeBlockedError } from './errors.js';

export interface CodexToolBoundaryOptions {
  engine?: PolicyEngineLike;
  interceptor?: ToolInterceptor;
  config?: AdapterConfig;
  createContext?: (runId: string) => SecurityContext;
}

type PendingRun = {
  toolName: string;
  input: unknown;
  context: SecurityContext;
};

export class CodexToolBoundary {
  private readonly interceptor: ToolInterceptor;
  private readonly config: AdapterConfig;
  private readonly createContext: (runId: string) => SecurityContext;

  private readonly contexts = new Map<string, SecurityContext>();
  private readonly pending = new Map<string, PendingRun>();

  constructor(options: CodexToolBoundaryOptions = {}) {
    this.config = options.config ?? {};

    if (options.interceptor) {
      this.interceptor = options.interceptor;
    } else if (options.engine) {
      this.interceptor = new BaseToolInterceptor(options.engine, this.config);
    } else {
      throw new Error('CodexToolBoundary requires { interceptor } or { engine }');
    }

    this.createContext =
      options.createContext
      ?? ((runId: string) =>
        createSecurityContext({
          sessionId: runId,
          metadata: { framework: 'codex' },
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
