import { createSecurityContext } from '@clawdstrike/adapter-core';
import type { AuditEvent, PolicyEngineLike, SecurityContext, ToolInterceptor } from '@clawdstrike/adapter-core';

import { ClawdstrikeViolationError } from './errors.js';
import { createLangChainInterceptor } from './interceptor.js';
import type { LangChainClawdstrikeConfig } from './types.js';

export interface ClawdstrikeCallbackHandlerOptions {
  engine?: PolicyEngineLike;
  interceptor?: ToolInterceptor;
  config?: LangChainClawdstrikeConfig;
  context?: SecurityContext;
  createContext?: (runId: string) => SecurityContext;
}

type SerializedToolLike = {
  name?: string;
  id?: unknown;
};

export class ClawdstrikeCallbackHandler {
  readonly name = 'clawdstrike';

  private readonly config: LangChainClawdstrikeConfig;
  private readonly interceptor: ToolInterceptor;
  private readonly createContext?: (runId: string) => SecurityContext;
  private readonly contexts = new Map<string, SecurityContext>();
  private readonly pending = new Map<string, { toolName: string; input: unknown; context: SecurityContext }>();

  constructor(options: ClawdstrikeCallbackHandlerOptions = {}) {
    this.config = options.config ?? {};
    const engine = options.engine;

    if (options.interceptor) {
      this.interceptor = options.interceptor;
    } else if (engine) {
      this.interceptor = createLangChainInterceptor(engine, this.config);
    } else {
      throw new Error('ClawdstrikeCallbackHandler requires { interceptor } or { engine }');
    }

    if (options.context) {
      this.contexts.set(options.context.sessionId, options.context);
    }

    this.createContext = options.createContext;
  }

  async handleToolStart(
    tool: SerializedToolLike,
    input: string,
    runId: string,
    _parentRunId?: string,
    _tags?: string[],
    _metadata?: Record<string, unknown>,
  ): Promise<void> {
    const toolName = this.resolveToolName(tool);
    const parsedInput = parseToolInput(input);
    const context = this.getContextForRun(runId);

    const result = await this.interceptor.beforeExecute(toolName, parsedInput, context);
    this.pending.set(runId, { toolName, input: parsedInput, context });

    if (!result.proceed) {
      throw new ClawdstrikeViolationError(toolName, result.decision);
    }
  }

  async handleToolEnd(
    output: unknown,
    runId: string,
    _parentRunId?: string,
    _tags?: string[],
  ): Promise<void> {
    const pending = this.pending.get(runId);
    if (!pending) {
      return;
    }

    await this.interceptor.afterExecute(pending.toolName, pending.input, output, pending.context);
    this.pending.delete(runId);
  }

  async handleToolError(
    error: Error,
    runId: string,
    _parentRunId?: string,
    _tags?: string[],
  ): Promise<void> {
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

  clearAuditEvents(): void {
    for (const ctx of this.contexts.values()) {
      ctx.auditEvents.length = 0;
    }
    this.contexts.clear();
  }

  private resolveToolName(tool: SerializedToolLike): string {
    const name = typeof tool?.name === 'string' ? tool.name : undefined;
    if (name) {
      return this.config.toolNameMapping?.[name] ?? name;
    }

    const id = tool?.id;
    if (Array.isArray(id) && typeof id[id.length - 1] === 'string') {
      const fallback = id[id.length - 1] as string;
      return this.config.toolNameMapping?.[fallback] ?? fallback;
    }

    return 'unknown';
  }

  private getContextForRun(runId: string): SecurityContext {
    const existing = this.contexts.get(runId);
    if (existing) {
      return existing;
    }

    const context =
      this.createContext?.(runId)
      ?? createSecurityContext({
        sessionId: runId,
        metadata: { framework: 'langchain' },
      });

    this.contexts.set(runId, context);
    return context;
  }
}

function parseToolInput(input: string): unknown {
  try {
    return JSON.parse(input) as unknown;
  } catch {
    return { raw: input };
  }
}
