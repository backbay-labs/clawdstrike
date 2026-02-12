import { BaseToolInterceptor, createSecurityContext } from '@clawdstrike/adapter-core';
import type {
  AdapterConfig,
  FrameworkAdapter,
  FrameworkHooks,
  GenericToolCall,
  PolicyEngineLike,
  ProcessedOutput,
  SecurityContext,
  SessionSummary,
} from '@clawdstrike/adapter-core';

import { ClawdstrikeCallbackHandler } from './callback-handler.js';
import { wrapTool, wrapTools } from './wrap.js';

export class LangChainAdapter implements FrameworkAdapter {
  readonly name = 'langchain';
  readonly version = '0.1.0';

  private readonly engine: PolicyEngineLike;
  private config: AdapterConfig = {};
  private interceptor: BaseToolInterceptor;

  constructor(engine: PolicyEngineLike, config: AdapterConfig = {}) {
    this.engine = engine;
    this.config = config;
    this.interceptor = new BaseToolInterceptor(engine, config);
  }

  async initialize(config: AdapterConfig): Promise<void> {
    this.config = config;
    this.interceptor = new BaseToolInterceptor(this.engine, config);
  }

  createContext(metadata: Record<string, unknown> = {}): SecurityContext {
    return createSecurityContext({
      metadata: { framework: 'langchain', ...metadata },
    });
  }

  async interceptToolCall(
    context: SecurityContext,
    toolCall: GenericToolCall,
  ) {
    return await this.interceptor.beforeExecute(toolCall.name, toolCall.parameters, context);
  }

  async processOutput(
    context: SecurityContext,
    toolCall: GenericToolCall,
    output: unknown,
  ): Promise<ProcessedOutput> {
    return await this.interceptor.afterExecute(toolCall.name, toolCall.parameters, output, context);
  }

  async finalizeContext(context: SecurityContext): Promise<SessionSummary> {
    const endTime = new Date();
    const startTime = context.createdAt;
    const duration = endTime.getTime() - startTime.getTime();

    const auditEvents = context.auditEvents;
    const toolsUsed = Array.from(
      new Set(auditEvents.map(e => e.toolName).filter(Boolean) as string[]),
    );

    const toolsBlocked = Array.from(context.blockedTools);
    const warningsIssued = auditEvents.filter(e => e.type === 'tool_call_warning').length;

    return {
      sessionId: context.sessionId,
      startTime,
      endTime,
      duration,
      totalToolCalls: context.checkCount,
      blockedToolCalls: context.violationCount,
      warningsIssued,
      toolsUsed,
      toolsBlocked,
      auditEvents,
      policy: this.config.policy ?? '',
      mode: this.config.mode ?? 'deterministic',
    };
  }

  getEngine(): PolicyEngineLike {
    return this.engine;
  }

  getHooks(): FrameworkHooks {
    return {
      createCallbackHandler: () =>
        new ClawdstrikeCallbackHandler({ interceptor: this.interceptor, config: this.config }),
      wrapTool: tool => wrapTool(tool as any, this.interceptor),
      injectIntoContext: ctx => ctx,
      extractFromContext: () => ({}),
    };
  }

  wrapTool<TTool extends { invoke?: (...args: any[]) => any; _call?: (...args: any[]) => any }>(
    tool: TTool,
    context: SecurityContext = this.createContext(),
  ): TTool {
    return wrapTool(tool, this.interceptor, { context });
  }

  wrapTools<TTool extends { invoke?: (...args: any[]) => any; _call?: (...args: any[]) => any }>(
    tools: readonly TTool[],
    context: SecurityContext = this.createContext(),
  ): TTool[] {
    return wrapTools(tools, this.interceptor, { context });
  }
}

