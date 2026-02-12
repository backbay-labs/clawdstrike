import { BaseToolInterceptor, createSecurityContext, createSessionSummary } from '@clawdstrike/adapter-core';
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
  readonly version = '0.1.1'; // TODO: derive from package.json at build time

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
    return createSessionSummary(context, this.config);
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
