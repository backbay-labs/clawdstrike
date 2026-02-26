import { createFrameworkAdapter } from '@clawdstrike/adapter-core';
import type {
  AdapterConfig,
  FrameworkAdapter,
  FrameworkHooks,
  GenericToolCall,
  InterceptResult,
  PolicyEngineLike,
  ProcessedOutput,
  SecurityContext,
  SessionSummary,
} from '@clawdstrike/adapter-core';

import { PolicyEngine } from './policy/engine.js';

/**
 * OpenClawAdapter implements the standard `FrameworkAdapter` interface from
 * `@clawdstrike/adapter-core`, providing a unified entry point that follows
 * the same pattern as the Claude, Vercel AI, LangChain, and other adapters.
 *
 * It delegates to the existing openclaw `PolicyEngine` for all security
 * evaluation while layering on the adapter-core interceptor, audit, and
 * context-management infrastructure.
 *
 * This is purely additive and does not change the existing hook-based
 * integration path.
 *
 * @example
 * ```ts
 * import { OpenClawAdapter, PolicyEngine } from '@clawdstrike/openclaw';
 *
 * const engine = new PolicyEngine({ policy: 'strict' });
 * const adapter = new OpenClawAdapter(engine);
 *
 * const ctx = adapter.createContext({ userId: 'user-1' });
 * const result = await adapter.interceptToolCall(ctx, toolCall);
 * ```
 */
export class OpenClawAdapter implements FrameworkAdapter {
  private readonly delegate: FrameworkAdapter;
  private readonly engine: PolicyEngine;

  constructor(engine: PolicyEngine, config: AdapterConfig = {}) {
    this.engine = engine;
    this.delegate = createFrameworkAdapter('openclaw', engine as PolicyEngineLike, config);
  }

  get name(): string {
    return this.delegate.name;
  }

  get version(): string {
    return this.delegate.version;
  }

  async initialize(config: AdapterConfig): Promise<void> {
    return this.delegate.initialize(config);
  }

  createContext(metadata?: Record<string, unknown>): SecurityContext {
    return this.delegate.createContext(metadata);
  }

  async interceptToolCall(
    context: SecurityContext,
    toolCall: GenericToolCall,
  ): Promise<InterceptResult> {
    return this.delegate.interceptToolCall(context, toolCall);
  }

  async processOutput(
    context: SecurityContext,
    toolCall: GenericToolCall,
    output: unknown,
  ): Promise<ProcessedOutput> {
    return this.delegate.processOutput(context, toolCall, output);
  }

  async finalizeContext(context: SecurityContext): Promise<SessionSummary> {
    return this.delegate.finalizeContext(context);
  }

  getEngine(): PolicyEngineLike {
    return this.engine;
  }

  getHooks(): FrameworkHooks {
    return this.delegate.getHooks();
  }
}
