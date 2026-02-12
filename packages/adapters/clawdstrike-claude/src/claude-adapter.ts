import { createFrameworkAdapter } from '@clawdstrike/adapter-core';
import type {
  AdapterConfig,
  FrameworkAdapter,
  GenericToolCall,
  PolicyEngineLike,
  SecurityContext,
} from '@clawdstrike/adapter-core';

export class ClaudeAdapter {
  private readonly delegate: FrameworkAdapter;

  constructor(engine: PolicyEngineLike, config: AdapterConfig = {}) {
    this.delegate = createFrameworkAdapter('claude', engine, config);
  }

  get name() { return this.delegate.name; }
  get version() { return this.delegate.version; }

  async initialize(config: AdapterConfig) {
    return this.delegate.initialize(config);
  }

  createContext(metadata?: Record<string, unknown>) {
    return this.delegate.createContext(metadata);
  }

  async interceptToolCall(context: SecurityContext, toolCall: GenericToolCall) {
    return this.delegate.interceptToolCall(context, toolCall);
  }

  async processOutput(context: SecurityContext, toolCall: GenericToolCall, output: unknown) {
    return this.delegate.processOutput(context, toolCall, output);
  }

  async finalizeContext(context: SecurityContext) {
    return this.delegate.finalizeContext(context);
  }

  getEngine() {
    return this.delegate.getEngine();
  }

  getHooks() {
    return this.delegate.getHooks();
  }
}
