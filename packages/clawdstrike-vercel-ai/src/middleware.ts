import { BaseToolInterceptor, PolicyEventFactory, createSecurityContext } from '@clawdstrike/adapter-core';
import type {
  AdapterConfig,
  Decision,
  PolicyEngineLike,
  SecurityContext,
} from '@clawdstrike/adapter-core';

import type { VercelAiToolLike } from './tools.js';
import { secureTools } from './tools.js';

export type VercelAiClawdstrikeConfig = AdapterConfig & {
  injectPolicyCheckTool?: boolean;
  policyCheckToolName?: string;
};

export interface SecureToolsOptions {
  context?: SecurityContext;
  getContext?: (toolName: string, input: unknown) => SecurityContext;
}

export interface CreateClawdstrikeMiddlewareOptions {
  engine: PolicyEngineLike;
  config?: VercelAiClawdstrikeConfig;
  context?: SecurityContext;
  createContext?: (metadata?: Record<string, unknown>) => SecurityContext;
}

export interface ClawdstrikeMiddleware {
  readonly engine: PolicyEngineLike;
  readonly interceptor: BaseToolInterceptor;

  createContext(metadata?: Record<string, unknown>): SecurityContext;
  wrapTools<T extends Record<string, VercelAiToolLike>>(
    tools: T,
    options?: SecureToolsOptions,
  ): T;

  getDecisionFor(toolName: string, input: unknown, context?: SecurityContext): Promise<Decision>;
}

export function createClawdstrikeMiddleware(
  options: CreateClawdstrikeMiddlewareOptions,
): ClawdstrikeMiddleware {
  const config: VercelAiClawdstrikeConfig = options.config ?? {};
  const engine = options.engine;

  const createContext =
    options.createContext ??
    ((metadata?: Record<string, unknown>) =>
      createSecurityContext({ metadata: { framework: 'vercel-ai', ...metadata } }));

  const defaultContext = options.context ?? createContext();
  const interceptor = new BaseToolInterceptor(engine, config);
  const eventFactory = new PolicyEventFactory();

  const policyCheckToolName = config.policyCheckToolName ?? 'policy_check';

  const wrapTools = <T extends Record<string, VercelAiToolLike>>(
    tools: T,
    options?: SecureToolsOptions,
  ): T => {
    const secured = secureTools(tools, interceptor, {
      context: options?.context ?? defaultContext,
      getContext: options?.getContext,
    });

    if (!config.injectPolicyCheckTool) {
      return secured;
    }

    return {
      ...secured,
      [policyCheckToolName]: {
        async execute(input: { toolName: string; input: unknown }) {
          const ctx = options?.context ?? defaultContext;
          const event = eventFactory.create(
            input.toolName,
            normalizeParams(input.input),
            ctx.sessionId,
          );
          return engine.evaluate(event);
        },
      },
    } as T;
  };

  return {
    engine,
    interceptor,
    createContext,
    wrapTools,
    async getDecisionFor(toolName: string, input: unknown, context?: SecurityContext): Promise<Decision> {
      const ctx = context ?? defaultContext;
      const event = eventFactory.create(toolName, normalizeParams(input), ctx.sessionId);
      return await engine.evaluate(event);
    },
  };
}

function normalizeParams(input: unknown): Record<string, unknown> {
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

