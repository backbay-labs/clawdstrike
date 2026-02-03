import { BaseToolInterceptor, PolicyEventFactory, createSecurityContext } from '@clawdstrike/adapter-core';
import type {
  AdapterConfig,
  AuditEvent,
  Decision,
  PolicyEngineLike,
  SecurityContext,
} from '@clawdstrike/adapter-core';

import type { VercelAiToolLike } from './tools.js';
import { secureTools } from './tools.js';
import { StreamingToolGuard } from './streaming-tool-guard.js';

export type VercelAiClawdstrikeConfig = AdapterConfig & {
  injectPolicyCheckTool?: boolean;
  policyCheckToolName?: string;
  streamingEvaluation?: boolean;
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
  aiSdk?: {
    experimental_wrapLanguageModel?: (args: unknown) => unknown;
  };
}

export interface ClawdstrikeMiddleware {
  readonly engine: PolicyEngineLike;
  readonly interceptor: BaseToolInterceptor;

  createContext(metadata?: Record<string, unknown>): SecurityContext;
  wrapLanguageModel<TModel extends object>(model: TModel): TModel;
  wrapTools<T extends Record<string, VercelAiToolLike>>(
    tools: T,
    options?: SecureToolsOptions,
  ): T;

  getDecisionFor(toolName: string, input: unknown, context?: SecurityContext): Promise<Decision>;
  getAuditLog(): AuditEvent[];
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
  const contexts = new Set<SecurityContext>([defaultContext]);

  const policyCheckToolName = config.policyCheckToolName ?? 'policy_check';

  const wrapTools = <T extends Record<string, VercelAiToolLike>>(
    tools: T,
    options?: SecureToolsOptions,
  ): T => {
    const rootContext = options?.context ?? defaultContext;
    contexts.add(rootContext);
    const secured = secureTools(tools, interceptor, {
      context: rootContext,
      getContext: options?.getContext,
    });

    if (!config.injectPolicyCheckTool) {
      return secured;
    }

    return {
      ...secured,
      [policyCheckToolName]: {
        async execute(input: { toolName: string; input: unknown }) {
          const ctx = rootContext;
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
    createContext: (metadata?: Record<string, unknown>) => {
      const ctx = createContext(metadata);
      contexts.add(ctx);
      return ctx;
    },
    wrapLanguageModel<TModel extends object>(model: TModel): TModel {
      const wrap = options.aiSdk?.experimental_wrapLanguageModel;
      if (wrap) {
        return createWrappedModel(model, wrap, interceptor, config, createContext, contexts) as TModel;
      }
      return createLazyWrappedModel(model, interceptor, config, createContext, contexts) as TModel;
    },
    wrapTools,
    async getDecisionFor(toolName: string, input: unknown, context?: SecurityContext): Promise<Decision> {
      const ctx = context ?? defaultContext;
      const event = eventFactory.create(toolName, normalizeParams(input), ctx.sessionId);
      return await engine.evaluate(event);
    },
    getAuditLog(): AuditEvent[] {
      return Array.from(contexts).flatMap(ctx => ctx.auditEvents);
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

function createLazyWrappedModel(
  model: object,
  interceptor: BaseToolInterceptor,
  config: VercelAiClawdstrikeConfig,
  createContext: (metadata?: Record<string, unknown>) => SecurityContext,
  contexts: Set<SecurityContext>,
): object {
  let wrappedPromise: Promise<object> | null = null;

  const getWrapped = async (): Promise<object> => {
    if (wrappedPromise) {
      return wrappedPromise;
    }

    wrappedPromise = (async () => {
      const ai = (await import('ai')) as { experimental_wrapLanguageModel?: (args: unknown) => unknown };
      if (typeof ai.experimental_wrapLanguageModel !== 'function') {
        throw new Error(`ai.experimental_wrapLanguageModel is not available`);
      }
      return createWrappedModel(model, ai.experimental_wrapLanguageModel, interceptor, config, createContext, contexts);
    })();

    return wrappedPromise;
  };

  return new Proxy(model, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver) as unknown;
      if (typeof value !== 'function') {
        return value;
      }
      return async (...args: unknown[]) => {
        const wrapped = await getWrapped();
        const fn = (wrapped as any)[prop] as (...innerArgs: unknown[]) => unknown;
        if (typeof fn !== 'function') {
          throw new Error(`Wrapped model is missing method ${String(prop)}`);
        }
        return await fn.apply(wrapped, args);
      };
    },
  });
}

function createWrappedModel(
  model: object,
  wrapLanguageModel: (args: unknown) => unknown,
  interceptor: BaseToolInterceptor,
  config: VercelAiClawdstrikeConfig,
  createContext: (metadata?: Record<string, unknown>) => SecurityContext,
  contexts: Set<SecurityContext>,
): object {
  return wrapLanguageModel({
    model,
    middleware: {
      wrapGenerate: async ({ doGenerate }: { doGenerate: () => Promise<any> }) => {
        const context = createContext({ operation: 'generate' });
        contexts.add(context);

        const result = await doGenerate();
        if (!result || !Array.isArray(result.toolCalls)) {
          return result;
        }

        const toolCalls = await Promise.all(
          result.toolCalls.map(async (call: any) => {
            const toolName = call.toolName ?? call.name;
            const args = call.args ?? call.parameters ?? call.input;

            if (typeof toolName !== 'string') {
              return call;
            }

            const interceptResult = await interceptor.beforeExecute(toolName, args, context);
            if (!interceptResult.proceed) {
              return {
                ...call,
                __clawdstrike_blocked: true,
                __clawdstrike_reason: interceptResult.decision.message ?? interceptResult.decision.reason ?? 'denied',
              };
            }

            return call;
          }),
        );

        return { ...result, toolCalls };
      },

      wrapStream: async ({ doStream }: { doStream: () => Promise<any> }) => {
        const context = createContext({ operation: 'stream' });
        contexts.add(context);

        const result = await doStream();
        const stream = result?.stream;
        if (!stream || config.streamingEvaluation !== true) {
          return result;
        }

        const guard = new StreamingToolGuard(interceptor, { config, context });
        const secureStream = transformUnknownStream(stream, chunk => guard.processChunk(chunk as any));
        return { ...result, stream: secureStream };
      },
    },
  }) as object;
}

function transformUnknownStream(
  stream: unknown,
  transform: (chunk: unknown) => Promise<unknown>,
): unknown {
  if (stream && typeof (stream as any).pipeThrough === 'function' && typeof TransformStream !== 'undefined') {
    return (stream as any).pipeThrough(
      new TransformStream({
        async transform(chunk, controller) {
          const processed = await transform(chunk);
          if (processed !== null && processed !== undefined) {
            controller.enqueue(processed);
          }
        },
      }),
    );
  }

  if (stream && typeof (stream as any)[Symbol.asyncIterator] === 'function') {
    return (async function* () {
      for await (const chunk of stream as AsyncIterable<unknown>) {
        const processed = await transform(chunk);
        if (processed !== null && processed !== undefined) {
          yield processed;
        }
      }
    })();
  }

  return stream;
}
