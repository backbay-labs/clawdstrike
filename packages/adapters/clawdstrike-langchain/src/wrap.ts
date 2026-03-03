import type {
  AdapterConfig,
  Decision,
  PolicyEngineLike,
  SecurityContext,
  ToolInterceptor,
} from "@clawdstrike/adapter-core";
import {
  createSecurityContext,
  resolveInterceptor,
  type SecuritySource,
  wrapExecuteWithInterceptor,
} from "@clawdstrike/adapter-core";

import { createLangChainInterceptor } from "./interceptor.js";

type LangChainInvokeLike<TInput = unknown, TOutput = unknown> = {
  invoke: (input: TInput, config?: unknown) => Promise<TOutput> | TOutput;
};

type LangChainCallLike<TInput = unknown, TOutput = unknown> = {
  _call: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
};

type LangChainToolLike = Partial<LangChainInvokeLike> &
  Partial<LangChainCallLike> & {
    name?: string;
  };

export interface WrapToolOptions {
  context?: SecurityContext;
  getContext?: (toolName: string, input: unknown) => SecurityContext;
}

/**
 * @deprecated Use SecuritySource from @clawdstrike/adapter-core.
 */
export type ClawdstrikeLike = {
  createInterceptor?: (config?: AdapterConfig) => Partial<ToolInterceptor> | ToolInterceptor;
};

/**
 * Secure a single LangChain tool using a Clawdstrike instance or PolicyEngineLike.
 *
 * @example Using with Clawdstrike (recommended)
 * ```typescript
 * import { Clawdstrike } from '@clawdstrike/sdk';
 * import { secureTool } from '@clawdstrike/langchain';
 *
 * const cs = await Clawdstrike.fromPolicy('./policy.yaml');
 * const secured = secureTool(myTool, cs);
 * ```
 */
export function secureTool<TTool extends LangChainToolLike>(
  tool: TTool,
  source: SecuritySource,
  options?: WrapToolOptions,
): TTool {
  const interceptor = resolveInterceptor(source);
  return wrapTool(tool, interceptor, options);
}

/**
 * Secure multiple LangChain tools using a Clawdstrike instance or PolicyEngineLike.
 *
 * @example
 * ```typescript
 * const cs = await Clawdstrike.fromPolicy('./policy.yaml');
 * const securedTools = secureTools([toolA, toolB], cs);
 * ```
 */
export function secureTools<TTool extends LangChainToolLike>(
  tools: readonly TTool[],
  source: SecuritySource,
  options?: WrapToolOptions,
): TTool[] {
  const interceptor = resolveInterceptor(source);
  return wrapTools(tools, interceptor, options);
}

/**
 * @deprecated Use secureTool(tool, source) instead.
 */
export function wrapTool<TTool extends LangChainToolLike>(
  tool: TTool,
  interceptor: ToolInterceptor,
  options?: WrapToolOptions,
): TTool {
  const context =
    options?.context ??
    createSecurityContext({
      metadata: { framework: "langchain" },
    });
  return wrapToolWithContext(tool, interceptor, context, options?.getContext);
}

/**
 * @deprecated Use secureTools(tools, source) instead.
 */
export function wrapTools<TTool extends LangChainToolLike>(
  tools: readonly TTool[],
  interceptor: ToolInterceptor,
  options?: WrapToolOptions,
): TTool[] {
  const context =
    options?.context ??
    createSecurityContext({
      metadata: { framework: "langchain" },
    });
  return tools.map((tool) => wrapToolWithContext(tool, interceptor, context, options?.getContext));
}

/**
 * @deprecated Use secureTool(tool, source) with a source that supports createInterceptor(config).
 */
export function wrapToolWithConfig<TTool extends LangChainToolLike>(
  tool: TTool,
  engine: PolicyEngineLike,
  config: AdapterConfig = {},
  options?: WrapToolOptions,
): TTool {
  const interceptor = createLangChainInterceptor(engine, config);
  const context =
    options?.context ??
    createSecurityContext({
      metadata: { framework: "langchain" },
    });

  return wrapToolWithContext(tool, interceptor, context, options?.getContext, {
    engine,
    config,
    options,
  });
}

/**
 * @deprecated Use secureTools(tools, source) with a source that supports createInterceptor(config).
 */
export function wrapToolsWithConfig<TTool extends LangChainToolLike>(
  tools: readonly TTool[],
  engine: PolicyEngineLike,
  config: AdapterConfig = {},
  options?: WrapToolOptions,
): TTool[] {
  const interceptor = createLangChainInterceptor(engine, config);
  const context =
    options?.context ??
    createSecurityContext({
      metadata: { framework: "langchain" },
    });

  return tools.map((tool) =>
    wrapToolWithContext(tool, interceptor, context, options?.getContext, {
      engine,
      config,
      options,
    }),
  );
}

function wrapToolWithContext<TTool extends LangChainToolLike>(
  tool: TTool,
  interceptor: ToolInterceptor,
  context: SecurityContext,
  getContext?: (toolName: string, input: unknown) => SecurityContext,
  withConfigSupport?: {
    engine: PolicyEngineLike;
    config: AdapterConfig;
    options?: WrapToolOptions;
  },
): TTool {
  const toolName = typeof tool.name === "string" && tool.name.length > 0 ? tool.name : "tool";
  const hasInvoke = typeof tool.invoke === "function";
  const hasCall = typeof tool._call === "function";

  if (!hasInvoke && !hasCall) {
    throw new Error(`Tool must implement invoke(input, ...) or _call(input, ...)`);
  }

  const originalInvoke = hasInvoke ? tool.invoke!.bind(tool) : undefined;
  const originalCall = hasCall ? tool._call!.bind(tool) : undefined;

  let lastDecision: Decision | null = null;
  const trackingInterceptor: ToolInterceptor = {
    beforeExecute: async (name, input, resolvedContext) => {
      const result = await interceptor.beforeExecute(name, input, resolvedContext);
      lastDecision = result.decision;
      return result;
    },
    afterExecute: async (name, input, output, resolvedContext) =>
      interceptor.afterExecute(name, input, output, resolvedContext),
    onError: async (name, input, error, resolvedContext) =>
      interceptor.onError(name, input, error, resolvedContext),
  };

  const wrappedInvoke = hasInvoke
    ? wrapExecuteWithInterceptor(
        toolName,
        (input: unknown, config?: unknown) => originalInvoke!(input, config),
        trackingInterceptor,
        context,
        getContext,
      )
    : undefined;

  const wrappedCall = hasCall
    ? wrapExecuteWithInterceptor(
        toolName,
        (input: unknown, ...rest: unknown[]) => originalCall!(input, ...rest),
        trackingInterceptor,
        context,
        getContext,
      )
    : undefined;

  return new Proxy(tool, {
    get(target, prop, receiver) {
      if (prop === "invoke" && wrappedInvoke) {
        return wrappedInvoke;
      }
      if (prop === "_call" && wrappedCall) {
        return wrappedCall;
      }
      if (prop === "getLastDecision") {
        return () => lastDecision;
      }
      if (prop === "withConfig" && withConfigSupport) {
        return (overrides: Partial<AdapterConfig>) =>
          wrapToolWithConfig(
            tool,
            withConfigSupport.engine,
            { ...withConfigSupport.config, ...overrides },
            withConfigSupport.options,
          );
      }

      const value = Reflect.get(target, prop, receiver) as unknown;
      if (typeof value === "function") {
        return (value as (...args: unknown[]) => unknown).bind(target);
      }
      return value;
    },
  });
}
