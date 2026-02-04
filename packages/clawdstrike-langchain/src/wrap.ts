import { BaseToolInterceptor, createSecurityContext } from '@clawdstrike/adapter-core';
import type {
  AdapterConfig,
  Decision,
  PolicyEngineLike,
  SecurityContext,
  ToolInterceptor,
} from '@clawdstrike/adapter-core';

import { ClawdstrikeViolationError } from './errors.js';
import { createLangChainInterceptor } from './interceptor.js';

type LangChainInvokeLike<TInput = unknown, TOutput = unknown> = {
  invoke: (input: TInput, config?: unknown) => Promise<TOutput> | TOutput;
};

type LangChainCallLike<TInput = unknown, TOutput = unknown> = {
  _call: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
};

type LangChainToolLike = Partial<LangChainInvokeLike> & Partial<LangChainCallLike> & {
  name?: string;
};

export interface WrapToolOptions {
  context?: SecurityContext;
  getContext?: (toolName: string, input: unknown) => SecurityContext;
}

/**
 * Clawdstrike-like interface for simple API.
 */
export interface ClawdstrikeLike {
  createInterceptor?: () => ToolInterceptor;
}

/**
 * Secure a single LangChain tool using a Clawdstrike instance or PolicyEngineLike.
 *
 * @example Using with Clawdstrike (recommended)
 * ```typescript
 * import { Clawdstrike } from '@clawdstrike/sdk';
 * import { secureTool } from '@clawdstrike/langchain';
 *
 * const cs = await Clawdstrike.fromPolicy('./policy.yaml');
 * const secureTool = secureTool(myTool, cs);
 * ```
 */
export function secureTool<TTool extends LangChainToolLike>(
  tool: TTool,
  csOrEngine: ClawdstrikeLike | PolicyEngineLike,
  options?: WrapToolOptions,
): TTool {
  const interceptor = resolveInterceptor(csOrEngine);
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
  csOrEngine: ClawdstrikeLike | PolicyEngineLike,
  options?: WrapToolOptions,
): TTool[] {
  const interceptor = resolveInterceptor(csOrEngine);
  return wrapTools(tools, interceptor, options);
}

function resolveInterceptor(csOrEngine: ClawdstrikeLike | PolicyEngineLike): ToolInterceptor {
  if (isClawdstrikeLike(csOrEngine)) {
    return csOrEngine.createInterceptor!();
  }
  // PolicyEngineLike
  return createLangChainInterceptor(csOrEngine, { metadata: { framework: 'langchain' } });
}

function isClawdstrikeLike(value: unknown): value is ClawdstrikeLike {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as ClawdstrikeLike).createInterceptor === 'function'
  );
}

/**
 * @deprecated Use secureTool(tool, clawdstrike) instead.
 */
export function wrapTool<TTool extends LangChainToolLike>(
  tool: TTool,
  interceptor: ToolInterceptor,
  options?: WrapToolOptions,
): TTool {
  const context =
    options?.context ??
    createSecurityContext({
      metadata: { framework: 'langchain' },
    });
  return wrapToolWithContext(tool, interceptor, context, options?.getContext);
}

/**
 * @deprecated Use secureTools(tools, clawdstrike) instead.
 */
export function wrapTools<TTool extends LangChainToolLike>(
  tools: readonly TTool[],
  interceptor: ToolInterceptor,
  options?: WrapToolOptions,
): TTool[] {
  const context =
    options?.context ??
    createSecurityContext({
      metadata: { framework: 'langchain' },
    });
  return tools.map(tool => wrapToolWithContext(tool, interceptor, context, options?.getContext));
}

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
      metadata: { framework: 'langchain' },
    });

  return wrapToolWithContext(tool, interceptor, context, options?.getContext, {
    engine,
    config,
    options,
  });
}

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
      metadata: { framework: 'langchain' },
    });

  return tools.map(tool =>
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
  const toolName = typeof tool.name === 'string' && tool.name.length > 0 ? tool.name : 'tool';
  const hasInvoke = typeof tool.invoke === 'function';
  const hasCall = typeof tool._call === 'function';

  if (!hasInvoke && !hasCall) {
    throw new Error(`Tool must implement invoke(input, ...) or _call(input, ...)`);
  }

  const originalInvoke = hasInvoke ? tool.invoke!.bind(tool) : undefined;
  const originalCall = hasCall ? tool._call!.bind(tool) : undefined;

  let lastDecision: Decision | null = null;

  const wrappedInvoke = hasInvoke
    ? async (input: unknown, config?: unknown) => {
        const resolvedContext = getContext ? getContext(toolName, input) : context;
        return runIntercepted(
          toolName,
          interceptor,
          resolvedContext,
          input,
          decision => {
            lastDecision = decision;
          },
          (nextInput: unknown) => originalInvoke!(nextInput, config),
        );
      }
    : undefined;

  const wrappedCall = hasCall
    ? async (input: unknown, ...rest: unknown[]) => {
        const resolvedContext = getContext ? getContext(toolName, input) : context;
        return runIntercepted(
          toolName,
          interceptor,
          resolvedContext,
          input,
          decision => {
            lastDecision = decision;
          },
          (nextInput: unknown) => originalCall!(nextInput, ...rest),
        );
      }
    : undefined;

  return new Proxy(tool, {
    get(target, prop, receiver) {
      if (prop === 'invoke' && wrappedInvoke) {
        return wrappedInvoke;
      }
      if (prop === '_call' && wrappedCall) {
        return wrappedCall;
      }
      if (prop === 'getLastDecision') {
        return () => lastDecision;
      }
      if (prop === 'withConfig' && withConfigSupport) {
        return (overrides: Partial<AdapterConfig>) =>
          wrapToolWithConfig(
            tool,
            withConfigSupport.engine,
            { ...withConfigSupport.config, ...overrides },
            withConfigSupport.options,
          );
      }

      const value = Reflect.get(target, prop, receiver) as unknown;
      if (typeof value === 'function') {
        return (value as (...args: unknown[]) => unknown).bind(target);
      }
      return value;
    },
  });
}

async function runIntercepted<TOutput>(
  toolName: string,
  interceptor: ToolInterceptor,
  context: SecurityContext,
  input: unknown,
  onDecision: (decision: Decision) => void,
  invoke: (nextInput: unknown) => Promise<TOutput> | TOutput,
): Promise<TOutput> {
  let interceptResult;
  try {
    interceptResult = await interceptor.beforeExecute(toolName, input, context);
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    await interceptor.onError(toolName, input, err, context);
    throw err;
  }

  onDecision(interceptResult.decision);

  if (!interceptResult.proceed) {
    const { decision } = interceptResult;
    throw new ClawdstrikeViolationError(toolName, decision);
  }

  const nextInput = interceptResult.modifiedParameters ?? input;

  if (interceptResult.replacementResult !== undefined) {
    const processed = await interceptor.afterExecute(
      toolName,
      nextInput,
      interceptResult.replacementResult as TOutput,
      context,
    );
    return processed.output as TOutput;
  }

  try {
    const output = await invoke(nextInput);
    const processed = await interceptor.afterExecute(toolName, nextInput, output, context);
    return processed.output as TOutput;
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    await interceptor.onError(toolName, nextInput, err, context);
    throw err;
  }
}
