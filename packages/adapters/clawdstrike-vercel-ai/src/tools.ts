import { BaseToolInterceptor, createSecurityContext } from '@clawdstrike/adapter-core';
import type { AdapterConfig, PolicyEngineLike, SecurityContext, ToolInterceptor } from '@clawdstrike/adapter-core';

import { ClawdstrikeBlockedError } from './errors.js';

export type VercelAiToolLike<TInput = unknown, TOutput = unknown> = {
  execute: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
};

export type VercelAiToolSet = Record<string, VercelAiToolLike>;

export interface SecureToolsOptions {
  context?: SecurityContext;
  getContext?: (toolName: string, input: unknown) => SecurityContext;
}

/**
 * Clawdstrike-like interface for simple API.
 * This allows accepting either a full Clawdstrike instance or a PolicyEngineLike.
 */
export interface ClawdstrikeLike {
  /** Creates an interceptor for tool wrapping */
  createInterceptor?: () => ToolInterceptor;
}

/**
 * Wrap Vercel AI tools with security checks.
 *
 * This is the simplified API that accepts a Clawdstrike instance or PolicyEngineLike.
 *
 * @example Using with Clawdstrike instance (recommended)
 * ```typescript
 * import { Clawdstrike } from '@clawdstrike/sdk';
 * import { secureTools } from '@clawdstrike/vercel-ai';
 *
 * const cs = await Clawdstrike.fromPolicy('./policy.yaml');
 * const tools = secureTools(myTools, cs);
 * ```
 *
 * @example Using with PolicyEngineLike (legacy)
 * ```typescript
 * import { createPolicyEngine } from '@clawdstrike/policy';
 * import { secureTools } from '@clawdstrike/vercel-ai';
 *
 * const engine = createPolicyEngine({ policyRef: './policy.yaml' });
 * const tools = secureTools(myTools, engine);
 * ```
 */
export function secureTools<TTools extends Record<string, VercelAiToolLike>>(
  tools: TTools,
  csOrInterceptor: ClawdstrikeLike | PolicyEngineLike | ToolInterceptor,
  options?: SecureToolsOptions,
): TTools {
  // Determine the interceptor to use
  let interceptor: ToolInterceptor;

  if (isToolInterceptor(csOrInterceptor)) {
    // Direct ToolInterceptor (legacy API)
    interceptor = csOrInterceptor;
  } else if (isClawdstrikeLike(csOrInterceptor)) {
    // Clawdstrike instance with createInterceptor method
    interceptor = csOrInterceptor.createInterceptor!();
  } else {
    // PolicyEngineLike - create a new interceptor
    const config: AdapterConfig = {};
    interceptor = new BaseToolInterceptor(csOrInterceptor, config);
  }

  const defaultContext = options?.context ?? createSecurityContext({
    metadata: { framework: 'vercel-ai' },
  });

  const secured = {} as TTools;
  for (const [toolName, tool] of Object.entries(tools)) {
    (secured as Record<string, VercelAiToolLike>)[toolName] = {
      ...(tool as object),
      execute: wrapExecute(toolName, tool.execute, interceptor, defaultContext, options?.getContext),
    } as VercelAiToolLike;
  }

  return secured;
}

/**
 * @deprecated Use secureTools with PolicyEngineLike instead.
 * Legacy function that takes an explicit interceptor.
 */
export function secureToolsLegacy<TTools extends Record<string, VercelAiToolLike>>(
  tools: TTools,
  interceptor: ToolInterceptor,
  options?: SecureToolsOptions,
): TTools {
  console.warn('secureToolsLegacy is deprecated. Use secureTools(tools, clawdstrike) instead.');
  return secureTools(tools, interceptor, options);
}

function isToolInterceptor(value: unknown): value is ToolInterceptor {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as ToolInterceptor).beforeExecute === 'function' &&
    typeof (value as ToolInterceptor).afterExecute === 'function' &&
    typeof (value as ToolInterceptor).onError === 'function'
  );
}

function isClawdstrikeLike(value: unknown): value is ClawdstrikeLike {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as ClawdstrikeLike).createInterceptor === 'function'
  );
}

function wrapExecute<TInput, TOutput>(
  toolName: string,
  execute: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput,
  interceptor: ToolInterceptor,
  defaultContext: SecurityContext,
  getContext?: (toolName: string, input: unknown) => SecurityContext,
): (input: TInput, ...rest: unknown[]) => Promise<TOutput> {
  return async (input: TInput, ...rest: unknown[]): Promise<TOutput> => {
    const context = getContext ? getContext(toolName, input) : defaultContext;

    let interceptResult;
    try {
      interceptResult = await interceptor.beforeExecute(toolName, input, context);
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      await interceptor.onError(toolName, input, err, context);
      throw err;
    }

    if (!interceptResult.proceed) {
      const { decision } = interceptResult;
      throw new ClawdstrikeBlockedError(toolName, decision);
    }

    const nextInput = (interceptResult.modifiedParameters as unknown as TInput) ?? input;

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
      const output = await execute(nextInput, ...rest);
      const processed = await interceptor.afterExecute(toolName, nextInput, output, context);
      return processed.output as TOutput;
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      await interceptor.onError(toolName, nextInput, err, context);
      throw err;
    }
  };
}
