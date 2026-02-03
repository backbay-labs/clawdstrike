import { createSecurityContext } from '@clawdstrike/adapter-core';
import type { SecurityContext, ToolInterceptor } from '@clawdstrike/adapter-core';

import { ClawdstrikeBlockedError } from './errors.js';

export type VercelAiToolLike<TInput = unknown, TOutput = unknown> = {
  execute: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
};

export type VercelAiToolSet = Record<string, VercelAiToolLike>;

export interface SecureToolsOptions {
  context?: SecurityContext;
  getContext?: (toolName: string, input: unknown) => SecurityContext;
}

export function secureTools<TTools extends Record<string, VercelAiToolLike>>(
  tools: TTools,
  interceptor: ToolInterceptor,
  options?: SecureToolsOptions,
): TTools {
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
