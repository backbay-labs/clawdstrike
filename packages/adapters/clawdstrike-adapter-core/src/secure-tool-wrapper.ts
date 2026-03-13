import type { AdapterConfig } from "./adapter.js";
import type { SecurityContext } from "./context.js";
import { createSecurityContext } from "./context.js";
import { ClawdstrikeBlockedError } from "./errors.js";
import type { ToolInterceptor } from "./interceptor.js";
import { resolveInterceptor, type SecuritySource } from "./resolve-interceptor.js";

export function wrapExecuteWithInterceptor<TInput, TOutput>(
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

    const nextInput =
      interceptResult.modifiedInput !== undefined
        ? (interceptResult.modifiedInput as TInput)
        : interceptResult.modifiedParameters !== undefined
          ? (interceptResult.modifiedParameters as unknown as TInput)
          : input;

    if (interceptResult.replacementResult !== undefined) {
      try {
        const processed = await interceptor.afterExecute(
          toolName,
          nextInput,
          interceptResult.replacementResult as TOutput,
          context,
        );
        return processed.output as TOutput;
      } catch (error) {
        const err = error instanceof Error ? error : new Error(String(error));
        await interceptor.onError(toolName, nextInput, err, context);
        throw err;
      }
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

export type ExecuteOrCallToolLike<TInput = unknown, TOutput = unknown> = {
  execute?: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
  call?: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
};

export interface SecureToolSetOptions {
  framework: string;
  context?: SecurityContext;
  getContext?: (toolName: string, input: unknown) => SecurityContext;
  translateToolCall?: AdapterConfig["translateToolCall"];
  broker?: AdapterConfig["broker"];
}

export function secureToolSet<TTools extends Record<string, ExecuteOrCallToolLike>>(
  tools: TTools,
  source: SecuritySource,
  options: SecureToolSetOptions,
): TTools {
  const resolverConfig =
    options.translateToolCall !== undefined || options.broker !== undefined
      ? ({
          ...(options.translateToolCall !== undefined
            ? { translateToolCall: options.translateToolCall }
            : {}),
          ...(options.broker !== undefined ? { broker: options.broker } : {}),
        } satisfies AdapterConfig)
      : undefined;
  const interceptor = resolveInterceptor(source, resolverConfig);

  const defaultContext =
    options.context ??
    createSecurityContext({
      metadata: { framework: options.framework },
    });

  const secured = {} as TTools;
  for (const [toolName, tool] of Object.entries(tools)) {
    const hasExecute = typeof tool.execute === "function";
    const hasCall = typeof tool.call === "function";
    if (!hasExecute && !hasCall) {
      (secured as Record<string, ExecuteOrCallToolLike>)[toolName] = tool;
      continue;
    }

    const wrappedTool = Object.create(
      Object.getPrototypeOf(tool),
      Object.getOwnPropertyDescriptors(tool as object),
    ) as ExecuteOrCallToolLike;
    if (hasExecute) {
      wrappedTool.execute = wrapExecuteWithInterceptor(
        toolName,
        tool.execute!.bind(tool),
        interceptor,
        defaultContext,
        options.getContext,
      );
    }
    if (hasCall) {
      wrappedTool.call = wrapExecuteWithInterceptor(
        toolName,
        tool.call!.bind(tool),
        interceptor,
        defaultContext,
        options.getContext,
      );
    }

    (secured as Record<string, ExecuteOrCallToolLike>)[toolName] = wrappedTool;
  }

  return secured;
}
