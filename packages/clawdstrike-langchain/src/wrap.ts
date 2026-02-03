import { createSecurityContext } from '@clawdstrike/adapter-core';
import type { SecurityContext, ToolInterceptor } from '@clawdstrike/adapter-core';

type LangChainInvokeLike<TInput = unknown, TOutput = unknown> = {
  invoke: (input: TInput, config?: unknown) => Promise<TOutput> | TOutput;
};

type LangChainCallLike<TInput = unknown, TOutput = unknown> = {
  _call: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
};

type LangChainToolLike = Partial<LangChainInvokeLike> & Partial<LangChainCallLike> & {
  name?: string;
};

export function wrapTool<TTool extends LangChainToolLike>(
  tool: TTool,
  interceptor: ToolInterceptor,
): TTool {
  const context = createSecurityContext({
    metadata: { framework: 'langchain' },
  });
  return wrapToolWithContext(tool, interceptor, context);
}

export function wrapTools<TTool extends LangChainToolLike>(
  tools: readonly TTool[],
  interceptor: ToolInterceptor,
): TTool[] {
  const context = createSecurityContext({
    metadata: { framework: 'langchain' },
  });
  return tools.map(tool => wrapToolWithContext(tool, interceptor, context));
}

function wrapToolWithContext<TTool extends LangChainToolLike>(
  tool: TTool,
  interceptor: ToolInterceptor,
  context: SecurityContext,
): TTool {
  const toolName = typeof tool.name === 'string' && tool.name.length > 0 ? tool.name : 'tool';
  const hasInvoke = typeof tool.invoke === 'function';
  const hasCall = typeof tool._call === 'function';

  if (!hasInvoke && !hasCall) {
    throw new Error(`Tool must implement invoke(input, ...) or _call(input, ...)`);
  }

  const originalInvoke = hasInvoke ? tool.invoke!.bind(tool) : undefined;
  const originalCall = hasCall ? tool._call!.bind(tool) : undefined;

  const wrappedInvoke = hasInvoke
    ? async (input: unknown, config?: unknown) =>
        runIntercepted(
          toolName,
          interceptor,
          context,
          input,
          (nextInput: unknown) => originalInvoke!(nextInput, config),
        )
    : undefined;

  const wrappedCall = hasCall
    ? async (input: unknown, ...rest: unknown[]) =>
        runIntercepted(
          toolName,
          interceptor,
          context,
          input,
          (nextInput: unknown) => originalCall!(nextInput, ...rest),
        )
    : undefined;

  return new Proxy(tool, {
    get(target, prop, receiver) {
      if (prop === 'invoke' && wrappedInvoke) {
        return wrappedInvoke;
      }
      if (prop === '_call' && wrappedCall) {
        return wrappedCall;
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

  if (!interceptResult.proceed) {
    const { decision } = interceptResult;
    const detail = decision.message ?? decision.reason ?? 'denied';
    throw new Error(`Tool '${toolName}' blocked: ${detail}`);
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

