import type { SecurityContext } from "@clawdstrike/adapter-core";
import {
  createSecurityContext,
  resolveInterceptor,
  type SecuritySource,
  wrapExecuteWithInterceptor,
} from "@clawdstrike/adapter-core";

export interface SecureToolsOptions {
  context?: SecurityContext;
  getContext?: (toolName: string, input: unknown) => SecurityContext;
}

type OpenCodeToolLike<TInput = unknown, TOutput = unknown> = {
  execute?: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
  call?: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
};

export function secureTools<TTools extends Record<string, OpenCodeToolLike>>(
  tools: TTools,
  source: SecuritySource,
  options?: SecureToolsOptions,
): TTools {
  const interceptor = resolveInterceptor(source);

  const defaultContext =
    options?.context ??
    createSecurityContext({
      metadata: { framework: "opencode" },
    });

  const secured = {} as TTools;
  for (const [toolName, tool] of Object.entries(tools)) {
    const originalExecute = tool.execute ?? tool.call;
    if (typeof originalExecute !== "function") {
      (secured as Record<string, OpenCodeToolLike>)[toolName] = tool;
      continue;
    }

    const wrapped = wrapExecuteWithInterceptor(
      toolName,
      originalExecute.bind(tool),
      interceptor,
      defaultContext,
      options?.getContext,
    );
    (secured as Record<string, OpenCodeToolLike>)[toolName] = {
      ...(tool as object),
      execute: wrapped,
      call: wrapped,
    } as OpenCodeToolLike;
  }

  return secured;
}
