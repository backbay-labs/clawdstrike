import type { SecurityContext, ToolInterceptor } from "@clawdstrike/adapter-core";
import {
  createSecurityContext,
  resolveInterceptor,
  type SecuritySource,
  wrapExecuteWithInterceptor,
} from "@clawdstrike/adapter-core";

export type VercelAiToolLike<TInput = unknown, TOutput = unknown> = {
  execute: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
};

export type VercelAiToolSet = Record<string, VercelAiToolLike>;

export interface SecureToolsOptions {
  context?: SecurityContext;
  getContext?: (toolName: string, input: unknown) => SecurityContext;
}

/**
 * Wrap Vercel AI tools with security checks.
 *
 * @example Using with Clawdstrike instance (recommended)
 * ```typescript
 * import { Clawdstrike } from '@clawdstrike/sdk';
 * import { secureTools } from '@clawdstrike/vercel-ai';
 *
 * const cs = await Clawdstrike.fromPolicy('./policy.yaml');
 * const tools = secureTools(myTools, cs);
 * ```
 */
export function secureTools<TTools extends Record<string, VercelAiToolLike>>(
  tools: TTools,
  source: SecuritySource,
  options?: SecureToolsOptions,
): TTools {
  const interceptor: ToolInterceptor = resolveInterceptor(source);

  const defaultContext =
    options?.context ??
    createSecurityContext({
      metadata: { framework: "vercel-ai" },
    });

  const secured = {} as TTools;
  for (const [toolName, tool] of Object.entries(tools)) {
    const boundExecute = tool.execute.bind(tool);
    (secured as Record<string, VercelAiToolLike>)[toolName] = {
      ...(tool as object),
      execute: wrapExecuteWithInterceptor(
        toolName,
        boundExecute,
        interceptor,
        defaultContext,
        options?.getContext,
      ),
    } as VercelAiToolLike;
  }

  return secured;
}
