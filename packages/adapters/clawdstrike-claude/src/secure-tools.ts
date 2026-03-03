import type { SecurityContext } from "@clawdstrike/adapter-core";
import {
  secureToolSet,
  type SecuritySource,
} from "@clawdstrike/adapter-core";

import { claudeCuaTranslator } from "./claude-cua-translator.js";

export interface SecureToolsOptions {
  context?: SecurityContext;
  getContext?: (toolName: string, input: unknown) => SecurityContext;
}

type ClaudeToolLike<TInput = unknown, TOutput = unknown> = {
  execute?: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
  call?: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
};

export function secureTools<TTools extends Record<string, ClaudeToolLike>>(
  tools: TTools,
  source: SecuritySource,
  options?: SecureToolsOptions,
): TTools {
  return secureToolSet(tools, source, {
    framework: "claude",
    translateToolCall: claudeCuaTranslator,
    context: options?.context,
    getContext: options?.getContext,
  });
}
