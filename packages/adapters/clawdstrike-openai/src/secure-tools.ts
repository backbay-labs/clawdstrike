import type { SecurityContext } from "@clawdstrike/adapter-core";
import {
  secureToolSet,
  type SecuritySource,
} from "@clawdstrike/adapter-core";

import type { OpenAIBrokerOptions } from "./broker.js";
import { createOpenAIBrokerExecutor } from "./broker.js";
import { openAICuaTranslator } from "./openai-cua-translator.js";

export interface SecureToolsOptions {
  context?: SecurityContext;
  getContext?: (toolName: string, input: unknown) => SecurityContext;
  broker?: OpenAIBrokerOptions;
}

type OpenAIToolLike<TInput = unknown, TOutput = unknown> = {
  execute?: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
  call?: (input: TInput, ...rest: unknown[]) => Promise<TOutput> | TOutput;
};

export function secureTools<TTools extends Record<string, OpenAIToolLike>>(
  tools: TTools,
  source: SecuritySource,
  options?: SecureToolsOptions,
): TTools {
  return secureToolSet(tools, source, {
    framework: "openai",
    translateToolCall: openAICuaTranslator,
    context: options?.context,
    getContext: options?.getContext,
    broker: options?.broker ? { executor: createOpenAIBrokerExecutor(options.broker) } : undefined,
  });
}
