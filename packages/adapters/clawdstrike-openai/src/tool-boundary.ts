import type {
  FrameworkToolBoundaryOptions,
  FrameworkToolDispatcher,
  ToolCallTranslationInput,
} from "@clawdstrike/adapter-core";
import { FrameworkToolBoundary, wrapFrameworkToolDispatcher } from "@clawdstrike/adapter-core";

import type { OpenAIBrokerOptions } from "./broker.js";
import { createOpenAIBrokerExecutor } from "./broker.js";
import { openAICuaTranslator } from "./openai-cua-translator.js";

export type OpenAIToolBoundaryOptions = FrameworkToolBoundaryOptions & {
  broker?: OpenAIBrokerOptions;
};
export type OpenAIToolDispatcher<TOutput = unknown> = FrameworkToolDispatcher<TOutput>;

function composeOptions(options: OpenAIToolBoundaryOptions = {}): OpenAIToolBoundaryOptions {
  const cfg = options.config ?? {};
  const userTranslator = cfg.translateToolCall;
  return {
    ...options,
    config: {
      ...cfg,
      ...(options.broker
        ? { broker: { executor: createOpenAIBrokerExecutor(options.broker) } }
        : {}),
      translateToolCall: (input: ToolCallTranslationInput) => {
        const translated = openAICuaTranslator(input);
        if (translated) return translated;
        return userTranslator ? userTranslator(input) : null;
      },
    },
  };
}

export class OpenAIToolBoundary extends FrameworkToolBoundary {
  constructor(options: OpenAIToolBoundaryOptions = {}) {
    super("openai", composeOptions(options));
  }
}

export const wrapOpenAIToolDispatcher = <TOutput = unknown>(
  boundary: OpenAIToolBoundary,
  dispatcher: OpenAIToolDispatcher<TOutput>,
) => wrapFrameworkToolDispatcher(boundary, dispatcher);
