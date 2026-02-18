import { FrameworkToolBoundary, wrapFrameworkToolDispatcher } from '@clawdstrike/adapter-core';
import type {
  FrameworkToolBoundaryOptions,
  FrameworkToolDispatcher,
  ToolCallTranslationInput,
} from '@clawdstrike/adapter-core';

import { openAICuaTranslator } from './openai-cua-translator.js';

export type OpenAIToolBoundaryOptions = FrameworkToolBoundaryOptions;
export type OpenAIToolDispatcher<TOutput = unknown> = FrameworkToolDispatcher<TOutput>;

function composeOptions(options: OpenAIToolBoundaryOptions = {}): OpenAIToolBoundaryOptions {
  const cfg = options.config ?? {};
  const userTranslator = cfg.translateToolCall;
  return {
    ...options,
    config: {
      ...cfg,
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
    super('openai', composeOptions(options));
  }
}

export const wrapOpenAIToolDispatcher = <TOutput = unknown>(
  boundary: OpenAIToolBoundary,
  dispatcher: OpenAIToolDispatcher<TOutput>,
) => wrapFrameworkToolDispatcher(boundary, dispatcher);
