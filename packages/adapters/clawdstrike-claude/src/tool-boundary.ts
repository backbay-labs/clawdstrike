import { FrameworkToolBoundary, wrapFrameworkToolDispatcher } from '@clawdstrike/adapter-core';
import type {
  FrameworkToolBoundaryOptions,
  FrameworkToolDispatcher,
  ToolCallTranslationInput,
} from '@clawdstrike/adapter-core';

import { claudeCuaTranslator } from './claude-cua-translator.js';

export type ClaudeToolBoundaryOptions = FrameworkToolBoundaryOptions;
export type ClaudeToolDispatcher<TOutput = unknown> = FrameworkToolDispatcher<TOutput>;

function composeOptions(options: ClaudeToolBoundaryOptions = {}): ClaudeToolBoundaryOptions {
  const cfg = options.config ?? {};
  const userTranslator = cfg.translateToolCall;
  return {
    ...options,
    config: {
      ...cfg,
      translateToolCall: (input: ToolCallTranslationInput) => {
        const translated = claudeCuaTranslator(input);
        if (translated) return translated;
        return userTranslator ? userTranslator(input) : null;
      },
    },
  };
}

export class ClaudeToolBoundary extends FrameworkToolBoundary {
  constructor(options: ClaudeToolBoundaryOptions = {}) {
    super('claude', composeOptions(options));
  }
}

export const wrapClaudeToolDispatcher = <TOutput = unknown>(
  boundary: ClaudeToolBoundary,
  dispatcher: ClaudeToolDispatcher<TOutput>,
) => wrapFrameworkToolDispatcher(boundary, dispatcher);
