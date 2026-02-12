import { FrameworkToolBoundary, wrapFrameworkToolDispatcher } from '@clawdstrike/adapter-core';
import type { FrameworkToolBoundaryOptions, FrameworkToolDispatcher } from '@clawdstrike/adapter-core';

export type OpenAIToolBoundaryOptions = FrameworkToolBoundaryOptions;
export type OpenAIToolDispatcher<TOutput = unknown> = FrameworkToolDispatcher<TOutput>;

export class OpenAIToolBoundary extends FrameworkToolBoundary {
  constructor(options: OpenAIToolBoundaryOptions = {}) {
    super('openai', options);
  }
}

export const wrapOpenAIToolDispatcher = <TOutput = unknown>(
  boundary: OpenAIToolBoundary,
  dispatcher: OpenAIToolDispatcher<TOutput>,
) => wrapFrameworkToolDispatcher(boundary, dispatcher);
