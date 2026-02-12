import { FrameworkToolBoundary, wrapFrameworkToolDispatcher } from '@clawdstrike/adapter-core';
import type { FrameworkToolBoundaryOptions, FrameworkToolDispatcher } from '@clawdstrike/adapter-core';

export type ClaudeToolBoundaryOptions = FrameworkToolBoundaryOptions;
export type ClaudeToolDispatcher<TOutput = unknown> = FrameworkToolDispatcher<TOutput>;

export class ClaudeToolBoundary extends FrameworkToolBoundary {
  constructor(options: ClaudeToolBoundaryOptions = {}) {
    super('claude', options);
  }
}

export const wrapClaudeToolDispatcher = <TOutput = unknown>(
  boundary: ClaudeToolBoundary,
  dispatcher: ClaudeToolDispatcher<TOutput>,
) => wrapFrameworkToolDispatcher(boundary, dispatcher);
