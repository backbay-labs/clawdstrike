import { FrameworkToolBoundary, wrapFrameworkToolDispatcher } from '@clawdstrike/adapter-core';
import type { FrameworkToolBoundaryOptions, FrameworkToolDispatcher } from '@clawdstrike/adapter-core';

export type OpenCodeToolBoundaryOptions = FrameworkToolBoundaryOptions;
export type OpenCodeToolDispatcher<TOutput = unknown> = FrameworkToolDispatcher<TOutput>;

export class OpenCodeToolBoundary extends FrameworkToolBoundary {
  constructor(options: OpenCodeToolBoundaryOptions = {}) {
    super('opencode', options);
  }
}

export const wrapOpenCodeToolDispatcher = <TOutput = unknown>(
  boundary: OpenCodeToolBoundary,
  dispatcher: OpenCodeToolDispatcher<TOutput>,
) => wrapFrameworkToolDispatcher(boundary, dispatcher);
