import { BaseToolInterceptor } from '@clawdstrike/adapter-core';
import type { PolicyEngineLike } from '@clawdstrike/adapter-core';

import type { LangChainClawdstrikeConfig } from './types.js';

export function createLangChainInterceptor(
  engine: PolicyEngineLike,
  config: LangChainClawdstrikeConfig = {},
): BaseToolInterceptor {
  const normalizeToolName = (name: string) => {
    const mapped = config.toolNameMapping?.[name] ?? name;
    return config.normalizeToolName ? config.normalizeToolName(mapped) : mapped;
  };

  return new BaseToolInterceptor(engine, {
    ...config,
    normalizeToolName,
  });
}

