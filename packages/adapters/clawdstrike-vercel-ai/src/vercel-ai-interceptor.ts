import { BaseToolInterceptor } from '@clawdstrike/adapter-core';
import type { AdapterConfig, PolicyEngineLike } from '@clawdstrike/adapter-core';

export type VercelAiInterceptorConfig = AdapterConfig;

export function createVercelAiInterceptor(
  engine: PolicyEngineLike,
  config: VercelAiInterceptorConfig = {},
): BaseToolInterceptor {
  return new BaseToolInterceptor(engine, config);
}

