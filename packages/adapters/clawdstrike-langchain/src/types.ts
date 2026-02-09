import type { AdapterConfig } from '@clawdstrike/adapter-core';

export type LangChainClawdstrikeConfig = AdapterConfig & {
  toolNameMapping?: Record<string, string>;
};

