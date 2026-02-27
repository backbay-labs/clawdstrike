import type { PolicyEngineLike, Decision } from '@clawdstrike/adapter-core';

export type EngineMode = 'standalone' | 'connected' | 'degraded';

export interface ModeChangeEvent {
  from: EngineMode;
  to: EngineMode;
  reason: string;
  timestamp: string;
}

export interface EnrichedProvenance {
  mode: EngineMode;
  engine: 'local' | 'remote';
  reason?: string;
  localPolicyRef?: string;
  localPolicyAge?: string;
  capabilitiesLost?: string[];
  timestamp: string;
}

export interface QueuedReceipt {
  event: unknown;
  decision: Decision;
  provenance: EnrichedProvenance;
  enqueuedAt: string;
}

export interface AdaptiveEngineOptions {
  local: PolicyEngineLike;
  remote?: PolicyEngineLike;
  initialMode?: EngineMode;
  probe?: {
    remoteHealthUrl?: string;
    intervalMs?: number;
    timeoutMs?: number;
  };
  receiptQueue?: {
    maxSize?: number;
    persistPath?: string;
  };
  onModeChange?: (event: ModeChangeEvent) => void;
}
