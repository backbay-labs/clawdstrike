import { LRUCache } from 'lru-cache';

import type { GuardResult } from './types.js';

export class GuardCache {
  private readonly cache: LRUCache<string, GuardResult>;

  constructor(maxBytes: number, ttlSeconds: number) {
    this.cache = new LRUCache<string, GuardResult>({
      maxSize: Math.max(1024, Math.trunc(maxBytes)),
      sizeCalculation: (value, key) => estimateSizeBytes(key, value),
      ttl: Math.max(1, Math.trunc(ttlSeconds)) * 1000,
      allowStale: false,
    });
  }

  get(key: string): GuardResult | undefined {
    return this.cache.get(key);
  }

  set(key: string, value: GuardResult): void {
    this.cache.set(key, value);
  }
}

function estimateSizeBytes(key: string, value: GuardResult): number {
  // Best-effort sizing; avoid throwing for circular references.
  let payload = '';
  try {
    payload = JSON.stringify(value);
  } catch {
    payload = `${value.guard}:${value.message}`;
  }
  return Buffer.byteLength(key, 'utf8') + Buffer.byteLength(payload, 'utf8');
}

