import { InMemoryAuditLogger } from '@clawdstrike/adapter-core';
import type { AuditEvent, AuditLogger } from '@clawdstrike/adapter-core';

import type { AuditStore } from './store.js';

export interface OpenClawAuditLoggerOptions {
  store?: AuditStore;
  maxEvents?: number;
}

/**
 * OpenClawAuditLogger bridges the adapter-core `AuditLogger` interface with
 * openclaw's existing `AuditStore` JSONL persistence layer.
 *
 * It wraps an `InMemoryAuditLogger` for fast in-process queries and
 * optionally forwards events to an `AuditStore` for durable persistence.
 */
export class OpenClawAuditLogger implements AuditLogger {
  private readonly memory: InMemoryAuditLogger;
  private readonly store: AuditStore | undefined;

  constructor(options: OpenClawAuditLoggerOptions = {}) {
    this.memory = new InMemoryAuditLogger(options.maxEvents);
    this.store = options.store;
  }

  async log(event: AuditEvent): Promise<void> {
    await this.memory.log(event);

    if (this.store) {
      this.store.append({
        type: event.type,
        resource: event.toolName ?? '',
        decision: event.decision?.status === 'deny' ? 'denied' : 'allowed',
        guard: event.decision?.guard,
        reason: event.decision?.reason ?? event.decision?.message,
        runId: event.sessionId,
      });
    }
  }

  async getSessionEvents(sessionId: string): Promise<AuditEvent[]> {
    return this.memory.getSessionEvents(sessionId);
  }

  async getContextEvents(contextId: string): Promise<AuditEvent[]> {
    return this.memory.getContextEvents(contextId);
  }

  async export(format: 'json' | 'csv' | 'jsonl'): Promise<string> {
    return this.memory.export(format);
  }

  async prune(olderThan: Date): Promise<number> {
    return this.memory.prune(olderThan);
  }
}
