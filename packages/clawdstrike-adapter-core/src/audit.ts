import type { Decision } from './types.js';

export type AuditEventType =
  | 'tool_call_start'
  | 'tool_call_blocked'
  | 'tool_call_allowed'
  | 'tool_call_warning'
  | 'tool_call_end'
  | 'tool_call_error'
  | 'output_sanitized'
  | 'session_start'
  | 'session_end';

export interface AuditEvent {
  id: string;
  type: AuditEventType;
  timestamp: Date;
  contextId: string;
  sessionId: string;
  toolName?: string;
  parameters?: Record<string, unknown>;
  output?: unknown;
  decision?: Decision;
  details?: Record<string, unknown>;
}

export interface AuditLogger {
  log(event: AuditEvent): Promise<void>;
  getSessionEvents(sessionId: string): Promise<AuditEvent[]>;
  getContextEvents(contextId: string): Promise<AuditEvent[]>;
  export(format: 'json' | 'csv' | 'jsonl'): Promise<string>;
  prune(olderThan: Date): Promise<number>;
}

export class InMemoryAuditLogger implements AuditLogger {
  private events: AuditEvent[] = [];
  private readonly maxEvents: number;

  constructor(maxEvents = 10_000) {
    this.maxEvents = maxEvents;
  }

  async log(event: AuditEvent): Promise<void> {
    this.events.push(event);

    if (this.events.length > this.maxEvents) {
      this.events = this.events.slice(-this.maxEvents);
    }
  }

  async getSessionEvents(sessionId: string): Promise<AuditEvent[]> {
    return this.events.filter(e => e.sessionId === sessionId);
  }

  async getContextEvents(contextId: string): Promise<AuditEvent[]> {
    return this.events.filter(e => e.contextId === contextId);
  }

  async export(format: 'json' | 'csv' | 'jsonl'): Promise<string> {
    switch (format) {
      case 'json':
        return JSON.stringify(this.events, null, 2);
      case 'jsonl':
        return this.events.map(e => JSON.stringify(e)).join('\n');
      case 'csv': {
        const headers = [
          'id',
          'type',
          'timestamp',
          'contextId',
          'sessionId',
          'toolName',
          'decision',
        ];
        const rows = this.events.map(e => [
          e.id,
          e.type,
          e.timestamp.toISOString(),
          e.contextId,
          e.sessionId,
          e.toolName ?? '',
          e.decision?.denied ? 'denied' : e.decision?.warn ? 'warn' : 'allowed',
        ]);
        return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
      }
    }
  }

  async prune(olderThan: Date): Promise<number> {
    const originalLength = this.events.length;
    this.events = this.events.filter(e => e.timestamp > olderThan);
    return originalLength - this.events.length;
  }
}

