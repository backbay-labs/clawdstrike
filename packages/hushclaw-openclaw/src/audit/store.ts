import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';

export interface AuditEvent {
  id: string;
  timestamp: number;
  type: string;
  resource: string;
  decision: 'allowed' | 'denied';
  guard?: string;
  reason?: string;
  runId?: string;
}

export class AuditStore {
  private path: string;
  private events: AuditEvent[] = [];

  constructor(path: string = '.hush/audit.jsonl') {
    this.path = path;
    this.load();
  }

  private load(): void {
    if (existsSync(this.path)) {
      const content = readFileSync(this.path, 'utf-8');
      this.events = content
        .split('\n')
        .filter(line => line.trim())
        .map(line => JSON.parse(line));
    }
  }

  append(event: Omit<AuditEvent, 'id' | 'timestamp'>): AuditEvent {
    const fullEvent: AuditEvent = {
      ...event,
      id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      timestamp: Date.now(),
    };
    this.events.push(fullEvent);

    const dir = dirname(this.path);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    writeFileSync(this.path, this.events.map(e => JSON.stringify(e)).join('\n') + '\n');

    return fullEvent;
  }

  query(options: {
    since?: number;
    guard?: string;
    denied?: boolean;
    limit?: number;
  } = {}): AuditEvent[] {
    let results = [...this.events];

    if (options.since) {
      results = results.filter(e => e.timestamp >= options.since!);
    }
    if (options.guard) {
      results = results.filter(e => e.guard === options.guard);
    }
    if (options.denied) {
      results = results.filter(e => e.decision === 'denied');
    }
    if (options.limit) {
      results = results.slice(-options.limit);
    }

    return results;
  }

  getById(id: string): AuditEvent | undefined {
    return this.events.find(e => e.id === id);
  }

  clear(): void {
    this.events = [];
    if (existsSync(this.path)) {
      writeFileSync(this.path, '');
    }
  }
}
