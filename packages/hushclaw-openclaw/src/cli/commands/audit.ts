import { writeFileSync } from 'fs';
import { AuditStore } from '../../audit/store.js';

interface QueryOptions {
  since?: string;
  guard?: string;
  denied?: boolean;
  auditPath?: string;
}

interface ExplainOptions {
  auditPath?: string;
}

interface ExportOptions {
  auditPath?: string;
}

export const auditCommands = {
  async query(options: QueryOptions = {}): Promise<void> {
    const store = new AuditStore(options.auditPath || '.hush/audit.jsonl');

    const queryOptions: { since?: number; guard?: string; denied?: boolean; limit?: number } = {
      limit: 50,
    };

    if (options.since) {
      const sinceDate = new Date(options.since);
      queryOptions.since = sinceDate.getTime();
    }
    if (options.guard) {
      queryOptions.guard = options.guard;
    }
    if (options.denied) {
      queryOptions.denied = true;
    }

    const events = store.query(queryOptions);

    if (events.length === 0) {
      console.log('No audit events found');
      return;
    }

    console.log('Audit Events:');
    console.log('=============');

    for (const event of events) {
      const date = new Date(event.timestamp).toISOString();
      const status = event.decision === 'allowed' ? 'ALLOWED' : 'DENIED';
      console.log(`\n[${date}] ${event.id}`);
      console.log(`  Action: ${event.type}`);
      console.log(`  Resource: ${event.resource}`);
      console.log(`  Decision: ${status}`);
      if (event.guard) console.log(`  Guard: ${event.guard}`);
      if (event.reason) console.log(`  Reason: ${event.reason}`);
    }
  },

  async explain(eventId: string, options: ExplainOptions = {}): Promise<void> {
    const store = new AuditStore(options.auditPath || '.hush/audit.jsonl');
    const event = store.getById(eventId);

    if (!event) {
      console.log(`Event ${eventId} not found`);
      return;
    }

    console.log('Event Details');
    console.log('=============');
    console.log(`\nEvent ID:    ${event.id}`);
    console.log(`Timestamp:   ${new Date(event.timestamp).toISOString()}`);
    console.log(`Action:      ${event.type}`);
    console.log(`Resource:    ${event.resource}`);
    console.log(`Decision:    ${event.decision === 'allowed' ? 'ALLOWED' : 'DENIED'}`);

    if (event.guard) {
      console.log(`\nGuard:       ${event.guard}`);
    }
    if (event.reason) {
      console.log(`Reason:      ${event.reason}`);
    }

    if (event.decision === 'denied') {
      console.log('\nRemediation:');
      console.log('------------');
      if (event.guard === 'ForbiddenPathGuard') {
        console.log('This path is protected by the ForbiddenPathGuard.');
        console.log('To allow access, remove it from filesystem.forbidden_paths in your policy.');
      } else if (event.guard === 'EgressAllowlistGuard') {
        console.log('This domain is not in the egress allowlist.');
        console.log('To allow access, add it to egress.allowed_domains in your policy.');
      } else {
        console.log('Review your policy configuration to understand why this was blocked.');
      }
    }
  },

  async export(file: string, options: ExportOptions = {}): Promise<void> {
    const store = new AuditStore(options.auditPath || '.hush/audit.jsonl');
    const events = store.query({});

    writeFileSync(file, JSON.stringify(events, null, 2));
    console.log(`Exported ${events.length} events to ${file}`);
  },
};
