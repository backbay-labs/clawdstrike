import { describe, it, expect } from 'vitest';
import { InMemoryAuditLogger, type AuditEvent } from './audit.js';

describe('InMemoryAuditLogger', () => {
  it('captures and queries events', async () => {
    const logger = new InMemoryAuditLogger();

    const event1: AuditEvent = {
      id: 'a1',
      type: 'tool_call_start',
      timestamp: new Date(),
      contextId: 'ctx-1',
      sessionId: 'sess-1',
      toolName: 'bash',
      parameters: { cmd: 'ls' },
    };

    const event2: AuditEvent = {
      id: 'a2',
      type: 'tool_call_end',
      timestamp: new Date(),
      contextId: 'ctx-1',
      sessionId: 'sess-1',
      toolName: 'bash',
      output: 'ok',
    };

    const event3: AuditEvent = {
      id: 'a3',
      type: 'session_start',
      timestamp: new Date(),
      contextId: 'ctx-2',
      sessionId: 'sess-2',
    };

    await logger.log(event1);
    await logger.log(event2);
    await logger.log(event3);

    const sess1 = await logger.getSessionEvents('sess-1');
    expect(sess1.map(e => e.id)).toEqual(['a1', 'a2']);

    const ctx1 = await logger.getContextEvents('ctx-1');
    expect(ctx1.map(e => e.id)).toEqual(['a1', 'a2']);
  });
});

