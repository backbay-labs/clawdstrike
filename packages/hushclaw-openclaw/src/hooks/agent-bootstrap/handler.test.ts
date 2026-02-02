import { describe, it, expect } from 'vitest';
import handler, { initialize } from './handler.js';
import type { AgentBootstrapEvent, HookEvent } from '../../types.js';

describe('agent:bootstrap handler', () => {
  it('ignores non-bootstrap events', async () => {
    const event: HookEvent = {
      type: 'other:event',
      timestamp: new Date().toISOString(),
      context: {} as any,
      messages: [],
    };
    await handler(event as any);
    expect((event as any).context.bootstrapFiles).toBeUndefined();
  });

  it('injects SECURITY.md into bootstrap files', async () => {
    initialize({ policy: 'hushclaw:ai-agent-minimal', mode: 'deterministic', logLevel: 'error' });

    const event: AgentBootstrapEvent = {
      type: 'agent:bootstrap',
      timestamp: new Date().toISOString(),
      context: {
        sessionId: 'test-session',
        agentId: 'test-agent',
        bootstrapFiles: [] as { path: string; content: string }[],
        cfg: { policy: 'hushclaw:ai-agent-minimal', mode: 'deterministic', logLevel: 'error' },
      },
    };
    await handler(event as any);
    expect(event.context.bootstrapFiles).toHaveLength(1);
    expect(event.context.bootstrapFiles[0].path).toBe('SECURITY.md');
    expect(event.context.bootstrapFiles[0].content).toContain('Security Policy');
    expect(event.context.bootstrapFiles[0].content).toContain('api.github.com');
    expect(event.context.bootstrapFiles[0].content).toContain('Enabled Guards');
    expect(event.context.bootstrapFiles[0].content).toContain('forbidden_path');
  });

  it('uses default policy when none provided', async () => {
    const event: AgentBootstrapEvent = {
      type: 'agent:bootstrap',
      timestamp: new Date().toISOString(),
      context: {
        sessionId: 'test-session',
        agentId: 'test-agent',
        bootstrapFiles: [] as { path: string; content: string }[],
        cfg: {},
      },
    };
    await handler(event as any);
    expect(event.context.bootstrapFiles).toHaveLength(1);
    expect(event.context.bootstrapFiles[0].content).toContain('policy_check');
  });
});
