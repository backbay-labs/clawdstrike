import { describe, it, expect } from 'vitest';
import handler from './handler.js';

describe('agent:bootstrap handler', () => {
  it('ignores non-bootstrap events', async () => {
    const event = {
      type: 'other:event',
      context: { bootstrapFiles: [] },
    };
    await handler(event as any);
    expect(event.context.bootstrapFiles).toHaveLength(0);
  });

  it('injects SECURITY.md into bootstrap files', async () => {
    const event = {
      type: 'agent:bootstrap',
      context: {
        bootstrapFiles: [] as { path: string; content: string }[],
        cfg: {
          hushclaw: {
            egress: {
              mode: 'allowlist' as const,
              allowed_domains: ['api.github.com'],
            },
          },
        },
      },
    };
    await handler(event as any);
    expect(event.context.bootstrapFiles).toHaveLength(1);
    expect(event.context.bootstrapFiles[0].path).toBe('SECURITY.md');
    expect(event.context.bootstrapFiles[0].content).toContain('Security Policy');
    expect(event.context.bootstrapFiles[0].content).toContain('api.github.com');
  });

  it('uses default policy when none provided', async () => {
    const event = {
      type: 'agent:bootstrap',
      context: {
        bootstrapFiles: [] as { path: string; content: string }[],
        cfg: {},
      },
    };
    await handler(event as any);
    expect(event.context.bootstrapFiles).toHaveLength(1);
    expect(event.context.bootstrapFiles[0].content).toContain('policy_check');
  });
});
