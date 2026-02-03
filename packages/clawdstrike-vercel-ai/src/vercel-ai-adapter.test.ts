import { describe, it, expect } from 'vitest';

import type { PolicyEngineLike } from '@clawdstrike/adapter-core';

import { VercelAIAdapter } from './vercel-ai-adapter.js';

describe('VercelAIAdapter', () => {
  it('evaluates tool calls via FrameworkAdapter interface', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        allowed: event.eventType !== 'command_exec',
        denied: event.eventType === 'command_exec',
        warn: false,
        reason: event.eventType === 'command_exec' ? 'blocked' : undefined,
      }),
    };

    const adapter = new VercelAIAdapter(engine, { blockOnViolation: true });
    await adapter.initialize({ blockOnViolation: true });

    const context = adapter.createContext();

    const blocked = await adapter.interceptToolCall(context, {
      id: '1',
      name: 'bash',
      parameters: { cmd: 'rm -rf /' },
      timestamp: new Date(),
      source: 'test',
    });

    expect(blocked.proceed).toBe(false);

    const summary = await adapter.finalizeContext(context);
    expect(summary.sessionId).toBe(context.sessionId);
    expect(summary.blockedToolCalls).toBeGreaterThanOrEqual(1);
  });
});
