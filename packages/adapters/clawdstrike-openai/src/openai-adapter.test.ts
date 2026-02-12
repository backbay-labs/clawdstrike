import { describe, it, expect } from 'vitest';

import type { PolicyEngineLike } from '@clawdstrike/adapter-core';

import { OpenAIAdapter } from './openai-adapter.js';

describe('OpenAIAdapter', () => {
  it('evaluates tool calls via FrameworkAdapter interface', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        status: event.eventType === 'command_exec' ? 'deny' : 'allow',
      }),
    };

    const adapter = new OpenAIAdapter(engine, { blockOnViolation: true });
    await adapter.initialize({ blockOnViolation: true });

    const context = adapter.createContext();

    const result = await adapter.interceptToolCall(context, {
      id: '1',
      name: 'bash',
      parameters: { cmd: 'rm -rf /' },
      timestamp: new Date(),
      source: 'test',
    });

    expect(result.proceed).toBe(false);
  });
});
