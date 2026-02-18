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

  it('translates OpenAI computer_use actions into canonical CUA events', async () => {
    let seenEventType: string | null = null;
    let seenAction: string | null = null;
    const engine: PolicyEngineLike = {
      evaluate: event => {
        seenEventType = event.eventType;
        if (event.data.type === 'cua') {
          seenAction = String(event.data.cuaAction);
        }
        return {
          status: event.eventType === 'input.inject' ? 'deny' : 'allow',
        };
      },
    };

    const adapter = new OpenAIAdapter(engine, { blockOnViolation: true });
    await adapter.initialize({ blockOnViolation: true });
    const context = adapter.createContext();

    const result = await adapter.interceptToolCall(context, {
      id: '2',
      name: 'computer_use',
      parameters: { action: 'click', x: 10, y: 20 },
      timestamp: new Date(),
      source: 'test',
    });

    expect(result.proceed).toBe(false);
    expect(seenEventType).toBe('input.inject');
    expect(seenAction).toBe('click');
  });

  it('fails closed when OpenAI translator sees unknown CUA action', async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ status: 'allow' }),
    };

    const adapter = new OpenAIAdapter(engine, { blockOnViolation: true });
    await adapter.initialize({ blockOnViolation: true });
    const context = adapter.createContext();

    const result = await adapter.interceptToolCall(context, {
      id: '3',
      name: 'computer_use',
      parameters: { action: 'mystery_action' },
      timestamp: new Date(),
      source: 'test',
    });

    expect(result.proceed).toBe(false);
    expect(result.decision.status).toBe('deny');
    expect(result.decision.guard).toBe('provider_translator');
  });
});
