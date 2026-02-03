import { describe, it, expect, vi } from 'vitest';

import type { PolicyEngineLike } from '@clawdstrike/adapter-core';

import { createClawdstrikeMiddleware } from './middleware.js';

describe('wrapLanguageModel', () => {
  it('wraps doGenerate and annotates blocked tool calls', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        allowed: event.eventType !== 'command_exec',
        denied: event.eventType === 'command_exec',
        warn: false,
        reason: event.eventType === 'command_exec' ? 'blocked' : undefined,
      }),
    };

    const experimental_wrapLanguageModel = vi.fn(({ model, middleware }) => ({
      ...model,
      doGenerate: () => middleware.wrapGenerate({ doGenerate: () => model.doGenerate() }),
    }));

    const security = createClawdstrikeMiddleware({
      engine,
      config: { blockOnViolation: true },
      aiSdk: { experimental_wrapLanguageModel },
    });

    const baseModel = {
      async doGenerate() {
        return {
          text: 'ok',
          toolCalls: [{ toolName: 'bash', args: { cmd: 'rm -rf /' } }],
        };
      },
    };

    const model = security.wrapLanguageModel(baseModel);
    const result = await (model as any).doGenerate();

    expect(experimental_wrapLanguageModel).toHaveBeenCalledTimes(1);
    expect(result.toolCalls[0].__clawdstrike_blocked).toBe(true);
    expect(typeof result.toolCalls[0].__clawdstrike_reason).toBe('string');
  });

  it('wraps doStream and uses StreamingToolGuard when enabled', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        allowed: event.eventType !== 'command_exec',
        denied: event.eventType === 'command_exec',
        warn: false,
        reason: 'blocked',
      }),
    };

    const experimental_wrapLanguageModel = vi.fn(({ model, middleware }) => ({
      ...model,
      doStream: () => middleware.wrapStream({ doStream: () => model.doStream() }),
    }));

    const security = createClawdstrikeMiddleware({
      engine,
      config: { blockOnViolation: true, streamingEvaluation: true },
      aiSdk: { experimental_wrapLanguageModel },
    });

    const baseModel = {
      async doStream() {
        const stream = new ReadableStream({
          start(controller) {
            controller.enqueue({ type: 'tool-call-start', toolCallId: '1', toolName: 'bash' });
            controller.enqueue({ type: 'tool-call-delta', toolCallId: '1', argsTextDelta: '{"cmd":"rm -rf /"}' });
            controller.enqueue({ type: 'tool-call', toolCallId: '1', toolName: 'bash', args: { cmd: 'rm -rf /' } });
            controller.close();
          },
        });

        return { stream };
      },
    };

    const model = security.wrapLanguageModel(baseModel);
    const result = await (model as any).doStream();

    const out: any[] = [];
    const reader = result.stream.getReader();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      out.push(value);
    }

    const toolCall = out.find(c => c.type === 'tool-call');
    expect(toolCall.__clawdstrike_blocked).toBe(true);
  });
});

