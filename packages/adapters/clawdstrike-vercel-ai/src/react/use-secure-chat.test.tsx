/* @vitest-environment jsdom */
import { describe, it, expect, vi } from 'vitest';
import { renderHook, act } from '@testing-library/react';

import type { UseChatOptions } from '@ai-sdk/react';
import type { PolicyEngineLike } from '@clawdstrike/adapter-core';

import { useSecureChat } from './use-secure-chat.js';

const useChatMock = vi.hoisted(() => vi.fn());

vi.mock('@ai-sdk/react', () => ({
  useChat: (options: UseChatOptions & { onToolCall?: any }) => useChatMock(options),
}));

describe('useSecureChat', () => {
  it('updates securityStatus and blocks denied tool calls (v2 `args` shape)', async () => {
    useChatMock.mockImplementation((options: any) => ({
      messages: [],
      input: '',
      handleInputChange: () => undefined,
      handleSubmit: () => undefined,
      isLoading: false,
      __triggerToolCall: (toolCall: any) => options.onToolCall?.({ toolCall }),
    }));

    const seenEvents: Array<{ eventType: string; data: unknown }> = [];
    const engine: PolicyEngineLike = {
      evaluate: event => {
        seenEvents.push({ eventType: event.eventType, data: event.data });
        return {
          status: event.eventType === 'command_exec' ? 'deny' : 'allow',
          reason: 'blocked',
        };
      },
    };

    const { result } = renderHook(() =>
      useSecureChat({
        // Minimal UseChatOptions shape for our mock.
        api: '/api/chat',
        engine,
      } as any),
    );

    await act(async () => {
      await expect(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (result.current as any).__triggerToolCall({ toolName: 'bash', args: { cmd: 'rm -rf /' } }),
      ).rejects.toThrow(/blocked/i);
    });

    expect(result.current.securityStatus.blocked).toBe(true);
    expect(result.current.securityStatus.violationCount).toBe(1);
    expect(result.current.blockedTools).toContain('bash');
    // The v2 `args` payload must reach the policy engine. The
    // `command_exec` event factory destructures `parameters.cmd`, so
    // the resulting command must be `rm` (the first token of `rm -rf /`).
    // If `args` were ignored, the engine would see an empty command.
    expect(seenEvents).toContainEqual({
      eventType: 'command_exec',
      data: expect.objectContaining({ command: 'rm' }),
    });
  });

  it('passes v3+ `input` payload to the policy engine and forwards toolCall to user callback', async () => {
    useChatMock.mockImplementation((options: any) => ({
      messages: [],
      input: '',
      handleInputChange: () => undefined,
      handleSubmit: () => undefined,
      isLoading: false,
      __triggerToolCall: (toolCall: any) => options.onToolCall?.({ toolCall }),
    }));

    const seenEvents: Array<{ eventType: string; data: unknown }> = [];
    const engine: PolicyEngineLike = {
      evaluate: event => {
        seenEvents.push({ eventType: event.eventType, data: event.data });
        return { status: 'allow' };
      },
    };

    const onToolCall = vi.fn();
    const { result } = renderHook(() =>
      useSecureChat({
        api: '/api/chat',
        engine,
        onToolCall,
      } as any),
    );

    await act(async () => {
      await (result.current as any).__triggerToolCall({
        toolName: 'read_file',
        input: { path: '/tmp/data' },
      });
    });

    // The v3+ `input` payload must reach the policy engine. The
    // `file_read` event factory pulls `parameters.path`.
    expect(seenEvents).toContainEqual({
      eventType: 'file_read',
      data: expect.objectContaining({ path: '/tmp/data' }),
    });
    // Forward must pass the original toolCall (with `input`) to the user callback.
    expect(onToolCall).toHaveBeenCalledWith({
      toolCall: { toolName: 'read_file', input: { path: '/tmp/data' } },
    });
    expect(result.current.securityStatus.blocked).toBe(false);
  });
});
