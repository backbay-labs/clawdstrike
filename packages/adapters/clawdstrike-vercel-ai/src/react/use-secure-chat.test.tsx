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
  it('updates securityStatus and blocks denied tool calls', async () => {
    useChatMock.mockImplementation((options: any) => ({
      messages: [],
      input: '',
      handleInputChange: () => undefined,
      handleSubmit: () => undefined,
      isLoading: false,
      __triggerToolCall: (toolCall: any) => options.onToolCall?.({ toolCall }),
    }));

    const engine: PolicyEngineLike = {
      evaluate: event => ({
        status: event.eventType === 'command_exec' ? 'deny' : 'allow',
        reason: 'blocked',
      }),
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
  });
});
