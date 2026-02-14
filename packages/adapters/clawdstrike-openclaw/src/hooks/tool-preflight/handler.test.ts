import { describe, it, expect, beforeEach } from 'vitest';

import handler, { initialize } from './handler.js';
import type { ToolCallEvent } from '../../types.js';

describe('tool-preflight handler', () => {
  beforeEach(() => {
    // Ensure tests don't accidentally exercise the interactive approval flow.
    delete process.env.CLAWDSTRIKE_APPROVAL_URL;
    delete process.env.CLAWDSTRIKE_AGENT_TOKEN;

    initialize({
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'deterministic',
      logLevel: 'error',
    });
  });

  it('preflights network tools even when the name looks read-only', async () => {
    const event: ToolCallEvent = {
      type: 'tool_call',
      timestamp: new Date().toISOString(),
      context: {
        sessionId: 'sess-test',
        toolCall: {
          toolName: 'web_search',
          params: { url: 'https://example.com' },
        },
      },
      preventDefault: false,
      messages: [],
    };

    await handler(event);

    expect(event.preventDefault).toBe(true);
    expect(event.messages.join('\n')).toMatch(/blocked web_search/i);
  });
});

