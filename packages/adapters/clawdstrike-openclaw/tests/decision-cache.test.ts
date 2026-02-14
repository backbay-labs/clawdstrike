/**
 * @clawdstrike/openclaw - Decision Cache Tests
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import toolGuardHandler, {
  initialize as initToolGuard,
  DecisionCache,
} from '../src/hooks/tool-guard/handler.js';
import type { ToolResultPersistEvent, ClawdstrikeConfig } from '../src/types.js';

function makeToolResultEvent(
  toolName: string,
  params: Record<string, unknown>,
  result: unknown = 'ok',
  sessionId = 'test-session',
): ToolResultPersistEvent {
  return {
    type: 'tool_result_persist',
    timestamp: new Date().toISOString(),
    context: {
      sessionId,
      toolResult: { toolName, params, result },
    },
    messages: [],
  };
}

describe('DecisionCache', () => {
  it('should store and retrieve decisions', () => {
    const cache = new DecisionCache(10, 60_000);
    const decision = { status: 'allow' as const };
    cache.set('key1', decision);
    expect(cache.get('key1')).toEqual(decision);
  });

  it('should return undefined for missing keys', () => {
    const cache = new DecisionCache(10, 60_000);
    expect(cache.get('nonexistent')).toBeUndefined();
  });

  it('should expire entries after TTL', () => {
    vi.useFakeTimers();
    const cache = new DecisionCache(10, 50); // 50ms TTL
    cache.set('key1', { status: 'allow' });

    // Should be present immediately
    expect(cache.get('key1')).toBeDefined();

    // Advance past TTL
    vi.advanceTimersByTime(100);
    expect(cache.get('key1')).toBeUndefined();
    vi.useRealTimers();
  });

  it('should evict oldest entries when at capacity', () => {
    const cache = new DecisionCache(3, 60_000);
    cache.set('key1', { status: 'allow' });
    cache.set('key2', { status: 'allow' });
    cache.set('key3', { status: 'allow' });

    // Adding a 4th should evict key1
    cache.set('key4', { status: 'allow' });
    expect(cache.get('key1')).toBeUndefined();
    expect(cache.get('key4')).toBeDefined();
    expect(cache.size).toBe(3);
  });

  it('should generate correct cache keys', () => {
    const key = DecisionCache.key('file_read', '/tmp/test.txt', '1.0.0');
    expect(key).toBe('file_read:/tmp/test.txt:1.0.0');
  });

  it('should clear all entries', () => {
    const cache = new DecisionCache(10, 60_000);
    cache.set('k1', { status: 'allow' });
    cache.set('k2', { status: 'allow' });
    cache.clear();
    expect(cache.size).toBe(0);
    expect(cache.get('k1')).toBeUndefined();
  });
});

describe('Decision caching in handler', () => {
  const config: ClawdstrikeConfig = {
    policy: 'clawdstrike:ai-agent-minimal',
    mode: 'deterministic',
    logLevel: 'error',
  };

  beforeEach(() => {
    initToolGuard(config);
  });

  it('should cache allow decisions for read_file', async () => {
    const ev1 = makeToolResultEvent('read', { path: '/project/src/index.ts' }, 'contents');
    await toolGuardHandler(ev1);
    expect(ev1.context.toolResult.error).toBeUndefined();

    // Cache should have an entry now
    const { decisionCache: cache } = await import('../src/hooks/tool-guard/handler.js');
    expect(cache.size).toBeGreaterThan(0);

    // Second identical call should hit cache
    const ev2 = makeToolResultEvent('read', { path: '/project/src/index.ts' }, 'contents');
    await toolGuardHandler(ev2);
    expect(ev2.context.toolResult.error).toBeUndefined();
  });

  it('should not cache command_exec (destructive)', async () => {
    const ev = makeToolResultEvent('exec', { command: 'ls -la' }, 'output');
    await toolGuardHandler(ev);

    // Exec maps to command_exec which is uncacheable
    const { decisionCache: cache } = await import('../src/hooks/tool-guard/handler.js');
    // Cache should not have grown for command_exec events
    const sizeBefore = cache.size;
    const ev2 = makeToolResultEvent('exec', { command: 'echo hello' }, 'hello');
    await toolGuardHandler(ev2);
    // command_exec should not add to cache
    expect(cache.size).toBe(sizeBefore);
  });

  it('should not cache in advisory mode', async () => {
    const advisoryConfig: ClawdstrikeConfig = {
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'advisory',
      logLevel: 'error',
    };
    initToolGuard(advisoryConfig);

    const { decisionCache: cache } = await import('../src/hooks/tool-guard/handler.js');
    expect(cache.size).toBe(0);

    const ev = makeToolResultEvent('read', { path: '/project/src/index.ts' }, 'contents');
    await toolGuardHandler(ev);

    // Advisory mode should not cache
    expect(cache.size).toBe(0);
  });

  it('should not cache in audit mode', async () => {
    const auditConfig: ClawdstrikeConfig = {
      policy: 'clawdstrike:ai-agent-minimal',
      mode: 'audit',
      logLevel: 'error',
    };
    initToolGuard(auditConfig);

    const { decisionCache: cache } = await import('../src/hooks/tool-guard/handler.js');
    const ev = makeToolResultEvent('read', { path: '/project/src/index.ts' }, 'contents');
    await toolGuardHandler(ev);
    expect(cache.size).toBe(0);
  });

  it('should not cache deny decisions', async () => {
    const { decisionCache: cache } = await import('../src/hooks/tool-guard/handler.js');
    const sizeBefore = cache.size;

    const ev = makeToolResultEvent('read', { path: `${require('os').homedir()}/.ssh/id_rsa` }, 'PRIVATE KEY');
    await toolGuardHandler(ev);

    // Deny should not be cached
    expect(cache.size).toBe(sizeBefore);
  });

  it('should key tool_call cache entries by tool parameters and output', async () => {
    const { decisionCache: cache } = await import('../src/hooks/tool-guard/handler.js');

    const ev1 = makeToolResultEvent('custom_tool', { a: 1 }, 'ok');
    await toolGuardHandler(ev1);
    const size1 = cache.size;
    expect(size1).toBeGreaterThan(0);

    // Identical invocation should hit cache (no new entry).
    const ev2 = makeToolResultEvent('custom_tool', { a: 1 }, 'ok');
    await toolGuardHandler(ev2);
    expect(cache.size).toBe(size1);

    // Different parameters should produce a different cache entry.
    const ev3 = makeToolResultEvent('custom_tool', { a: 2 }, 'ok');
    await toolGuardHandler(ev3);
    expect(cache.size).toBe(size1 + 1);

    // Same parameters but different output should also bypass cache.
    const size2 = cache.size;
    const ev4 = makeToolResultEvent('custom_tool', { a: 2 }, 'different');
    await toolGuardHandler(ev4);
    expect(cache.size).toBe(size2 + 1);
  });
});
