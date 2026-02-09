import { describe, it, expect } from 'vitest';

import type { PolicyEngineLike } from '@clawdstrike/adapter-core';

import { addSecurityRouting, createSecurityCheckpoint, sanitizeState, wrapToolNode } from './langgraph.js';

describe('createSecurityCheckpoint', () => {
  it('returns block when any pending tool call is denied', async () => {
    const engine: PolicyEngineLike = {
      evaluate: event => ({
        status: event.eventType === 'command_exec' ? 'deny' : 'allow',
        reason: event.eventType === 'command_exec' ? 'blocked' : undefined,
      }),
    };

    const checkpoint = createSecurityCheckpoint({ engine, config: { blockOnViolation: true } });

    const decision = await checkpoint.check({
      toolCalls: [{ name: 'bash', args: { cmd: 'rm -rf /' } }],
    });

    expect(decision.status).toBe('deny');
    await expect(checkpoint.route({ toolCalls: [{ name: 'bash', args: {} }] })).resolves.toBe('block');
  });
});

describe('sanitizeState', () => {
  it('recursively redacts strings when engine provides redactSecrets', () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ status: 'allow' }),
      redactSecrets: value => value.replaceAll('SECRET', '[REDACTED]'),
    };

    const input = { ok: true, secret: 'SECRET', nested: { arr: ['SECRET'] } };
    expect(sanitizeState(input, engine)).toEqual({
      ok: true,
      secret: '[REDACTED]',
      nested: { arr: ['[REDACTED]'] },
    });
  });
});

describe('addSecurityRouting', () => {
  it('adds conditional edges using checkpoint.route', async () => {
    const checkpoint = {
      name: 'clawdstrike_checkpoint',
      async check() {
        return { status: 'allow' as const };
      },
      async route() {
        return 'allow' as const;
      },
    };

    const addConditionalEdges = (from: string, condition: any, mapping: Record<string, string>) => {
      expect(from).toBe('node');
      expect(mapping.allow).toBe('ok');
      expect(mapping.block).toBe('nope');
      expect(mapping.warn).toBe('warn');
      return condition({}) as any;
    };

    const graph = { addConditionalEdges };
    addSecurityRouting(graph as any, 'node', checkpoint, { allow: 'ok', block: 'nope', warn: 'warn' });
  });
});

describe('wrapToolNode', () => {
  it('sanitizes state output when engine provides redactSecrets', async () => {
    const engine: PolicyEngineLike = {
      evaluate: () => ({ status: 'allow' }),
      redactSecrets: value => value.replaceAll('SECRET', '[REDACTED]'),
    };

    const checkpoint = createSecurityCheckpoint({ engine });

    const nodes = new Map<string, any>();
    nodes.set('tool', async (state: any) => ({ ...state, output: 'SECRET' }));
    const graph = { nodes, addNode: (name: string, node: any) => nodes.set(name, node) };

    wrapToolNode(graph as any, 'tool', checkpoint, { engine });

    const result = await nodes.get('tool')({ toolCalls: [] });
    expect(result.output).toBe('[REDACTED]');
  });
});
