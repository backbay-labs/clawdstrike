import { describe, it, expect } from 'vitest';
import { PolicyEventFactory } from './policy-event-factory.js';

describe('PolicyEventFactory', () => {
  it('infers event type from tool name', () => {
    const factory = new PolicyEventFactory();
    expect(factory.inferEventType('cat', {})).toBe('file_read');
    expect(factory.inferEventType('writeFile', {})).toBe('file_write');
    expect(factory.inferEventType('bash', {})).toBe('command_exec');
  });

  it('infers event type from parameters', () => {
    const factory = new PolicyEventFactory();

    expect(factory.inferEventType('unknown', { path: '/tmp/a' })).toBe('file_read');
    expect(
      factory.inferEventType('unknown', { path: '/tmp/a', content: 'hi' }),
    ).toBe('file_write');
    expect(factory.inferEventType('unknown', { url: 'https://example.com' })).toBe(
      'network_egress',
    );
    expect(factory.inferEventType('unknown', { cmd: 'ls -la' })).toBe(
      'command_exec',
    );
    expect(factory.inferEventType('unknown', { foo: 'bar' })).toBe('tool_call');
  });
});

