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

  it('drops invalid numeric port suffixes when parsing network targets', () => {
    const factory = new PolicyEventFactory();

    const event = factory.create('fetch', { url: 'api.example.com:0' });
    expect(event.eventType).toBe('network_egress');
    expect(event.data.type).toBe('network');

    if (event.data.type === 'network') {
      expect(event.data.host).toBe('api.example.com');
      expect(event.data.port).toBe(443);
    }
  });

  it('rejects invalid explicit port overrides and keeps parsed/default port', () => {
    const factory = new PolicyEventFactory();

    const invalidOverrides = [0, -1, 65536, '0', '70000', '443abc', 'abc'];
    for (const override of invalidOverrides) {
      const event = factory.create('fetch', { url: 'api.example.com', port: override });
      expect(event.eventType).toBe('network_egress');
      expect(event.data.type).toBe('network');

      if (event.data.type === 'network') {
        expect(event.data.host).toBe('api.example.com');
        expect(event.data.port).toBe(443);
      }
    }

    const valid = factory.create('fetch', { url: 'api.example.com', port: '8080' });
    expect(valid.data.type).toBe('network');
    if (valid.data.type === 'network') {
      expect(valid.data.port).toBe(8080);
    }
  });

  it('fails closed for hostless or scheme-only network targets', () => {
    const factory = new PolicyEventFactory();

    const fileEvent = factory.create('fetch', { url: 'file:///tmp/a' });
    expect(fileEvent.eventType).toBe('network_egress');
    expect(fileEvent.data.type).toBe('network');

    if (fileEvent.data.type === 'network') {
      expect(fileEvent.data.host).toBe('');
    }

    const mailtoEvent = factory.create('fetch', { url: 'mailto:user@example.com' });
    expect(mailtoEvent.eventType).toBe('network_egress');
    expect(mailtoEvent.data.type).toBe('network');

    if (mailtoEvent.data.type === 'network') {
      expect(mailtoEvent.data.host).toBe('');
    }

    const urnEvent = factory.create('fetch', { url: 'urn:isbn:0451450523' });
    expect(urnEvent.eventType).toBe('network_egress');
    expect(urnEvent.data.type).toBe('network');

    if (urnEvent.data.type === 'network') {
      expect(urnEvent.data.host).toBe('');
    }
  });
});
