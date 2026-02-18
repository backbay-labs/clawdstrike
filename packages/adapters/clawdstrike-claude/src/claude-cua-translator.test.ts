import { describe, expect, it } from 'vitest';

import { claudeCuaTranslator } from './claude-cua-translator.js';

describe('claudeCuaTranslator', () => {
  it('returns null for non-CUA tools', () => {
    const translated = claudeCuaTranslator({
      framework: 'claude',
      toolName: 'bash',
      parameters: { cmd: 'echo hello' },
      rawInput: { cmd: 'echo hello' },
      sessionId: 'sess-1',
      contextMetadata: {},
    });

    expect(translated).toBeNull();
  });

  it('maps mouse_click to input.inject with click cuaAction', () => {
    const translated = claudeCuaTranslator({
      framework: 'claude',
      toolName: 'computer',
      parameters: { action: 'mouse_click', coordinate_x: 10, coordinate_y: 20 },
      rawInput: { action: 'mouse_click', coordinate_x: 10, coordinate_y: 20 },
      sessionId: 'sess-2',
      contextMetadata: {},
    });

    expect(translated).not.toBeNull();
    expect(translated?.eventType).toBe('input.inject');
    expect(translated?.data.type).toBe('cua');
    if (translated?.data.type === 'cua') {
      expect(translated.data.cuaAction).toBe('click');
      expect(translated.data.input_type).toBe('mouse');
    }
  });

  it('maps navigate to remote.session.connect with outbound direction', () => {
    const translated = claudeCuaTranslator({
      framework: 'claude',
      toolName: 'computer',
      parameters: { action: 'navigate', url: 'https://example.com' },
      rawInput: { action: 'navigate', url: 'https://example.com' },
      sessionId: 'sess-3',
      contextMetadata: {},
    });

    expect(translated).not.toBeNull();
    expect(translated?.eventType).toBe('remote.session.connect');
    expect(translated?.data.type).toBe('cua');
    if (translated?.data.type === 'cua') {
      expect(translated.data.cuaAction).toBe('navigate');
      expect(translated.data.direction).toBe('outbound');
      expect(translated.data.host).toBe('example.com');
      expect(translated.data.port).toBe(443);
      expect(translated.data.url).toBe('https://example.com');
    }
  });

  it('preserves explicit destination metadata for connect actions', () => {
    const translated = claudeCuaTranslator({
      framework: 'claude',
      toolName: 'computer',
      parameters: {
        action: 'connect',
        host: 'rdp.internal.example',
        port: '3389',
      },
      rawInput: {
        action: 'connect',
        host: 'rdp.internal.example',
        port: '3389',
      },
      sessionId: 'sess-3b',
      contextMetadata: {},
    });

    expect(translated).not.toBeNull();
    expect(translated?.eventType).toBe('remote.session.connect');
    expect(translated?.data.type).toBe('cua');
    if (translated?.data.type === 'cua') {
      expect(translated.data.cuaAction).toBe('navigate');
      expect(translated.data.direction).toBe('outbound');
      expect(translated.data.host).toBe('rdp.internal.example');
      expect(translated.data.port).toBe(3389);
    }
  });

  it('throws on unknown Claude CUA action', () => {
    expect(() =>
      claudeCuaTranslator({
        framework: 'claude',
        toolName: 'computer',
        parameters: { action: 'mystery_action' },
        rawInput: { action: 'mystery_action' },
        sessionId: 'sess-4',
        contextMetadata: {},
      }),
    ).toThrow(/does not support action/i);
  });
});
