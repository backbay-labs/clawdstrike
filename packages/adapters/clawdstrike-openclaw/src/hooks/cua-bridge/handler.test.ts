import { describe, it, expect, beforeEach } from 'vitest';
import { mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import handler, {
  isCuaToolCall,
  classifyCuaAction,
  extractActionToken,
  buildCuaEvent,
  initialize,
  CUA_ERROR_CODES,
} from './handler.js';
import { PolicyEventFactory } from '@clawdstrike/adapter-core';
import type { ToolCallEvent } from '../../types.js';

// ── Helpers ─────────────────────────────────────────────────────────

function makeToolCallEvent(
  toolName: string,
  params: Record<string, unknown> = {},
  sessionId = 'test-session-001',
): ToolCallEvent {
  return {
    type: 'tool_call',
    timestamp: new Date().toISOString(),
    context: {
      sessionId,
      toolCall: { toolName, params },
    },
    preventDefault: false,
    messages: [],
  };
}

// ── Tests ───────────────────────────────────────────────────────────

describe('CUA Bridge Handler', () => {
  const testDir = join(tmpdir(), `clawdstrike-openclaw-cua-bridge-${Date.now()}`);

  beforeEach(() => {
    mkdirSync(testDir, { recursive: true });
    const policyPath = join(testDir, 'cua-bridge-policy.yaml');
    writeFileSync(policyPath, `
version: "1.2.0"
guards:
  egress_allowlist:
    enabled: true
    default_action: allow
    allow:
      - "*"
  computer_use:
    enabled: true
    mode: guardrail
    allowed_actions:
      - "remote.session.connect"
      - "remote.session.disconnect"
      - "remote.session.reconnect"
      - "input.inject"
      - "remote.clipboard"
      - "remote.file_transfer"
      - "remote.audio"
      - "remote.drive_mapping"
      - "remote.printing"
      - "remote.session_share"
  remote_desktop_side_channel:
    enabled: true
    clipboard_enabled: true
    file_transfer_enabled: true
    audio_enabled: true
    drive_mapping_enabled: true
    printing_enabled: true
    session_share_enabled: true
  input_injection_capability:
    enabled: true
`);
    initialize({ policy: policyPath });
  });

  describe('isCuaToolCall', () => {
    it('detects cua_ prefix', () => {
      expect(isCuaToolCall('cua_click', {})).toBe(true);
    });

    it('detects cua. prefix', () => {
      expect(isCuaToolCall('cua.type', {})).toBe(true);
    });

    it('detects computer_use_ prefix', () => {
      expect(isCuaToolCall('computer_use_connect', {})).toBe(true);
    });

    it('detects plain computer_use tool shape', () => {
      expect(isCuaToolCall('computer_use', { action: 'connect' })).toBe(true);
    });

    it('detects remote_desktop_ prefix', () => {
      expect(isCuaToolCall('remote_desktop_click', {})).toBe(true);
    });

    it('detects rdp_ prefix', () => {
      expect(isCuaToolCall('rdp_connect', {})).toBe(true);
    });

    it('detects explicit __cua metadata', () => {
      expect(isCuaToolCall('some_tool', { __cua: true })).toBe(true);
    });

    it('detects explicit cua_action metadata', () => {
      expect(isCuaToolCall('some_tool', { cua_action: 'click' })).toBe(true);
    });

    it('rejects non-CUA tool', () => {
      expect(isCuaToolCall('file_read', {})).toBe(false);
    });

    it('rejects tool with __cua=false', () => {
      expect(isCuaToolCall('some_tool', { __cua: false })).toBe(false);
    });
  });

  describe('extractActionToken', () => {
    it('extracts from cua_ prefix', () => {
      expect(extractActionToken('cua_click', {})).toBe('click');
    });

    it('extracts from computer_use_ prefix', () => {
      expect(extractActionToken('computer_use_connect', {})).toBe('connect');
    });

    it('extracts from plain computer_use action param', () => {
      expect(extractActionToken('computer_use', { action: 'click' })).toBe('click');
    });

    it('prefers explicit cua_action param', () => {
      expect(extractActionToken('cua_click', { cua_action: 'type' })).toBe('type');
    });

    it('returns null for non-CUA tool', () => {
      expect(extractActionToken('file_read', {})).toBe(null);
    });
  });

  describe('classifyCuaAction', () => {
    it('classifies connect tokens', () => {
      expect(classifyCuaAction('connect')).toBe('connect');
      expect(classifyCuaAction('session_start')).toBe('connect');
      expect(classifyCuaAction('open')).toBe('connect');
      expect(classifyCuaAction('launch')).toBe('connect');
    });

    it('classifies disconnect tokens', () => {
      expect(classifyCuaAction('disconnect')).toBe('disconnect');
      expect(classifyCuaAction('session_end')).toBe('disconnect');
      expect(classifyCuaAction('close')).toBe('disconnect');
    });

    it('classifies reconnect tokens', () => {
      expect(classifyCuaAction('reconnect')).toBe('reconnect');
      expect(classifyCuaAction('session_resume')).toBe('reconnect');
    });

    it('classifies input injection tokens', () => {
      expect(classifyCuaAction('click')).toBe('input_inject');
      expect(classifyCuaAction('type')).toBe('input_inject');
      expect(classifyCuaAction('key')).toBe('input_inject');
      expect(classifyCuaAction('mouse')).toBe('input_inject');
      expect(classifyCuaAction('scroll')).toBe('input_inject');
    });

    it('classifies clipboard tokens', () => {
      expect(classifyCuaAction('clipboard_read')).toBe('clipboard_read');
      expect(classifyCuaAction('clipboard_write')).toBe('clipboard_write');
      expect(classifyCuaAction('paste_from')).toBe('clipboard_read');
      expect(classifyCuaAction('copy_to')).toBe('clipboard_write');
    });

    it('classifies file transfer tokens', () => {
      expect(classifyCuaAction('file_upload')).toBe('file_upload');
      expect(classifyCuaAction('upload')).toBe('file_upload');
      expect(classifyCuaAction('file_download')).toBe('file_download');
      expect(classifyCuaAction('download')).toBe('file_download');
    });

    it('classifies side channel tokens', () => {
      expect(classifyCuaAction('session_share')).toBe('session_share');
      expect(classifyCuaAction('audio')).toBe('audio');
      expect(classifyCuaAction('drive_mapping')).toBe('drive_mapping');
      expect(classifyCuaAction('printing')).toBe('printing');
    });

    it('returns null for unknown action', () => {
      expect(classifyCuaAction('screen_record')).toBe(null);
      expect(classifyCuaAction('unknown_action')).toBe(null);
    });
  });

  describe('buildCuaEvent', () => {
    it('builds connect event with correct eventType', () => {
      const event = buildCuaEvent('sess-1', 'connect', {});
      expect(event.eventType).toBe('remote.session.connect');
      expect(event.sessionId).toBe('sess-1');
      expect(event.data.type).toBe('cua');
      expect((event.data as any).cuaAction).toBe('session.connect');
    });

    it('preserves connect destination metadata for egress checks', () => {
      const event = buildCuaEvent('sess-1', 'connect', {
        url: 'https://desk.example.com/session',
      });
      expect(event.eventType).toBe('remote.session.connect');
      expect(event.data.type).toBe('cua');
      if (event.data.type === 'cua') {
        expect(event.data.host).toBe('desk.example.com');
        expect(event.data.port).toBe(443);
        expect(event.data.url).toBe('https://desk.example.com/session');
      }
    });

    it('builds disconnect event', () => {
      const event = buildCuaEvent('sess-1', 'disconnect', {});
      expect(event.eventType).toBe('remote.session.disconnect');
      expect((event.data as any).cuaAction).toBe('session.disconnect');
    });

    it('builds reconnect event with continuity hash', () => {
      const event = buildCuaEvent('sess-1', 'reconnect', {
        continuityPrevSessionHash: 'abc123',
      });
      expect(event.eventType).toBe('remote.session.reconnect');
      expect((event.data as any).continuityPrevSessionHash).toBe('abc123');
    });

    it('builds input inject event', () => {
      const event = buildCuaEvent('sess-1', 'input_inject', {});
      expect(event.eventType).toBe('input.inject');
      expect((event.data as any).cuaAction).toBe('input.inject');
    });

    it('builds clipboard read event', () => {
      const event = buildCuaEvent('sess-1', 'clipboard_read', {});
      expect(event.eventType).toBe('remote.clipboard');
      expect((event.data as any).direction).toBe('read');
    });

    it('builds clipboard write event', () => {
      const event = buildCuaEvent('sess-1', 'clipboard_write', {});
      expect(event.eventType).toBe('remote.clipboard');
      expect((event.data as any).direction).toBe('write');
    });

    it('builds file upload event', () => {
      const event = buildCuaEvent('sess-1', 'file_upload', {});
      expect(event.eventType).toBe('remote.file_transfer');
      expect((event.data as any).direction).toBe('upload');
    });

    it('builds file download event', () => {
      const event = buildCuaEvent('sess-1', 'file_download', {});
      expect(event.eventType).toBe('remote.file_transfer');
      expect((event.data as any).direction).toBe('download');
    });

    it('builds session_share event', () => {
      const event = buildCuaEvent('sess-1', 'session_share', {});
      expect(event.eventType).toBe('remote.session_share');
      expect((event.data as any).cuaAction).toBe('session_share');
    });

    it('builds remote.audio event', () => {
      const event = buildCuaEvent('sess-1', 'audio', {});
      expect(event.eventType).toBe('remote.audio');
      expect((event.data as any).cuaAction).toBe('audio');
    });

    it('builds remote.drive_mapping event', () => {
      const event = buildCuaEvent('sess-1', 'drive_mapping', {});
      expect(event.eventType).toBe('remote.drive_mapping');
      expect((event.data as any).cuaAction).toBe('drive_mapping');
    });

    it('builds remote.printing event', () => {
      const event = buildCuaEvent('sess-1', 'printing', {});
      expect(event.eventType).toBe('remote.printing');
      expect((event.data as any).cuaAction).toBe('printing');
    });

    it('includes adapter-core source metadata', () => {
      const event = buildCuaEvent('sess-1', 'connect', {});
      expect(event.metadata?.source).toBe('adapter-core');
    });
  });

  describe('handler integration', () => {
    it('passes through non-CUA tool calls', async () => {
      const event = makeToolCallEvent('file_read', { path: '/tmp/test' });
      await handler(event);
      expect(event.preventDefault).toBe(false);
      expect(event.messages).toHaveLength(0);
    });

    it('allows recognized CUA connect action', async () => {
      const event = makeToolCallEvent('cua_connect', { url: 'https://example.com' });
      await handler(event);
      expect(event.preventDefault).toBe(false);
      expect(event.messages.some((m) => m.includes('CUA connect allowed'))).toBe(true);
    });

    it('allows recognized CUA click action', async () => {
      const event = makeToolCallEvent('cua_click', { x: 100, y: 200 });
      await handler(event);
      expect(event.preventDefault).toBe(false);
      expect(event.messages.some((m) => m.includes('CUA input_inject allowed'))).toBe(true);
    });

    it('denies unknown CUA action type (fail closed)', async () => {
      const event = makeToolCallEvent('cua_screen_record', {});
      await handler(event);
      expect(event.preventDefault).toBe(true);
      expect(event.messages.some((m) => m.includes(CUA_ERROR_CODES.UNKNOWN_ACTION))).toBe(true);
    });

    it('denies CUA action with missing session ID', async () => {
      const event = makeToolCallEvent('cua_click', {}, '');
      await handler(event);
      expect(event.preventDefault).toBe(true);
      expect(event.messages.some((m) => m.includes(CUA_ERROR_CODES.SESSION_MISSING))).toBe(true);
    });

    it('denies CUA action with __cua flag but no extractable action', async () => {
      const event = makeToolCallEvent('generic_tool', { __cua: true });
      await handler(event);
      expect(event.preventDefault).toBe(true);
      expect(event.messages.some((m) => m.includes(CUA_ERROR_CODES.MISSING_METADATA))).toBe(true);
    });

    it('uses explicit cua_action param for classification', async () => {
      const event = makeToolCallEvent('generic_tool', { cua_action: 'click' });
      await handler(event);
      expect(event.preventDefault).toBe(false);
      expect(event.messages.some((m) => m.includes('CUA input_inject allowed'))).toBe(true);
    });

    it('handles plain computer_use + action shape', async () => {
      const event = makeToolCallEvent('computer_use', { action: 'connect', url: 'https://example.com' });
      await handler(event);
      expect(event.preventDefault).toBe(false);
      expect(event.messages.some((m) => m.includes('CUA connect allowed'))).toBe(true);
    });

    it('handles clipboard via computer_use_ prefix', async () => {
      const event = makeToolCallEvent('computer_use_clipboard_read', {});
      await handler(event);
      expect(event.preventDefault).toBe(false);
      expect(event.messages.some((m) => m.includes('CUA clipboard_read allowed'))).toBe(true);
    });

    it('handles file transfer via rdp_ prefix', async () => {
      const event = makeToolCallEvent('rdp_upload', {});
      await handler(event);
      expect(event.preventDefault).toBe(false);
      expect(event.messages.some((m) => m.includes('CUA file_upload allowed'))).toBe(true);
    });

    it('handles disconnect via cua. prefix', async () => {
      const event = makeToolCallEvent('cua.disconnect', {});
      await handler(event);
      expect(event.preventDefault).toBe(false);
      expect(event.messages.some((m) => m.includes('CUA disconnect allowed'))).toBe(true);
    });

    it('does not modify non-tool_call events', async () => {
      const event = {
        type: 'agent:bootstrap' as const,
        timestamp: new Date().toISOString(),
        context: {
          sessionId: 'test',
          agentId: 'a',
          bootstrapFiles: [],
          cfg: {},
        },
      };
      await handler(event as any);
      // No errors, no side effects
    });
  });

  describe('parity with adapter-core', () => {
    it('CUA connect via OpenClaw produces same event type as direct factory', () => {
      const openclawEvent = buildCuaEvent('sess-1', 'connect', {});
      const directFactory = new PolicyEventFactory();
      const directEvent = directFactory.createCuaConnectEvent('sess-1');
      expect(openclawEvent.eventType).toBe(directEvent.eventType);
      expect(openclawEvent.data.type).toBe(directEvent.data.type);
      expect((openclawEvent.data as any).cuaAction).toBe((directEvent.data as any).cuaAction);
    });

    it('CUA input inject via OpenClaw produces same event type as direct factory', () => {
      const openclawEvent = buildCuaEvent('sess-1', 'input_inject', {});
      const directFactory = new PolicyEventFactory();
      const directEvent = directFactory.createCuaInputInjectEvent('sess-1');
      expect(openclawEvent.eventType).toBe(directEvent.eventType);
      expect(openclawEvent.data.type).toBe(directEvent.data.type);
    });

    it('CUA clipboard via OpenClaw produces same event type as direct factory', () => {
      const openclawEvent = buildCuaEvent('sess-1', 'clipboard_write', {});
      const directFactory = new PolicyEventFactory();
      const directEvent = directFactory.createCuaClipboardEvent('sess-1', 'write');
      expect(openclawEvent.eventType).toBe(directEvent.eventType);
      expect((openclawEvent.data as any).direction).toBe((directEvent.data as any).direction);
    });
  });
});
