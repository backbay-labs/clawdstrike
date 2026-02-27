/**
 * @clawdstrike/openclaw - OpenClaw Translator Tests
 */

import { describe, it, expect } from 'vitest';
import { openclawTranslator, composeOpenClawConfig } from '../src/translator/openclaw-translator.js';
import type { ToolCallTranslationInput, PolicyEvent } from '@clawdstrike/adapter-core';

function makeInput(
  toolName: string,
  parameters: Record<string, unknown> = {},
  sessionId?: string,
): ToolCallTranslationInput {
  return {
    framework: 'openclaw',
    toolName,
    parameters,
    rawInput: { toolName, parameters },
    sessionId,
  };
}

describe('openclawTranslator', () => {
  // ── File Read ──────────────────────────────────────────────────────

  describe('file_read events', () => {
    it('should classify "read_file" as file_read', () => {
      const event = openclawTranslator(makeInput('read_file', { path: '/tmp/test.txt' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('file_read');
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'file',
        path: '/tmp/test.txt',
        operation: 'read',
      }));
    });

    it('should classify "cat" as file_read', () => {
      const event = openclawTranslator(makeInput('cat', { path: '/etc/hosts' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('file_read');
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'file',
        path: '/etc/hosts',
        operation: 'read',
      }));
    });

    it('should classify "list_files" as file_read', () => {
      const event = openclawTranslator(makeInput('list_files', { path: '/tmp' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('file_read');
    });

    it('should classify "readFile" (camelCase) as file_read', () => {
      const event = openclawTranslator(makeInput('readFile', { file_path: '/foo/bar.txt' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('file_read');
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'file',
        path: '/foo/bar.txt',
        operation: 'read',
      }));
    });

    it('should extract path from file_path param', () => {
      const event = openclawTranslator(makeInput('get_file', { file_path: '/opt/data.csv' }));
      expect(event).not.toBeNull();
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'file',
        path: '/opt/data.csv',
      }));
    });

    it('should extract path from filepath param', () => {
      const event = openclawTranslator(makeInput('read', { filepath: '/opt/data.csv' }));
      expect(event).not.toBeNull();
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'file',
        path: '/opt/data.csv',
      }));
    });
  });

  // ── File Write ─────────────────────────────────────────────────────

  describe('file_write events', () => {
    it('should classify "write_file" as file_write', () => {
      const event = openclawTranslator(makeInput('write_file', { path: '/tmp/out.txt', content: 'hello' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('file_write');
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'file',
        path: '/tmp/out.txt',
        operation: 'write',
        content: 'hello',
      }));
    });

    it('should classify "edit" as file_write', () => {
      const event = openclawTranslator(makeInput('edit', { path: '/tmp/a.txt', content: 'data' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('file_write');
    });

    it('should classify "create_file" as file_write', () => {
      const event = openclawTranslator(makeInput('create_file', { path: '/tmp/new.txt', content: 'new' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('file_write');
    });

    it('should classify "save_document" as file_write', () => {
      const event = openclawTranslator(makeInput('save_document', { file: '/tmp/doc.md', content: '# Title' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('file_write');
    });
  });

  // ── Command Exec ───────────────────────────────────────────────────

  describe('command_exec events', () => {
    it('should classify "exec" as command_exec', () => {
      const event = openclawTranslator(makeInput('exec', { command: 'ls -la' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('command_exec');
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'command',
        command: 'ls',
        args: ['-la'],
      }));
    });

    it('should classify "bash" as command_exec', () => {
      const event = openclawTranslator(makeInput('bash', { command: 'echo hello world' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('command_exec');
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'command',
        command: 'echo',
        args: ['hello', 'world'],
      }));
    });

    it('should classify "run_command" as command_exec', () => {
      const event = openclawTranslator(makeInput('run_command', { cmd: 'npm test' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('command_exec');
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'command',
        command: 'npm',
        args: ['test'],
      }));
    });

    it('should extract command from "cmd" param', () => {
      const event = openclawTranslator(makeInput('execute_bash', { cmd: 'git status' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('command_exec');
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'command',
        command: 'git',
        args: ['status'],
      }));
    });

    it('should include workingDir from cwd param', () => {
      const event = openclawTranslator(makeInput('bash', { command: 'ls', cwd: '/home/user' }));
      expect(event).not.toBeNull();
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'command',
        command: 'ls',
        workingDir: '/home/user',
      }));
    });
  });

  // ── Network Egress ─────────────────────────────────────────────────

  describe('network_egress events', () => {
    it('should classify "http_get" as network_egress', () => {
      const event = openclawTranslator(makeInput('http_get', { url: 'https://example.com/api' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('network_egress');
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'network',
        host: 'example.com',
        port: 443,
        url: 'https://example.com/api',
      }));
    });

    it('should classify "fetch" as network_egress', () => {
      const event = openclawTranslator(makeInput('fetch', { url: 'http://api.local:8080/data' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('network_egress');
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'network',
        host: 'api.local',
        port: 8080,
        url: 'http://api.local:8080/data',
      }));
    });

    it('should classify "web_search" as network_egress', () => {
      const event = openclawTranslator(makeInput('web_search', { url: 'https://google.com/search?q=test' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('network_egress');
    });

    it('should extract network info from endpoint param', () => {
      const event = openclawTranslator(makeInput('api_call', { endpoint: 'https://internal.svc:9090/v2' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('network_egress');
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'network',
        host: 'internal.svc',
        port: 9090,
      }));
    });

    it('should extract network info from href param', () => {
      const event = openclawTranslator(makeInput('curl', { href: 'https://cdn.example.com/file.js' }));
      expect(event).not.toBeNull();
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'network',
        host: 'cdn.example.com',
        port: 443,
      }));
    });

    it('should fall back to host/port when url is missing', () => {
      const event = openclawTranslator(makeInput('socket_connect', { host: 'db.local', port: 5432 }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('network_egress');
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'network',
        host: 'db.local',
        port: 5432,
      }));
    });
  });

  // ── Patch Apply ────────────────────────────────────────────────────

  describe('patch_apply events', () => {
    it('should classify "apply_patch" as patch_apply (via "patch" token)', () => {
      const event = openclawTranslator(makeInput('apply_patch', {
        filePath: 'src/main.rs',
        patch: '--- a/src/main.rs\n+++ b/src/main.rs',
      }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('patch_apply');
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'patch',
        filePath: 'src/main.rs',
        patchContent: '--- a/src/main.rs\n+++ b/src/main.rs',
      }));
    });

    it('should classify "diff_viewer" as patch_apply (via "diff" token)', () => {
      const event = openclawTranslator(makeInput('diff_viewer', { path: 'a.txt', diff: 'diff content' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('patch_apply');
    });
  });

  // ── Unknown/Unclassified Tools ─────────────────────────────────────

  describe('unknown tools', () => {
    it('should return null for truly unknown tools with no recognizable params', () => {
      const event = openclawTranslator(makeInput('mystery_tool', { data: 'something' }));
      expect(event).toBeNull();
    });

    it('should return null for empty tool name with no recognizable params', () => {
      const event = openclawTranslator(makeInput('', { data: 'test' }));
      expect(event).toBeNull();
    });
  });

  // ── Parameter-based Fallback Heuristics ────────────────────────────

  describe('parameter-based fallback for unknown tools', () => {
    it('should infer command_exec from { command } param on unknown tool', () => {
      const event = openclawTranslator(makeInput('mystery_action', { command: 'ls -la' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('command_exec');
      expect(event!.data).toEqual(expect.objectContaining({
        type: 'command',
        command: 'ls',
        args: ['-la'],
      }));
    });

    it('should infer network_egress from { url } param on unknown tool', () => {
      const event = openclawTranslator(makeInput('mystery_action', { url: 'https://example.com' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('network_egress');
    });

    it('should infer file_read from { file_path } param with no write payload', () => {
      const event = openclawTranslator(makeInput('mystery_action', { file_path: '/etc/passwd' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('file_read');
    });

    it('should infer file_write from { file_path, content } params', () => {
      const event = openclawTranslator(makeInput('mystery_action', { file_path: '/tmp/out.txt', content: 'data' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('file_write');
    });

    it('should infer patch_apply from { patch } param on unknown tool', () => {
      const event = openclawTranslator(makeInput('mystery_action', { patch: '--- a/f\n+++ b/f' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).toBe('patch_apply');
    });

    it('should NOT classify { file_path, content } as patch_apply (C2 parity)', () => {
      const event = openclawTranslator(makeInput('mystery_action', { file_path: '/tmp/out.txt', content: 'data' }));
      expect(event).not.toBeNull();
      expect(event!.eventType).not.toBe('patch_apply');
      expect(event!.eventType).toBe('file_write');
    });
  });

  // ── CUA Delegation ─────────────────────────────────────────────────

  describe('CUA tool delegation', () => {
    it('should translate CUA connect tool call', () => {
      const event = openclawTranslator(makeInput(
        'cua_connect',
        { url: 'https://remote.host' },
        'cua-session-1',
      ));
      expect(event).not.toBeNull();
      expect(event!.data).toEqual(expect.objectContaining({ type: 'cua' }));
    });

    it('should translate CUA input inject tool call', () => {
      const event = openclawTranslator(makeInput(
        'cua_click',
        { input_type: 'mouse' },
        'cua-session-2',
      ));
      expect(event).not.toBeNull();
      expect(event!.data).toEqual(expect.objectContaining({ type: 'cua' }));
    });

    it('should return null for CUA tools without sessionId', () => {
      const event = openclawTranslator(makeInput('cua_connect', { url: 'https://remote.host' }));
      expect(event).toBeNull();
    });

    it('should return null for CUA tools with unknown action', () => {
      const event = openclawTranslator(makeInput(
        'cua_nonexistent_action',
        {},
        'cua-session-3',
      ));
      expect(event).toBeNull();
    });

    it('should translate computer_use tool with action param', () => {
      const event = openclawTranslator(makeInput(
        'computer',
        { action: 'click', input_type: 'mouse' },
        'cua-session-4',
      ));
      expect(event).not.toBeNull();
      expect(event!.data).toEqual(expect.objectContaining({ type: 'cua' }));
    });
  });

  // ── Metadata ───────────────────────────────────────────────────────

  describe('event metadata', () => {
    it('should include source and toolName in metadata', () => {
      const event = openclawTranslator(makeInput('read_file', { path: '/tmp/f.txt' }));
      expect(event).not.toBeNull();
      expect(event!.metadata).toEqual(expect.objectContaining({
        source: 'openclaw-translator',
        toolName: 'read_file',
      }));
    });

    it('should include sessionId when provided', () => {
      const event = openclawTranslator(makeInput('read_file', { path: '/tmp/f.txt' }, 'sess-123'));
      expect(event).not.toBeNull();
      expect(event!.sessionId).toBe('sess-123');
    });

    it('should generate unique event IDs', () => {
      const e1 = openclawTranslator(makeInput('read_file', { path: '/tmp/a.txt' }));
      const e2 = openclawTranslator(makeInput('read_file', { path: '/tmp/b.txt' }));
      expect(e1).not.toBeNull();
      expect(e2).not.toBeNull();
      expect(e1!.eventId).not.toBe(e2!.eventId);
      expect(e1!.eventId).toMatch(/^oclaw-/);
    });
  });
});

// ── composeOpenClawConfig ────────────────────────────────────────────

describe('composeOpenClawConfig', () => {
  it('should return config with openclaw translator as translateToolCall', () => {
    const result = composeOpenClawConfig({});
    expect(result.translateToolCall).toBeDefined();
    expect(typeof result.translateToolCall).toBe('function');
  });

  it('should use openclaw translator for known tools', () => {
    const result = composeOpenClawConfig({});
    const event = result.translateToolCall!(makeInput('read_file', { path: '/tmp/a.txt' }));
    expect(event).not.toBeNull();
    expect(event!.eventType).toBe('file_read');
  });

  it('should fall through to user translator when openclaw returns null', () => {
    const userTranslator = (input: ToolCallTranslationInput): PolicyEvent | null => {
      if (input.toolName === 'my_custom_tool') {
        return {
          eventId: 'user-evt-1',
          eventType: 'custom',
          timestamp: new Date().toISOString(),
          data: { type: 'custom', customType: 'user-defined' },
        };
      }
      return null;
    };

    const result = composeOpenClawConfig({ translateToolCall: userTranslator });
    const event = result.translateToolCall!(makeInput('my_custom_tool', { data: 'x' }));
    expect(event).not.toBeNull();
    expect(event!.eventId).toBe('user-evt-1');
    expect(event!.eventType).toBe('custom');
  });

  it('should return null when both translators return null', () => {
    const userTranslator = () => null;
    const result = composeOpenClawConfig({ translateToolCall: userTranslator });
    const event = result.translateToolCall!(makeInput('unknown_thing', { data: 'y' }));
    expect(event).toBeNull();
  });

  it('should return null for unknown tools when no user translator provided', () => {
    const result = composeOpenClawConfig({});
    const event = result.translateToolCall!(makeInput('unknown_thing', { data: 'y' }));
    expect(event).toBeNull();
  });

  it('should preserve other config properties', () => {
    const result = composeOpenClawConfig({
      blockOnViolation: true,
      sanitizeOutputs: false,
      policy: 'clawdstrike:strict',
    });
    expect(result.blockOnViolation).toBe(true);
    expect(result.sanitizeOutputs).toBe(false);
    expect(result.policy).toBe('clawdstrike:strict');
    expect(result.translateToolCall).toBeDefined();
  });

  it('should give openclaw translator priority over user translator', () => {
    const userTranslator = (input: ToolCallTranslationInput): PolicyEvent | null => {
      // User translator that would also handle read_file but differently
      return {
        eventId: 'user-override',
        eventType: 'custom',
        timestamp: new Date().toISOString(),
        data: { type: 'custom', customType: 'user-file-read' },
      };
    };

    const result = composeOpenClawConfig({ translateToolCall: userTranslator });
    const event = result.translateToolCall!(makeInput('read_file', { path: '/tmp/a.txt' }));
    // OpenClaw translator handles this, so user translator should NOT be called
    expect(event).not.toBeNull();
    expect(event!.eventType).toBe('file_read');
    expect(event!.eventId).not.toBe('user-override');
  });
});
