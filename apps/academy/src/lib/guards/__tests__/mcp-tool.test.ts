import { describe, it, expect } from 'vitest';
import { evaluateMcpTool } from '../mcp-tool';
import type { GuardAction } from '../types';

const defaultConfig = {};

describe('evaluateMcpTool', () => {
  it('denies shell_exec in block list', () => {
    const action: GuardAction = { type: 'mcp_tool', tool: 'shell_exec' };
    const result = evaluateMcpTool(defaultConfig, action);
    expect(result.allowed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.guard).toBe('mcp_tool');
  });

  it('denies run_command in block list', () => {
    const action: GuardAction = { type: 'mcp_tool', tool: 'run_command' };
    const result = evaluateMcpTool(defaultConfig, action);
    expect(result.allowed).toBe(false);
  });

  it('denies raw_file_write in block list', () => {
    const action: GuardAction = { type: 'mcp_tool', tool: 'raw_file_write' };
    const result = evaluateMcpTool(defaultConfig, action);
    expect(result.allowed).toBe(false);
  });

  it('allows file_read not in block list with default allow', () => {
    const action: GuardAction = { type: 'mcp_tool', tool: 'file_read', args: { path: '/tmp/x' } };
    const result = evaluateMcpTool(defaultConfig, action);
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe('info');
  });

  it('denies args exceeding max_args_size', () => {
    const largeArgs: Record<string, unknown> = { data: 'x'.repeat(1_200_000) };
    const action: GuardAction = { type: 'mcp_tool', tool: 'file_read', args: largeArgs };
    const result = evaluateMcpTool(defaultConfig, action);
    expect(result.allowed).toBe(false);
    expect(result.severity).toBe('error');
  });

  it('allows non-mcp_tool actions (passthrough)', () => {
    const action: GuardAction = { type: 'file_access', path: '/tmp/test' };
    const result = evaluateMcpTool(defaultConfig, action);
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe('info');
  });

  it('uses custom block list from config', () => {
    const config = { block: ['my_tool'], default_action: 'allow' };
    const action: GuardAction = { type: 'mcp_tool', tool: 'my_tool' };
    const result = evaluateMcpTool(config, action);
    expect(result.allowed).toBe(false);
  });

  it('uses custom allow list from config', () => {
    const config = { allow: ['safe_tool'], block: [], default_action: 'block' };
    const action: GuardAction = { type: 'mcp_tool', tool: 'safe_tool' };
    const result = evaluateMcpTool(config, action);
    expect(result.allowed).toBe(true);
  });
});
