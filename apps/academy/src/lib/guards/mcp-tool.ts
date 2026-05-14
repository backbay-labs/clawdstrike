/**
 * MCP Tool Guard Simulation
 *
 * Controls MCP tool invocations via block/allow lists and argument size limits.
 * Default configuration from rulesets/default.yaml.
 */
import type { GuardAction, GuardResult } from './types';

/** Default block list from rulesets/default.yaml */
const DEFAULT_BLOCK = ['shell_exec', 'run_command', 'raw_file_write', 'raw_file_delete'];
const DEFAULT_ALLOW: string[] = [];
const DEFAULT_ACTION = 'allow';
const DEFAULT_MAX_ARGS_SIZE = 1_048_576; // 1 MiB

export function evaluateMcpTool(
  config: Record<string, unknown>,
  action: GuardAction,
): GuardResult {
  // Only evaluate mcp_tool actions
  if (action.type !== 'mcp_tool') {
    return {
      allowed: true,
      guard: 'mcp_tool',
      severity: 'info',
      message: 'Action type not evaluated by mcp_tool guard',
    };
  }

  const tool = action.tool;
  const args = action.args;
  const block = (config.block as string[] | undefined) ?? DEFAULT_BLOCK;
  const allow = (config.allow as string[] | undefined) ?? DEFAULT_ALLOW;
  const defaultAction =
    (config.default_action as string | undefined) ?? DEFAULT_ACTION;
  const maxArgsSize =
    (config.max_args_size as number | undefined) ?? DEFAULT_MAX_ARGS_SIZE;

  // Check block list first (takes precedence)
  if (block.includes(tool)) {
    return {
      allowed: false,
      guard: 'mcp_tool',
      severity: 'critical',
      message: `MCP tool blocked: ${tool}`,
      details: { tool, reason: 'block_list' },
    };
  }

  // Check args size
  if (args) {
    const argsSize = JSON.stringify(args).length;
    if (argsSize > maxArgsSize) {
      return {
        allowed: false,
        guard: 'mcp_tool',
        severity: 'error',
        message: `MCP tool args exceed max size: ${argsSize} > ${maxArgsSize}`,
        details: { tool, args_size: argsSize, max_args_size: maxArgsSize },
      };
    }
  }

  // Check allow list
  if (allow.length > 0 && allow.includes(tool)) {
    return {
      allowed: true,
      guard: 'mcp_tool',
      severity: 'info',
      message: `MCP tool allowed: ${tool}`,
      details: { tool, reason: 'allow_list' },
    };
  }

  // Apply default action
  if (defaultAction === 'block') {
    // If allow list exists and tool is not in it, deny
    if (allow.length > 0) {
      return {
        allowed: false,
        guard: 'mcp_tool',
        severity: 'error',
        message: `MCP tool not in allow list: ${tool}`,
        details: { tool, reason: 'not_in_allow_list' },
      };
    }
    return {
      allowed: false,
      guard: 'mcp_tool',
      severity: 'error',
      message: `MCP tool blocked by default: ${tool}`,
      details: { tool, reason: 'default_block' },
    };
  }

  return {
    allowed: true,
    guard: 'mcp_tool',
    severity: 'info',
    message: `MCP tool allowed: ${tool}`,
    details: { tool },
  };
}
