import { Guard, GuardAction, GuardContext, GuardResult, Severity } from "./types";

const DEFAULT_BLOCKED_TOOLS = [
  // Dangerous shell operations
  "shell_exec",
  "run_command",
  // Direct file system access that bypasses guards
  "raw_file_write",
  "raw_file_delete",
];

const DEFAULT_REQUIRE_CONFIRMATION = ["file_write", "file_delete", "git_push"];

export interface McpToolConfig {
  /** Enable/disable this guard */
  enabled?: boolean;
  /** Allowed tool names (if non-empty, only these are allowed) */
  allow?: string[];
  /** Blocked tool names (takes precedence over allow) */
  block?: string[];
  /** Tools that require confirmation */
  requireConfirmation?: string[];
  /** Default action when tool is not in allow/block lists */
  defaultAction?: "allow" | "block";
  /** Maximum arguments size in bytes */
  maxArgsSize?: number;
}

export enum ToolDecision {
  Allow = "allow",
  Block = "block",
  RequireConfirmation = "require_confirmation",
}

/**
 * Guard that controls MCP tool invocations.
 *
 * Supports:
 * - Allowlist mode (only specified tools allowed)
 * - Blocklist mode (specified tools blocked)
 * - Confirmation requirement for sensitive tools
 * - Argument size limits
 */
export class McpToolGuard implements Guard {
  readonly name = "mcp_tool";
  private enabled: boolean;
  private allowSet: Set<string>;
  private blockSet: Set<string>;
  private confirmSet: Set<string>;
  private defaultAction: "allow" | "block";
  private maxArgsSize: number;

  constructor(config: McpToolConfig = {}) {
    this.enabled = config.enabled ?? true;
    this.allowSet = new Set(config.allow ?? []);
    this.blockSet = new Set(config.block ?? DEFAULT_BLOCKED_TOOLS);
    this.confirmSet = new Set(config.requireConfirmation ?? DEFAULT_REQUIRE_CONFIRMATION);
    this.defaultAction = config.defaultAction ?? "allow";
    this.maxArgsSize = config.maxArgsSize ?? 1024 * 1024; // 1MB default
  }

  handles(action: GuardAction): boolean {
    return this.enabled && action.actionType === "mcp_tool";
  }

  check(action: GuardAction, _context: GuardContext): GuardResult {
    if (!this.enabled) {
      return GuardResult.allow(this.name);
    }
    if (!this.handles(action)) {
      return GuardResult.allow(this.name);
    }

    const toolName = action.tool;
    if (!toolName) {
      return GuardResult.allow(this.name);
    }

    // Check args size
    const argsSize = action.args ? JSON.stringify(action.args).length : 0;
    if (argsSize > this.maxArgsSize) {
      return GuardResult.block(
        this.name,
        Severity.ERROR,
        `Tool arguments too large: ${argsSize} bytes (max: ${this.maxArgsSize})`
      );
    }

    const decision = this.isAllowed(toolName);

    switch (decision) {
      case ToolDecision.Allow:
        return GuardResult.allow(this.name);

      case ToolDecision.Block:
        return GuardResult.block(
          this.name,
          Severity.ERROR,
          `Tool '${toolName}' is blocked by policy`
        ).withDetails({
          tool: toolName,
          reason: "blocked_by_policy",
        });

      case ToolDecision.RequireConfirmation:
        return GuardResult.warn(
          this.name,
          `Tool '${toolName}' requires confirmation`
        ).withDetails({
          tool: toolName,
          requiresConfirmation: true,
        });
    }
  }

  /**
   * Check if a tool is allowed.
   */
  isAllowed(toolName: string): ToolDecision {
    // Blocked takes precedence
    if (this.blockSet.has(toolName)) {
      return ToolDecision.Block;
    }

    // Check if requires confirmation
    if (this.confirmSet.has(toolName)) {
      return ToolDecision.RequireConfirmation;
    }

    // Check allowlist mode
    if (this.allowSet.size > 0) {
      // Allowlist mode: only allowed tools pass
      if (this.allowSet.has(toolName)) {
        return ToolDecision.Allow;
      } else {
        return ToolDecision.Block;
      }
    }

    // Default action
    return this.defaultAction === "block" ? ToolDecision.Block : ToolDecision.Allow;
  }
}
