/**
 * @clawdstrike/openclaw - Type Definitions
 *
 * Core types for the Clawdstrike security plugin for OpenClaw.
 *
 * Types that are structurally identical to @clawdstrike/adapter-core are
 * re-exported from that package to maintain a single source of truth and
 * eliminate unsafe casts between parallel definitions.
 */

// ---------------------------------------------------------------------------
// Re-exports from @clawdstrike/adapter-core (structurally identical types)
// ---------------------------------------------------------------------------

// DecisionReasonCode is a plain `string` alias in both packages.
// Re-export so consumers keep the same semantic name.
// Also re-export the concrete event-data interfaces so files that import
// e.g. `FileEventData` from '../types.js' continue to resolve.
export type {
  CommandEventData,
  CuaEventData,
  Decision,
  DecisionReasonCode,
  DecisionStatus,
  EvaluationMode,
  EventData,
  EventType,
  FileEventData,
  InboundConfig,
  LogLevel,
  NetworkEventData,
  PatchEventData,
  PolicyEvent,
  SecretEventData,
  Severity,
  ToolEventData,
} from "@clawdstrike/adapter-core";

// ---------------------------------------------------------------------------
// Openclaw-specific types (no adapter-core equivalent)
// ---------------------------------------------------------------------------

/**
 * Action to take on policy violation
 */
export type ViolationAction = "cancel" | "warn" | "isolate" | "escalate";

/**
 * Network egress mode
 */
export type EgressMode = "allowlist" | "denylist" | "open" | "deny_all";

export type ComputerUseMode = "observe" | "guardrail" | "fail_closed";

export interface ComputerUseGuardConfig {
  enabled?: boolean;
  mode?: ComputerUseMode;
  allowed_actions?: string[];
}

export interface RemoteDesktopSideChannelGuardConfig {
  enabled?: boolean;
  clipboard_enabled?: boolean;
  file_transfer_enabled?: boolean;
  audio_enabled?: boolean;
  drive_mapping_enabled?: boolean;
  printing_enabled?: boolean;
  session_share_enabled?: boolean;
  max_transfer_size_bytes?: number;
}

export interface InputInjectionCapabilityGuardConfig {
  enabled?: boolean;
  allowed_input_types?: string[];
  require_postcondition_probe?: boolean;
}

import type {
  ClawdstrikeConfig as AdapterCoreClawdstrikeConfig,
  GuardToggles as AdapterCoreGuardToggles,
  InboundConfig as AdapterCoreInboundConfig,
} from "@clawdstrike/adapter-core";

// Keep openclaw config tolerant to newer guard toggles even when adapter-core
// package versions lag behind this package.
export interface GuardToggles extends AdapterCoreGuardToggles {
  spider_sense?: boolean;
}

export interface ClawdstrikeConfig extends Omit<AdapterCoreClawdstrikeConfig, "guards"> {
  guards?: GuardToggles;
  inbound?: AdapterCoreInboundConfig;
}

export interface PolicyGuards extends GuardToggles {
  custom?: unknown;
  computer_use?: ComputerUseGuardConfig;
  remote_desktop_side_channel?: RemoteDesktopSideChannelGuardConfig;
  input_injection_capability?: InputInjectionCapabilityGuardConfig;
}

// Import Severity for use in local interfaces below.
import type { Severity as _Severity } from "@clawdstrike/adapter-core";

/**
 * Result from a single guard check
 */
export interface GuardResult {
  /** Guard status */
  status: "allow" | "deny" | "warn";
  /** Reason message */
  reason?: string;
  /** Severity (for deny) */
  severity?: _Severity;
  /** Guard name */
  guard: string;
}

/**
 * Security policy configuration
 *
 * NOTE: This is intentionally NOT re-exported from adapter-core.
 * adapter-core defines Policy as `Record<string, unknown>` (opaque),
 * whereas openclaw requires a rich structured type for guard evaluation.
 */
export interface Policy {
  /** Policy version identifier */
  version?: string;
  /** Base policy to extend */
  extends?: string;
  /** Network egress configuration */
  egress?: EgressPolicy;
  /** Filesystem access configuration */
  filesystem?: FilesystemPolicy;
  /** Command execution configuration */
  execution?: ExecutionPolicy;
  /** Tool/MCP restrictions */
  tools?: ToolPolicy;
  /** Resource limits */
  limits?: ResourceLimits;
  /** Guard-level toggles */
  guards?: PolicyGuards;
  /** Action to take on violation */
  on_violation?: ViolationAction;
}

/**
 * Network egress policy
 */
export interface EgressPolicy {
  /** Egress mode */
  mode: EgressMode;
  /** Allowed domains (for allowlist mode) */
  allowed_domains?: string[];
  /** Allowed IP CIDRs */
  allowed_cidrs?: string[];
  /** Denied domains (takes precedence) */
  denied_domains?: string[];
}

/**
 * Filesystem access policy
 */
export interface FilesystemPolicy {
  /** Directories where writes are allowed */
  allowed_write_roots?: string[];
  /** Paths that must never be accessed */
  forbidden_paths?: string[];
  /** Allowed read paths (empty = all allowed) */
  allowed_read_paths?: string[];
}

/**
 * Command execution policy
 */
export interface ExecutionPolicy {
  /** Allowed commands (empty = all allowed) */
  allowed_commands?: string[];
  /** Denied command patterns (regex) */
  denied_patterns?: string[];
}

/**
 * Tool access policy
 */
export interface ToolPolicy {
  /** Allowed tools (empty = all allowed) */
  allowed?: string[];
  /** Denied tools */
  denied?: string[];
}

/**
 * Resource limits
 */
export interface ResourceLimits {
  /** Maximum execution time in seconds */
  max_execution_seconds?: number;
  /** Maximum memory in MB */
  max_memory_mb?: number;
  /** Maximum output size in bytes */
  max_output_bytes?: number;
}

/**
 * Policy lint result
 */
export interface PolicyLintResult {
  /** Whether policy is valid */
  valid: boolean;
  /** Validation errors */
  errors: string[];
  /** Validation warnings */
  warnings: string[];
}

/**
 * Secret pattern for detection
 */
export interface SecretPattern {
  /** Pattern name */
  name: string;
  /** Regex pattern */
  pattern: RegExp;
  /** Severity if detected */
  severity: _Severity;
  /** Description */
  description: string;
}

/**
 * Dangerous pattern for patch integrity
 */
export interface DangerousPattern {
  /** Pattern name */
  name: string;
  /** Regex pattern */
  pattern: RegExp;
  /** Severity if detected */
  severity: _Severity;
  /** Description */
  description: string;
}

// Import ClawdstrikeConfig for use in local interfaces.
import type { ClawdstrikeConfig as _ClawdstrikeConfig } from "@clawdstrike/adapter-core";

/**
 * OpenClaw Plugin API interface (minimal for type safety)
 */
export interface PluginAPI {
  /** Get plugin configuration */
  getConfig<T = _ClawdstrikeConfig>(): T;
  /** Register a tool */
  registerTool(tool: ToolDefinition): void;
  /** Register CLI commands */
  registerCli(callback: (ctx: CliContext) => void): void;
  /** Register a background service */
  registerService(service: ServiceDefinition): void;
  /** Get logger */
  getLogger(): Logger;
}

/**
 * Tool definition for registration
 */
export interface ToolDefinition {
  /** Tool name */
  name: string;
  /** Tool description */
  description: string;
  /** JSON Schema for parameters */
  schema: Record<string, unknown>;
  /** Tool execution function */
  execute: (params: Record<string, unknown>) => Promise<unknown>;
}

/**
 * CLI context for command registration
 */
export interface CliContext {
  program: {
    command(name: string): CommandBuilder;
  };
}

/**
 * Command builder interface
 */
export interface CommandBuilder {
  description(desc: string): CommandBuilder;
  command(name: string): CommandBuilder;
  action(fn: (...args: unknown[]) => Promise<void> | void): CommandBuilder;
  argument(name: string, desc?: string): CommandBuilder;
  option(flags: string, desc?: string, defaultValue?: unknown): CommandBuilder;
}

/**
 * Service definition for background processes
 */
export interface ServiceDefinition {
  /** Service ID */
  id: string;
  /** Start function */
  start: () => Promise<void>;
  /** Stop function */
  stop: () => Promise<void>;
}

/**
 * Logger interface
 */
export interface Logger {
  debug(message: string, ...args: unknown[]): void;
  info(message: string, ...args: unknown[]): void;
  warn(message: string, ...args: unknown[]): void;
  error(message: string, ...args: unknown[]): void;
}

/**
 * Hook event context for tool_result_persist
 */
export interface ToolResultPersistEvent {
  type: "tool_result_persist";
  timestamp: string;
  context: {
    sessionId: string;
    toolResult: {
      toolName: string;
      params: Record<string, unknown>;
      result: unknown;
      error?: string;
    };
  };
  messages: string[];
}

/**
 * Modern OpenClaw tool_result_persist hook payload (v2026 runtime).
 */
export interface ModernToolResultPersistEvent {
  toolName?: string;
  toolCallId?: string;
  message: unknown;
  isSynthetic?: boolean;
}

/**
 * Hook event context for agent:bootstrap
 */
export interface AgentBootstrapEvent {
  type: "agent:bootstrap";
  timestamp: string;
  context: {
    sessionId: string;
    agentId: string;
    bootstrapFiles: Array<{
      path: string;
      content: string;
    }>;
    cfg: _ClawdstrikeConfig;
  };
}

/**
 * Hook event context for tool_call (pre-execution).
 * Accepts both 'tool_call' (legacy) and 'before_tool_call' (v2026.2.1+).
 */
export interface ToolCallEvent {
  type: "tool_call" | "before_tool_call";
  timestamp: string;
  context: {
    sessionId: string;
    toolCall: {
      toolName: string;
      params: Record<string, unknown>;
    };
  };
  /** Set to true to block execution */
  preventDefault: boolean;
  /** Messages to relay to the agent */
  messages: string[];
}

/**
 * Hook event context for inbound pre-LLM message checks.
 */
export interface InboundMessageEvent {
  type: "inbound_message" | "user_input";
  timestamp: string;
  context: {
    sessionId: string;
    message: {
      id?: string;
      text: string;
      senderId?: string;
      senderName?: string;
      channel?: string;
      chatType?: "dm" | "group" | "channel";
      timestamp?: string;
      metadata?: Record<string, unknown>;
      blocked?: boolean;
    };
  };
  messages: string[];
}

/**
 * Modern OpenClaw before_tool_call hook payload (v2026 runtime).
 */
export interface BeforeToolCallHookEvent {
  toolName: string;
  params: Record<string, unknown>;
}

/**
 * Modern OpenClaw hook context payload.
 */
export interface OpenClawHookContext {
  agentId?: string;
  sessionKey?: string;
  toolName?: string;
  toolCallId?: string;
}

/**
 * Generic hook event type
 */
export type HookEvent = ToolResultPersistEvent | AgentBootstrapEvent | ToolCallEvent | InboundMessageEvent;

/**
 * Hook handler function type
 */
export interface BeforeToolCallHookResult {
  block: boolean;
  blockReason?: string;
  params?: Record<string, unknown>;
}

export interface ToolResultPersistHookResult {
  message?: unknown;
}

export type HookHandlerResult = void | BeforeToolCallHookResult | ToolResultPersistHookResult;

export type HookHandler = (
  event: HookEvent,
  ctx?: OpenClawHookContext,
) => Promise<HookHandlerResult> | HookHandlerResult;
