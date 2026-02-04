/**
 * @clawdstrike/openclaw - Type Definitions
 *
 * Core types for the Clawdstrike security plugin for OpenClaw.
 */

/**
 * Severity level for policy violations
 */
export type Severity = 'low' | 'medium' | 'high' | 'critical';

/**
 * Enforcement mode for policy evaluation
 */
export type EvaluationMode = 'deterministic' | 'advisory' | 'audit';

/**
 * Log level for plugin output
 */
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

/**
 * Action to take on policy violation
 */
export type ViolationAction = 'cancel' | 'warn' | 'isolate' | 'escalate';

/**
 * Network egress mode
 */
export type EgressMode = 'allowlist' | 'denylist' | 'open' | 'deny_all';

/**
 * Event type discriminator for policy evaluation
 */
export type EventType =
  | 'file_read'
  | 'file_write'
  | 'command_exec'
  | 'network_egress'
  | 'tool_call'
  | 'patch_apply'
  | 'secret_access';

/**
 * Plugin configuration schema
 */
export interface ClawdstrikeConfig {
  /** Path to policy YAML or built-in ruleset name */
  policy?: string;
  /** Enforcement mode */
  mode?: EvaluationMode;
  /** Logging level */
  logLevel?: LogLevel;
  /** Guard enable/disable toggles */
  guards?: GuardToggles;
}

/**
 * Guard enable/disable toggles
 */
export interface GuardToggles {
  forbidden_path?: boolean;
  egress?: boolean;
  secret_leak?: boolean;
  patch_integrity?: boolean;
  mcp_tool?: boolean;
}

/**
 * Execution event to be evaluated by policy engine
 */
export interface PolicyEvent {
  /** Unique event identifier */
  eventId: string;
  /** Event type */
  eventType: EventType;
  /** Event timestamp (ISO 8601) */
  timestamp: string;
  /** Associated session/run identifier */
  sessionId?: string;
  /** Event-specific data */
  data: EventData;
  /** Optional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Union type for event-specific data
 */
export type EventData =
  | FileEventData
  | CommandEventData
  | NetworkEventData
  | ToolEventData
  | PatchEventData
  | SecretEventData;

/**
 * File read/write event data
 */
export interface FileEventData {
  type: 'file';
  /** Absolute path to the file */
  path: string;
  /** Optional raw content (small files only; best-effort) */
  content?: string;
  /** Optional base64-encoded content */
  contentBase64?: string;
  /** Optional content hash (for write verification) */
  contentHash?: string;
  /** Operation type */
  operation: 'read' | 'write';
}

/**
 * Command execution event data
 */
export interface CommandEventData {
  type: 'command';
  /** Command name or path */
  command: string;
  /** Command arguments */
  args: string[];
  /** Working directory */
  workingDir?: string;
}

/**
 * Network egress event data
 */
export interface NetworkEventData {
  type: 'network';
  /** Target hostname or IP */
  host: string;
  /** Target port */
  port: number;
  /** Protocol (tcp, udp, etc.) */
  protocol?: string;
  /** Full URL if available */
  url?: string;
}

/**
 * Tool invocation event data
 */
export interface ToolEventData {
  type: 'tool';
  /** Tool name (e.g., "bash", "file_write", "web_search") */
  toolName: string;
  /** Tool parameters */
  parameters: Record<string, unknown>;
  /** Tool result (for post-execution checks) */
  result?: string;
}

/**
 * Patch/diff application event data
 */
export interface PatchEventData {
  type: 'patch';
  /** Target file path */
  filePath: string;
  /** Patch content (diff or full content) */
  patchContent: string;
  /** Optional patch hash */
  patchHash?: string;
}

/**
 * Secret access event data
 */
export interface SecretEventData {
  type: 'secret';
  /** Secret identifier or name */
  secretName: string;
  /** Scope (environment, file, etc.) */
  scope: string;
}

/**
 * Decision status for security checks.
 * - 'allow': Operation is permitted
 * - 'warn': Operation is permitted but flagged for review
 * - 'deny': Operation is blocked
 */
export type DecisionStatus = 'allow' | 'warn' | 'deny';

/**
 * Result of policy evaluation
 */
export interface Decision {
  /** The decision status: 'allow', 'warn', or 'deny' */
  status?: DecisionStatus;
  /** Whether the event is allowed @deprecated Use status === 'allow' || status === 'warn' */
  allowed: boolean;
  /** Whether the event is explicitly denied @deprecated Use status === 'deny' */
  denied: boolean;
  /** Whether to show a warning @deprecated Use status === 'warn' */
  warn: boolean;
  /** Reason for denial (if denied) */
  reason?: string;
  /** Guard that made the decision */
  guard?: string;
  /** Severity of the violation */
  severity?: Severity;
  /** Additional message */
  message?: string;
}

/**
 * Result from a single guard check
 */
export interface GuardResult {
  /** Guard status */
  status: 'allow' | 'deny' | 'warn';
  /** Reason message */
  reason?: string;
  /** Severity (for deny) */
  severity?: Severity;
  /** Guard name */
  guard: string;
}

/**
 * Security policy configuration
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
  guards?: GuardToggles & { custom?: unknown };
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
  severity: Severity;
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
  severity: Severity;
  /** Description */
  description: string;
}

/**
 * OpenClaw Plugin API interface (minimal for type safety)
 */
export interface PluginAPI {
  /** Get plugin configuration */
  getConfig<T = ClawdstrikeConfig>(): T;
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
  type: 'tool_result_persist';
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
 * Hook event context for agent:bootstrap
 */
export interface AgentBootstrapEvent {
  type: 'agent:bootstrap';
  timestamp: string;
  context: {
    sessionId: string;
    agentId: string;
    bootstrapFiles: Array<{
      path: string;
      content: string;
    }>;
    cfg: ClawdstrikeConfig;
  };
}

/**
 * Generic hook event type
 */
export type HookEvent = ToolResultPersistEvent | AgentBootstrapEvent;

/**
 * Hook handler function type
 */
export type HookHandler = (event: HookEvent) => Promise<void> | void;
