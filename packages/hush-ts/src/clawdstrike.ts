/**
 * Unified Clawdstrike SDK entry point.
 *
 * This module provides the main `Clawdstrike` class that serves as a single
 * entry point for 80% of use cases. It offers:
 * - Simple check API for common security checks
 * - Session management for stateful operations
 * - Framework integration helpers
 *
 * @example Basic usage
 * ```typescript
 * import { Clawdstrike } from '@clawdstrike/sdk';
 *
 * const cs = await Clawdstrike.fromPolicy('./policy.yaml');
 *
 * const decision = await cs.checkFile('/etc/passwd', 'read');
 * if (decision.status === 'deny') {
 *   console.error('Access denied:', decision.message);
 * }
 * ```
 *
 * @example With defaults
 * ```typescript
 * const cs = Clawdstrike.withDefaults('strict');
 * ```
 *
 * @example Session-based usage
 * ```typescript
 * const session = cs.session({ userId: 'user-123' });
 * await session.check('read_file', { path: '/etc/passwd' });
 * const summary = session.getSummary();
 * ```
 *
 * @packageDocumentation
 */

import { GuardAction, GuardContext, Severity } from './guards/types.js';
import type { Guard, GuardResult } from './guards/types.js';

// ============================================================
// Types
// ============================================================

/**
 * Decision status for security checks.
 */
export type DecisionStatus = 'allow' | 'warn' | 'deny';

/**
 * Severity level for security violations.
 */
export type { Severity };

/**
 * Decision returned from policy evaluation.
 */
export interface Decision {
  /** The decision status: 'allow', 'warn', or 'deny' */
  status: DecisionStatus;
  /** Name of the guard that made this decision */
  guard?: string;
  /** Severity level of the violation */
  severity?: Severity;
  /** Human-readable message describing the decision */
  message?: string;
  /** Additional reason for the decision */
  reason?: string;
  /** Additional structured details */
  details?: unknown;
}

/**
 * Options for creating a Clawdstrike session.
 */
export interface SessionOptions {
  /** Unique session identifier */
  sessionId?: string;
  /** User identifier */
  userId?: string;
  /** Agent identifier */
  agentId?: string;
  /** Working directory context */
  cwd?: string;
  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Summary of a session's security activity.
 */
export interface SessionSummary {
  sessionId: string;
  checkCount: number;
  allowCount: number;
  warnCount: number;
  denyCount: number;
  blockedActions: string[];
  duration: number;
}

/**
 * Preset ruleset levels for common use cases.
 */
export type Ruleset = 'loose' | 'moderate' | 'strict' | 'enterprise';

/**
 * Configuration for Clawdstrike.
 */
export interface ClawdstrikeConfig {
  /** Policy object or path */
  policy?: PolicySpec;
  /** Guards to use */
  guards?: Guard[];
  /** Ruleset preset */
  ruleset?: Ruleset;
  /** Fail on first deny */
  failFast?: boolean;
  /** Working directory */
  cwd?: string;
}

/**
 * Policy specification - can be a path, URL, or inline object.
 */
export type PolicySpec = string | Record<string, unknown>;

/**
 * Generic tool set type for framework integration.
 */
export type ToolSet = Record<string, unknown>;

/**
 * Tool interceptor for framework integration.
 */
export interface ToolInterceptor {
  beforeExecute(
    toolName: string,
    input: unknown,
    context: ClawdstrikeSession,
  ): Promise<{ proceed: boolean; decision: Decision }>;
  afterExecute(
    toolName: string,
    input: unknown,
    output: unknown,
    context: ClawdstrikeSession,
  ): Promise<{ output: unknown; modified: boolean }>;
}

// ============================================================
// Internal helpers
// ============================================================

function createId(prefix: string): string {
  const timestamp = Date.now().toString(36);
  const random = Math.random().toString(36).substring(2, 8);
  return `${prefix}_${timestamp}_${random}`;
}

function guardResultToDecision(result: GuardResult): Decision {
  let status: DecisionStatus;
  if (!result.allowed) {
    status = 'deny';
  } else if (result.severity === Severity.WARNING) {
    status = 'warn';
  } else {
    status = 'allow';
  }

  return {
    status,
    guard: result.guard,
    severity: result.severity,
    message: result.message,
    details: result.details,
  };
}

function allowDecision(guard?: string): Decision {
  return {
    status: 'allow',
    guard,
    severity: Severity.INFO,
    message: 'Allowed',
  };
}

// ============================================================
// ClawdstrikeSession
// ============================================================

/**
 * A stateful security session for tracking multiple checks.
 */
export class ClawdstrikeSession {
  readonly sessionId: string;
  readonly userId?: string;
  readonly agentId?: string;
  readonly cwd?: string;
  readonly metadata: Record<string, unknown>;
  readonly createdAt: Date;

  private readonly guards: Guard[];
  private readonly failFast: boolean;
  private checkCount = 0;
  private allowCount = 0;
  private warnCount = 0;
  private denyCount = 0;
  private blockedActions: string[] = [];

  constructor(guards: Guard[], options: SessionOptions = {}, failFast = false) {
    this.guards = guards;
    this.failFast = failFast;
    this.sessionId = options.sessionId ?? createId('sess');
    this.userId = options.userId;
    this.agentId = options.agentId;
    this.cwd = options.cwd;
    this.metadata = options.metadata ?? {};
    this.createdAt = new Date();
  }

  /**
   * Check an action against the policy.
   */
  async check(action: string, params: Record<string, unknown> = {}): Promise<Decision> {
    this.checkCount++;

    const guardAction = this.createGuardAction(action, params);
    const guardContext = this.createGuardContext();
    let warningDecision: Decision | undefined;

    for (const guard of this.guards) {
      if (!guard.handles(guardAction)) {
        continue;
      }

      const result = guard.check(guardAction, guardContext);
      const decision = guardResultToDecision(result);

      if (decision.status === 'deny') {
        this.denyCount++;
        this.blockedActions.push(action);
        return decision;
      }

      if (decision.status === 'warn') {
        this.warnCount++;
        warningDecision ??= decision;
        if (this.failFast) {
          return decision;
        }
      }
    }

    if (warningDecision) {
      return warningDecision;
    }

    this.allowCount++;
    return allowDecision('session');
  }

  /**
   * Check file access.
   */
  async checkFile(path: string, operation: 'read' | 'write' = 'read'): Promise<Decision> {
    return this.check(operation === 'write' ? 'file_write' : 'file_access', { path });
  }

  /**
   * Check command execution.
   */
  async checkCommand(command: string, args: string[] = []): Promise<Decision> {
    return this.check('shell_command', { command, args });
  }

  /**
   * Check network egress.
   */
  async checkNetwork(url: string): Promise<Decision> {
    let host: string;
    let port: number;

    try {
      const parsed = new URL(url);
      host = parsed.hostname;
      port = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);
    } catch {
      host = url;
      port = 443;
    }

    return this.check('network_egress', { host, port, url });
  }

  /**
   * Check a patch/diff operation.
   */
  async checkPatch(path: string, patch: string): Promise<Decision> {
    return this.check('patch', { path, diff: patch });
  }

  /**
   * Get session summary.
   */
  getSummary(): SessionSummary {
    return {
      sessionId: this.sessionId,
      checkCount: this.checkCount,
      allowCount: this.allowCount,
      warnCount: this.warnCount,
      denyCount: this.denyCount,
      blockedActions: [...this.blockedActions],
      duration: Date.now() - this.createdAt.getTime(),
    };
  }

  private createGuardAction(action: string, params: Record<string, unknown>): GuardAction {
    return new GuardAction(
      action,
      params.path as string | undefined,
      params.content as Uint8Array | undefined,
      params.host as string | undefined,
      params.port as number | undefined,
      params.tool as string | undefined,
      params.args as Record<string, unknown> | undefined,
      params.command as string | undefined,
      params.diff as string | undefined,
      params.customType as string | undefined,
      params.customData as Record<string, unknown> | undefined,
    );
  }

  private createGuardContext(): GuardContext {
    return new GuardContext({
      cwd: this.cwd,
      sessionId: this.sessionId,
      agentId: this.agentId,
      metadata: this.metadata,
    });
  }
}

// ============================================================
// Clawdstrike (Main Entry Point)
// ============================================================

/**
 * Unified Clawdstrike SDK entry point.
 *
 * This class provides a simple, ergonomic API for security checks that
 * handles 80% of use cases. For advanced usage, see the Guards API.
 *
 * @example
 * ```typescript
 * // From policy file
 * const cs = await Clawdstrike.fromPolicy('./policy.yaml');
 *
 * // With preset ruleset
 * const cs = Clawdstrike.withDefaults('strict');
 *
 * // Simple checks
 * const decision = await cs.checkFile('/etc/passwd');
 * if (decision.status === 'deny') {
 *   throw new Error(`Access denied: ${decision.message}`);
 * }
 *
 * // Session-based usage
 * const session = cs.session({ userId: 'user-123' });
 * await session.checkCommand('rm', ['-rf', '/']);
 * console.log(session.getSummary());
 * ```
 */
export class Clawdstrike {
  private readonly guards: Guard[];
  private readonly config: ClawdstrikeConfig;
  private readonly defaultContext: GuardContext;

  private constructor(config: ClawdstrikeConfig, guards: Guard[]) {
    this.config = config;
    this.guards = guards;
    this.defaultContext = new GuardContext({ cwd: config.cwd });
  }

  // ============================================================
  // Factory Methods
  // ============================================================

  /**
   * Create Clawdstrike instance from a policy file.
   *
   * @param yamlOrPath - Path to YAML policy file or inline YAML string
   * @returns Promise resolving to configured Clawdstrike instance
   *
   * @example
   * ```typescript
   * const cs = await Clawdstrike.fromPolicy('./clawdstrike.yaml');
   * ```
   */
  static async fromPolicy(yamlOrPath: string): Promise<Clawdstrike> {
    // For now, we create an instance with default guards
    // Full policy loading would integrate with @clawdstrike/policy
    const guards = Clawdstrike.getDefaultGuards('moderate');
    return new Clawdstrike({ policy: yamlOrPath }, guards);
  }

  /**
   * Create Clawdstrike instance connected to a daemon.
   *
   * @param url - Daemon URL (e.g., 'http://localhost:8080')
   * @param apiKey - Optional API key for authentication
   * @returns Promise resolving to configured Clawdstrike instance
   *
   * @example
   * ```typescript
   * const cs = await Clawdstrike.fromDaemon('http://localhost:8080', 'my-api-key');
   * ```
   */
  static async fromDaemon(url: string, _apiKey?: string): Promise<Clawdstrike> {
    // Daemon mode uses remote policy evaluation
    // This is a placeholder - full implementation would use ClawdstrikeClient
    const guards = Clawdstrike.getDefaultGuards('moderate');
    return new Clawdstrike({ policy: url }, guards);
  }

  /**
   * Create Clawdstrike instance with a preset ruleset.
   *
   * @param ruleset - Preset security level: 'loose', 'moderate', 'strict', or 'enterprise'
   * @returns Configured Clawdstrike instance
   *
   * @example
   * ```typescript
   * // Quick start with sensible defaults
   * const cs = Clawdstrike.withDefaults('strict');
   * ```
   */
  static withDefaults(ruleset: Ruleset = 'moderate'): Clawdstrike {
    const guards = Clawdstrike.getDefaultGuards(ruleset);
    return new Clawdstrike({ ruleset }, guards);
  }

  /**
   * Create Clawdstrike instance with custom configuration.
   *
   * @param config - Configuration options
   * @returns Configured Clawdstrike instance
   */
  static configure(config: ClawdstrikeConfig): Clawdstrike {
    const guards = config.guards ?? Clawdstrike.getDefaultGuards(config.ruleset ?? 'moderate');
    return new Clawdstrike(config, guards);
  }

  private static getDefaultGuards(_ruleset: Ruleset): Guard[] {
    // Import guards dynamically to avoid circular dependencies
    // These would be populated based on the ruleset
    // For now, return empty array - guards are added when needed
    return [];
  }

  // ============================================================
  // Simple Check API
  // ============================================================

  /**
   * Check an action against the policy.
   *
   * @param action - Action type (e.g., 'read_file', 'exec_command')
   * @param params - Action parameters
   * @returns Decision indicating whether the action is allowed
   *
   * @example
   * ```typescript
   * const decision = await cs.check('read_file', { path: '/etc/passwd' });
   * ```
   */
  async check(action: string, params: Record<string, unknown> = {}): Promise<Decision> {
    const guardAction = this.createGuardAction(action, params);
    let warningDecision: Decision | undefined;

    for (const guard of this.guards) {
      if (!guard.handles(guardAction)) {
        continue;
      }

      const result = guard.check(guardAction, this.defaultContext);
      const decision = guardResultToDecision(result);

      if (decision.status === 'deny') {
        return decision;
      }

      if (decision.status === 'warn') {
        warningDecision ??= decision;
        if (this.config.failFast) {
          return decision;
        }
      }
    }

    return warningDecision ?? allowDecision();
  }

  /**
   * Check file access.
   *
   * @param path - File path to check
   * @param operation - Operation type: 'read' or 'write'
   * @returns Decision indicating whether access is allowed
   *
   * @example
   * ```typescript
   * const decision = await cs.checkFile('/etc/passwd', 'read');
   * ```
   */
  async checkFile(path: string, operation: 'read' | 'write' = 'read'): Promise<Decision> {
    return this.check(operation === 'write' ? 'file_write' : 'file_access', { path });
  }

  /**
   * Check command execution.
   *
   * @param command - Command to execute
   * @param args - Command arguments
   * @returns Decision indicating whether execution is allowed
   *
   * @example
   * ```typescript
   * const decision = await cs.checkCommand('rm', ['-rf', '/']);
   * ```
   */
  async checkCommand(command: string, args: string[] = []): Promise<Decision> {
    return this.check('shell_command', { command, args });
  }

  /**
   * Check network egress.
   *
   * @param url - Target URL
   * @returns Decision indicating whether egress is allowed
   *
   * @example
   * ```typescript
   * const decision = await cs.checkNetwork('https://api.example.com');
   * ```
   */
  async checkNetwork(url: string): Promise<Decision> {
    let host: string;
    let port: number;

    try {
      const parsed = new URL(url);
      host = parsed.hostname;
      port = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);
    } catch {
      host = url;
      port = 443;
    }

    return this.check('network_egress', { host, port, url });
  }

  /**
   * Check a patch/diff operation.
   *
   * @param path - File path being patched
   * @param patch - Patch content (unified diff format)
   * @returns Decision indicating whether the patch is allowed
   *
   * @example
   * ```typescript
   * const decision = await cs.checkPatch('src/main.ts', unifiedDiff);
   * ```
   */
  async checkPatch(path: string, patch: string): Promise<Decision> {
    return this.check('patch', { path, diff: patch });
  }

  // ============================================================
  // Session Management
  // ============================================================

  /**
   * Create a new security session.
   *
   * Sessions track security checks over time and provide aggregated
   * statistics. Use sessions for request-scoped or conversation-scoped
   * security tracking.
   *
   * @param options - Session configuration
   * @returns New ClawdstrikeSession instance
   *
   * @example
   * ```typescript
   * const session = cs.session({ userId: 'user-123' });
   *
   * // Multiple checks in the session
   * await session.checkFile('/path/to/file');
   * await session.checkCommand('ls', ['-la']);
   *
   * // Get aggregated statistics
   * const summary = session.getSummary();
   * console.log(`Checks: ${summary.checkCount}, Denies: ${summary.denyCount}`);
   * ```
   */
  session(options: SessionOptions = {}): ClawdstrikeSession {
    return new ClawdstrikeSession(
      this.guards,
      { ...options, cwd: options.cwd ?? this.config.cwd },
      this.config.failFast,
    );
  }

  // ============================================================
  // Framework Integration
  // ============================================================

  /**
   * Wrap a tool set with security checks.
   *
   * This method wraps each tool in the set with security interception,
   * checking actions before execution and sanitizing outputs after.
   *
   * @param tools - Tool set to wrap
   * @returns Wrapped tool set with same interface
   *
   * @example
   * ```typescript
   * const tools = { readFile, writeFile, execCommand };
   * const secureTools = cs.wrapTools(tools);
   * ```
   */
  wrapTools<T extends ToolSet>(tools: T): T {
    const wrapped: Record<string, unknown> = {};

    for (const [name, tool] of Object.entries(tools)) {
      if (typeof tool === 'function') {
        wrapped[name] = this.wrapTool(name, tool as (...args: unknown[]) => unknown);
      } else if (typeof tool === 'object' && tool !== null && 'execute' in tool) {
        // Handle tool objects with execute method (common pattern)
        wrapped[name] = {
          ...tool,
          execute: this.wrapTool(name, (tool as { execute: (...args: unknown[]) => unknown }).execute),
        };
      } else {
        wrapped[name] = tool;
      }
    }

    return wrapped as T;
  }

  /**
   * Create a tool interceptor for manual integration.
   *
   * Use this for frameworks that require explicit interceptor setup.
   *
   * @returns ToolInterceptor instance
   *
   * @example
   * ```typescript
   * const interceptor = cs.createInterceptor();
   *
   * // In your framework's tool execution
   * const result = await interceptor.beforeExecute(toolName, input, session);
   * if (!result.proceed) {
   *   throw new Error(`Blocked: ${result.decision.message}`);
   * }
   * ```
   */
  createInterceptor(): ToolInterceptor {
    return {
      beforeExecute: async (
        toolName: string,
        input: unknown,
        context: ClawdstrikeSession,
      ): Promise<{ proceed: boolean; decision: Decision }> => {
        const params = typeof input === 'object' && input !== null
          ? input as Record<string, unknown>
          : { value: input };

        const decision = await context.check(toolName, params);
        return {
          proceed: decision.status !== 'deny',
          decision,
        };
      },
      afterExecute: async (
        _toolName: string,
        _input: unknown,
        output: unknown,
        _context: ClawdstrikeSession,
      ): Promise<{ output: unknown; modified: boolean }> => {
        // Output sanitization would be applied here
        return { output, modified: false };
      },
    };
  }

  // ============================================================
  // Internal Helpers
  // ============================================================

  private wrapTool(
    name: string,
    fn: (...args: unknown[]) => unknown,
  ): (...args: unknown[]) => Promise<unknown> {
    const self = this;
    return async function wrappedTool(...args: unknown[]): Promise<unknown> {
      const params = args[0] && typeof args[0] === 'object'
        ? args[0] as Record<string, unknown>
        : { args };

      const decision = await self.check(name, params);
      if (decision.status === 'deny') {
        throw new Error(`Clawdstrike blocked ${name}: ${decision.message}`);
      }

      return fn(...args);
    };
  }

  private createGuardAction(action: string, params: Record<string, unknown>): GuardAction {
    return new GuardAction(
      action,
      params.path as string | undefined,
      params.content as Uint8Array | undefined,
      params.host as string | undefined,
      params.port as number | undefined,
      params.tool as string | undefined,
      params.args as Record<string, unknown> | undefined,
      params.command as string | undefined,
      params.diff as string | undefined,
      params.customType as string | undefined,
      params.customData as Record<string, unknown> | undefined,
    );
  }
}

export default Clawdstrike;
