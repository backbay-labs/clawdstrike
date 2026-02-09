/**
 * Severity level for guard violations.
 */
export enum Severity {
  INFO = "info",
  WARNING = "warning",
  ERROR = "error",
  CRITICAL = "critical",
}

/**
 * Canonical severity vocabulary (per ADR 0003 / adapter-core).
 */
export type CanonicalSeverity = "low" | "medium" | "high" | "critical";

/**
 * Convert SDK Severity enum to the canonical (adapter-core) vocabulary.
 *
 * Mapping:
 *   INFO     -> low
 *   WARNING  -> medium
 *   ERROR    -> high
 *   CRITICAL -> critical
 */
export function toCanonicalSeverity(severity: Severity): CanonicalSeverity {
  switch (severity) {
    case Severity.INFO:
      return "low";
    case Severity.WARNING:
      return "medium";
    case Severity.ERROR:
      return "high";
    case Severity.CRITICAL:
      return "critical";
  }
}

/**
 * Convert canonical (adapter-core) severity to the SDK Severity enum.
 */
export function fromCanonicalSeverity(canonical: CanonicalSeverity): Severity {
  switch (canonical) {
    case "low":
      return Severity.INFO;
    case "medium":
      return Severity.WARNING;
    case "high":
      return Severity.ERROR;
    case "critical":
      return Severity.CRITICAL;
  }
}

/**
 * Result of a guard check.
 */
export class GuardResult {
  constructor(
    public readonly allowed: boolean,
    public readonly guard: string,
    public readonly severity: Severity,
    public readonly message: string,
    public details?: Record<string, unknown>
  ) {}

  /**
   * Create an allow result.
   */
  static allow(guard: string): GuardResult {
    return new GuardResult(true, guard, Severity.INFO, "Allowed");
  }

  /**
   * Create a block result.
   */
  static block(guard: string, severity: Severity, message: string): GuardResult {
    return new GuardResult(false, guard, severity, message);
  }

  /**
   * Create a warning result (allowed but logged).
   */
  static warn(guard: string, message: string): GuardResult {
    return new GuardResult(true, guard, Severity.WARNING, message);
  }

  /**
   * Add details to the result.
   */
  withDetails(details: Record<string, unknown>): GuardResult {
    this.details = details;
    return this;
  }
}

/**
 * Context passed to guards for evaluation.
 */
export class GuardContext {
  readonly cwd?: string;
  readonly sessionId?: string;
  readonly agentId?: string;
  readonly metadata?: Record<string, unknown>;

  constructor(
    data: {
      cwd?: string;
      sessionId?: string;
      agentId?: string;
      metadata?: Record<string, unknown>;
    } = {}
  ) {
    this.cwd = data.cwd;
    this.sessionId = data.sessionId;
    this.agentId = data.agentId;
    this.metadata = data.metadata;
  }
}

/**
 * Action to be checked by guards.
 */
export class GuardAction {
  constructor(
    public readonly actionType: string,
    public readonly path?: string,
    public readonly content?: Uint8Array,
    public readonly host?: string,
    public readonly port?: number,
    public readonly tool?: string,
    public readonly args?: Record<string, unknown>,
    public readonly command?: string,
    public readonly diff?: string,
    public readonly customType?: string,
    public readonly customData?: Record<string, unknown>
  ) {}

  /**
   * Create a file access action.
   */
  static fileAccess(path: string): GuardAction {
    return new GuardAction("file_access", path);
  }

  /**
   * Create a file write action.
   */
  static fileWrite(path: string, content: Uint8Array): GuardAction {
    return new GuardAction("file_write", path, content);
  }

  /**
   * Create a network egress action.
   */
  static networkEgress(host: string, port: number): GuardAction {
    return new GuardAction("network_egress", undefined, undefined, host, port);
  }

  /**
   * Create a shell command action.
   */
  static shellCommand(command: string): GuardAction {
    return new GuardAction(
      "shell_command",
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      command
    );
  }

  /**
   * Create an MCP tool action.
   */
  static mcpTool(tool: string, args: Record<string, unknown>): GuardAction {
    return new GuardAction(
      "mcp_tool",
      undefined,
      undefined,
      undefined,
      undefined,
      tool,
      args
    );
  }

  /**
   * Create a patch action.
   */
  static patch(path: string, diff: string): GuardAction {
    return new GuardAction(
      "patch",
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      diff
    );
  }

  /**
   * Create a custom action.
   */
  static custom(customType: string, data: Record<string, unknown>): GuardAction {
    return new GuardAction(
      "custom",
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      customType,
      data
    );
  }
}

/**
 * Abstract base interface for security guards.
 */
export interface Guard {
  /**
   * Name of the guard.
   */
  readonly name: string;

  /**
   * Check if this guard handles the given action type.
   */
  handles(action: GuardAction): boolean;

  /**
   * Evaluate the action.
   */
  check(action: GuardAction, context: GuardContext): GuardResult;
}
