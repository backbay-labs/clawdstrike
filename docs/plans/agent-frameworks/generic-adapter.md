# Generic Adapter Pattern

## Overview

The Generic Adapter Pattern provides a framework-agnostic foundation for integrating Clawdstrike security into any AI agent framework. This document defines the core abstractions, interfaces, and patterns that all framework-specific integrations build upon.

By establishing a consistent adapter pattern, we ensure:
- Uniform security semantics across frameworks
- Reusable policy evaluation logic
- Consistent audit trail format
- Portable security configurations

## Version Compatibility

| Package | Minimum Version | Notes |
|---------|----------------|-------|
| **@clawdstrike/adapter-core** | 1.0.0 | Core adapter interfaces and utilities |
| **@clawdstrike/openclaw** | 0.1.0 | Policy engine dependency |
| **TypeScript** | 5.0.0 | Required for generic type features |
| **Node.js** | 18.0.0 | Required for async/await patterns |

## Problem Statement

### Challenges with Multiple Frameworks

1. **Diverse APIs**: Each framework has unique tool definition, execution, and lifecycle APIs.

2. **Different Execution Models**: Some frameworks are synchronous, others async; some use streaming, others batch processing.

3. **Varying State Management**: Agent state (memory, context) is handled differently across frameworks.

4. **Inconsistent Tool Schemas**: Tool parameter definitions vary (JSON Schema, Zod, Pydantic, custom).

5. **Multiple Languages**: Frameworks exist in TypeScript, Python, Rust, and Go.

### Goals

| Goal | Description |
|------|-------------|
| **Abstraction** | Define interfaces that work regardless of underlying framework |
| **Extensibility** | Easy to add support for new frameworks |
| **Consistency** | Same security behavior across all integrations |
| **Performance** | Minimal overhead for policy evaluation |
| **Testability** | Mock implementations for unit testing |

## Architecture

### Layered Design

```
┌─────────────────────────────────────────────────────────────────┐
│                     Application Layer                            │
│  (Framework-specific code: LangChain, CrewAI, Vercel AI, etc.)  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Framework Adapter Layer                       │
│  (@clawdstrike/langchain, @clawdstrike/crewai, etc.)           │
│  - Implements FrameworkAdapter interface                        │
│  - Translates framework events to Clawdstrike events            │
│  - Applies security decisions back to framework                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Generic Adapter Core                         │
│  (@clawdstrike/adapter-core)                                    │
│  - ToolInterceptor, OutputSanitizer, AuditLogger               │
│  - SecurityContext, DecisionRouter                              │
│  - PolicyEventFactory, DecisionHandler                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Clawdstrike Policy Engine                     │
│  (@clawdstrike/openclaw)                                        │
│  - PolicyEngine, Guards, Validators                             │
│  - Policy loading, evaluation, caching                          │
└─────────────────────────────────────────────────────────────────┘
```

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                   @clawdstrike/adapter-core                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Interfaces                                                       │
│  ├── FrameworkAdapter<TContext>                                  │
│  ├── ToolInterceptor<TInput, TOutput>                           │
│  ├── OutputSanitizer<T>                                         │
│  ├── SecurityContextProvider                                     │
│  ├── AuditLogger                                                 │
│  └── DecisionHandler                                             │
│                                                                   │
│  Implementations                                                  │
│  ├── BaseToolInterceptor                                         │
│  ├── DefaultOutputSanitizer                                      │
│  ├── InMemoryAuditLogger                                         │
│  ├── PolicyEventFactory                                          │
│  └── DecisionRouter                                              │
│                                                                   │
│  Utilities                                                        │
│  ├── createAdapter(config) -> FrameworkAdapter                   │
│  ├── normalizeToolParams(params) -> NormalizedParams             │
│  ├── inferEventType(toolName, params) -> EventType              │
│  ├── createSecurityPrompt(policy) -> string                     │
│  └── mergeConfigs(base, override) -> Config                     │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

## Core Interfaces

### TypeScript Definitions

```typescript
import { PolicyEngine, Decision, PolicyEvent, Policy, ClawdstrikeConfig } from '@clawdstrike/openclaw';

// =============================================================================
// Framework Adapter Interface
// =============================================================================

/**
 * Main interface that all framework-specific adapters must implement.
 * TContext is the framework-specific execution context.
 */
export interface FrameworkAdapter<TContext = unknown> {
  /** Adapter name for identification */
  readonly name: string;

  /** Adapter version */
  readonly version: string;

  /** Initialize the adapter with configuration */
  initialize(config: AdapterConfig): Promise<void>;

  /** Create a security context for a new session/request */
  createContext(metadata?: Record<string, unknown>): SecurityContext;

  /** Intercept a tool call before execution */
  interceptToolCall(
    context: SecurityContext,
    toolCall: GenericToolCall,
  ): Promise<InterceptResult>;

  /** Process tool output after execution */
  processOutput(
    context: SecurityContext,
    toolCall: GenericToolCall,
    output: unknown,
  ): Promise<ProcessedOutput>;

  /** Handle the end of a session/request */
  finalizeContext(context: SecurityContext): Promise<SessionSummary>;

  /** Get the underlying policy engine */
  getEngine(): PolicyEngine;

  /** Get adapter-specific hooks for the framework */
  getHooks(): FrameworkHooks<TContext>;
}

/**
 * Adapter configuration
 */
export interface AdapterConfig extends ClawdstrikeConfig {
  /** Whether to block on policy violation */
  blockOnViolation?: boolean;

  /** Whether to sanitize outputs */
  sanitizeOutputs?: boolean;

  /** Whether to inject security prompt */
  injectSecurityPrompt?: boolean;

  /** Tool name normalization function */
  normalizeToolName?: (name: string) => string;

  /** Tools to exclude from security checks */
  excludedTools?: string[];

  /** Audit configuration */
  audit?: AuditConfig;

  /** Custom event handlers */
  handlers?: EventHandlers;
}

/**
 * Audit configuration
 */
export interface AuditConfig {
  /** Whether to enable audit logging */
  enabled?: boolean;

  /** Audit logger implementation */
  logger?: AuditLogger;

  /** Events to log */
  events?: AuditEventType[];

  /** Whether to include tool parameters in logs */
  logParameters?: boolean;

  /** Whether to include tool outputs in logs */
  logOutputs?: boolean;

  /** PII redaction for audit logs */
  redactPII?: boolean;
}

/**
 * Event handlers for custom behavior
 */
export interface EventHandlers {
  /** Called before policy evaluation */
  onBeforeEvaluate?: (toolCall: GenericToolCall) => void;

  /** Called after policy evaluation */
  onAfterEvaluate?: (toolCall: GenericToolCall, decision: Decision) => void;

  /** Called when a tool is blocked */
  onBlocked?: (toolCall: GenericToolCall, decision: Decision) => void;

  /** Called when a warning is issued */
  onWarning?: (toolCall: GenericToolCall, decision: Decision) => void;

  /** Called on any error */
  onError?: (error: Error, toolCall?: GenericToolCall) => void;
}

// =============================================================================
// Security Context
// =============================================================================

/**
 * Security context for a session/request
 */
export interface SecurityContext {
  /** Unique context ID */
  readonly id: string;

  /** Session ID (may span multiple contexts) */
  readonly sessionId: string;

  /** User ID if available */
  readonly userId?: string;

  /** Creation timestamp */
  readonly createdAt: Date;

  /** Active policy */
  readonly policy: Policy;

  /** Context metadata */
  readonly metadata: Record<string, unknown>;

  /** Accumulated audit events */
  readonly auditEvents: AuditEvent[];

  /** Tools blocked in this context */
  readonly blockedTools: Set<string>;

  /** Number of policy checks */
  checkCount: number;

  /** Number of violations */
  violationCount: number;

  /** Add an audit event */
  addAuditEvent(event: AuditEvent): void;

  /** Record a blocked tool */
  recordBlocked(toolName: string, decision: Decision): void;

  /** Get a summary of the security state */
  getSummary(): ContextSummary;
}

/**
 * Summary of security context state
 */
export interface ContextSummary {
  contextId: string;
  sessionId: string;
  duration: number;
  checkCount: number;
  violationCount: number;
  blockedTools: string[];
  warnings: number;
}

// =============================================================================
// Tool Call Abstraction
// =============================================================================

/**
 * Generic tool call representation (framework-agnostic)
 */
export interface GenericToolCall {
  /** Unique call ID */
  id: string;

  /** Tool name */
  name: string;

  /** Normalized parameters */
  parameters: Record<string, unknown>;

  /** Raw parameters as received from framework */
  rawParameters?: unknown;

  /** Tool call timestamp */
  timestamp: Date;

  /** Source framework */
  source: string;

  /** Additional metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Result of intercepting a tool call
 */
export interface InterceptResult {
  /** Whether to proceed with execution */
  proceed: boolean;

  /** Modified parameters (if any) */
  modifiedParameters?: Record<string, unknown>;

  /** Replacement result (skip execution) */
  replacementResult?: unknown;

  /** Warning to include with result */
  warning?: string;

  /** The policy decision */
  decision: Decision;

  /** Processing duration in ms */
  duration: number;
}

/**
 * Processed output after sanitization
 */
export interface ProcessedOutput {
  /** Sanitized output */
  output: unknown;

  /** Whether output was modified */
  modified: boolean;

  /** Redaction details */
  redactions?: RedactionInfo[];

  /** Post-execution decision (if different from pre) */
  postDecision?: Decision;
}

/**
 * Information about a redaction
 */
export interface RedactionInfo {
  /** Type of redacted content */
  type: 'secret' | 'pii' | 'sensitive';

  /** Pattern that matched */
  pattern: string;

  /** Location in output */
  location?: string;
}

// =============================================================================
// Tool Interceptor
// =============================================================================

/**
 * Tool interceptor interface
 */
export interface ToolInterceptor<TInput = unknown, TOutput = unknown> {
  /** Intercept before tool execution */
  beforeExecute(
    toolName: string,
    input: TInput,
    context: SecurityContext,
  ): Promise<InterceptResult>;

  /** Process after tool execution */
  afterExecute(
    toolName: string,
    input: TInput,
    output: TOutput,
    context: SecurityContext,
  ): Promise<ProcessedOutput>;

  /** Handle tool execution error */
  onError(
    toolName: string,
    input: TInput,
    error: Error,
    context: SecurityContext,
  ): Promise<void>;
}

// =============================================================================
// Output Sanitizer
// =============================================================================

/**
 * Output sanitizer interface
 */
export interface OutputSanitizer<T = unknown> {
  /** Sanitize output value */
  sanitize(output: T, context: SecurityContext): T;

  /** Check if output contains sensitive data */
  containsSensitive(output: T): boolean;

  /** Get redaction info for output */
  getRedactions(output: T): RedactionInfo[];
}

// =============================================================================
// Audit Logger
// =============================================================================

/**
 * Audit event types
 */
export type AuditEventType =
  | 'tool_call_start'
  | 'tool_call_blocked'
  | 'tool_call_allowed'
  | 'tool_call_warning'
  | 'tool_call_end'
  | 'tool_call_error'
  | 'output_sanitized'
  | 'session_start'
  | 'session_end';

/**
 * Audit event structure
 */
export interface AuditEvent {
  /** Event ID */
  id: string;

  /** Event type */
  type: AuditEventType;

  /** Event timestamp */
  timestamp: Date;

  /** Context ID */
  contextId: string;

  /** Session ID */
  sessionId: string;

  /** Tool name (if applicable) */
  toolName?: string;

  /** Tool parameters (if configured) */
  parameters?: Record<string, unknown>;

  /** Tool output (if configured) */
  output?: unknown;

  /** Policy decision */
  decision?: Decision;

  /** Additional details */
  details?: Record<string, unknown>;
}

/**
 * Audit logger interface
 */
export interface AuditLogger {
  /** Log an audit event */
  log(event: AuditEvent): Promise<void>;

  /** Get events for a session */
  getSessionEvents(sessionId: string): Promise<AuditEvent[]>;

  /** Get events for a context */
  getContextEvents(contextId: string): Promise<AuditEvent[]>;

  /** Export events in a format */
  export(format: 'json' | 'csv' | 'jsonl'): Promise<string>;

  /** Clear old events */
  prune(olderThan: Date): Promise<number>;
}

// =============================================================================
// Framework Hooks
// =============================================================================

/**
 * Framework-specific hooks
 */
export interface FrameworkHooks<TContext = unknown> {
  /** Create framework-native callback handler */
  createCallbackHandler?(): unknown;

  /** Wrap a framework-native tool */
  wrapTool?<T>(tool: T): T;

  /** Inject security into framework context */
  injectIntoContext?(context: TContext): TContext;

  /** Extract security-relevant info from context */
  extractFromContext?(context: TContext): Record<string, unknown>;
}

// =============================================================================
// Session Summary
// =============================================================================

/**
 * Summary of a completed session
 */
export interface SessionSummary {
  /** Session ID */
  sessionId: string;

  /** Start time */
  startTime: Date;

  /** End time */
  endTime: Date;

  /** Duration in ms */
  duration: number;

  /** Total tool calls */
  totalToolCalls: number;

  /** Blocked tool calls */
  blockedToolCalls: number;

  /** Warnings issued */
  warningsIssued: number;

  /** Tools used */
  toolsUsed: string[];

  /** Tools blocked */
  toolsBlocked: string[];

  /** Audit events */
  auditEvents: AuditEvent[];

  /** Policy used */
  policy: string;

  /** Mode used */
  mode: string;
}
```

## Base Implementations

### BaseToolInterceptor

```typescript
import { PolicyEngine, Decision, PolicyEvent } from '@clawdstrike/openclaw';

/**
 * Base implementation of ToolInterceptor
 */
export class BaseToolInterceptor implements ToolInterceptor {
  protected readonly engine: PolicyEngine;
  protected readonly config: AdapterConfig;
  protected readonly sanitizer: OutputSanitizer;
  protected readonly eventFactory: PolicyEventFactory;

  constructor(
    engine: PolicyEngine,
    config: AdapterConfig,
    sanitizer?: OutputSanitizer,
  ) {
    this.engine = engine;
    this.config = config;
    this.sanitizer = sanitizer ?? new DefaultOutputSanitizer(engine);
    this.eventFactory = new PolicyEventFactory();
  }

  async beforeExecute(
    toolName: string,
    input: unknown,
    context: SecurityContext,
  ): Promise<InterceptResult> {
    const startTime = Date.now();

    // Check exclusions
    if (this.config.excludedTools?.includes(toolName)) {
      return {
        proceed: true,
        decision: { allowed: true, denied: false, warn: false },
        duration: Date.now() - startTime,
      };
    }

    // Normalize tool name
    const normalizedName = this.config.normalizeToolName?.(toolName) ?? toolName;

    // Create policy event
    const params = this.normalizeParams(input);
    const event = this.eventFactory.create(normalizedName, params);

    // Notify handler
    this.config.handlers?.onBeforeEvaluate?.({
      id: event.eventId,
      name: normalizedName,
      parameters: params,
      timestamp: new Date(),
      source: 'generic',
    });

    // Evaluate policy
    const decision = await this.engine.evaluate(event);
    context.checkCount++;

    // Notify handler
    this.config.handlers?.onAfterEvaluate?.(
      { id: event.eventId, name: normalizedName, parameters: params, timestamp: new Date(), source: 'generic' },
      decision,
    );

    // Handle decision
    if (decision.denied) {
      context.violationCount++;
      context.recordBlocked(normalizedName, decision);

      this.config.handlers?.onBlocked?.(
        { id: event.eventId, name: normalizedName, parameters: params, timestamp: new Date(), source: 'generic' },
        decision,
      );

      // Add audit event
      context.addAuditEvent({
        id: `${event.eventId}-blocked`,
        type: 'tool_call_blocked',
        timestamp: new Date(),
        contextId: context.id,
        sessionId: context.sessionId,
        toolName: normalizedName,
        parameters: this.config.audit?.logParameters ? params : undefined,
        decision,
      });

      if (this.config.blockOnViolation !== false) {
        return {
          proceed: false,
          decision,
          duration: Date.now() - startTime,
        };
      }
    }

    if (decision.warn) {
      this.config.handlers?.onWarning?.(
        { id: event.eventId, name: normalizedName, parameters: params, timestamp: new Date(), source: 'generic' },
        decision,
      );

      context.addAuditEvent({
        id: `${event.eventId}-warning`,
        type: 'tool_call_warning',
        timestamp: new Date(),
        contextId: context.id,
        sessionId: context.sessionId,
        toolName: normalizedName,
        decision,
      });
    }

    // Add start audit event
    context.addAuditEvent({
      id: `${event.eventId}-start`,
      type: 'tool_call_start',
      timestamp: new Date(),
      contextId: context.id,
      sessionId: context.sessionId,
      toolName: normalizedName,
      parameters: this.config.audit?.logParameters ? params : undefined,
      decision,
    });

    return {
      proceed: true,
      decision,
      warning: decision.warn ? decision.message : undefined,
      duration: Date.now() - startTime,
    };
  }

  async afterExecute(
    toolName: string,
    input: unknown,
    output: unknown,
    context: SecurityContext,
  ): Promise<ProcessedOutput> {
    let processedOutput = output;
    let modified = false;
    let redactions: RedactionInfo[] = [];

    // Sanitize output if enabled
    if (this.config.sanitizeOutputs !== false) {
      const sanitized = this.sanitizer.sanitize(output, context);
      if (sanitized !== output) {
        processedOutput = sanitized;
        modified = true;
        redactions = this.sanitizer.getRedactions(output);
      }
    }

    // Add end audit event
    context.addAuditEvent({
      id: `${context.id}-${Date.now()}-end`,
      type: 'tool_call_end',
      timestamp: new Date(),
      contextId: context.id,
      sessionId: context.sessionId,
      toolName,
      output: this.config.audit?.logOutputs ? processedOutput : undefined,
      details: modified ? { redactions } : undefined,
    });

    return {
      output: processedOutput,
      modified,
      redactions,
    };
  }

  async onError(
    toolName: string,
    input: unknown,
    error: Error,
    context: SecurityContext,
  ): Promise<void> {
    this.config.handlers?.onError?.(error, {
      id: `${context.id}-${Date.now()}`,
      name: toolName,
      parameters: this.normalizeParams(input),
      timestamp: new Date(),
      source: 'generic',
    });

    context.addAuditEvent({
      id: `${context.id}-${Date.now()}-error`,
      type: 'tool_call_error',
      timestamp: new Date(),
      contextId: context.id,
      sessionId: context.sessionId,
      toolName,
      details: { error: error.message },
    });
  }

  protected normalizeParams(input: unknown): Record<string, unknown> {
    if (typeof input === 'object' && input !== null) {
      return input as Record<string, unknown>;
    }
    if (typeof input === 'string') {
      try {
        return JSON.parse(input);
      } catch {
        return { raw: input };
      }
    }
    return { value: input };
  }
}
```

### DefaultOutputSanitizer

```typescript
import { PolicyEngine } from '@clawdstrike/openclaw';

/**
 * Default output sanitizer implementation
 */
export class DefaultOutputSanitizer implements OutputSanitizer {
  private readonly engine: PolicyEngine;

  constructor(engine: PolicyEngine) {
    this.engine = engine;
  }

  sanitize<T>(output: T, context: SecurityContext): T {
    if (output === null || output === undefined) {
      return output;
    }

    if (typeof output === 'string') {
      return this.engine.redactSecrets(output) as unknown as T;
    }

    if (Array.isArray(output)) {
      return output.map(item => this.sanitize(item, context)) as unknown as T;
    }

    if (typeof output === 'object') {
      const sanitized: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(output as Record<string, unknown>)) {
        sanitized[key] = this.sanitize(value, context);
      }
      return sanitized as T;
    }

    return output;
  }

  containsSensitive<T>(output: T): boolean {
    const str = typeof output === 'string' ? output : JSON.stringify(output);
    const redacted = this.engine.redactSecrets(str);
    return redacted !== str;
  }

  getRedactions<T>(output: T): RedactionInfo[] {
    // This would need pattern-specific tracking in the engine
    // Simplified implementation
    const redactions: RedactionInfo[] = [];

    if (this.containsSensitive(output)) {
      redactions.push({
        type: 'secret',
        pattern: 'detected',
      });
    }

    return redactions;
  }
}
```

### PolicyEventFactory

```typescript
import { PolicyEvent } from '@clawdstrike/openclaw';

// EventType is derived from PolicyEvent for consistency across all adapters
type EventType = PolicyEvent['eventType'];

/**
 * Factory for creating policy events from tool calls
 */
export class PolicyEventFactory {
  private readonly toolTypeMapping: Map<RegExp, EventType> = new Map([
    [/read|cat|get_file|load/i, 'file_read'],
    [/write|save|create_file|store/i, 'file_write'],
    [/exec|shell|bash|command|run/i, 'command_exec'],
    [/fetch|http|request|curl|wget|browse/i, 'network_egress'],
    [/patch|diff|apply/i, 'patch_apply'],
  ]);

  /**
   * Create a policy event from tool call
   */
  create(
    toolName: string,
    parameters: Record<string, unknown>,
    sessionId?: string,
  ): PolicyEvent {
    const eventType = this.inferEventType(toolName, parameters);
    const eventId = this.generateEventId();

    return {
      eventId,
      eventType,
      timestamp: new Date().toISOString(),
      sessionId,
      data: this.createEventData(eventType, toolName, parameters),
      metadata: {
        source: 'generic-adapter',
        toolName,
      },
    };
  }

  /**
   * Infer event type from tool name and parameters
   */
  inferEventType(
    toolName: string,
    parameters: Record<string, unknown>,
  ): EventType {
    for (const [pattern, eventType] of this.toolTypeMapping) {
      if (pattern.test(toolName)) {
        return eventType;
      }
    }

    // Check parameters for hints
    if (parameters.path || parameters.file || parameters.filepath) {
      if (parameters.content || parameters.data) {
        return 'file_write';
      }
      return 'file_read';
    }

    if (parameters.url || parameters.endpoint || parameters.host) {
      return 'network_egress';
    }

    if (parameters.command || parameters.cmd) {
      return 'command_exec';
    }

    return 'tool_call';
  }

  /**
   * Create event data based on type
   */
  private createEventData(
    eventType: EventType,
    toolName: string,
    parameters: Record<string, unknown>,
  ): PolicyEvent['data'] {
    switch (eventType) {
      case 'file_read':
      case 'file_write':
        return {
          type: 'file',
          path: String(
            parameters.path ??
            parameters.file ??
            parameters.filepath ??
            parameters.filename ??
            ''
          ),
          operation: eventType === 'file_read' ? 'read' : 'write',
        };

      case 'command_exec': {
        const cmdStr = String(parameters.command ?? parameters.cmd ?? '');
        const parts = cmdStr.split(/\s+/);
        return {
          type: 'command',
          command: parts[0] ?? '',
          args: parts.slice(1),
          workingDir: parameters.cwd as string | undefined,
        };
      }

      case 'network_egress': {
        const url = String(
          parameters.url ??
          parameters.endpoint ??
          parameters.href ??
          ''
        );
        try {
          const parsed = new URL(url.includes('://') ? url : `https://${url}`);
          return {
            type: 'network',
            host: parsed.hostname,
            port: parseInt(parsed.port) || (parsed.protocol === 'https:' ? 443 : 80),
            url,
          };
        } catch {
          return {
            type: 'network',
            host: String(parameters.host ?? url),
            port: Number(parameters.port ?? 443),
            url,
          };
        }
      }

      case 'patch_apply':
        return {
          type: 'patch',
          filePath: String(parameters.path ?? parameters.file ?? ''),
          patchContent: String(parameters.patch ?? parameters.diff ?? parameters.content ?? ''),
        };

      default:
        return {
          type: 'tool',
          toolName,
          parameters,
        };
    }
  }

  private generateEventId(): string {
    return `evt-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
  }

  /**
   * Register a custom tool type mapping
   */
  registerMapping(pattern: RegExp, eventType: EventType): void {
    this.toolTypeMapping.set(pattern, eventType);
  }
}
```

### InMemoryAuditLogger

```typescript
/**
 * In-memory audit logger implementation
 */
export class InMemoryAuditLogger implements AuditLogger {
  private events: AuditEvent[] = [];
  private readonly maxEvents: number;

  constructor(maxEvents = 10000) {
    this.maxEvents = maxEvents;
  }

  async log(event: AuditEvent): Promise<void> {
    this.events.push(event);

    // Prune if over limit
    if (this.events.length > this.maxEvents) {
      this.events = this.events.slice(-this.maxEvents);
    }
  }

  async getSessionEvents(sessionId: string): Promise<AuditEvent[]> {
    return this.events.filter(e => e.sessionId === sessionId);
  }

  async getContextEvents(contextId: string): Promise<AuditEvent[]> {
    return this.events.filter(e => e.contextId === contextId);
  }

  async export(format: 'json' | 'csv' | 'jsonl'): Promise<string> {
    switch (format) {
      case 'json':
        return JSON.stringify(this.events, null, 2);

      case 'jsonl':
        return this.events.map(e => JSON.stringify(e)).join('\n');

      case 'csv': {
        const headers = ['id', 'type', 'timestamp', 'contextId', 'sessionId', 'toolName', 'decision'];
        const rows = this.events.map(e => [
          e.id,
          e.type,
          e.timestamp.toISOString(),
          e.contextId,
          e.sessionId,
          e.toolName ?? '',
          e.decision?.denied ? 'denied' : e.decision?.warn ? 'warn' : 'allowed',
        ]);
        return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
      }
    }
  }

  async prune(olderThan: Date): Promise<number> {
    const originalLength = this.events.length;
    this.events = this.events.filter(e => e.timestamp > olderThan);
    return originalLength - this.events.length;
  }
}
```

## Creating a Framework Adapter

### Step-by-Step Guide

```typescript
import {
  FrameworkAdapter,
  AdapterConfig,
  SecurityContext,
  GenericToolCall,
  InterceptResult,
  ProcessedOutput,
  SessionSummary,
  FrameworkHooks,
  BaseToolInterceptor,
  InMemoryAuditLogger,
  DefaultOutputSanitizer,
} from '@clawdstrike/adapter-core';
import { PolicyEngine } from '@clawdstrike/openclaw';

/**
 * Example: Creating an adapter for a hypothetical framework "AgentX"
 */

// Step 1: Define framework-specific context type
interface AgentXContext {
  agent: AgentXAgent;
  conversation: AgentXConversation;
  tools: AgentXTool[];
}

// Step 2: Implement the FrameworkAdapter interface
export class AgentXAdapter implements FrameworkAdapter<AgentXContext> {
  readonly name = 'agentx';
  readonly version = '1.0.0';

  private engine!: PolicyEngine;
  private config!: AdapterConfig;
  private interceptor!: BaseToolInterceptor;
  private auditLogger!: AuditLogger;
  private contexts: Map<string, SecurityContext> = new Map();

  async initialize(config: AdapterConfig): Promise<void> {
    this.config = config;
    this.engine = new PolicyEngine(config);
    this.auditLogger = config.audit?.logger ?? new InMemoryAuditLogger();
    this.interceptor = new BaseToolInterceptor(
      this.engine,
      config,
      new DefaultOutputSanitizer(this.engine),
    );
  }

  createContext(metadata?: Record<string, unknown>): SecurityContext {
    const id = `ctx-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
    const sessionId = (metadata?.sessionId as string) ?? id;

    const context: SecurityContext = {
      id,
      sessionId,
      userId: metadata?.userId as string | undefined,
      createdAt: new Date(),
      policy: this.engine.getPolicy(),
      metadata: metadata ?? {},
      auditEvents: [],
      blockedTools: new Set(),
      checkCount: 0,
      violationCount: 0,

      addAuditEvent(event: AuditEvent) {
        this.auditEvents.push(event);
      },

      recordBlocked(toolName: string, decision: Decision) {
        this.blockedTools.add(toolName);
      },

      getSummary(): ContextSummary {
        return {
          contextId: this.id,
          sessionId: this.sessionId,
          duration: Date.now() - this.createdAt.getTime(),
          checkCount: this.checkCount,
          violationCount: this.violationCount,
          blockedTools: Array.from(this.blockedTools),
          warnings: this.auditEvents.filter(e => e.type === 'tool_call_warning').length,
        };
      },
    };

    this.contexts.set(id, context);
    return context;
  }

  async interceptToolCall(
    context: SecurityContext,
    toolCall: GenericToolCall,
  ): Promise<InterceptResult> {
    return this.interceptor.beforeExecute(
      toolCall.name,
      toolCall.parameters,
      context,
    );
  }

  async processOutput(
    context: SecurityContext,
    toolCall: GenericToolCall,
    output: unknown,
  ): Promise<ProcessedOutput> {
    return this.interceptor.afterExecute(
      toolCall.name,
      toolCall.parameters,
      output,
      context,
    );
  }

  async finalizeContext(context: SecurityContext): Promise<SessionSummary> {
    // Log all events to audit logger
    for (const event of context.auditEvents) {
      await this.auditLogger.log(event);
    }

    // Clean up
    this.contexts.delete(context.id);

    return {
      sessionId: context.sessionId,
      startTime: context.createdAt,
      endTime: new Date(),
      duration: Date.now() - context.createdAt.getTime(),
      totalToolCalls: context.auditEvents.filter(e => e.type === 'tool_call_start').length,
      blockedToolCalls: context.violationCount,
      warningsIssued: context.auditEvents.filter(e => e.type === 'tool_call_warning').length,
      toolsUsed: [...new Set(context.auditEvents.filter(e => e.toolName).map(e => e.toolName!))],
      toolsBlocked: Array.from(context.blockedTools),
      auditEvents: context.auditEvents,
      policy: this.config.policy ?? 'default',
      mode: this.config.mode ?? 'deterministic',
    };
  }

  getEngine(): PolicyEngine {
    return this.engine;
  }

  getHooks(): FrameworkHooks<AgentXContext> {
    return {
      // Create a callback handler for AgentX
      createCallbackHandler: () => {
        return new AgentXSecurityCallback(this);
      },

      // Wrap an AgentX tool
      wrapTool: <T extends AgentXTool>(tool: T): T => {
        const originalExecute = tool.execute.bind(tool);
        const adapter = this;

        tool.execute = async function (params: unknown, ctx: AgentXContext) {
          const securityContext = adapter.contexts.get(ctx.conversation.id)
            ?? adapter.createContext({ sessionId: ctx.conversation.id });

          const toolCall: GenericToolCall = {
            id: `${tool.name}-${Date.now()}`,
            name: tool.name,
            parameters: params as Record<string, unknown>,
            timestamp: new Date(),
            source: 'agentx',
          };

          const intercept = await adapter.interceptToolCall(securityContext, toolCall);

          if (!intercept.proceed) {
            throw new Error(`Tool blocked: ${intercept.decision.reason}`);
          }

          const result = await originalExecute(intercept.modifiedParameters ?? params, ctx);

          const processed = await adapter.processOutput(securityContext, toolCall, result);

          return processed.output;
        };

        return tool;
      },

      // Inject security into AgentX context
      injectIntoContext: (ctx: AgentXContext): AgentXContext => {
        const securityContext = this.createContext({
          sessionId: ctx.conversation.id,
        });

        // Inject security prompt into agent
        ctx.agent.systemPrompt = this.createSecurityPrompt() + '\n\n' + ctx.agent.systemPrompt;

        return ctx;
      },
    };
  }

  private createSecurityPrompt(): string {
    const policy = this.engine.getPolicy();
    const guards = this.engine.enabledGuards();

    return `## Security Constraints

Active guards: ${guards.join(', ')}

Forbidden paths: ${policy.filesystem?.forbidden_paths?.join(', ') ?? 'None'}
Network mode: ${policy.egress?.mode ?? 'open'}

Always verify actions comply with security policy.`;
  }
}

// Step 3: Create framework-specific callback handler
class AgentXSecurityCallback {
  constructor(private adapter: AgentXAdapter) {}

  onToolStart(tool: AgentXTool, params: unknown, ctx: AgentXContext): void {
    // Framework-specific pre-execution hook
  }

  onToolEnd(tool: AgentXTool, result: unknown, ctx: AgentXContext): void {
    // Framework-specific post-execution hook
  }
}
```

## Usage Example

```typescript
import { AgentXAdapter } from '@clawdstrike/agentx';
import { AgentX, Tool, Conversation } from 'agentx';

// Initialize adapter
const adapter = new AgentXAdapter();
await adapter.initialize({
  policy: 'clawdstrike:ai-agent',
  mode: 'deterministic',
  blockOnViolation: true,
  sanitizeOutputs: true,
  handlers: {
    onBlocked: (toolCall, decision) => {
      console.error(`Blocked: ${toolCall.name} - ${decision.reason}`);
    },
  },
});

// Get framework hooks
const hooks = adapter.getHooks();

// Wrap tools
const secureTools = myTools.map(tool => hooks.wrapTool!(tool));

// Create agent with security
const agent = new AgentX({
  tools: secureTools,
  callback: hooks.createCallbackHandler!(),
});

// Inject security into context
const ctx = hooks.injectIntoContext!({
  agent,
  conversation: new Conversation(),
  tools: secureTools,
});

// Run agent
const result = await agent.run('Help me with a task', ctx);

// Get session summary
const context = adapter.contexts.values().next().value;
if (context) {
  const summary = await adapter.finalizeContext(context);
  console.log('Session Summary:', summary);
}
```

## Testing the Adapter

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import {
  BaseToolInterceptor,
  DefaultOutputSanitizer,
  PolicyEventFactory,
  InMemoryAuditLogger,
} from '@clawdstrike/adapter-core';
import { PolicyEngine } from '@clawdstrike/openclaw';

describe('BaseToolInterceptor', () => {
  let engine: PolicyEngine;
  let interceptor: BaseToolInterceptor;

  beforeEach(() => {
    engine = new PolicyEngine({ policy: 'clawdstrike:ai-agent' });
    interceptor = new BaseToolInterceptor(engine, {
      blockOnViolation: true,
    });
  });

  it('should block forbidden paths', async () => {
    const context = createMockContext();

    const result = await interceptor.beforeExecute(
      'read_file',
      { path: '~/.ssh/id_rsa' },
      context,
    );

    expect(result.proceed).toBe(false);
    expect(result.decision.denied).toBe(true);
  });

  it('should allow safe paths', async () => {
    const context = createMockContext();

    const result = await interceptor.beforeExecute(
      'read_file',
      { path: './documents/readme.txt' },
      context,
    );

    expect(result.proceed).toBe(true);
    expect(result.decision.denied).toBe(false);
  });
});

describe('DefaultOutputSanitizer', () => {
  let sanitizer: DefaultOutputSanitizer;

  beforeEach(() => {
    const engine = new PolicyEngine({});
    sanitizer = new DefaultOutputSanitizer(engine);
  });

  it('should redact secrets', () => {
    const output = 'API key: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
    const context = createMockContext();

    const sanitized = sanitizer.sanitize(output, context);

    expect(sanitized).not.toContain('ghp_');
  });

  it('should detect sensitive data', () => {
    const output = { key: 'sk-proj-xxxxxxxxxxxxxxxxxxxxxxxx' };

    expect(sanitizer.containsSensitive(output)).toBe(true);
  });
});

describe('PolicyEventFactory', () => {
  let factory: PolicyEventFactory;

  beforeEach(() => {
    factory = new PolicyEventFactory();
  });

  it('should infer file_read from tool name', () => {
    const eventType = factory.inferEventType('read_file', {});
    expect(eventType).toBe('file_read');
  });

  it('should infer network_egress from URL parameter', () => {
    const eventType = factory.inferEventType('custom_tool', {
      url: 'https://example.com',
    });
    expect(eventType).toBe('network_egress');
  });

  it('should create correct event data', () => {
    const event = factory.create('bash', { command: 'ls -la /tmp' });

    expect(event.eventType).toBe('command_exec');
    expect(event.data.type).toBe('command');
    expect((event.data as any).command).toBe('ls');
    expect((event.data as any).args).toContain('-la');
  });
});
```

## Implementation Phases

### Phase 1: Core Interfaces (Week 1)

- [ ] Define all TypeScript interfaces
- [ ] Create type exports
- [ ] Write interface documentation

### Phase 2: Base Implementations (Week 2-3)

- [ ] BaseToolInterceptor
- [ ] DefaultOutputSanitizer
- [ ] PolicyEventFactory
- [ ] InMemoryAuditLogger
- [ ] SecurityContext implementation

### Phase 3: Utilities (Week 4)

- [ ] Configuration merging
- [ ] Tool name normalization
- [ ] Security prompt generation
- [ ] Event type inference

### Phase 4: Testing (Week 5)

- [ ] Unit tests for all implementations
- [ ] Integration tests
- [ ] Mock implementations for testing
- [ ] Documentation and examples
