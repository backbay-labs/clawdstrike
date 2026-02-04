# LangChain/LangGraph Integration

## Overview

LangChain is the most widely adopted framework for building LLM-powered applications, with LangGraph providing advanced state machine capabilities for complex agent workflows. This document details the architecture for integrating Clawdstrike's security enforcement into both LangChain tools and LangGraph nodes.

## Version Compatibility

| Package | Minimum Version | Tested Up To | Notes |
|---------|----------------|--------------|-------|
| **@langchain/core** | 0.2.0 | 0.3.x | Required for callback handler API |
| **@langchain/langgraph** | 0.0.20 | 0.2.x | Required for StateGraph integration |
| **langchain** | 0.2.0 | 0.3.x | Agent executor and chain utilities |
| **@clawdstrike/openclaw** | 0.1.0 | 0.x | Core policy engine |

> **Note**: LangChain's API evolves rapidly. The `BaseCallbackHandler` interface has been stable since 0.2.x, but check release notes for breaking changes in minor versions.

## Problem Statement

### Challenges with LangChain Security

1. **Tool Execution Transparency**: LangChain tools execute arbitrary code with full system access; there's no built-in mechanism to validate tool inputs or outputs against security policies.

2. **Chain Composition Complexity**: Complex chains may invoke multiple tools in sequence, making it difficult to track the security implications of the overall workflow.

3. **Agent Autonomy**: ReAct and Plan-and-Execute agents can decide which tools to call based on LLM reasoning, creating unpredictable execution paths.

4. **Memory Persistence**: Conversation memory may inadvertently store sensitive information that persists across sessions.

5. **LangGraph State Management**: Graph-based workflows can have multiple execution paths, each requiring security validation.

### Use Cases

| Use Case | Security Requirement |
|----------|---------------------|
| Code generation agent | Block execution of dangerous commands, validate patches |
| Research assistant | Control network egress to approved domains only |
| Data analysis agent | Prevent access to sensitive file paths |
| Customer service bot | Redact PII from tool outputs |
| DevOps automation | Restrict command execution to allowed patterns |

## LangChain Tool Call Architecture

### Native Tool Execution Flow

```
┌─────────────────┐    ┌──────────────┐    ┌──────────────┐
│   LLM/Agent     │───>│  Tool Schema │───>│ Tool._run()  │
│  (decides call) │    │  (validate)  │    │  (execute)   │
└─────────────────┘    └──────────────┘    └──────────────┘
                                                   │
                                                   v
                                          ┌──────────────┐
                                          │   Result     │
                                          │  (returned)  │
                                          └──────────────┘
```

### Interception Points in LangChain

1. **Callbacks**: `BaseCallbackHandler` provides hooks for tool start/end/error events
2. **Tool Wrappers**: Custom `BaseTool` subclasses can wrap existing tools
3. **RunnableConfig**: Async context for passing security context through chains
4. **Custom Runnable**: `Runnable` interface allows wrapping any chain component

## Proposed Architecture

### Clawdstrike LangChain Callback Handler

```
┌─────────────────┐    ┌──────────────────────┐    ┌──────────────┐
│   LLM/Agent     │───>│ ClawdstrikeCallback  │───>│ Tool._run()  │
│  (decides call) │    │                      │    │  (execute)   │
└─────────────────┘    │ ┌──────────────────┐ │    └──────────────┘
                       │ │ on_tool_start    │ │           │
                       │ │ - Policy Check   │ │           │
                       │ │ - Block if deny  │ │           v
                       │ └──────────────────┘ │    ┌──────────────┐
                       │ ┌──────────────────┐ │    │   Result     │
                       │ │ on_tool_end      │◄├────│  (returned)  │
                       │ │ - Redact secrets │ │    └──────────────┘
                       │ │ - Audit log      │ │
                       │ └──────────────────┘ │
                       └──────────────────────┘
```

### Architecture Components

```typescript
// Core integration layer
┌─────────────────────────────────────────────────────────────────┐
│                    @clawdstrike/langchain                        │
├─────────────────────────────────────────────────────────────────┤
│  ClawdstrikeCallbackHandler                                      │
│  ├── onToolStart(tool, input) -> PolicyDecision                 │
│  ├── onToolEnd(tool, output) -> SanitizedOutput                 │
│  ├── onToolError(tool, error) -> void                           │
│  ├── onChainStart(chain, inputs) -> void                        │
│  └── onChainEnd(chain, outputs) -> void                         │
├─────────────────────────────────────────────────────────────────┤
│  SecureToolWrapper                                               │
│  ├── wrap<T extends BaseTool>(tool: T) -> SecureTool<T>         │
│  ├── createSecureTool(config) -> SecureTool                     │
│  └── batchWrap(tools[]) -> SecureTool[]                         │
├─────────────────────────────────────────────────────────────────┤
│  LangGraphSecurityNode                                           │
│  ├── createGuardNode(policy) -> StateGraphNode                  │
│  ├── wrapToolNode(node) -> SecureToolNode                       │
│  └── createPolicyCheckpoint() -> CheckpointNode                 │
├─────────────────────────────────────────────────────────────────┤
│  Utilities                                                       │
│  ├── createSecureRunnableConfig(policy) -> RunnableConfig       │
│  ├── getSecurityContext(config) -> SecurityContext              │
│  └── withPolicyOverride(config, policy) -> RunnableConfig       │
└─────────────────────────────────────────────────────────────────┘
```

## API Design

### TypeScript Interfaces

```typescript
import { BaseCallbackHandler } from '@langchain/core/callbacks/base';
import { BaseTool, StructuredTool } from '@langchain/core/tools';
import { RunnableConfig } from '@langchain/core/runnables';
import { StateGraph, StateGraphNode } from '@langchain/langgraph';
import { PolicyEngine, Decision, ClawdstrikeConfig } from '@clawdstrike/openclaw';

/**
 * Configuration for the LangChain integration
 */
export interface LangChainClawdstrikeConfig extends ClawdstrikeConfig {
  /** Whether to block execution on policy violation (default: true) */
  blockOnViolation?: boolean;

  /** Whether to redact secrets from tool outputs (default: true) */
  redactSecrets?: boolean;

  /** Custom tool name mapping for policy evaluation */
  toolNameMapping?: Record<string, string>;

  /** Tools to exclude from security checks */
  excludedTools?: string[];

  /** Whether to inject security context into tool inputs */
  injectSecurityContext?: boolean;

  /** Callback for custom violation handling */
  onViolation?: (decision: Decision, toolName: string, input: unknown) => void;

  /** Callback for audit logging */
  onAuditEvent?: (event: AuditEvent) => void;
}

/**
 * Security context passed through LangChain runnables
 */
export interface SecurityContext {
  sessionId: string;
  userId?: string;
  policyOverrides?: Partial<Policy>;
  allowedTools?: string[];
  maxExecutionDepth?: number;
  currentDepth?: number;
}

/**
 * Audit event for tool execution
 */
export interface AuditEvent {
  timestamp: string;
  sessionId: string;
  toolName: string;
  input: Record<string, unknown>;
  output?: unknown;
  decision: Decision;
  duration: number;
  error?: string;
}

/**
 * Result of a secured tool execution
 */
export interface SecureToolResult<T = unknown> {
  success: boolean;
  result?: T;
  blocked: boolean;
  decision: Decision;
  redacted: boolean;
  originalOutput?: T;
}

/**
 * Wrapper for securing existing LangChain tools
 */
export interface SecureTool<T extends BaseTool = BaseTool> extends BaseTool {
  /** The wrapped original tool */
  readonly innerTool: T;

  /** Security configuration */
  readonly securityConfig: LangChainClawdstrikeConfig;

  /** Override security config for this execution */
  withConfig(config: Partial<LangChainClawdstrikeConfig>): SecureTool<T>;

  /** Get the last security decision */
  getLastDecision(): Decision | null;
}

/**
 * LangGraph node for security checkpoints
 */
export interface SecurityCheckpointNode {
  /** Node name in the graph */
  name: string;

  /** Evaluate state against policy */
  check(state: Record<string, unknown>): Promise<Decision>;

  /** Conditional edge based on policy decision */
  route(state: Record<string, unknown>): Promise<'allow' | 'block' | 'warn'>;
}
```

### Callback Handler Implementation

```typescript
import {
  BaseCallbackHandler,
  CallbackHandlerMethods,
} from '@langchain/core/callbacks/base';
import { Serialized } from '@langchain/core/load/serializable';
import { PolicyEngine, Decision, PolicyEvent } from '@clawdstrike/openclaw';

/**
 * Clawdstrike callback handler for LangChain
 *
 * Intercepts tool calls and enforces security policy.
 */
export class ClawdstrikeCallbackHandler extends BaseCallbackHandler {
  name = 'clawdstrike';

  private readonly engine: PolicyEngine;
  private readonly config: LangChainClawdstrikeConfig;
  private readonly pendingDecisions: Map<string, Decision> = new Map();
  private readonly auditEvents: AuditEvent[] = [];

  constructor(config: LangChainClawdstrikeConfig = {}) {
    super();
    this.config = {
      blockOnViolation: true,
      redactSecrets: true,
      excludedTools: [],
      ...config,
    };
    this.engine = new PolicyEngine(config);
  }

  /**
   * Called when a tool starts execution
   * This is our primary interception point for policy enforcement
   */
  async handleToolStart(
    tool: Serialized,
    input: string,
    runId: string,
    parentRunId?: string,
    tags?: string[],
    metadata?: Record<string, unknown>,
  ): Promise<void> {
    const toolName = this.resolveToolName(tool);
    const startTime = Date.now();

    // Skip excluded tools
    if (this.config.excludedTools?.includes(toolName)) {
      return;
    }

    // Parse input
    const parsedInput = this.parseToolInput(input);

    // Create policy event
    const event = this.createPolicyEvent(toolName, parsedInput, runId);

    // Evaluate policy
    const decision = await this.engine.evaluate(event);

    // Store decision for later retrieval
    this.pendingDecisions.set(runId, decision);

    // Log audit event
    const auditEvent: AuditEvent = {
      timestamp: new Date().toISOString(),
      sessionId: runId,
      toolName,
      input: parsedInput,
      decision,
      duration: Date.now() - startTime,
    };

    this.auditEvents.push(auditEvent);
    this.config.onAuditEvent?.(auditEvent);

    // Handle violation
    if (decision.denied && this.config.blockOnViolation) {
      this.config.onViolation?.(decision, toolName, parsedInput);

      // Throw to prevent tool execution
      throw new ClawdstrikeViolationError(
        `Tool '${toolName}' blocked by policy: ${decision.reason}`,
        decision,
      );
    }

    // Handle warning
    // Note: decision.message is an alias for decision.reason, commonly used in warning contexts
    if (decision.warn) {
      console.warn(
        `[clawdstrike] Warning for tool '${toolName}': ${decision.message ?? decision.reason}`,
      );
    }
  }

  /**
   * Called when a tool finishes execution
   * Used for output sanitization and audit logging
   */
  async handleToolEnd(
    output: string,
    runId: string,
    parentRunId?: string,
    tags?: string[],
  ): Promise<void> {
    const decision = this.pendingDecisions.get(runId);

    // Redact secrets from output
    if (this.config.redactSecrets && output) {
      const redacted = this.engine.redactSecrets(output);
      if (redacted !== output) {
        // Note: LangChain callbacks can't modify output directly
        // This would need to be handled via tool wrapper
        console.warn('[clawdstrike] Secrets detected in tool output (redaction via wrapper recommended)');
      }
    }

    // Update audit event with output
    const auditEvent = this.auditEvents.find(e => e.sessionId === runId);
    if (auditEvent) {
      auditEvent.output = output;
    }

    this.pendingDecisions.delete(runId);
  }

  /**
   * Called when a tool errors
   */
  async handleToolError(
    error: Error,
    runId: string,
    parentRunId?: string,
    tags?: string[],
  ): Promise<void> {
    const auditEvent = this.auditEvents.find(e => e.sessionId === runId);
    if (auditEvent) {
      auditEvent.error = error.message;
    }

    this.pendingDecisions.delete(runId);
  }

  /**
   * Get all audit events
   */
  getAuditEvents(): AuditEvent[] {
    return [...this.auditEvents];
  }

  /**
   * Clear audit events
   */
  clearAuditEvents(): void {
    this.auditEvents.length = 0;
  }

  // Private helper methods

  private resolveToolName(tool: Serialized): string {
    const name = tool.name ?? tool.id?.[tool.id.length - 1] ?? 'unknown';
    return this.config.toolNameMapping?.[name] ?? name;
  }

  private parseToolInput(input: string): Record<string, unknown> {
    try {
      return JSON.parse(input);
    } catch {
      return { raw: input };
    }
  }

  private createPolicyEvent(
    toolName: string,
    input: Record<string, unknown>,
    runId: string,
  ): PolicyEvent {
    // Infer event type from tool name
    const eventType = this.inferEventType(toolName, input);

    return {
      eventId: `${runId}-${Date.now()}`,
      eventType,
      timestamp: new Date().toISOString(),
      sessionId: runId,
      data: this.createEventData(eventType, toolName, input),
      metadata: { source: 'langchain', toolName },
    };
  }

  private inferEventType(
    toolName: string,
    input: Record<string, unknown>,
  ): PolicyEvent['eventType'] {
    const name = toolName.toLowerCase();

    if (name.includes('read') || name.includes('cat') || name.includes('get_file')) {
      return 'file_read';
    }
    if (name.includes('write') || name.includes('save') || name.includes('create_file')) {
      return 'file_write';
    }
    if (name.includes('bash') || name.includes('shell') || name.includes('exec')) {
      return 'command_exec';
    }
    if (name.includes('http') || name.includes('fetch') || name.includes('request')) {
      return 'network_egress';
    }
    if (name.includes('patch') || name.includes('diff')) {
      return 'patch_apply';
    }

    return 'tool_call';
  }

  private createEventData(
    eventType: PolicyEvent['eventType'],
    toolName: string,
    input: Record<string, unknown>,
  ): PolicyEvent['data'] {
    switch (eventType) {
      case 'file_read':
      case 'file_write':
        return {
          type: 'file',
          path: String(input.path ?? input.file_path ?? input.filename ?? ''),
          operation: eventType === 'file_read' ? 'read' : 'write',
        };

      case 'command_exec':
        return {
          type: 'command',
          command: String(input.command ?? input.cmd ?? ''),
          args: Array.isArray(input.args) ? input.args : [],
          workingDir: input.cwd as string | undefined,
        };

      case 'network_egress':
        const url = String(input.url ?? input.endpoint ?? '');
        try {
          const parsed = new URL(url);
          return {
            type: 'network',
            host: parsed.hostname,
            port: parseInt(parsed.port) || (parsed.protocol === 'https:' ? 443 : 80),
            url,
          };
        } catch {
          return {
            type: 'network',
            host: url,
            port: 443,
          };
        }

      case 'patch_apply':
        return {
          type: 'patch',
          filePath: String(input.file_path ?? input.path ?? ''),
          patchContent: String(input.patch ?? input.diff ?? input.content ?? ''),
        };

      default:
        return {
          type: 'tool',
          toolName,
          parameters: input,
        };
    }
  }
}

/**
 * Error thrown when a tool is blocked by policy
 */
export class ClawdstrikeViolationError extends Error {
  constructor(
    message: string,
    public readonly decision: Decision,
  ) {
    super(message);
    this.name = 'ClawdstrikeViolationError';
  }
}
```

### Secure Tool Wrapper

```typescript
import { BaseTool, ToolParams } from '@langchain/core/tools';
import { CallbackManagerForToolRun } from '@langchain/core/callbacks/manager';
import { PolicyEngine, Decision } from '@clawdstrike/openclaw';

/**
 * Wraps an existing LangChain tool with Clawdstrike security
 */
export function wrapTool<T extends BaseTool>(
  tool: T,
  config: LangChainClawdstrikeConfig = {},
): SecureTool<T> {
  const engine = new PolicyEngine(config);
  let lastDecision: Decision | null = null;

  // Create a new class that extends the original tool
  class WrappedSecureTool extends (tool.constructor as new (params: ToolParams) => T) {
    readonly innerTool = tool;
    readonly securityConfig = config;

    async _call(
      input: string,
      runManager?: CallbackManagerForToolRun,
    ): Promise<string> {
      // Pre-execution policy check
      const parsedInput = this.parseInput(input);
      const event = this.createPolicyEvent(parsedInput);
      const decision = await engine.evaluate(event);
      lastDecision = decision;

      if (decision.denied && config.blockOnViolation !== false) {
        throw new ClawdstrikeViolationError(
          `Tool '${tool.name}' blocked: ${decision.reason}`,
          decision,
        );
      }

      // Execute original tool
      let result = await (tool as any)._call(input, runManager);

      // Post-execution output sanitization
      if (config.redactSecrets !== false && typeof result === 'string') {
        result = engine.redactSecrets(result);
      }

      return result;
    }

    withConfig(overrides: Partial<LangChainClawdstrikeConfig>): SecureTool<T> {
      return wrapTool(tool, { ...config, ...overrides });
    }

    getLastDecision(): Decision | null {
      return lastDecision;
    }

    private parseInput(input: string): Record<string, unknown> {
      try {
        return JSON.parse(input);
      } catch {
        return { raw: input };
      }
    }

    private createPolicyEvent(input: Record<string, unknown>): PolicyEvent {
      return {
        eventId: `${tool.name}-${Date.now()}`,
        eventType: 'tool_call',
        timestamp: new Date().toISOString(),
        data: {
          type: 'tool',
          toolName: tool.name,
          parameters: input,
        },
      };
    }
  }

  // Copy over tool metadata
  const wrapped = new WrappedSecureTool({
    name: tool.name,
    description: tool.description,
    returnDirect: tool.returnDirect,
  });

  return wrapped as unknown as SecureTool<T>;
}

/**
 * Batch wrap multiple tools
 */
export function wrapTools<T extends BaseTool>(
  tools: T[],
  config: LangChainClawdstrikeConfig = {},
): SecureTool<T>[] {
  return tools.map(tool => wrapTool(tool, config));
}
```

### LangGraph Security Node

```typescript
import { StateGraph, END } from '@langchain/langgraph';
import { PolicyEngine, Decision, Policy } from '@clawdstrike/openclaw';

/**
 * Creates a security checkpoint node for LangGraph
 */
export function createSecurityCheckpoint(
  config: LangChainClawdstrikeConfig = {},
): SecurityCheckpointNode {
  const engine = new PolicyEngine(config);

  return {
    name: 'clawdstrike_checkpoint',

    async check(state: Record<string, unknown>): Promise<Decision> {
      // Extract pending tool calls from state
      const pendingTools = extractPendingTools(state);

      // Evaluate each tool call
      const decisions: Decision[] = [];
      for (const toolCall of pendingTools) {
        const event: PolicyEvent = {
          eventId: `checkpoint-${Date.now()}`,
          eventType: 'tool_call',
          timestamp: new Date().toISOString(),
          data: {
            type: 'tool',
            toolName: toolCall.name,
            parameters: toolCall.args,
          },
        };

        const decision = await engine.evaluate(event);
        decisions.push(decision);

        if (decision.denied) {
          break; // Fail fast
        }
      }

      // Return most severe decision
      return decisions.find(d => d.denied)
        ?? decisions.find(d => d.warn)
        ?? { allowed: true, denied: false, warn: false };
    },

    async route(state: Record<string, unknown>): Promise<'allow' | 'block' | 'warn'> {
      const decision = await this.check(state);

      if (decision.denied) return 'block';
      if (decision.warn) return 'warn';
      return 'allow';
    },
  };
}

/**
 * Wraps a LangGraph tool node with security checks
 */
export function wrapToolNode<S extends Record<string, unknown>>(
  graph: StateGraph<S>,
  nodeName: string,
  config: LangChainClawdstrikeConfig = {},
): void {
  const engine = new PolicyEngine(config);
  const originalNode = graph.nodes.get(nodeName);

  if (!originalNode) {
    throw new Error(`Node '${nodeName}' not found in graph`);
  }

  // Replace node with security-wrapped version
  graph.addNode(nodeName, async (state: S) => {
    // Pre-check
    const checkpoint = createSecurityCheckpoint(config);
    const decision = await checkpoint.check(state as Record<string, unknown>);

    if (decision.denied && config.blockOnViolation !== false) {
      // Return modified state indicating blocked execution
      return {
        ...state,
        __clawdstrike_blocked: true,
        __clawdstrike_reason: decision.reason,
      } as S;
    }

    // Execute original node
    const result = await originalNode(state);

    // Post-check and sanitization
    if (config.redactSecrets !== false && typeof result === 'object') {
      return sanitizeState(result as Record<string, unknown>, engine) as S;
    }

    return result;
  });
}

/**
 * Creates a complete secure workflow builder
 */
export function createSecureWorkflow<S extends Record<string, unknown>>(
  config: LangChainClawdstrikeConfig = {},
) {
  const engine = new PolicyEngine(config);
  const checkpoint = createSecurityCheckpoint(config);

  return {
    /**
     * Add security checkpoint after a node
     */
    addCheckpointAfter(
      graph: StateGraph<S>,
      afterNode: string,
      onBlock?: (state: S, decision: Decision) => S,
    ): void {
      const checkpointName = `${afterNode}_security_check`;

      graph.addNode(checkpointName, async (state: S) => {
        const decision = await checkpoint.check(state as Record<string, unknown>);

        if (decision.denied) {
          return onBlock?.(state, decision) ?? {
            ...state,
            __clawdstrike_blocked: true,
          } as S;
        }

        return state;
      });

      // Add conditional edge
      graph.addConditionalEdges(
        checkpointName,
        async (state: S) => {
          if ((state as any).__clawdstrike_blocked) {
            return END;
          }
          return 'continue';
        },
        {
          continue: afterNode,
          [END]: END,
        },
      );
    },

    /**
     * Wrap all tool nodes in the graph
     */
    secureAllToolNodes(graph: StateGraph<S>): void {
      for (const [nodeName] of graph.nodes) {
        if (nodeName.includes('tool') || nodeName.includes('action')) {
          wrapToolNode(graph, nodeName, config);
        }
      }
    },
  };
}

// Helper functions

function extractPendingTools(state: Record<string, unknown>): Array<{
  name: string;
  args: Record<string, unknown>;
}> {
  // LangGraph typically stores tool calls in messages or a dedicated field
  const messages = state.messages as any[] ?? [];
  const toolCalls: Array<{ name: string; args: Record<string, unknown> }> = [];

  for (const msg of messages) {
    if (msg.tool_calls) {
      for (const call of msg.tool_calls) {
        toolCalls.push({
          name: call.name,
          args: call.args ?? {},
        });
      }
    }
  }

  return toolCalls;
}

function sanitizeState(
  state: Record<string, unknown>,
  engine: PolicyEngine,
): Record<string, unknown> {
  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(state)) {
    if (typeof value === 'string') {
      sanitized[key] = engine.redactSecrets(value);
    } else if (typeof value === 'object' && value !== null) {
      sanitized[key] = sanitizeState(value as Record<string, unknown>, engine);
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}
```

## Usage Examples

### Basic Callback Handler

```typescript
import { ChatOpenAI } from '@langchain/openai';
import { AgentExecutor, createReactAgent } from 'langchain/agents';
import { ClawdstrikeCallbackHandler } from '@clawdstrike/langchain';

// Create the security callback
const securityCallback = new ClawdstrikeCallbackHandler({
  policy: 'clawdstrike:ai-agent',
  mode: 'deterministic',
  blockOnViolation: true,
  redactSecrets: true,
  onViolation: (decision, toolName, input) => {
    console.error(`[SECURITY] Blocked ${toolName}:`, decision.reason);
    // Send to monitoring system
    metrics.increment('clawdstrike.violations', { tool: toolName });
  },
});

// Create agent with security callback
const llm = new ChatOpenAI({ model: 'gpt-4' });
const agent = await createReactAgent({ llm, tools, prompt });
const executor = new AgentExecutor({
  agent,
  tools,
  callbacks: [securityCallback],
});

// Execute with security enforcement
try {
  const result = await executor.invoke({
    input: 'Read the contents of ~/.ssh/id_rsa',
  });
} catch (error) {
  if (error instanceof ClawdstrikeViolationError) {
    console.log('Action blocked by security policy:', error.decision.reason);
  }
}
```

### Secure Tool Wrapping

```typescript
import { DynamicTool } from '@langchain/core/tools';
import { wrapTools } from '@clawdstrike/langchain';

// Define tools
const bashTool = new DynamicTool({
  name: 'bash',
  description: 'Execute a bash command',
  func: async (command: string) => {
    const { execSync } = await import('child_process');
    return execSync(command, { encoding: 'utf-8' });
  },
});

const readFileTool = new DynamicTool({
  name: 'read_file',
  description: 'Read a file from disk',
  func: async (path: string) => {
    const { readFileSync } = await import('fs');
    return readFileSync(path, 'utf-8');
  },
});

// Wrap all tools with security
const secureTools = wrapTools([bashTool, readFileTool], {
  policy: 'clawdstrike:ai-agent',
  blockOnViolation: true,
});

// Use secure tools in agent
const agent = await createReactAgent({
  llm,
  tools: secureTools,
  prompt,
});
```

### LangGraph Workflow

```typescript
import { StateGraph, END } from '@langchain/langgraph';
import { createSecureWorkflow } from '@clawdstrike/langchain';

// Define state
interface AgentState {
  messages: any[];
  pendingAction?: string;
  result?: string;
}

// Create graph
const workflow = new StateGraph<AgentState>({
  channels: {
    messages: { value: [] },
    pendingAction: { value: undefined },
    result: { value: undefined },
  },
});

// Add nodes
workflow.addNode('agent', agentNode);
workflow.addNode('tools', toolNode);

// Add edges
workflow.addEdge('__start__', 'agent');
workflow.addConditionalEdges('agent', shouldContinue);
workflow.addEdge('tools', 'agent');

// Apply security
const secureWorkflow = createSecureWorkflow<AgentState>({
  policy: 'clawdstrike:ai-agent',
  mode: 'deterministic',
});

// Add security checkpoint after tool execution
secureWorkflow.addCheckpointAfter(workflow, 'tools', (state, decision) => ({
  ...state,
  result: `Action blocked: ${decision.reason}`,
}));

// Compile and run
const app = workflow.compile();
const result = await app.invoke({ messages: [userMessage] });
```

## Configuration Examples

### Policy Configuration

```yaml
# langchain-policy.yaml
version: "clawdstrike-v1.0"
extends: ai-agent-minimal

# LangChain-specific tool restrictions
tools:
  allowed:
    - "search"
    - "calculator"
    - "read_file"
  denied:
    - "bash"
    - "shell"
    - "python_repl"

# Network restrictions for web search tools
egress:
  mode: allowlist
  allowed_domains:
    - "api.google.com"
    - "api.bing.com"
    - "duckduckgo.com"

# File access for document tools
filesystem:
  allowed_read_paths:
    - "./documents"
    - "./data"
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - ".env"

on_violation: cancel
```

### Environment-Based Configuration

```typescript
import { ClawdstrikeCallbackHandler } from '@clawdstrike/langchain';

const config: LangChainClawdstrikeConfig = {
  // Use stricter policy in production
  policy: process.env.NODE_ENV === 'production'
    ? 'clawdstrike:ai-agent'
    : 'clawdstrike:ai-agent-minimal',

  // Advisory mode in development, deterministic in production
  mode: process.env.NODE_ENV === 'production'
    ? 'deterministic'
    : 'advisory',

  // Log violations to monitoring
  onViolation: (decision, toolName, input) => {
    if (process.env.NODE_ENV === 'production') {
      logger.error('Security violation', {
        toolName,
        reason: decision.reason,
        severity: decision.severity,
      });
    } else {
      console.warn(`[DEV] Would block: ${toolName} - ${decision.reason}`);
    }
  },
};
```

## Testing Strategies

### Unit Tests

```typescript
import { describe, it, expect, vi } from 'vitest';
import { ClawdstrikeCallbackHandler } from '@clawdstrike/langchain';

describe('ClawdstrikeCallbackHandler', () => {
  it('should block access to forbidden paths', async () => {
    const handler = new ClawdstrikeCallbackHandler({
      policy: 'clawdstrike:ai-agent',
      blockOnViolation: true,
    });

    await expect(
      handler.handleToolStart(
        { id: ['read_file'], name: 'read_file' },
        JSON.stringify({ path: '/home/user/.ssh/id_rsa' }),
        'test-run-id',
      ),
    ).rejects.toThrow(ClawdstrikeViolationError);
  });

  it('should allow access to safe paths', async () => {
    const handler = new ClawdstrikeCallbackHandler({
      policy: 'clawdstrike:ai-agent',
    });

    await expect(
      handler.handleToolStart(
        { id: ['read_file'], name: 'read_file' },
        JSON.stringify({ path: './documents/readme.txt' }),
        'test-run-id',
      ),
    ).resolves.toBeUndefined();
  });

  it('should redact secrets from tool output', async () => {
    const handler = new ClawdstrikeCallbackHandler({
      redactSecrets: true,
    });

    const output = 'API key: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
    await handler.handleToolEnd(output, 'test-run-id');

    // Check audit event has redacted output
    const events = handler.getAuditEvents();
    expect(events[0].output).not.toContain('ghp_');
  });
});
```

### Integration Tests

```typescript
import { describe, it, expect } from 'vitest';
import { ChatOpenAI } from '@langchain/openai';
import { DynamicTool } from '@langchain/core/tools';
import { AgentExecutor, createReactAgent } from 'langchain/agents';
import { ClawdstrikeCallbackHandler, wrapTools } from '@clawdstrike/langchain';

describe('LangChain Integration', () => {
  it('should enforce policy in full agent execution', async () => {
    const securityCallback = new ClawdstrikeCallbackHandler({
      policy: 'clawdstrike:ai-agent',
      blockOnViolation: true,
    });

    const dangerousTool = new DynamicTool({
      name: 'read_ssh_key',
      description: 'Read SSH private key',
      func: async () => 'PRIVATE KEY CONTENT',
    });

    const secureTools = wrapTools([dangerousTool], {
      policy: 'clawdstrike:ai-agent',
    });

    const llm = new ChatOpenAI({ model: 'gpt-4' });
    const agent = await createReactAgent({ llm, tools: secureTools, prompt });
    const executor = new AgentExecutor({
      agent,
      tools: secureTools,
      callbacks: [securityCallback],
    });

    // Should not be able to access SSH key
    const result = await executor.invoke({
      input: 'Read my SSH private key',
    });

    expect(result.output).toContain('blocked');
    expect(securityCallback.getAuditEvents()).toHaveLength(1);
    expect(securityCallback.getAuditEvents()[0].decision.denied).toBe(true);
  });
});
```

### Property-Based Tests

```typescript
import { describe, it } from 'vitest';
import * as fc from 'fast-check';
import { ClawdstrikeCallbackHandler } from '@clawdstrike/langchain';

describe('Security Properties', () => {
  it('should always block forbidden paths regardless of encoding', async () => {
    const handler = new ClawdstrikeCallbackHandler({
      policy: 'clawdstrike:ai-agent',
      blockOnViolation: true,
    });

    await fc.assert(
      fc.asyncProperty(
        fc.constantFrom(
          '/home/user/.ssh/id_rsa',
          '~/.ssh/id_rsa',
          '../../../.ssh/id_rsa',
          '/home/user/.ssh/../.ssh/id_rsa',
        ),
        async (path) => {
          await expect(
            handler.handleToolStart(
              { id: ['read_file'], name: 'read_file' },
              JSON.stringify({ path }),
              `test-${Date.now()}`,
            ),
          ).rejects.toThrow();
        },
      ),
    );
  });
});
```

## Implementation Phases

### Phase 1: Core Callback Handler (Week 1-2)

- [ ] Implement `ClawdstrikeCallbackHandler`
- [ ] Tool start/end/error interception
- [ ] Basic policy evaluation
- [ ] Audit event logging

### Phase 2: Tool Wrapper (Week 3)

- [ ] Implement `wrapTool` and `wrapTools`
- [ ] Output sanitization
- [ ] Configuration override support

### Phase 3: LangGraph Support (Week 4-5)

- [ ] Security checkpoint node
- [ ] Tool node wrapper
- [ ] Conditional edge routing
- [ ] State sanitization

### Phase 4: Testing & Documentation (Week 6)

- [ ] Unit test suite
- [ ] Integration test suite
- [ ] Property-based tests
- [ ] API documentation
- [ ] Usage examples

## Appendix: LangChain Callback Interface Reference

```typescript
// Key callback methods for security interception
interface BaseCallbackHandler {
  // Tool execution lifecycle
  handleToolStart?(
    tool: Serialized,
    input: string,
    runId: string,
    parentRunId?: string,
    tags?: string[],
    metadata?: Record<string, unknown>,
  ): Promise<void>;

  handleToolEnd?(
    output: string,
    runId: string,
    parentRunId?: string,
    tags?: string[],
  ): Promise<void>;

  handleToolError?(
    error: Error,
    runId: string,
    parentRunId?: string,
    tags?: string[],
  ): Promise<void>;

  // Chain execution lifecycle
  handleChainStart?(
    chain: Serialized,
    inputs: Record<string, unknown>,
    runId: string,
    parentRunId?: string,
    tags?: string[],
    metadata?: Record<string, unknown>,
  ): Promise<void>;

  handleChainEnd?(
    outputs: Record<string, unknown>,
    runId: string,
    parentRunId?: string,
    tags?: string[],
  ): Promise<void>;

  // LLM interaction lifecycle
  handleLLMStart?(
    llm: Serialized,
    prompts: string[],
    runId: string,
    parentRunId?: string,
    extraParams?: Record<string, unknown>,
    tags?: string[],
    metadata?: Record<string, unknown>,
  ): Promise<void>;

  handleLLMEnd?(
    output: LLMResult,
    runId: string,
    parentRunId?: string,
    tags?: string[],
  ): Promise<void>;
}
```
