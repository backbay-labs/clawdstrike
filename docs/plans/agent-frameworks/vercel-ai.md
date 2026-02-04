# Vercel AI SDK Integration

## Overview

The Vercel AI SDK is a TypeScript-first library for building AI-powered applications with streaming support, React hooks, and edge runtime compatibility. It provides a unified interface for multiple LLM providers and a streamlined tool-calling mechanism.

This document details the architecture for integrating Clawdstrike's security enforcement into Vercel AI SDK's middleware layer, focusing on tool call interception in both streaming and non-streaming contexts.

## Version Compatibility

| Package | Minimum Version | Tested Up To | Notes |
|---------|----------------|--------------|-------|
| **ai** | 3.0.0 | 3.4.x | Core Vercel AI SDK |
| **@ai-sdk/openai** | 0.0.20 | 0.0.x | OpenAI provider |
| **@ai-sdk/anthropic** | 0.0.20 | 0.0.x | Anthropic provider |
| **@clawdstrike/vercel-ai** | 1.0.0 | 1.x | Clawdstrike integration |
| **React** | 18.0.0 | 18.x | For useSecureChat hook |
| **Next.js** | 13.4.0 | 14.x | For API route examples |

> **Important**: This integration uses `experimental_wrapLanguageModel` from the AI SDK. While stable for production use, the `experimental_` prefix indicates the API may change in future major versions. Monitor AI SDK release notes for updates.

## Problem Statement

### Challenges with Vercel AI SDK Security

1. **Streaming Tool Calls**: Tool calls can arrive as streaming deltas, requiring incremental policy evaluation.

2. **Edge Runtime Constraints**: Security checks must be lightweight enough for edge deployment.

3. **Multi-Provider Support**: The same security policies should work across OpenAI, Anthropic, Google, and other providers.

4. **React Integration**: Security state needs to be accessible in React components for UI feedback.

5. **Middleware Chain**: Multiple middleware layers may need to coordinate security decisions.

### Use Cases

| Use Case | Security Requirement |
|----------|---------------------|
| AI chatbot with tools | Restrict tool access based on user role |
| Code generation assistant | Sandbox code execution, validate outputs |
| Data retrieval agent | Control database access, redact PII |
| Content moderation | Block harmful content generation |
| Customer service bot | Prevent unauthorized data access |

## Vercel AI SDK Architecture Analysis

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                      Vercel AI SDK                               │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │    Provider     │  │    Streaming    │  │   React Hooks   │ │
│  │  (OpenAI, etc.) │  │    Runtime      │  │  (useChat, etc.)│ │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘ │
│           │                    │                    │           │
│           └────────────────────┼────────────────────┘           │
│                                ▼                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                      Core Functions                         │ │
│  │  generateText() | streamText() | generateObject()          │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                │                                 │
│                                ▼                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                    Tool Execution                           │ │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │ │
│  │  │ Tool Schema  │  │ Tool Invoke  │  │ Tool Result  │     │ │
│  │  │  (Zod/JSON)  │  │  (execute)   │  │  (return)    │     │ │
│  │  └──────────────┘  └──────────────┘  └──────────────┘     │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Tool Execution Flow

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  LLM Stream  │───>│  Parse Tool  │───>│   Validate   │
│   Response   │    │    Call      │    │   Schema     │
└──────────────┘    └──────────────┘    └──────┬───────┘
                                               │
                                               ▼
                    ┌──────────────┐    ┌──────────────┐
                    │   Return     │<───│   Execute    │
                    │   Result     │    │   Tool       │
                    └──────────────┘    └──────────────┘
```

### Interception Points

1. **Middleware**: Global request/response transformation
2. **Tool Definition**: Wrap tool `execute` function
3. **Stream Processing**: Intercept streamed tool calls
4. **Result Processing**: Sanitize tool outputs before return

## Proposed Architecture

### Clawdstrike Vercel AI Middleware

```
┌─────────────────────────────────────────────────────────────────┐
│                    Secure AI Pipeline                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              ClawdstrikeMiddleware                       │   │
│  │  ┌───────────────┐  ┌───────────────┐  ┌─────────────┐ │   │
│  │  │  Pre-Request  │  │   Streaming   │  │ Post-Result │ │   │
│  │  │    Guard      │  │  Tool Guard   │  │   Guard     │ │   │
│  │  └───────┬───────┘  └───────┬───────┘  └──────┬──────┘ │   │
│  │          │                  │                  │        │   │
│  │          └──────────────────┼──────────────────┘        │   │
│  │                             ▼                            │   │
│  │  ┌─────────────────────────────────────────────────────┐│   │
│  │  │                   PolicyEngine                      ││   │
│  │  └─────────────────────────────────────────────────────┘│   │
│  └─────────────────────────────────────────────────────────┘   │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                  Vercel AI Core                          │   │
│  │  generateText() | streamText() | tool.execute()         │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

### Architecture Components

```typescript
// Core integration layer
┌─────────────────────────────────────────────────────────────────┐
│                    @clawdstrike/vercel-ai                        │
├─────────────────────────────────────────────────────────────────┤
│  createClawdstrikeMiddleware(config) -> Middleware               │
│  ├── wrapRequest(request) -> SecureRequest                      │
│  ├── wrapTools(tools) -> SecureTools                            │
│  ├── wrapStream(stream) -> SecureStream                         │
│  └── getSecurityContext() -> SecurityContext                    │
├─────────────────────────────────────────────────────────────────┤
│  secureTools(tools, config) -> SecureToolSet                     │
│  ├── wrapTool(tool) -> SecureTool                               │
│  ├── createPolicyCheckTool(engine) -> Tool                      │
│  └── getToolDecision(tool, params) -> Decision                  │
├─────────────────────────────────────────────────────────────────┤
│  useSecureChat(options) -> SecureChatHelpers                     │
│  ├── messages, input, handleSubmit                              │
│  ├── securityStatus -> SecurityStatus                           │
│  ├── blockedTools -> string[]                                   │
│  └── lastDecision -> Decision | null                            │
├─────────────────────────────────────────────────────────────────┤
│  StreamingToolGuard                                              │
│  ├── processChunk(chunk) -> ProcessedChunk                      │
│  ├── accumulateToolCall(delta) -> void                          │
│  ├── evaluatePendingCall() -> Decision                          │
│  └── getAccumulatedCalls() -> ToolCall[]                        │
└─────────────────────────────────────────────────────────────────┘
```

## API Design

### TypeScript Interfaces

```typescript
import { CoreTool, LanguageModel, StreamTextResult } from 'ai';
import { PolicyEngine, Decision, Policy, ClawdstrikeConfig } from '@clawdstrike/openclaw';

/**
 * Configuration for Vercel AI SDK integration
 */
export interface VercelAIClawdstrikeConfig extends ClawdstrikeConfig {
  /** Whether to block tool calls that violate policy */
  blockOnViolation?: boolean;

  /** Whether to redact secrets from tool outputs */
  redactSecrets?: boolean;

  /** Whether to evaluate streaming tool calls incrementally */
  streamingEvaluation?: boolean;

  /** Tools to exclude from security checks */
  excludedTools?: string[];

  /** Custom tool name mapping for policy evaluation */
  toolNameMapping?: Record<string, string>;

  /** Callback for security decisions */
  onDecision?: (decision: Decision, context: DecisionContext) => void;

  /** Callback for blocked tool calls */
  onBlocked?: (toolName: string, params: unknown, decision: Decision) => void;

  /** Inject policy_check tool for agent use */
  injectPolicyCheckTool?: boolean;

  /** Security headers to add to responses */
  securityHeaders?: Record<string, string>;
}

/**
 * Context for security decisions
 */
export interface DecisionContext {
  toolName: string;
  parameters: Record<string, unknown>;
  timestamp: string;
  requestId?: string;
  userId?: string;
}

/**
 * Security status for React components
 */
export interface SecurityStatus {
  /** Whether the last operation was blocked */
  blocked: boolean;

  /** Warning message if any */
  warning?: string;

  /** Last decision details */
  lastDecision?: Decision;

  /** Tools that have been blocked in this session */
  blockedTools: string[];

  /** Number of security checks performed */
  checkCount: number;

  /** Number of violations detected */
  violationCount: number;
}

/**
 * Secure tool wrapper type
 */
export interface SecureTool<TParams = unknown, TResult = unknown> extends CoreTool<TParams, TResult> {
  /** Security configuration */
  readonly securityConfig: VercelAIClawdstrikeConfig;

  /** Get the last decision for this tool */
  getLastDecision(): Decision | null;

  /** Check if parameters would be allowed */
  checkParams(params: TParams): Promise<Decision>;
}

/**
 * Secure chat hook return type
 */
export interface SecureChatHelpers {
  /** Chat messages */
  messages: Message[];

  /** Current input value */
  input: string;

  /** Handle input change */
  handleInputChange: (e: React.ChangeEvent<HTMLInputElement>) => void;

  /** Handle form submit */
  handleSubmit: (e: React.FormEvent) => void;

  /** Loading state */
  isLoading: boolean;

  /** Security status */
  securityStatus: SecurityStatus;

  /** Blocked tools in current session */
  blockedTools: string[];

  /** Last security decision */
  lastDecision: Decision | null;

  /** Clear blocked tools list */
  clearBlockedTools: () => void;

  /** Get decision for a potential tool call */
  preflightCheck: (toolName: string, params: unknown) => Promise<Decision>;
}

/**
 * Middleware configuration
 */
export interface MiddlewareConfig {
  /** Policy engine instance */
  engine?: PolicyEngine;

  /** Policy configuration */
  policy?: string | Policy;

  /** Security mode */
  mode?: 'deterministic' | 'advisory' | 'audit';

  /** Request ID extractor */
  getRequestId?: (request: Request) => string;

  /** User ID extractor */
  getUserId?: (request: Request) => string | undefined;
}
```

### Middleware Implementation

```typescript
// Note: experimental_wrapLanguageModel is stable but may be renamed in future versions
// Check AI SDK release notes when upgrading
import { experimental_wrapLanguageModel as wrapLanguageModel, LanguageModelV1 } from 'ai';
import { PolicyEngine, Decision, PolicyEvent } from '@clawdstrike/openclaw';

/**
 * Creates Clawdstrike middleware for Vercel AI SDK
 *
 * @remarks
 * Uses experimental_wrapLanguageModel which provides model-level interception.
 * This API is production-ready but may be renamed in AI SDK 4.x.
 */
export function createClawdstrikeMiddleware(
  config: VercelAIClawdstrikeConfig = {},
): ClawdstrikeMiddleware {
  const engine = new PolicyEngine(config);
  const auditLog: AuditEntry[] = [];

  return {
    /**
     * Wrap a language model with security enforcement
     */
    wrapLanguageModel(model: LanguageModelV1): LanguageModelV1 {
      return wrapLanguageModel({
        model,
        middleware: {
          // Intercept tool calls before execution
          transformParams: async ({ params }) => {
            // Inject security context into system prompt
            if (config.injectPolicyCheckTool) {
              params.prompt = injectSecurityPrompt(params.prompt, engine);
            }
            return params;
          },

          // Process streaming responses
          wrapGenerate: async ({ doGenerate }) => {
            const result = await doGenerate();

            // Post-process tool calls
            if (result.toolCalls && result.toolCalls.length > 0) {
              const processedCalls = await Promise.all(
                result.toolCalls.map(async (call) => {
                  const decision = await evaluateToolCall(call, engine, config);

                  if (decision.denied && config.blockOnViolation !== false) {
                    return {
                      ...call,
                      __clawdstrike_blocked: true,
                      __clawdstrike_reason: decision.reason,
                    };
                  }

                  return call;
                }),
              );

              return {
                ...result,
                toolCalls: processedCalls,
              };
            }

            return result;
          },

          // Process streaming tool calls
          wrapStream: async ({ doStream }) => {
            const { stream, ...rest } = await doStream();
            const guard = new StreamingToolGuard(engine, config);

            const secureStream = stream.pipeThrough(
              new TransformStream({
                transform: async (chunk, controller) => {
                  const processed = await guard.processChunk(chunk);
                  if (processed) {
                    controller.enqueue(processed);
                  }
                },
              }),
            );

            return { stream: secureStream, ...rest };
          },
        },
      });
    },

    /**
     * Wrap tools with security checks
     */
    wrapTools<T extends Record<string, CoreTool>>(tools: T): T {
      const wrapped: Record<string, CoreTool> = {};

      for (const [name, tool] of Object.entries(tools)) {
        if (config.excludedTools?.includes(name)) {
          wrapped[name] = tool;
          continue;
        }

        wrapped[name] = createSecureTool(name, tool, engine, config);
      }

      // Optionally inject policy_check tool
      if (config.injectPolicyCheckTool) {
        wrapped.policy_check = createPolicyCheckTool(engine);
      }

      return wrapped as T;
    },

    /**
     * Get the policy engine
     */
    getEngine(): PolicyEngine {
      return engine;
    },

    /**
     * Get audit log
     */
    getAuditLog(): AuditEntry[] {
      return [...auditLog];
    },
  };
}

/**
 * Create a security-wrapped tool
 */
function createSecureTool(
  name: string,
  tool: CoreTool,
  engine: PolicyEngine,
  config: VercelAIClawdstrikeConfig,
): SecureTool {
  let lastDecision: Decision | null = null;

  const secureTool: SecureTool = {
    ...tool,
    securityConfig: config,

    async execute(params: unknown): Promise<unknown> {
      // Pre-execution policy check
      const event = createPolicyEvent(name, params as Record<string, unknown>);
      const decision = await engine.evaluate(event);
      lastDecision = decision;

      // Notify callback
      config.onDecision?.(decision, {
        toolName: name,
        parameters: params as Record<string, unknown>,
        timestamp: new Date().toISOString(),
      });

      // Block if denied
      if (decision.denied && config.blockOnViolation !== false) {
        config.onBlocked?.(name, params, decision);
        throw new ClawdstrikeBlockedError(
          `Tool '${name}' blocked by security policy: ${decision.reason}`,
          decision,
        );
      }

      // Execute original tool
      let result = await tool.execute(params);

      // Post-execution sanitization
      if (config.redactSecrets !== false) {
        result = sanitizeOutput(result, engine);
      }

      return result;
    },

    getLastDecision(): Decision | null {
      return lastDecision;
    },

    async checkParams(params: unknown): Promise<Decision> {
      const event = createPolicyEvent(name, params as Record<string, unknown>);
      return engine.evaluate(event);
    },
  };

  return secureTool;
}

/**
 * Create the policy_check tool for agent use
 */
function createPolicyCheckTool(engine: PolicyEngine): CoreTool {
  return {
    description: 'Check if an action is allowed by security policy before attempting it',
    parameters: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['file_read', 'file_write', 'network', 'command', 'tool_call'],
          description: 'Type of action to check',
        },
        resource: {
          type: 'string',
          description: 'Resource to check (path, URL, command, or tool name)',
        },
      },
      required: ['action', 'resource'],
    },
    execute: async ({ action, resource }: { action: string; resource: string }) => {
      const event = buildPolicyEvent(action, resource);
      const decision = await engine.evaluate(event);

      return {
        allowed: decision.allowed,
        denied: decision.denied,
        reason: decision.reason ?? (decision.allowed ? 'Action is allowed' : 'Action is denied'),
        suggestion: decision.denied ? getSuggestion(action, resource) : undefined,
      };
    },
  };
}

/**
 * Streaming tool guard for incremental evaluation
 */
class StreamingToolGuard {
  private readonly engine: PolicyEngine;
  private readonly config: VercelAIClawdstrikeConfig;
  private pendingToolCalls: Map<string, PartialToolCall> = new Map();

  constructor(engine: PolicyEngine, config: VercelAIClawdstrikeConfig) {
    this.engine = engine;
    this.config = config;
  }

  /**
   * Process a stream chunk
   */
  async processChunk(chunk: StreamChunk): Promise<StreamChunk | null> {
    // Handle tool call start
    if (chunk.type === 'tool-call-start') {
      this.pendingToolCalls.set(chunk.toolCallId, {
        id: chunk.toolCallId,
        name: chunk.toolName,
        args: '',
      });
      return chunk;
    }

    // Handle tool call argument delta
    if (chunk.type === 'tool-call-delta') {
      const pending = this.pendingToolCalls.get(chunk.toolCallId);
      if (pending) {
        pending.args += chunk.argsTextDelta;
      }
      return chunk;
    }

    // Handle tool call completion - evaluate before tool execution
    if (chunk.type === 'tool-call') {
      const pending = this.pendingToolCalls.get(chunk.toolCallId);
      if (pending) {
        try {
          const args = JSON.parse(pending.args || '{}');
          const event = createPolicyEvent(pending.name, args);
          const decision = await this.engine.evaluate(event);

          if (decision.denied && this.config.blockOnViolation !== false) {
            this.config.onBlocked?.(pending.name, args, decision);

            // Return a modified chunk indicating the tool was blocked
            return {
              ...chunk,
              __clawdstrike_blocked: true,
              __clawdstrike_reason: decision.reason,
            };
          }
        } catch (e) {
          // JSON parse error - let it through for schema validation to catch
        }

        this.pendingToolCalls.delete(chunk.toolCallId);
      }
      return chunk;
    }

    // Handle tool result - sanitize output
    if (chunk.type === 'tool-result' && this.config.redactSecrets !== false) {
      return {
        ...chunk,
        result: sanitizeOutput(chunk.result, this.engine),
      };
    }

    return chunk;
  }
}

// Helper functions

function createPolicyEvent(
  toolName: string,
  params: Record<string, unknown>,
): PolicyEvent {
  const eventType = inferEventType(toolName);

  return {
    eventId: `vercel-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    eventType,
    timestamp: new Date().toISOString(),
    data: createEventData(eventType, toolName, params),
    metadata: { source: 'vercel-ai', toolName },
  };
}

function inferEventType(toolName: string): PolicyEvent['eventType'] {
  const name = toolName.toLowerCase();

  if (name.includes('read') || name.includes('get_file')) return 'file_read';
  if (name.includes('write') || name.includes('save') || name.includes('create_file')) return 'file_write';
  if (name.includes('exec') || name.includes('shell') || name.includes('bash')) return 'command_exec';
  if (name.includes('fetch') || name.includes('http') || name.includes('request')) return 'network_egress';
  if (name.includes('patch') || name.includes('diff')) return 'patch_apply';

  return 'tool_call';
}

function createEventData(
  eventType: PolicyEvent['eventType'],
  toolName: string,
  params: Record<string, unknown>,
): PolicyEvent['data'] {
  switch (eventType) {
    case 'file_read':
    case 'file_write':
      return {
        type: 'file',
        path: String(params.path ?? params.file ?? params.filename ?? ''),
        operation: eventType === 'file_read' ? 'read' : 'write',
      };

    case 'command_exec':
      const cmd = String(params.command ?? params.cmd ?? '');
      const parts = cmd.split(/\s+/);
      return {
        type: 'command',
        command: parts[0] ?? '',
        args: parts.slice(1),
      };

    case 'network_egress':
      const url = String(params.url ?? params.endpoint ?? '');
      try {
        const parsed = new URL(url);
        return {
          type: 'network',
          host: parsed.hostname,
          port: parseInt(parsed.port) || (parsed.protocol === 'https:' ? 443 : 80),
          url,
        };
      } catch {
        return { type: 'network', host: url, port: 443 };
      }

    default:
      return {
        type: 'tool',
        toolName,
        parameters: params,
      };
  }
}

function sanitizeOutput(output: unknown, engine: PolicyEngine): unknown {
  if (typeof output === 'string') {
    return engine.redactSecrets(output);
  }

  if (Array.isArray(output)) {
    return output.map(item => sanitizeOutput(item, engine));
  }

  if (typeof output === 'object' && output !== null) {
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(output)) {
      sanitized[key] = sanitizeOutput(value, engine);
    }
    return sanitized;
  }

  return output;
}

function injectSecurityPrompt(prompt: unknown[], engine: PolicyEngine): unknown[] {
  const policy = engine.getPolicy();
  const guards = engine.enabledGuards();

  const securityMessage = {
    role: 'system',
    content: `## Security Policy

You have access to a policy_check tool. Use it before attempting potentially restricted operations.

### Active Guards
${guards.map(g => `- ${g}`).join('\n')}

### Restrictions
- Forbidden paths: ${policy.filesystem?.forbidden_paths?.join(', ') ?? 'None'}
- Network mode: ${policy.egress?.mode ?? 'open'}
- Denied tools: ${policy.tools?.denied?.join(', ') ?? 'None'}

Always check policy compliance before executing sensitive operations.`,
  };

  return [securityMessage, ...prompt];
}

function buildPolicyEvent(action: string, resource: string): PolicyEvent {
  const eventId = `policy-check-${Date.now()}`;
  const timestamp = new Date().toISOString();

  switch (action) {
    case 'file_read':
      return {
        eventId,
        eventType: 'file_read',
        timestamp,
        data: { type: 'file', path: resource, operation: 'read' },
      };
    case 'file_write':
      return {
        eventId,
        eventType: 'file_write',
        timestamp,
        data: { type: 'file', path: resource, operation: 'write' },
      };
    case 'network':
      try {
        const url = new URL(resource.includes('://') ? resource : `https://${resource}`);
        return {
          eventId,
          eventType: 'network_egress',
          timestamp,
          data: {
            type: 'network',
            host: url.hostname,
            port: parseInt(url.port) || 443,
            url: resource,
          },
        };
      } catch {
        return {
          eventId,
          eventType: 'network_egress',
          timestamp,
          data: { type: 'network', host: resource, port: 443 },
        };
      }
    case 'command':
      const parts = resource.split(/\s+/);
      return {
        eventId,
        eventType: 'command_exec',
        timestamp,
        data: {
          type: 'command',
          command: parts[0] ?? '',
          args: parts.slice(1),
        },
      };
    default:
      return {
        eventId,
        eventType: 'tool_call',
        timestamp,
        data: { type: 'tool', toolName: resource, parameters: {} },
      };
  }
}

function getSuggestion(action: string, resource: string): string {
  if (action === 'file_read' || action === 'file_write') {
    if (resource.includes('.ssh')) return 'SSH keys are protected. Use environment variables for credentials.';
    if (resource.includes('.env')) return '.env files are protected. Use process.env for configuration.';
  }
  if (action === 'network') {
    return 'Try using an approved domain from the allowlist.';
  }
  if (action === 'command') {
    if (resource.includes('sudo')) return 'Elevated privileges are not available.';
    if (resource.includes('rm -rf')) return 'Destructive commands are blocked.';
  }
  return 'Consider an alternative approach within security policy.';
}

/**
 * Error thrown when a tool is blocked
 */
export class ClawdstrikeBlockedError extends Error {
  constructor(
    message: string,
    public readonly decision: Decision,
  ) {
    super(message);
    this.name = 'ClawdstrikeBlockedError';
  }
}
```

### React Hook Integration

```typescript
import { useChat, UseChatOptions, Message } from 'ai/react';
import { useState, useCallback, useMemo } from 'react';
import { PolicyEngine, Decision } from '@clawdstrike/openclaw';

/**
 * Secure chat hook with security status tracking
 */
export function useSecureChat(
  options: UseChatOptions & {
    securityConfig?: VercelAIClawdstrikeConfig;
  },
): SecureChatHelpers {
  const { securityConfig, ...chatOptions } = options;

  const engine = useMemo(
    () => new PolicyEngine(securityConfig ?? {}),
    [securityConfig],
  );

  const [securityStatus, setSecurityStatus] = useState<SecurityStatus>({
    blocked: false,
    blockedTools: [],
    checkCount: 0,
    violationCount: 0,
  });

  const [lastDecision, setLastDecision] = useState<Decision | null>(null);

  // Wrap onToolCall to add security
  const secureToolCall = useCallback(
    async ({ toolCall }: { toolCall: ToolCall }) => {
      const event = createPolicyEvent(
        toolCall.toolName,
        toolCall.args as Record<string, unknown>,
      );
      const decision = await engine.evaluate(event);

      setLastDecision(decision);
      setSecurityStatus((prev) => ({
        ...prev,
        checkCount: prev.checkCount + 1,
        blocked: decision.denied,
        warning: decision.warn ? decision.message : undefined,
        lastDecision: decision,
        violationCount: prev.violationCount + (decision.denied ? 1 : 0),
        blockedTools: decision.denied
          ? [...new Set([...prev.blockedTools, toolCall.toolName])]
          : prev.blockedTools,
      }));

      if (decision.denied && securityConfig?.blockOnViolation !== false) {
        throw new ClawdstrikeBlockedError(
          `Tool blocked: ${decision.reason}`,
          decision,
        );
      }

      // Call original handler if provided
      return options.onToolCall?.({ toolCall });
    },
    [engine, securityConfig, options.onToolCall],
  );

  const chatHelpers = useChat({
    ...chatOptions,
    onToolCall: secureToolCall,
  });

  const clearBlockedTools = useCallback(() => {
    setSecurityStatus((prev) => ({
      ...prev,
      blockedTools: [],
    }));
  }, []);

  const preflightCheck = useCallback(
    async (toolName: string, params: unknown): Promise<Decision> => {
      const event = createPolicyEvent(toolName, params as Record<string, unknown>);
      return engine.evaluate(event);
    },
    [engine],
  );

  return {
    ...chatHelpers,
    securityStatus,
    blockedTools: securityStatus.blockedTools,
    lastDecision,
    clearBlockedTools,
    preflightCheck,
  };
}
```

## Usage Examples

### Basic Middleware Setup

```typescript
import { generateText, tool } from 'ai';
import { openai } from '@ai-sdk/openai';
import { createClawdstrikeMiddleware } from '@clawdstrike/vercel-ai';
import { z } from 'zod';

// Create middleware
const security = createClawdstrikeMiddleware({
  policy: 'clawdstrike:ai-agent',
  mode: 'deterministic',
  blockOnViolation: true,
  redactSecrets: true,
  injectPolicyCheckTool: true,
  onBlocked: (toolName, params, decision) => {
    console.error(`[SECURITY] Blocked ${toolName}:`, decision.reason);
  },
});

// Define tools
const tools = security.wrapTools({
  readFile: tool({
    description: 'Read a file from disk',
    parameters: z.object({
      path: z.string().describe('File path to read'),
    }),
    execute: async ({ path }) => {
      const fs = await import('fs/promises');
      return fs.readFile(path, 'utf-8');
    },
  }),

  executeCommand: tool({
    description: 'Execute a shell command',
    parameters: z.object({
      command: z.string().describe('Command to execute'),
    }),
    execute: async ({ command }) => {
      const { execSync } = await import('child_process');
      return execSync(command, { encoding: 'utf-8' });
    },
  }),
});

// Use with wrapped model
const model = security.wrapLanguageModel(openai('gpt-4-turbo'));

const result = await generateText({
  model,
  tools,
  prompt: 'Read the contents of ~/.ssh/id_rsa',
});

// Tool call will be blocked by policy
console.log(result.text);
```

### Streaming with Security

```typescript
import { streamText } from 'ai';
import { createClawdstrikeMiddleware } from '@clawdstrike/vercel-ai';

const security = createClawdstrikeMiddleware({
  policy: 'clawdstrike:ai-agent',
  streamingEvaluation: true,
});

const model = security.wrapLanguageModel(openai('gpt-4-turbo'));
const tools = security.wrapTools(myTools);

const result = await streamText({
  model,
  tools,
  prompt: 'Help me with my code',
});

// Stream with security checks on tool calls
for await (const chunk of result.textStream) {
  process.stdout.write(chunk);
}
```

### React Component

```tsx
import { useSecureChat } from '@clawdstrike/vercel-ai/react';

export function SecureChatUI() {
  const {
    messages,
    input,
    handleInputChange,
    handleSubmit,
    isLoading,
    securityStatus,
    blockedTools,
    preflightCheck,
  } = useSecureChat({
    api: '/api/chat',
    securityConfig: {
      policy: 'clawdstrike:ai-agent',
      blockOnViolation: true,
    },
  });

  return (
    <div className="chat-container">
      {/* Security Status Banner */}
      {securityStatus.blocked && (
        <div className="security-warning">
          Action blocked: {securityStatus.lastDecision?.reason}
        </div>
      )}

      {securityStatus.warning && (
        <div className="security-notice">
          Warning: {securityStatus.warning}
        </div>
      )}

      {/* Messages */}
      <div className="messages">
        {messages.map((m) => (
          <div key={m.id} className={`message ${m.role}`}>
            {m.content}
          </div>
        ))}
      </div>

      {/* Blocked Tools List */}
      {blockedTools.length > 0 && (
        <div className="blocked-tools">
          <strong>Blocked tools:</strong> {blockedTools.join(', ')}
        </div>
      )}

      {/* Input Form */}
      <form onSubmit={handleSubmit}>
        <input
          value={input}
          onChange={handleInputChange}
          placeholder="Type your message..."
          disabled={isLoading}
        />
        <button type="submit" disabled={isLoading}>
          Send
        </button>
      </form>

      {/* Security Stats */}
      <div className="security-stats">
        Checks: {securityStatus.checkCount} |
        Violations: {securityStatus.violationCount}
      </div>
    </div>
  );
}
```

### Next.js API Route

```typescript
// app/api/chat/route.ts
import { streamText } from 'ai';
import { openai } from '@ai-sdk/openai';
import { createClawdstrikeMiddleware } from '@clawdstrike/vercel-ai';

const security = createClawdstrikeMiddleware({
  policy: 'clawdstrike:ai-agent',
  mode: 'deterministic',
  onBlocked: (tool, params, decision) => {
    // Log to monitoring
    console.error('[Security]', { tool, params, decision });
  },
});

export async function POST(req: Request) {
  const { messages } = await req.json();

  const model = security.wrapLanguageModel(openai('gpt-4-turbo'));
  const tools = security.wrapTools(myTools);

  const result = await streamText({
    model,
    tools,
    messages,
  });

  return result.toAIStreamResponse({
    headers: {
      'X-Clawdstrike-Policy': 'ai-agent',
      'X-Clawdstrike-Mode': 'deterministic',
    },
  });
}
```

## Configuration Examples

### Policy for Chatbot

```yaml
# chatbot-policy.yaml
version: "clawdstrike-v1.0"
extends: ai-agent-minimal

egress:
  mode: allowlist
  allowed_domains:
    - "api.openai.com"
    - "api.anthropic.com"
    - "www.google.com"

filesystem:
  forbidden_paths:
    - "~/*"
    - "/etc/*"
    - ".env*"
  allowed_read_paths:
    - "./public"
    - "./data"

tools:
  allowed:
    - "search"
    - "calculator"
    - "read_file"
  denied:
    - "execute_command"
    - "write_file"

on_violation: cancel
```

### Environment-Based Configuration

```typescript
import { createClawdstrikeMiddleware } from '@clawdstrike/vercel-ai';

const security = createClawdstrikeMiddleware({
  policy: process.env.NODE_ENV === 'production'
    ? 'clawdstrike:ai-agent'
    : 'clawdstrike:ai-agent-minimal',

  mode: process.env.NODE_ENV === 'production'
    ? 'deterministic'
    : 'advisory',

  blockOnViolation: process.env.NODE_ENV === 'production',

  onBlocked: (tool, params, decision) => {
    if (process.env.NODE_ENV === 'production') {
      // Send to monitoring service
      fetch('/api/security-log', {
        method: 'POST',
        body: JSON.stringify({ tool, params, decision }),
      });
    } else {
      console.warn('[DEV] Would block:', tool, decision.reason);
    }
  },
});
```

## Testing Strategies

### Unit Tests

```typescript
import { describe, it, expect, vi } from 'vitest';
import { createClawdstrikeMiddleware, ClawdstrikeBlockedError } from '@clawdstrike/vercel-ai';
import { tool } from 'ai';
import { z } from 'zod';

describe('Vercel AI Middleware', () => {
  it('should block access to forbidden paths', async () => {
    const security = createClawdstrikeMiddleware({
      policy: 'clawdstrike:ai-agent',
      blockOnViolation: true,
    });

    const tools = security.wrapTools({
      readFile: tool({
        description: 'Read file',
        parameters: z.object({ path: z.string() }),
        execute: async ({ path }) => 'content',
      }),
    });

    await expect(
      tools.readFile.execute({ path: '/home/user/.ssh/id_rsa' }),
    ).rejects.toThrow(ClawdstrikeBlockedError);
  });

  it('should allow access to safe paths', async () => {
    const security = createClawdstrikeMiddleware({
      policy: 'clawdstrike:ai-agent',
    });

    const mockRead = vi.fn().mockResolvedValue('file content');

    const tools = security.wrapTools({
      readFile: tool({
        description: 'Read file',
        parameters: z.object({ path: z.string() }),
        execute: mockRead,
      }),
    });

    await tools.readFile.execute({ path: './documents/readme.txt' });
    expect(mockRead).toHaveBeenCalled();
  });

  it('should redact secrets from output', async () => {
    const security = createClawdstrikeMiddleware({
      redactSecrets: true,
    });

    const tools = security.wrapTools({
      getConfig: tool({
        description: 'Get config',
        parameters: z.object({}),
        execute: async () => ({
          apiKey: 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
          name: 'test',
        }),
      }),
    });

    const result = await tools.getConfig.execute({});
    expect((result as any).apiKey).not.toContain('ghp_');
    expect((result as any).name).toBe('test');
  });
});

describe('StreamingToolGuard', () => {
  it('should evaluate tool calls as they stream', async () => {
    const security = createClawdstrikeMiddleware({
      streamingEvaluation: true,
      blockOnViolation: true,
    });

    // Test with mock stream chunks
    const guard = new StreamingToolGuard(
      security.getEngine(),
      { blockOnViolation: true },
    );

    await guard.processChunk({
      type: 'tool-call-start',
      toolCallId: '1',
      toolName: 'readFile',
    });

    await guard.processChunk({
      type: 'tool-call-delta',
      toolCallId: '1',
      argsTextDelta: '{"path": "~/.ssh/id_rsa"}',
    });

    const result = await guard.processChunk({
      type: 'tool-call',
      toolCallId: '1',
      toolName: 'readFile',
      args: { path: '~/.ssh/id_rsa' },
    });

    expect((result as any).__clawdstrike_blocked).toBe(true);
  });
});
```

### Integration Tests

```typescript
import { describe, it, expect } from 'vitest';
import { generateText } from 'ai';
import { openai } from '@ai-sdk/openai';
import { createClawdstrikeMiddleware } from '@clawdstrike/vercel-ai';

describe('Full Pipeline Integration', () => {
  it('should enforce policy in complete generation', async () => {
    const blocked: string[] = [];

    const security = createClawdstrikeMiddleware({
      policy: 'clawdstrike:ai-agent',
      blockOnViolation: true,
      onBlocked: (tool) => blocked.push(tool),
    });

    const model = security.wrapLanguageModel(openai('gpt-4-turbo'));
    const tools = security.wrapTools(dangerousTools);

    // This should not throw but tool calls should be blocked
    const result = await generateText({
      model,
      tools,
      prompt: 'Delete all files in the home directory',
      maxToolRoundtrips: 1,
    });

    expect(blocked.length).toBeGreaterThan(0);
  });
});
```

## Implementation Phases

### Phase 1: Core Middleware (Week 1-2)

- [ ] Implement `createClawdstrikeMiddleware`
- [ ] Tool wrapping with security checks
- [ ] Basic output sanitization
- [ ] Decision callbacks

### Phase 2: Streaming Support (Week 3)

- [ ] `StreamingToolGuard` implementation
- [ ] Incremental tool call evaluation
- [ ] Stream transformation

### Phase 3: React Integration (Week 4)

- [ ] `useSecureChat` hook
- [ ] Security status tracking
- [ ] Preflight check utility
- [ ] TypeScript types for React

### Phase 4: Testing & Documentation (Week 5)

- [ ] Unit test suite
- [ ] Integration tests
- [ ] Performance benchmarks
- [ ] API documentation
- [ ] Example applications
