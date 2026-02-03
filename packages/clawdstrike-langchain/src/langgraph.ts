import { createSecurityContext } from '@clawdstrike/adapter-core';
import type {
  AdapterConfig,
  Decision,
  PolicyEngineLike,
  SecurityContext,
  ToolInterceptor,
} from '@clawdstrike/adapter-core';

import { createLangChainInterceptor } from './interceptor.js';

export interface PendingToolCall {
  name: string;
  args: unknown;
}

export interface SecurityCheckpointNode {
  name: string;
  check(state: Record<string, unknown>): Promise<Decision>;
  route(state: Record<string, unknown>): Promise<'allow' | 'block' | 'warn'>;
}

export interface SecurityCheckpointOptions {
  engine?: PolicyEngineLike;
  interceptor?: ToolInterceptor;
  config?: AdapterConfig;
  context?: SecurityContext;
  createContext?: (state: Record<string, unknown>) => SecurityContext;
  extractToolCalls?: (state: Record<string, unknown>) => PendingToolCall[];
}

export function createSecurityCheckpoint(
  options: SecurityCheckpointOptions,
): SecurityCheckpointNode {
  const interceptor =
    options.interceptor
    ?? (options.engine
      ? createLangChainInterceptor(options.engine, options.config)
      : undefined);

  if (!interceptor) {
    throw new Error('createSecurityCheckpoint requires { interceptor } or { engine }');
  }

  const extractToolCalls = options.extractToolCalls ?? defaultExtractToolCalls;
  const createContext =
    options.createContext
    ?? ((state: Record<string, unknown>) =>
      options.context
      ?? createSecurityContext({
        sessionId: typeof state.sessionId === 'string' ? state.sessionId : undefined,
        metadata: { framework: 'langgraph' },
      }));

  return {
    name: 'clawdstrike_checkpoint',

    async check(state: Record<string, unknown>): Promise<Decision> {
      const toolCalls = extractToolCalls(state);
      const context = createContext(state);

      let warningDecision: Decision | null = null;

      for (const call of toolCalls) {
        const result = await interceptor.beforeExecute(call.name, call.args, context);

        if (result.decision.denied) {
          return result.decision;
        }

        if (result.decision.warn && !warningDecision) {
          warningDecision = result.decision;
        }
      }

      return (
        warningDecision
        ?? { allowed: true, denied: false, warn: false }
      );
    },

    async route(state: Record<string, unknown>): Promise<'allow' | 'block' | 'warn'> {
      const decision = await this.check(state);
      if (decision.denied) return 'block';
      if (decision.warn) return 'warn';
      return 'allow';
    },
  };
}

export function wrapToolNode<S extends Record<string, unknown>>(
  graph: { nodes: Map<string, (state: S) => Promise<S> | S>; addNode: (name: string, node: (state: S) => Promise<S> | S) => void },
  nodeName: string,
  checkpoint: SecurityCheckpointNode,
  options?: {
    engine?: PolicyEngineLike;
    sanitize?: boolean;
  },
): void {
  const original = graph.nodes.get(nodeName);
  if (!original) {
    throw new Error(`Node '${nodeName}' not found`);
  }

  graph.addNode(nodeName, async (state: S) => {
    const decision = await checkpoint.check(state as Record<string, unknown>);
    if (decision.denied) {
      return {
        ...state,
        __clawdstrike_blocked: true,
        __clawdstrike_reason: decision.message ?? decision.reason ?? 'denied',
      } as S;
    }

    const nextState = await original(state);

    if (options?.sanitize === false) {
      return nextState;
    }

    const engine = options?.engine;
    if (!engine?.redactSecrets) {
      return nextState;
    }

    return sanitizeState(nextState, engine) as S;
  });
}

export function sanitizeState(value: unknown, engine: PolicyEngineLike): unknown {
  if (value === null || value === undefined) {
    return value;
  }

  if (typeof value === 'string') {
    return engine.redactSecrets ? engine.redactSecrets(value) : value;
  }

  if (typeof value !== 'object') {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map(item => sanitizeState(item, engine));
  }

  const rec = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(rec)) {
    out[k] = sanitizeState(v, engine);
  }
  return out;
}

export function addSecurityRouting<S extends Record<string, unknown>>(
  graph: { addConditionalEdges?: (from: string, condition: (state: S) => Promise<string> | string, mapping: Record<string, string>) => void },
  fromNode: string,
  checkpoint: SecurityCheckpointNode,
  mapping: { allow: string; block: string; warn: string },
): void {
  if (typeof graph.addConditionalEdges !== 'function') {
    throw new Error('Graph does not support addConditionalEdges');
  }

  graph.addConditionalEdges(
    fromNode,
    async (state: S) => checkpoint.route(state as Record<string, unknown>),
    mapping,
  );
}

function defaultExtractToolCalls(state: Record<string, unknown>): PendingToolCall[] {
  const raw = state.toolCalls ?? state.tool_calls ?? state.pendingToolCalls;
  if (!Array.isArray(raw)) {
    return [];
  }

  const calls: PendingToolCall[] = [];
  for (const item of raw) {
    if (typeof item !== 'object' || item === null) {
      continue;
    }
    const rec = item as Record<string, unknown>;
    const name = typeof rec.name === 'string' ? rec.name : typeof rec.toolName === 'string' ? rec.toolName : undefined;
    if (!name) {
      continue;
    }
    calls.push({ name, args: rec.args ?? rec.parameters ?? rec.input });
  }
  return calls;
}
