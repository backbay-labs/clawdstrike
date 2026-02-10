import { createSecurityContext } from '@clawdstrike/adapter-core';
import type { AdapterConfig, SecurityContext, ToolInterceptor } from '@clawdstrike/adapter-core';

export type StreamChunk = Record<string, unknown> & {
  type?: string;
  toolCallId?: string;
  toolName?: string;
  toolCallType?: string;
  args?: unknown;
  argsTextDelta?: string;
  result?: unknown;
};

export interface StreamingToolGuardOptions {
  context?: SecurityContext;
  getContext?: (chunk: StreamChunk) => SecurityContext;
  config?: AdapterConfig;
}

type PendingToolCall = {
  id: string;
  name: string;
  argsText: string;
};

export class StreamingToolGuard {
  private readonly interceptor: ToolInterceptor;
  private readonly config: AdapterConfig;
  private readonly context: SecurityContext;
  private readonly getContext?: (chunk: StreamChunk) => SecurityContext;
  private readonly pendingToolCalls = new Map<string, PendingToolCall>();

  constructor(interceptor: ToolInterceptor, options: StreamingToolGuardOptions = {}) {
    this.interceptor = interceptor;
    this.config = options.config ?? {};
    this.context =
      options.context
      ?? createSecurityContext({ metadata: { framework: 'vercel-ai', streaming: true } });
    this.getContext = options.getContext;
  }

  async processChunk(chunk: StreamChunk): Promise<StreamChunk | null> {
    const type = chunk.type;
    if (!type) {
      return chunk;
    }

    if (type === 'tool-call-start' || type === 'tool-call-streaming-start') {
      const toolCallId = chunk.toolCallId;
      const toolName = chunk.toolName ?? (chunk as any).name;
      if (typeof toolCallId === 'string') {
        const name = typeof toolName === 'string' ? toolName : 'unknown';
        this.pendingToolCalls.set(toolCallId, { id: toolCallId, name, argsText: '' });
      }
      return chunk;
    }

    if (type === 'tool-call-delta') {
      const toolCallId = chunk.toolCallId;
      if (typeof toolCallId !== 'string') {
        return chunk;
      }
      const pending =
        this.pendingToolCalls.get(toolCallId)
        ?? (() => {
          const toolName = chunk.toolName ?? (chunk as any).name;
          const name = typeof toolName === 'string' ? toolName : 'unknown';
          const entry = { id: toolCallId, name, argsText: '' };
          this.pendingToolCalls.set(toolCallId, entry);
          return entry;
        })();
      if (typeof chunk.argsTextDelta === 'string') {
        pending.argsText += chunk.argsTextDelta;
      }
      return chunk;
    }

    if (type === 'tool-call') {
      const toolCallId = chunk.toolCallId;
      const toolName = chunk.toolName ?? (chunk as any).name;
      if (typeof toolCallId !== 'string' || typeof toolName !== 'string') {
        return chunk;
      }

      const pending = this.pendingToolCalls.get(toolCallId);
      const args = pending
        ? parseJsonBestEffort(pending.argsText)
        : parseJsonBestEffort(chunk.args);
      const context = this.getContext ? this.getContext(chunk) : this.context;

      const result = await this.interceptor.beforeExecute(toolName, args, context);

      this.pendingToolCalls.delete(toolCallId);

      if (!result.proceed) {
        return {
          ...chunk,
          __clawdstrike_blocked: true,
          __clawdstrike_reason: result.decision.message ?? result.decision.reason ?? 'denied',
        };
      }

      return chunk;
    }

    if (type === 'tool-result') {
      if (this.config.sanitizeOutputs === false) {
        return chunk;
      }

      const toolName = chunk.toolName;
      if (typeof toolName !== 'string') {
        return chunk;
      }

      const context = this.getContext ? this.getContext(chunk) : this.context;
      const processed = await this.interceptor.afterExecute(toolName, {}, chunk.result, context);

      return {
        ...chunk,
        result: processed.output,
        __clawdstrike_redacted: processed.modified ? true : undefined,
      };
    }

    return chunk;
  }
}

function parseJsonBestEffort(value: unknown): unknown {
  if (typeof value !== 'string') {
    return value ?? {};
  }
  const trimmed = value.trim();
  if (!trimmed) return {};
  try {
    return JSON.parse(trimmed) as unknown;
  } catch {
    return { raw: value };
  }
}
