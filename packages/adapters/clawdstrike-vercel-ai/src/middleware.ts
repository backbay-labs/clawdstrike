import { BaseToolInterceptor, PolicyEventFactory, createSecurityContext } from '@clawdstrike/adapter-core';
import type {
  AdapterConfig,
  AuditEvent,
  Decision,
  PolicyEngineLike,
  SecurityContext,
} from '@clawdstrike/adapter-core';

import {
  InstructionHierarchyEnforcer,
  InstructionLevel,
  JailbreakDetector,
  OutputSanitizer,
  PromptWatermarker,
  SanitizationStream,
  type HierarchyEnforcerConfig,
  type JailbreakDetectorConfig,
  type OutputSanitizerConfig,
  type WatermarkConfig,
} from '@clawdstrike/sdk';

import type { VercelAiToolLike } from './tools.js';
import { secureTools } from './tools.js';
import { ClawdstrikePromptSecurityError } from './errors.js';
import { StreamingToolGuard } from './streaming-tool-guard.js';

export type PromptSecurityMode = 'audit' | 'warn' | 'block';

export interface VercelAiPromptSecurityConfig {
  enabled?: boolean;
  mode?: PromptSecurityMode;
  applicationId?: string;
  sessionId?: string;

  instructionHierarchy?: {
    enabled?: boolean;
    config?: HierarchyEnforcerConfig;
  };

  watermarking?: {
    enabled?: boolean;
    config?: WatermarkConfig;
  };

  jailbreakDetection?: {
    enabled?: boolean;
    config?: JailbreakDetectorConfig;
  };

  outputSanitization?: {
    enabled?: boolean;
    config?: OutputSanitizerConfig;
  };
}

export type VercelAiClawdstrikeConfig = AdapterConfig & {
  injectPolicyCheckTool?: boolean;
  policyCheckToolName?: string;
  streamingEvaluation?: boolean;
  promptSecurity?: VercelAiPromptSecurityConfig;
};

export interface SecureToolsOptions {
  context?: SecurityContext;
  getContext?: (toolName: string, input: unknown) => SecurityContext;
}

export interface CreateClawdstrikeMiddlewareOptions {
  engine: PolicyEngineLike;
  config?: VercelAiClawdstrikeConfig;
  context?: SecurityContext;
  createContext?: (metadata?: Record<string, unknown>) => SecurityContext;
  aiSdk?: {
    experimental_wrapLanguageModel?: (args: unknown) => unknown;
  };
}

export interface ClawdstrikeMiddleware {
  readonly engine: PolicyEngineLike;
  readonly interceptor: BaseToolInterceptor;

  createContext(metadata?: Record<string, unknown>): SecurityContext;
  wrapLanguageModel<TModel extends object>(model: TModel): TModel;
  wrapTools<T extends Record<string, VercelAiToolLike>>(
    tools: T,
    options?: SecureToolsOptions,
  ): T;

  getDecisionFor(toolName: string, input: unknown, context?: SecurityContext): Promise<Decision>;
  getAuditLog(): AuditEvent[];
}

export function createClawdstrikeMiddleware(
  options: CreateClawdstrikeMiddlewareOptions,
): ClawdstrikeMiddleware {
  const config: VercelAiClawdstrikeConfig = options.config ?? {};
  const engine = options.engine;
  const promptSecurity = createPromptSecurityRuntime(config);

  const createContext =
    options.createContext ??
    ((metadata?: Record<string, unknown>) =>
      createSecurityContext({ metadata: { framework: 'vercel-ai', ...metadata } }));

  const defaultContext = options.context ?? createContext();
  const interceptor = new BaseToolInterceptor(engine, config);
  const eventFactory = new PolicyEventFactory();
  const contexts = new Set<SecurityContext>([defaultContext]);

  const policyCheckToolName = config.policyCheckToolName ?? 'policy_check';

  const wrapTools = <T extends Record<string, VercelAiToolLike>>(
    tools: T,
    options?: SecureToolsOptions,
  ): T => {
    const rootContext = options?.context ?? defaultContext;
    contexts.add(rootContext);
    const secured = secureTools(tools, interceptor, {
      context: rootContext,
      getContext: options?.getContext,
    });

    if (!config.injectPolicyCheckTool) {
      return secured;
    }

    return {
      ...secured,
      [policyCheckToolName]: {
        async execute(input: { toolName: string; input: unknown }) {
          const ctx = rootContext;
          const event = eventFactory.create(
            input.toolName,
            normalizeParams(input.input),
            ctx.sessionId,
          );
          return engine.evaluate(event);
        },
      },
    } as T;
  };

  return {
    engine,
    interceptor,
    createContext: (metadata?: Record<string, unknown>) => {
      const ctx = createContext(metadata);
      contexts.add(ctx);
      return ctx;
    },
    wrapLanguageModel<TModel extends object>(model: TModel): TModel {
      const wrap = options.aiSdk?.experimental_wrapLanguageModel;
      if (wrap) {
        return createWrappedModel(model, wrap, interceptor, config, createContext, contexts, promptSecurity) as TModel;
      }
      return createLazyWrappedModel(model, interceptor, config, createContext, contexts, promptSecurity) as TModel;
    },
    wrapTools,
    async getDecisionFor(toolName: string, input: unknown, context?: SecurityContext): Promise<Decision> {
      const ctx = context ?? defaultContext;
      const event = eventFactory.create(toolName, normalizeParams(input), ctx.sessionId);
      return await engine.evaluate(event);
    },
    getAuditLog(): AuditEvent[] {
      return Array.from(contexts).flatMap(ctx => ctx.auditEvents);
    },
  };
}

function normalizeParams(input: unknown): Record<string, unknown> {
  if (typeof input === 'object' && input !== null) {
    return input as Record<string, unknown>;
  }
  if (typeof input === 'string') {
    try {
      return JSON.parse(input) as Record<string, unknown>;
    } catch {
      return { raw: input };
    }
  }
  return { value: input };
}

function createLazyWrappedModel(
  model: object,
  interceptor: BaseToolInterceptor,
  config: VercelAiClawdstrikeConfig,
  createContext: (metadata?: Record<string, unknown>) => SecurityContext,
  contexts: Set<SecurityContext>,
  promptSecurity: PromptSecurityRuntime | null,
): object {
  let wrappedPromise: Promise<object> | null = null;

  const getWrapped = async (): Promise<object> => {
    if (wrappedPromise) {
      return wrappedPromise;
    }

    wrappedPromise = (async () => {
      const ai = (await import('ai')) as { experimental_wrapLanguageModel?: (args: unknown) => unknown };
      if (typeof ai.experimental_wrapLanguageModel !== 'function') {
        throw new Error(`ai.experimental_wrapLanguageModel is not available`);
      }
      return createWrappedModel(model, ai.experimental_wrapLanguageModel, interceptor, config, createContext, contexts, promptSecurity);
    })();

    return wrappedPromise;
  };

  return new Proxy(model, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver) as unknown;
      if (typeof value !== 'function') {
        return value;
      }
      return async (...args: unknown[]) => {
        const wrapped = await getWrapped();
        const fn = (wrapped as any)[prop] as (...innerArgs: unknown[]) => unknown;
        if (typeof fn !== 'function') {
          throw new Error(`Wrapped model is missing method ${String(prop)}`);
        }
        return await fn.apply(wrapped, args);
      };
    },
  });
}

function createWrappedModel(
  model: object,
  wrapLanguageModel: (args: unknown) => unknown,
  interceptor: BaseToolInterceptor,
  config: VercelAiClawdstrikeConfig,
  createContext: (metadata?: Record<string, unknown>) => SecurityContext,
  contexts: Set<SecurityContext>,
  promptSecurity: PromptSecurityRuntime | null,
): object {
  return wrapLanguageModel({
    model,
    middleware: {
      wrapGenerate: async ({ doGenerate, params }: { doGenerate: () => Promise<any>; params: any }) => {
        const context = createContext({ operation: 'generate' });
        contexts.add(context);

        if (promptSecurity) {
          const next = await applyPromptSecurityToParams(promptSecurity, params, context);
          Object.assign(params, next);
        }

        const result = await doGenerate();
        if (promptSecurity) {
          maybeSanitizeGeneratedText(promptSecurity, result, context);
        }

        if (!result || !Array.isArray(result.toolCalls)) {
          return result;
        }

        const toolCalls = await Promise.all(
          result.toolCalls.map(async (call: any) => {
            const toolName = call.toolName ?? call.name;
            const args = parseJsonBestEffort(call.args ?? call.parameters ?? call.input);

            if (typeof toolName !== 'string') {
              return call;
            }

            const interceptResult = await interceptor.beforeExecute(toolName, args, context);
            if (!interceptResult.proceed) {
              return {
                ...call,
                __clawdstrike_blocked: true,
                __clawdstrike_reason: interceptResult.decision.message ?? interceptResult.decision.reason ?? 'denied',
              };
            }

            return call;
          }),
        );

        return { ...result, toolCalls };
      },

      wrapStream: async ({ doStream, params }: { doStream: () => Promise<any>; params: any }) => {
        const context = createContext({ operation: 'stream' });
        contexts.add(context);

        if (promptSecurity) {
          const next = await applyPromptSecurityToParams(promptSecurity, params, context);
          Object.assign(params, next);
        }

        const result = await doStream();
        const stream = result?.stream;
        if (!stream) {
          return result;
        }

        const sanitizerStreamRef: SanitizerStreamRef | null =
          promptSecurity?.outputSanitizer && promptSecurity.enabled.outputSanitization
            ? { stream: promptSecurity.outputSanitizer.createStream() }
            : null;

        const guard = config.streamingEvaluation === true
          ? new StreamingToolGuard(interceptor, { config, context })
          : null;

        if (!guard && !sanitizerStreamRef) {
          return result;
        }

        const secureStream = transformUnknownStream(stream, async (chunk) => {
          let current = chunk as any;
          if (guard) {
            const guarded = await guard.processChunk(current);
            if (guarded == null) {
              return null;
            }
            current = guarded as any;
          }

          const out = sanitizeStreamChunkIfNeeded(promptSecurity, sanitizerStreamRef, current, context);
          return out;
        });
        return { ...result, stream: secureStream };
      },
    },
  }) as object;
}

function transformUnknownStream(
  stream: unknown,
  transform: (chunk: unknown) => Promise<unknown | unknown[]>,
): unknown {
  if (stream && typeof (stream as any).pipeThrough === 'function' && typeof TransformStream !== 'undefined') {
    return (stream as any).pipeThrough(
      new TransformStream({
        async transform(chunk, controller) {
          const processed = await transform(chunk);
          if (Array.isArray(processed)) {
            for (const item of processed) {
              if (item !== null && item !== undefined) controller.enqueue(item);
            }
          } else if (processed !== null && processed !== undefined) {
            controller.enqueue(processed);
          }
        },
      }),
    );
  }

  if (stream && typeof (stream as any)[Symbol.asyncIterator] === 'function') {
    return (async function* () {
      for await (const chunk of stream as AsyncIterable<unknown>) {
        const processed = await transform(chunk);
        if (Array.isArray(processed)) {
          for (const item of processed) {
            if (item !== null && item !== undefined) yield item;
          }
        } else if (processed !== null && processed !== undefined) {
          yield processed;
        }
      }
    })();
  }

  return stream;
}

type PromptSecurityRuntime = {
  enabled: {
    instructionHierarchy: boolean;
    watermarking: boolean;
    jailbreakDetection: boolean;
    outputSanitization: boolean;
  };
  mode: PromptSecurityMode;
  applicationId: string;
  sessionId?: string;
  jailbreakWarnThreshold: number;
  jailbreakBlockThreshold: number;
  hierarchy?: InstructionHierarchyEnforcer;
  jailbreak?: JailbreakDetector;
  outputSanitizer?: OutputSanitizer;
  getWatermarker?: () => Promise<PromptWatermarker>;
};

function createPromptSecurityRuntime(config: VercelAiClawdstrikeConfig): PromptSecurityRuntime | null {
  const cfg = config.promptSecurity;
  if (!cfg?.enabled) {
    return null;
  }

  const mode: PromptSecurityMode =
    cfg.mode
    ?? (config.mode === 'audit' ? 'audit' : config.mode === 'advisory' ? 'warn' : config.blockOnViolation ? 'block' : 'warn');

  const instructionHierarchyEnabled = cfg.instructionHierarchy?.enabled !== false;
  const watermarkingEnabled = cfg.watermarking?.enabled === true;
  const jailbreakEnabled = cfg.jailbreakDetection?.enabled !== false;
  const outputSanitizationEnabled = cfg.outputSanitization?.enabled !== false;

  const jailbreakWarnThreshold = cfg.jailbreakDetection?.config?.warnThreshold ?? 30;
  const jailbreakBlockThreshold = cfg.jailbreakDetection?.config?.blockThreshold ?? 70;

  const hierarchy = instructionHierarchyEnabled
    ? new InstructionHierarchyEnforcer({
      reminders: { enabled: false },
      ...(cfg.instructionHierarchy?.config ?? {}),
    })
    : undefined;

  const jailbreak = jailbreakEnabled ? new JailbreakDetector(cfg.jailbreakDetection?.config ?? {}) : undefined;

  const outputSanitizer = outputSanitizationEnabled ? new OutputSanitizer(cfg.outputSanitization?.config ?? {}) : undefined;

  let watermarkerPromise: Promise<PromptWatermarker> | null = null;
  const getWatermarker = watermarkingEnabled
    ? () => {
      if (!watermarkerPromise) {
        watermarkerPromise = PromptWatermarker.create(cfg.watermarking?.config ?? {});
      }
      return watermarkerPromise;
    }
    : undefined;

  return {
    enabled: {
      instructionHierarchy: instructionHierarchyEnabled,
      watermarking: watermarkingEnabled,
      jailbreakDetection: jailbreakEnabled,
      outputSanitization: outputSanitizationEnabled,
    },
    mode,
    applicationId: cfg.applicationId ?? 'unknown',
    sessionId: cfg.sessionId,
    jailbreakWarnThreshold,
    jailbreakBlockThreshold,
    hierarchy,
    jailbreak,
    outputSanitizer,
    getWatermarker,
  };
}

async function applyPromptSecurityToParams(
  runtime: PromptSecurityRuntime,
  params: any,
  context: SecurityContext,
): Promise<any> {
  let out = params;
  const prompt = out?.prompt;

  if (runtime.enabled.jailbreakDetection && runtime.jailbreak) {
    const lastUserText = extractLastUserText(prompt);
    if (lastUserText) {
      const sessionId = runtime.sessionId ?? context.sessionId;
      const r = await runtime.jailbreak.detect(lastUserText, sessionId);
      const shouldWarn = r.riskScore >= runtime.jailbreakWarnThreshold;
      const shouldBlock = r.riskScore >= runtime.jailbreakBlockThreshold;

      if (shouldWarn) {
        context.addAuditEvent({
          id: createEventId('psjb'),
          type: 'prompt_security_jailbreak',
          timestamp: new Date(),
          contextId: context.id,
          sessionId: context.sessionId,
          details: {
            blocked: shouldBlock,
            riskScore: r.riskScore,
            severity: r.severity,
            fingerprint: r.fingerprint,
            signals: r.signals.map(s => s.id),
            canonicalization: r.canonicalization,
            session: r.session ? { ...r.session, sessionId: undefined } : undefined,
          },
        });
      }

      if (shouldBlock && runtime.mode === 'block') {
        throw new ClawdstrikePromptSecurityError(
          'jailbreak_detection',
          `Blocked: jailbreak detection triggered (${r.severity}, score=${r.riskScore})`,
          { fingerprint: r.fingerprint, riskScore: r.riskScore, severity: r.severity },
        );
      }
    }
  }

  if (runtime.enabled.instructionHierarchy && runtime.hierarchy && Array.isArray(prompt) && prompt.some(isPromptMessageTextful)) {
    out = {
      ...out,
      prompt: applyInstructionHierarchyToPrompt(runtime.hierarchy, prompt, context, runtime.mode),
    };
  }

  if (runtime.enabled.watermarking && runtime.getWatermarker && Array.isArray((out as any)?.prompt)) {
    out = {
      ...out,
      prompt: await applyPromptWatermark(runtime, (out as any).prompt, context),
    };
  }

  return out;
}

function createEventId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function applyInstructionHierarchyToPrompt(
  enforcer: InstructionHierarchyEnforcer,
  prompt: any[],
  context: SecurityContext,
  mode: PromptSecurityMode,
): any[] {
  const inputs = prompt
    .map((msg, idx) => {
      if (!isPromptMessageTextful(msg)) return null;
      const role = (msg as any).role;
      const level = role === 'system' ? InstructionLevel.System : InstructionLevel.User;

      return {
        id: `p${idx}`,
        level,
        role,
        content: extractMessageText(msg),
        source: {
          type: role === 'system' ? 'developer' : 'user',
          trusted: role === 'system',
        },
      };
    })
    .filter(Boolean);

  const result = enforcer.enforce(inputs as any);

  context.addAuditEvent({
    id: createEventId('psih'),
    type: 'prompt_security_instruction_hierarchy',
    timestamp: new Date(),
    contextId: context.id,
    sessionId: context.sessionId,
    details: {
      valid: result.valid,
      conflicts: result.conflicts.map(c => ({
        id: c.id,
        ruleId: c.ruleId,
        severity: c.severity,
        action: c.action,
        triggers: c.triggers,
      })),
      stats: result.stats,
    },
  });

  if (!result.valid && mode === 'block') {
    throw new ClawdstrikePromptSecurityError(
      'instruction_hierarchy',
      'Blocked: instruction hierarchy violation detected',
      { conflicts: result.conflicts.map(c => ({ ruleId: c.ruleId, severity: c.severity, triggers: c.triggers })) },
    );
  }

  const outPrompt: any[] = [];
  let cursor = 0;
  const resolveIdx = (id: string): number | null => {
    if (!id.startsWith('p')) return null;
    const n = Number(id.slice(1));
    return Number.isInteger(n) ? n : null;
  };

  for (const m of result.messages) {
    const idx = resolveIdx(m.id);
    if (idx === null || idx < 0 || idx >= prompt.length) {
      outPrompt.push({ role: 'system', content: m.content });
      continue;
    }

    while (cursor < idx) {
      outPrompt.push(prompt[cursor]);
      cursor += 1;
    }
    outPrompt.push(applyTextToPromptMessage(prompt[idx], m.content));
    cursor = idx + 1;
  }

  while (cursor < prompt.length) {
    outPrompt.push(prompt[cursor]);
    cursor += 1;
  }

  return outPrompt;
}

async function applyPromptWatermark(
  runtime: PromptSecurityRuntime,
  prompt: any[],
  context: SecurityContext,
): Promise<any[]> {
  const wm = await runtime.getWatermarker!();
  const sessionId = runtime.sessionId ?? context.sessionId;
  const payload = wm.generatePayload(runtime.applicationId, sessionId);
  const watermarked = await wm.watermark('', payload);
  const watermarkText = watermarked.watermarked.trimEnd();

  // Lazy import to avoid pulling crypto into environments that never enable watermarking.
  const { WatermarkExtractor } = await import('@clawdstrike/sdk');
  const fingerprint = new WatermarkExtractor().fingerprint(watermarked.watermark);

  context.addAuditEvent({
    id: createEventId('pswm'),
    type: 'prompt_security_watermark',
    timestamp: new Date(),
    contextId: context.id,
    sessionId: context.sessionId,
    details: {
      fingerprint,
      publicKey: watermarked.watermark.publicKey,
      applicationId: payload.applicationId,
      sessionId: payload.sessionId,
      createdAt: payload.createdAt,
      sequenceNumber: payload.sequenceNumber,
    },
  });

  return [{ role: 'system', content: watermarkText }, ...prompt];
}

type SanitizerStreamRef = { stream: SanitizationStream | null };

function sanitizeStreamChunkIfNeeded(
  runtime: PromptSecurityRuntime | null,
  streamRef: SanitizerStreamRef | null,
  chunk: any,
  context: SecurityContext,
): unknown | unknown[] | null {
  if (!runtime?.outputSanitizer || !runtime.enabled.outputSanitization || !streamRef?.stream) {
    return chunk;
  }

  if (!chunk || typeof chunk !== 'object') {
    return chunk;
  }

  const type = (chunk as any).type;
  if (type === 'text-delta') {
    const delta = (chunk as any).textDelta;
    if (typeof delta !== 'string') {
      return chunk;
    }

    const sanitized = streamRef.stream.write(delta);
    if (!sanitized) {
      return null;
    }
    if (sanitized === delta) {
      return chunk;
    }
    return { ...chunk, textDelta: sanitized };
  }

  if (type === 'finish' || type === 'error') {
    const final = streamRef.stream.end();
    streamRef.stream = null;

    if (final.redacted) {
      context.addAuditEvent({
        id: createEventId('psos'),
        type: 'prompt_security_output_sanitized',
        timestamp: new Date(),
        contextId: context.id,
        sessionId: context.sessionId,
        details: {
          findings: final.findings.map(f => ({ id: f.id, category: f.category, detector: f.detector })),
          redactionsCount: final.redactions.length,
        },
      });
    }

    if (type === 'finish' && final.sanitized) {
      return [{ type: 'text-delta', textDelta: final.sanitized }, chunk];
    }
    return chunk;
  }

  if (type === 'tool-result') {
    const toolResult = (chunk as any).result;
    if (typeof toolResult === 'string') {
      const r = runtime.outputSanitizer.sanitizeSync(toolResult);
      if (r.redacted) {
        context.addAuditEvent({
          id: createEventId('psos'),
          type: 'prompt_security_output_sanitized',
          timestamp: new Date(),
          contextId: context.id,
          sessionId: context.sessionId,
          toolName: (chunk as any).toolName,
          details: {
            findings: r.findings.map(f => ({ id: f.id, category: f.category, detector: f.detector })),
            redactionsCount: r.redactions.length,
          },
        });
        return { ...chunk, result: r.sanitized, __clawdstrike_redacted: true };
      }
    }
  }

  return chunk;
}

function extractLastUserText(prompt: unknown): string | null {
  if (!Array.isArray(prompt)) return null;
  let last: string | null = null;
  for (const msg of prompt) {
    if (!msg || typeof msg !== 'object') continue;
    if ((msg as any).role !== 'user') continue;
    const content = (msg as any).content;
    if (!Array.isArray(content)) continue;
    const parts = content.filter((p: any) => p && typeof p === 'object' && p.type === 'text' && typeof p.text === 'string');
    const joined = parts.map((p: any) => p.text).join('');
    last = joined;
  }
  return last && last.trim().length ? last : null;
}

function applyTextToPromptMessage(originalMessage: any, newText: string): any {
  if (!originalMessage || typeof originalMessage !== 'object') return originalMessage;
  const role = (originalMessage as any).role;
  if (role === 'system' && typeof (originalMessage as any).content === 'string') {
    return { ...originalMessage, content: newText };
  }

  if ((role === 'user' || role === 'assistant') && Array.isArray((originalMessage as any).content)) {
    const parts = (originalMessage as any).content as any[];
    const outParts: any[] = [];
    let inserted = false;
    for (const part of parts) {
      if (part && typeof part === 'object' && part.type === 'text') {
        if (!inserted) {
          outParts.push({ ...part, text: newText });
          inserted = true;
        }
        continue;
      }
      outParts.push(part);
    }
    if (!inserted) {
      outParts.unshift({ type: 'text', text: newText });
    }
    return { ...originalMessage, content: outParts };
  }

  return originalMessage;
}

function isPromptMessageTextful(msg: any): boolean {
  if (!msg || typeof msg !== 'object') return false;
  const role = (msg as any).role;
  if (role === 'system') return typeof (msg as any).content === 'string';
  if (role === 'user' || role === 'assistant') {
    const content = (msg as any).content;
    if (!Array.isArray(content)) return false;
    return content.some((p: any) => p && typeof p === 'object' && p.type === 'text' && typeof p.text === 'string' && p.text.length > 0);
  }
  return false;
}

function extractMessageText(msg: any): string {
  const role = msg?.role;
  if (role === 'system' && typeof msg.content === 'string') return msg.content;
  if ((role === 'user' || role === 'assistant') && Array.isArray(msg.content)) {
    return msg.content
      .filter((p: any) => p && typeof p === 'object' && p.type === 'text' && typeof p.text === 'string')
      .map((p: any) => p.text)
      .join('');
  }
  return '';
}

function maybeSanitizeGeneratedText(runtime: PromptSecurityRuntime | null, result: any, context: SecurityContext): void {
  if (!runtime?.outputSanitizer || !runtime.enabled.outputSanitization) return;
  const text = result?.text;
  if (typeof text !== 'string' || !text) return;

  const r = runtime.outputSanitizer.sanitizeSync(text);
  if (!r.redacted) return;

  result.text = r.sanitized;
  result.__clawdstrike_redacted = true;
  context.addAuditEvent({
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
    type: 'prompt_security_output_sanitized',
    timestamp: new Date(),
    contextId: context.id,
    sessionId: context.sessionId,
    details: {
      findings: r.findings.map(f => ({ id: f.id, category: f.category, detector: f.detector })),
      redactionsCount: r.redactions.length,
    },
  });
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
