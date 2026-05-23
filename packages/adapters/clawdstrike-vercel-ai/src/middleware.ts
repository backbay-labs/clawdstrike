import type {
  LanguageModelV2CallOptions,
  LanguageModelV2Message,
  LanguageModelV2Prompt,
  LanguageModelV2StreamPart,
  LanguageModelV2TextPart,
  LanguageModelV2ToolCallPart,
} from "@ai-sdk/provider";
import type {
  AdapterConfig,
  AuditEvent,
  Decision,
  PolicyEngineLike,
  PolicyEvent,
  SecurityContext,
} from "@clawdstrike/adapter-core";
import {
  BaseToolInterceptor,
  createSecurityContext,
  PolicyEventFactory,
  publishPolicyEventToLocalEdr,
} from "@clawdstrike/adapter-core";

import {
  type HierarchyEnforcerConfig,
  InstructionHierarchyEnforcer,
  InstructionLevel,
  JailbreakDetector,
  type JailbreakDetectorConfig,
  OutputSanitizer,
  type OutputSanitizerConfig,
  PromptWatermarker,
  SanitizationStream,
  type WatermarkConfig,
} from "@clawdstrike/sdk";
import { ClawdstrikeBlockedError, ClawdstrikePromptSecurityError } from "./errors.js";
import { StreamingToolGuard } from "./streaming-tool-guard.js";
import type { VercelAiToolLike } from "./tools.js";
import { secureTools } from "./tools.js";

/**
 * Local mirror of `@clawdstrike/sdk`'s `InstructionHierarchyEnforcer`
 * conflict shape. Re-declared here (rather than imported) to avoid a
 * runtime dep on the SDK's deeper type tree from this surface.
 */
interface HierarchyConflict {
  id: string;
  ruleId: string;
  severity: string;
  action: string;
  triggers: string[];
}

/**
 * Local mirror of `@clawdstrike/sdk`'s `SanitizationResult.findings[number]`.
 */
interface PromptSecurityFinding {
  id?: string;
  category?: string;
  detector?: string;
}

/**
 * Best-effort vendor tool-call shape. Matches both
 * {@link LanguageModelV2ToolCallPart} and the looser `result.toolCalls`
 * entries returned by some providers — they may carry `args`/`parameters`/
 * `input` interchangeably and either `toolName` or `name`.
 */
interface VendorToolCall {
  toolName?: string;
  name?: string;
  args?: unknown;
  parameters?: unknown;
  input?: unknown;
}

/**
 * Vendor signal-shape for `JailbreakDetector.detect(...).signals[]`.
 * The SDK exports a richer type but we only consume `.id` here.
 */
interface JailbreakSignal {
  id: string;
}

export type PromptSecurityMode = "audit" | "warn" | "block";

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
  /**
   * When `true`, permit the middleware to keep operating with no-op
   * detectors if the WASM-backed prompt-security components fail to
   * initialize.
   *
   * Default: `false` — middleware construction will throw a
   * `ClawdstrikeMiddlewareInitError` rather than silently disable security
   * features. This preserves fail-closed semantics for production
   * deployments.
   */
  allowDegradedSecurity?: boolean;
  /**
   * Optional callback fired when degraded mode is opted into AND a
   * prompt-security detector fails to initialize. Only invoked when
   * `allowDegradedSecurity: true`. Each detector failure produces one call
   * with the reason string.
   */
  onDegrade?: (reason: string) => void;
};

/**
 * Thrown when the middleware refuses to start because WASM-backed
 * prompt-security detectors could not initialize and the caller did NOT
 * opt into degraded operation.
 */
export class ClawdstrikeMiddlewareInitError extends Error {
  public readonly detectors: readonly string[];
  public readonly cause?: unknown;
  constructor(detectors: readonly string[], cause?: unknown) {
    super(
      `Clawdstrike middleware: WASM detectors failed to initialize (${detectors.join(", ") || "unknown"}). ` +
        "To allow degraded operation, set allowDegradedSecurity: true.",
    );
    this.name = "ClawdstrikeMiddlewareInitError";
    this.detectors = detectors;
    this.cause = cause;
  }
}

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
    /** Stable name in `ai@5+`. Preferred. */
    wrapLanguageModel?: (args: unknown) => unknown;
    /** Legacy name removed in `ai@5+`. Kept for callers on `ai@3-4`. */
    experimental_wrapLanguageModel?: (args: unknown) => unknown;
  };
}

export interface ClawdstrikeMiddleware {
  readonly engine: PolicyEngineLike;
  readonly interceptor: BaseToolInterceptor;

  createContext(metadata?: Record<string, unknown>): SecurityContext;
  wrapLanguageModel<TModel extends object>(model: TModel): TModel;
  wrapTools<T extends Record<string, VercelAiToolLike>>(tools: T, options?: SecureToolsOptions): T;

  getDecisionFor(toolName: string, input: unknown, context?: SecurityContext): Promise<Decision>;
  getAuditLog(): AuditEvent[];
}

/**
 * Construct a Clawdstrike middleware for use with the Vercel AI SDK.
 *
 * Fail-closed semantics:
 *  - If `config.promptSecurity?.enabled` is true and one or more of the
 *    WASM-backed detectors (InstructionHierarchyEnforcer, JailbreakDetector,
 *    OutputSanitizer) fails to initialize, this function THROWS a
 *    {@link ClawdstrikeMiddlewareInitError} by default.
 *  - To allow the middleware to keep operating with the affected detectors
 *    disabled (no-op), set `config.allowDegradedSecurity: true`. This is an
 *    explicit, audit-visible opt-in. Pair it with `config.onDegrade` to
 *    receive structured notifications about which detectors are degraded.
 *
 * @throws {ClawdstrikeMiddlewareInitError} when WASM detectors fail and
 *   degraded mode is not opted into.
 */
export function createClawdstrikeMiddleware(
  options: CreateClawdstrikeMiddlewareOptions,
): ClawdstrikeMiddleware {
  const config: VercelAiClawdstrikeConfig = options.config ?? {};
  const engine = options.engine;
  const promptSecurity = createPromptSecurityRuntime(config);

  const createContext =
    options.createContext ??
    ((metadata?: Record<string, unknown>) =>
      createSecurityContext({ metadata: { framework: "vercel-ai", ...metadata } }));

  const defaultContext = options.context ?? createContext();
  const interceptor = new BaseToolInterceptor(engine, config);
  const eventFactory = new PolicyEventFactory();
  const contexts = new Set<SecurityContext>([defaultContext]);

  const policyCheckToolName = config.policyCheckToolName ?? "policy_check";

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
      const wrap =
        options.aiSdk?.wrapLanguageModel ?? options.aiSdk?.experimental_wrapLanguageModel;
      if (wrap) {
        return createWrappedModel(
          model,
          wrap,
          interceptor,
          config,
          createContext,
          contexts,
          promptSecurity,
        ) as TModel;
      }
      return createLazyWrappedModel(
        model,
        interceptor,
        config,
        createContext,
        contexts,
        promptSecurity,
      ) as TModel;
    },
    wrapTools,
    async getDecisionFor(
      toolName: string,
      input: unknown,
      context?: SecurityContext,
    ): Promise<Decision> {
      const ctx = context ?? defaultContext;
      const event = eventFactory.create(toolName, normalizeParams(input), ctx.sessionId);
      return await engine.evaluate(event);
    },
    getAuditLog(): AuditEvent[] {
      return Array.from(contexts).flatMap((ctx) => ctx.auditEvents);
    },
  };
}

function normalizeParams(input: unknown): Record<string, unknown> {
  if (typeof input === "object" && input !== null) {
    return input as Record<string, unknown>;
  }
  if (typeof input === "string") {
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
      // `experimental_wrapLanguageModel` was removed in `ai@5+` and renamed
      // to `wrapLanguageModel`. Prefer the stable export; fall back to the
      // legacy name for callers still on `ai@3-4`.
      const ai = (await import("ai")) as {
        wrapLanguageModel?: (args: unknown) => unknown;
        experimental_wrapLanguageModel?: (args: unknown) => unknown;
      };
      const wrap = ai.wrapLanguageModel ?? ai.experimental_wrapLanguageModel;
      if (typeof wrap !== "function") {
        throw new Error(
          `ai.wrapLanguageModel is not available (also tried legacy ai.experimental_wrapLanguageModel)`,
        );
      }
      return createWrappedModel(
        model,
        wrap,
        interceptor,
        config,
        createContext,
        contexts,
        promptSecurity,
      );
    })();

    return wrappedPromise;
  };

  return new Proxy(model, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver) as unknown;
      if (typeof value !== "function") {
        return value;
      }
      return async (...args: unknown[]) => {
        const wrapped = await getWrapped();
        // Proxy forward: `prop` is a `string | symbol` indexed onto an
        // opaque LanguageModel-shaped object whose method set varies per
        // provider. Coerce through a permissive record shape rather than
        // `any` so callers don't lose all type safety on the boundary.
        const fn = (wrapped as Record<string | symbol, unknown>)[prop] as
          | ((...innerArgs: unknown[]) => unknown)
          | undefined;
        if (typeof fn !== "function") {
          throw new Error(`Wrapped model is missing method ${String(prop)}`);
        }
        return await Reflect.apply(fn, wrapped, args);
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
      wrapGenerate: async ({
        doGenerate,
        params,
      }: {
        doGenerate: () => Promise<{
          toolCalls?: VendorToolCall[];
          text?: string;
          [k: string]: unknown;
        }>;
        params: LanguageModelV2CallOptions;
      }) => {
        const context = createContext({ operation: "generate" });
        contexts.add(context);

        if (promptSecurity) {
          emitWasmDegradedEvents(promptSecurity, config, context);
          const next = await applyPromptSecurityToParams(promptSecurity, config, params, context);
          Object.assign(params, next);
        }

        const result = await doGenerate();
        if (promptSecurity) {
          maybeSanitizeGeneratedText(promptSecurity, config, result, context);
        }

        if (!result || !Array.isArray(result.toolCalls)) {
          return result;
        }

        const toolCalls = await Promise.all(
          result.toolCalls.map(async (call: VendorToolCall) => {
            const toolName = call.toolName ?? call.name;
            const args = parseJsonBestEffort(call.args ?? call.parameters ?? call.input);

            if (typeof toolName !== "string") {
              return call;
            }

            const interceptResult = await interceptor.beforeExecute(toolName, args, context);
            if (!interceptResult.proceed) {
              throw new ClawdstrikeBlockedError(toolName, interceptResult.decision);
            }

            return call;
          }),
        );

        return { ...result, toolCalls };
      },

      wrapStream: async ({
        doStream,
        params,
      }: {
        doStream: () => Promise<{ stream?: unknown; [k: string]: unknown }>;
        params: LanguageModelV2CallOptions;
      }) => {
        const context = createContext({ operation: "stream" });
        contexts.add(context);

        if (promptSecurity) {
          emitWasmDegradedEvents(promptSecurity, config, context);
          const next = await applyPromptSecurityToParams(promptSecurity, config, params, context);
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

        const guard =
          config.streamingEvaluation === true
            ? new StreamingToolGuard(interceptor, { config, context })
            : null;

        if (!guard && !sanitizerStreamRef) {
          return result;
        }

        const secureStream = transformUnknownStream(stream, async (chunk) => {
          let current = chunk as LanguageModelV2StreamPart;
          if (guard) {
            const guarded = await guard.processChunk(current as never);
            if (guarded == null) {
              return null;
            }
            current = guarded as unknown as LanguageModelV2StreamPart;
          }

          const out = sanitizeStreamChunkIfNeeded(
            promptSecurity,
            config,
            sanitizerStreamRef,
            current,
            context,
          );
          return out;
        });
        return { ...result, stream: secureStream };
      },
    },
  }) as object;
}

/**
 * Duck-typed adapter over the two supported runtime stream shapes:
 *  - WHATWG `ReadableStream<T>` (browser / Node Web Streams) — exposes `pipeThrough`
 *  - `AsyncIterable<T>` — exposes `Symbol.asyncIterator`
 *
 * These have no shared TypeScript supertype, so the local `StreamLike`
 * interface unifies them at the unknown boundary.
 */
interface StreamLike {
  pipeThrough?: (transform: TransformStream<unknown, unknown>) => unknown;
  [Symbol.asyncIterator]?: () => AsyncIterator<unknown>;
}

function transformUnknownStream(
  stream: unknown,
  transform: (chunk: unknown) => Promise<unknown | unknown[]>,
): unknown {
  const candidate = stream as StreamLike | null | undefined;
  if (
    candidate &&
    typeof candidate.pipeThrough === "function" &&
    typeof TransformStream !== "undefined"
  ) {
    return candidate.pipeThrough(
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

  if (candidate && typeof candidate[Symbol.asyncIterator] === "function") {
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
  degraded: string[];
};

function createPromptSecurityRuntime(
  config: VercelAiClawdstrikeConfig,
): PromptSecurityRuntime | null {
  const cfg = config.promptSecurity;
  if (!cfg?.enabled) {
    return null;
  }

  const mode: PromptSecurityMode =
    cfg.mode ??
    (config.mode === "audit"
      ? "audit"
      : config.mode === "advisory"
        ? "warn"
        : config.blockOnViolation
          ? "block"
          : "warn");

  const instructionHierarchyEnabled = cfg.instructionHierarchy?.enabled !== false;
  const watermarkingEnabled = cfg.watermarking?.enabled === true;
  const jailbreakEnabled = cfg.jailbreakDetection?.enabled !== false;
  const outputSanitizationEnabled = cfg.outputSanitization?.enabled !== false;

  const jailbreakWarnThreshold = cfg.jailbreakDetection?.config?.warnThreshold ?? 30;
  const jailbreakBlockThreshold = cfg.jailbreakDetection?.config?.blockThreshold ?? 70;

  const degraded: string[] = [];
  const degradeFailures: Array<{ detector: string; cause: unknown }> = [];
  const allowDegraded = config.allowDegradedSecurity === true;

  const handleWasmFailure = (detector: string, err: unknown) => {
    const message = err instanceof Error ? err.message : String(err);
    const reason = `${detector} unavailable: ${message}`;
    if (allowDegraded) {
      // biome-ignore lint/suspicious/noConsole: degraded-mode diagnostic
      console.warn(
        `[clawdstrike/vercel-ai] DEGRADED SECURITY — ${reason}. Detector disabled (no-op).`,
      );
      degraded.push(detector);
      try {
        config.onDegrade?.(reason);
      } catch (cbErr) {
        // biome-ignore lint/suspicious/noConsole: callback error surfacing
        console.warn(
          `[clawdstrike/vercel-ai] onDegrade callback threw: ${
            cbErr instanceof Error ? cbErr.message : String(cbErr)
          }`,
        );
      }
    } else {
      degradeFailures.push({ detector, cause: err });
    }
  };

  const isWasmInitError = (err: unknown): boolean =>
    err instanceof Error && /wasm/i.test(err.message);

  let hierarchy: InstructionHierarchyEnforcer | undefined;
  if (instructionHierarchyEnabled) {
    try {
      hierarchy = new InstructionHierarchyEnforcer({
        reminders: { enabled: false },
        ...(cfg.instructionHierarchy?.config ?? {}),
      });
    } catch (err) {
      if (isWasmInitError(err)) {
        handleWasmFailure("InstructionHierarchyEnforcer", err);
      } else {
        throw err;
      }
    }
  }

  let jailbreak: JailbreakDetector | undefined;
  if (jailbreakEnabled) {
    try {
      jailbreak = new JailbreakDetector(cfg.jailbreakDetection?.config ?? {});
    } catch (err) {
      if (isWasmInitError(err)) {
        handleWasmFailure("JailbreakDetector", err);
      } else {
        throw err;
      }
    }
  }

  let outputSanitizer: OutputSanitizer | undefined;
  if (outputSanitizationEnabled) {
    try {
      outputSanitizer = new OutputSanitizer(cfg.outputSanitization?.config ?? {});
    } catch (err) {
      if (isWasmInitError(err)) {
        handleWasmFailure("OutputSanitizer", err);
      } else {
        throw err;
      }
    }
  }

  if (!allowDegraded && degradeFailures.length > 0) {
    // Fail-closed: refuse to construct the middleware with no-op detectors.
    // Throwing at construction (rather than per-request) surfaces the
    // misconfiguration immediately during boot.
    throw new ClawdstrikeMiddlewareInitError(
      degradeFailures.map((f) => f.detector),
      degradeFailures[0]?.cause,
    );
  }

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
    applicationId: cfg.applicationId ?? "unknown",
    sessionId: cfg.sessionId,
    jailbreakWarnThreshold,
    jailbreakBlockThreshold,
    hierarchy,
    jailbreak,
    outputSanitizer,
    getWatermarker,
    degraded,
  };
}

function emitWasmDegradedEvents(
  runtime: PromptSecurityRuntime,
  config: VercelAiClawdstrikeConfig,
  context: SecurityContext,
): void {
  for (const detector of runtime.degraded) {
    recordPromptSecurityAuditEvent(config, context, {
      id: createEventId("wdeg"),
      type: "wasm_degraded",
      timestamp: new Date(),
      contextId: context.id,
      sessionId: context.sessionId,
      details: { detector, reason: "WASM backend unavailable" },
    });
  }
}

async function applyPromptSecurityToParams(
  runtime: PromptSecurityRuntime,
  config: VercelAiClawdstrikeConfig,
  params: LanguageModelV2CallOptions,
  context: SecurityContext,
): Promise<LanguageModelV2CallOptions> {
  let out: LanguageModelV2CallOptions = params;
  const prompt = out?.prompt;

  if (runtime.enabled.jailbreakDetection && runtime.jailbreak) {
    const lastUserText = extractLastUserText(prompt);
    if (lastUserText) {
      const sessionId = runtime.sessionId ?? context.sessionId;
      const r = await runtime.jailbreak.detect(lastUserText, sessionId);
      const shouldWarn = r.riskScore >= runtime.jailbreakWarnThreshold;
      const shouldBlock = r.riskScore >= runtime.jailbreakBlockThreshold;

      if (shouldWarn) {
        recordPromptSecurityAuditEvent(config, context, {
          id: createEventId("psjb"),
          type: "prompt_security_jailbreak",
          timestamp: new Date(),
          contextId: context.id,
          sessionId: context.sessionId,
          details: {
            blocked: shouldBlock,
            riskScore: r.riskScore,
            severity: r.severity,
            fingerprint: r.fingerprint,
            signals: r.signals.map((s: JailbreakSignal) => s.id),
            canonicalization: r.canonicalization,
            session: r.session ? { ...r.session, sessionId: undefined } : undefined,
          },
        });
      }

      if (shouldBlock && runtime.mode === "block") {
        throw new ClawdstrikePromptSecurityError(
          "jailbreak_detection",
          `Blocked: jailbreak detection triggered (${r.severity}, score=${r.riskScore})`,
          { fingerprint: r.fingerprint, riskScore: r.riskScore, severity: r.severity },
        );
      }
    }
  }

  if (
    runtime.enabled.instructionHierarchy &&
    runtime.hierarchy &&
    Array.isArray(prompt) &&
    prompt.some(isPromptMessageTextful)
  ) {
    out = {
      ...out,
      prompt: applyInstructionHierarchyToPrompt(
        runtime.hierarchy,
        prompt,
        context,
        runtime.mode,
        config,
      ),
    };
  }

  if (runtime.enabled.watermarking && runtime.getWatermarker && Array.isArray(out?.prompt)) {
    out = {
      ...out,
      prompt: await applyPromptWatermark(runtime, config, out.prompt, context),
    };
  }

  return out;
}

function createEventId(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function recordPromptSecurityAuditEvent(
  config: VercelAiClawdstrikeConfig,
  context: SecurityContext,
  event: AuditEvent,
): void {
  context.addAuditEvent(event);
  void publishPolicyEventToLocalEdr(
    buildPromptSecurityPolicyEventForEdr(config, context, event),
    config.edr,
  );
}

export function buildPromptSecurityPolicyEventForEdr(
  config: VercelAiClawdstrikeConfig,
  context: SecurityContext,
  event: AuditEvent,
): PolicyEvent {
  return {
    eventId: `vercel-ai-prompt-security-${event.id}`,
    eventType: "custom",
    timestamp: event.timestamp.toISOString(),
    sessionId: event.sessionId,
    data: {
      type: "custom",
      customType: event.type,
      auditEventId: event.id,
      contextId: event.contextId,
      toolName: event.toolName,
      promptContentOmitted: true,
      modelOutputOmitted: true,
      ...safePromptSecurityDetails(event.type, event.details),
    },
    metadata: {
      ...sanitizePromptSecurityMetadata(context.metadata),
      collectorKind: "vercel_ai_prompt_security",
      source: "vercel-ai.prompt-security",
      promptSecurity: true,
      applicationId: config.promptSecurity?.applicationId,
      mode: config.promptSecurity?.mode,
      policyAllowed: promptSecurityPolicyAllowed(event),
      auditEventType: event.type,
      contextId: context.id,
      payloadScrubbed: true,
    },
  };
}

function safePromptSecurityDetails(
  type: AuditEvent["type"],
  details: Record<string, unknown> | undefined,
): Record<string, unknown> {
  const record = details ?? {};

  switch (type) {
    case "wasm_degraded":
      return {
        detector: stringField(record.detector),
        reason: stringField(record.reason),
      };
    case "prompt_security_jailbreak":
      return {
        blocked: record.blocked === true,
        riskScore: numberField(record.riskScore),
        severity: stringField(record.severity),
        fingerprint: stringField(record.fingerprint),
        signals: stringArrayField(record.signals),
        canonicalization: summarizeObject(record.canonicalization),
        session: summarizeObject(record.session),
      };
    case "prompt_security_instruction_hierarchy":
      return {
        valid: record.valid === true,
        conflictCount: Array.isArray(record.conflicts) ? record.conflicts.length : 0,
        conflicts: Array.isArray(record.conflicts)
          ? record.conflicts.map((conflict) => {
              const c = asRecord(conflict);
              return {
                ruleId: stringField(c?.ruleId),
                severity: stringField(c?.severity),
                action: stringField(c?.action),
                triggerCount: Array.isArray(c?.triggers) ? c.triggers.length : 0,
              };
            })
          : [],
        stats: summarizeObject(record.stats),
      };
    case "prompt_security_watermark":
      return {
        fingerprint: stringField(record.fingerprint),
        publicKey: stringField(record.publicKey),
        applicationId: stringField(record.applicationId),
        sessionId: stringField(record.sessionId),
        createdAt: stringField(record.createdAt),
        sequenceNumber: numberField(record.sequenceNumber),
      };
    case "prompt_security_output_sanitized":
      return {
        redactionsCount: numberField(record.redactionsCount),
        findings: Array.isArray(record.findings)
          ? record.findings.map((finding) => {
              const f = asRecord(finding);
              return {
                id: stringField(f?.id),
                category: stringField(f?.category),
                detector: stringField(f?.detector),
              };
            })
          : [],
      };
    default:
      return {
        detailKeys: Object.keys(record).slice(0, 50),
      };
  }
}

function promptSecurityPolicyAllowed(event: AuditEvent): boolean | undefined {
  if (event.type !== "prompt_security_jailbreak") return undefined;
  return asRecord(event.details)?.blocked !== true;
}

const EDR_METADATA_SENSITIVE_KEY =
  /(?:secret|token|password|passwd|credential|api[_-]?key|authorization|cookie|session|private[_-]?key|access[_-]?key|refresh[_-]?token|id[_-]?token|client[_-]?secret)/i;
const EDR_METADATA_CONTENT_KEY =
  /(?:content|body|payload|patch|diff|result|output|prompt|input|message|raw)/i;
const EDR_SECRET_LIKE_VALUE =
  /(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;

function sanitizePromptSecurityMetadata(
  metadata: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(metadata)) {
    out[key] = sanitizePromptSecurityMetadataValue(key, value);
  }
  return out;
}

function sanitizePromptSecurityMetadataValue(key: string, value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "boolean" || typeof value === "number") return value;

  if (typeof value === "string") {
    if (
      EDR_METADATA_SENSITIVE_KEY.test(key) ||
      EDR_METADATA_CONTENT_KEY.test(key) ||
      EDR_SECRET_LIKE_VALUE.test(value)
    ) {
      return { omitted: true, length: value.length };
    }
    if (value.length > 256) {
      return { omitted: true, reason: "large_string", length: value.length };
    }
    return value;
  }

  if (Array.isArray(value)) {
    return { valueType: "array", itemCount: value.length };
  }

  if (typeof value === "object") {
    const keys = Object.keys(value as Record<string, unknown>);
    return { valueType: "object", keyCount: keys.length, keys: keys.slice(0, 25) };
  }

  return String(value);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function stringField(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function numberField(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function stringArrayField(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string").slice(0, 50)
    : [];
}

function summarizeObject(value: unknown): Record<string, unknown> | undefined {
  const record = asRecord(value);
  if (!record) return undefined;
  const keys = Object.keys(record).slice(0, 50);
  return {
    keyCount: Object.keys(record).length,
    keys,
  };
}

function applyInstructionHierarchyToPrompt(
  enforcer: InstructionHierarchyEnforcer,
  prompt: LanguageModelV2Prompt,
  context: SecurityContext,
  mode: PromptSecurityMode,
  config: VercelAiClawdstrikeConfig,
): LanguageModelV2Prompt {
  const inputs = prompt
    .map((msg, idx) => {
      if (!isPromptMessageTextful(msg)) return null;
      const role = msg.role;
      const level = role === "system" ? InstructionLevel.System : InstructionLevel.User;

      return {
        id: `p${idx}`,
        level,
        role,
        content: extractMessageText(msg),
        source: {
          type: role === "system" ? "developer" : "user",
          trusted: role === "system",
        },
      };
    })
    .filter(Boolean);

  // Cast `inputs` at the enforcer boundary: the hierarchy enforcer's
  // `enforce` signature accepts an SDK-internal `InstructionInput[]`
  // shape that is structurally identical to what we build here, but the
  // SDK does not currently re-export it.
  const result = enforcer.enforce(inputs as never);

  recordPromptSecurityAuditEvent(config, context, {
    id: createEventId("psih"),
    type: "prompt_security_instruction_hierarchy",
    timestamp: new Date(),
    contextId: context.id,
    sessionId: context.sessionId,
    details: {
      valid: result.valid,
      conflicts: result.conflicts.map((c: HierarchyConflict) => ({
        id: c.id,
        ruleId: c.ruleId,
        severity: c.severity,
        action: c.action,
        triggers: c.triggers,
      })),
      stats: result.stats,
    },
  });

  if (!result.valid && mode === "block") {
    throw new ClawdstrikePromptSecurityError(
      "instruction_hierarchy",
      "Blocked: instruction hierarchy violation detected",
      {
        conflicts: result.conflicts.map((c: HierarchyConflict) => ({
          ruleId: c.ruleId,
          severity: c.severity,
          triggers: c.triggers,
        })),
      },
    );
  }

  const outPrompt: LanguageModelV2Message[] = [];
  let cursor = 0;
  const resolveIdx = (id: string): number | null => {
    if (!id.startsWith("p")) return null;
    const n = Number(id.slice(1));
    return Number.isInteger(n) ? n : null;
  };

  for (const m of result.messages) {
    const idx = resolveIdx(m.id);
    if (idx === null || idx < 0 || idx >= prompt.length) {
      outPrompt.push({
        role: "system",
        content: m.content,
      });
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
  config: VercelAiClawdstrikeConfig,
  prompt: LanguageModelV2Prompt,
  context: SecurityContext,
): Promise<LanguageModelV2Prompt> {
  const wm = await runtime.getWatermarker!();
  const sessionId = runtime.sessionId ?? context.sessionId;
  const payload = wm.generatePayload(runtime.applicationId, sessionId);
  const watermarked = await wm.watermark("", payload);
  const watermarkText = watermarked.watermarked.trimEnd();

  // Lazy import to avoid pulling crypto into environments that never enable watermarking.
  const { WatermarkExtractor } = await import("@clawdstrike/sdk");
  const fingerprint = new WatermarkExtractor().fingerprint(watermarked.watermark);

  recordPromptSecurityAuditEvent(config, context, {
    id: createEventId("pswm"),
    type: "prompt_security_watermark",
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

  return [{ role: "system", content: watermarkText }, ...prompt];
}

type SanitizerStreamRef = { stream: SanitizationStream | null };

function sanitizeStreamChunkIfNeeded(
  runtime: PromptSecurityRuntime | null,
  config: VercelAiClawdstrikeConfig,
  streamRef: SanitizerStreamRef | null,
  chunk: LanguageModelV2StreamPart,
  context: SecurityContext,
): unknown | unknown[] | null {
  if (!runtime?.outputSanitizer || !runtime.enabled.outputSanitization || !streamRef?.stream) {
    return chunk;
  }

  if (!chunk || typeof chunk !== "object") {
    return chunk;
  }

  const type = chunk.type;
  if (type === "text-delta") {
    // V2 stream-part text-delta carries the delta as `delta` (V3+) or
    // `textDelta` (V2-era providers). Accept either field; emit using the
    // incoming shape preserved by spread.
    const partRecord = chunk as Record<string, unknown>;
    const delta =
      typeof partRecord.textDelta === "string"
        ? (partRecord.textDelta as string)
        : typeof partRecord.delta === "string"
          ? (partRecord.delta as string)
          : undefined;
    if (typeof delta !== "string") {
      return chunk;
    }

    const result = streamRef.stream.write(delta);
    if (!result) {
      return null;
    }
    // Use the stream-processed chunk. This may differ from the incoming delta
    // due to buffering and cross-boundary redaction.
    return { ...chunk, textDelta: result.sanitized };
  }

  if (type === "finish" || type === "error") {
    const final = streamRef.stream.flush();
    streamRef.stream = null;

    if (final.wasRedacted) {
      recordPromptSecurityAuditEvent(config, context, {
        id: createEventId("psos"),
        type: "prompt_security_output_sanitized",
        timestamp: new Date(),
        contextId: context.id,
        sessionId: context.sessionId,
        details: {
          findings: final.findings.map((f: PromptSecurityFinding) => ({
            id: f.id,
            category: f.category,
            detector: f.detector,
          })),
          redactionsCount: final.redactions.length,
        },
      });
    }

    // Always emit remaining buffered text before the finish/error event.
    // Without this, clean (non-redacted) text accumulated in the buffer
    // since the last flush would be silently dropped.
    if (type === "finish" && final.sanitized.length > 0) {
      return [{ type: "text-delta", textDelta: final.sanitized }, chunk];
    }
    return chunk;
  }

  if (type === "tool-result") {
    const partRecord = chunk as Record<string, unknown>;
    const toolResult = partRecord.result;
    if (typeof toolResult === "string") {
      const r = runtime.outputSanitizer.sanitize(toolResult);
      if (r.wasRedacted) {
        const toolNameField = partRecord.toolName;
        recordPromptSecurityAuditEvent(config, context, {
          id: createEventId("psos"),
          type: "prompt_security_output_sanitized",
          timestamp: new Date(),
          contextId: context.id,
          sessionId: context.sessionId,
          toolName: typeof toolNameField === "string" ? toolNameField : undefined,
          details: {
            findings: r.findings.map((f: PromptSecurityFinding) => ({
              id: f.id,
              category: f.category,
              detector: f.detector,
            })),
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
  for (const rawMsg of prompt) {
    if (!rawMsg || typeof rawMsg !== "object") continue;
    const msg = rawMsg as LanguageModelV2Message;
    if (msg.role !== "user") continue;
    const content = msg.content;
    if (!Array.isArray(content)) continue;
    const parts = content.filter(
      (p): p is LanguageModelV2TextPart =>
        !!p &&
        typeof p === "object" &&
        (p as { type?: unknown }).type === "text" &&
        typeof (p as { text?: unknown }).text === "string",
    );
    const joined = parts.map((p) => p.text).join("");
    last = joined;
  }
  return last && last.trim().length ? last : null;
}

function applyTextToPromptMessage(
  originalMessage: LanguageModelV2Message,
  newText: string,
): LanguageModelV2Message {
  if (!originalMessage || typeof originalMessage !== "object") return originalMessage;
  const role = originalMessage.role;
  if (role === "system" && typeof originalMessage.content === "string") {
    return { ...originalMessage, content: newText };
  }

  if ((role === "user" || role === "assistant") && Array.isArray(originalMessage.content)) {
    type Part = LanguageModelV2Message extends { content: infer C }
      ? C extends Array<infer P>
        ? P
        : never
      : never;
    const parts = originalMessage.content as Part[];
    const outParts: Part[] = [];
    let inserted = false;
    for (const part of parts) {
      if (part && typeof part === "object" && (part as { type?: unknown }).type === "text") {
        if (!inserted) {
          outParts.push({ ...(part as object), text: newText } as Part);
          inserted = true;
        }
        continue;
      }
      outParts.push(part);
    }
    if (!inserted) {
      outParts.unshift({ type: "text", text: newText } as unknown as Part);
    }
    // Cast back to the discriminated union — outParts is the structurally
    // correct content-array variant for the role-narrowed branch.
    return { ...originalMessage, content: outParts } as LanguageModelV2Message;
  }

  return originalMessage;
}

function isPromptMessageTextful(msg: LanguageModelV2Message): boolean {
  if (!msg || typeof msg !== "object") return false;
  const role = msg.role;
  if (role === "system") return typeof msg.content === "string";
  if (role === "user" || role === "assistant") {
    const content = msg.content;
    if (!Array.isArray(content)) return false;
    return content.some(
      (p) =>
        !!p &&
        typeof p === "object" &&
        (p as { type?: unknown }).type === "text" &&
        typeof (p as { text?: unknown }).text === "string" &&
        (p as { text: string }).text.length > 0,
    );
  }
  return false;
}

function extractMessageText(msg: LanguageModelV2Message): string {
  const role = msg?.role;
  if (role === "system" && typeof msg.content === "string") return msg.content;
  if ((role === "user" || role === "assistant") && Array.isArray(msg.content)) {
    const texts: string[] = [];
    for (const p of msg.content) {
      if (
        p &&
        typeof p === "object" &&
        (p as { type?: unknown }).type === "text" &&
        typeof (p as { text?: unknown }).text === "string"
      ) {
        texts.push((p as LanguageModelV2TextPart).text);
      }
    }
    return texts.join("");
  }
  return "";
}

function maybeSanitizeGeneratedText(
  runtime: PromptSecurityRuntime | null,
  config: VercelAiClawdstrikeConfig,
  result: { text?: string; __clawdstrike_redacted?: boolean; [k: string]: unknown },
  context: SecurityContext,
): void {
  if (!runtime?.outputSanitizer || !runtime.enabled.outputSanitization) return;
  const text = result?.text;
  if (typeof text !== "string" || !text) return;

  const r = runtime.outputSanitizer.sanitize(text);
  if (!r.wasRedacted) return;

  result.text = r.sanitized;
  result.__clawdstrike_redacted = true;
  recordPromptSecurityAuditEvent(config, context, {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
    type: "prompt_security_output_sanitized",
    timestamp: new Date(),
    contextId: context.id,
    sessionId: context.sessionId,
    details: {
      findings: r.findings.map((f: PromptSecurityFinding) => ({
        id: f.id,
        category: f.category,
        detector: f.detector,
      })),
      redactionsCount: r.redactions.length,
    },
  });
}

function parseJsonBestEffort(value: unknown): unknown {
  if (typeof value !== "string") {
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
