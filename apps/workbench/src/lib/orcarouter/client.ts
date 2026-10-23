/**
 * Minimal OrcaRouter client used by the provider panel's connection test and
 * by any entry that wants to prove the credential works.
 *
 * OrcaRouter speaks the OpenAI wire format against
 * `https://api.orcarouter.ai/v1`, so this is a thin Bearer-auth wrapper — it is
 * not a general "custom base URL" escape hatch: the origin comes from
 * `resolveOrcaRouterOrigins()`.
 */

import {
  orcaRouterChatCompletionsUrl,
  orcaRouterEmbeddingsUrl,
  type OrcaRouterOrigins,
} from "./provider";

export type OrcaRouterRequestErrorKind =
  | "auth"
  | "rate_limited"
  | "network"
  | "timeout"
  | "http"
  | "invalid_response";

export class OrcaRouterRequestError extends Error {
  readonly kind: OrcaRouterRequestErrorKind;
  readonly status: number | null;

  constructor(kind: OrcaRouterRequestErrorKind, message: string, status: number | null = null) {
    super(message);
    this.name = "OrcaRouterRequestError";
    this.kind = kind;
    this.status = status;
  }
}

export interface OrcaRouterClientOptions {
  origins: OrcaRouterOrigins;
  apiKey: string;
  fetchFn?: typeof fetch;
  timeoutMs?: number;
}

export interface EmbeddingResult {
  embedding: number[];
  model: string;
}

export interface ChatResult {
  content: string;
  model: string;
  usage: { input: number; output: number } | null;
}

const DEFAULT_TIMEOUT_MS = 20_000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

function assertKey(apiKey: string): void {
  if (!apiKey.trim()) {
    throw new OrcaRouterRequestError("auth", "No OrcaRouter credential is configured");
  }
}

async function postJson(
  url: string,
  apiKey: string,
  body: unknown,
  options: OrcaRouterClientOptions,
): Promise<unknown> {
  assertKey(apiKey);
  const fetchFn = options.fetchFn ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetchFn(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        accept: "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (err) {
    const aborted = err instanceof Error && err.name === "AbortError";
    throw new OrcaRouterRequestError(
      aborted ? "timeout" : "network",
      aborted
        ? "OrcaRouter request timed out"
        : "Could not reach the OrcaRouter inference endpoint",
    );
  } finally {
    clearTimeout(timer);
  }

  const raw = await response.text().catch(() => "");
  if (raw.length > MAX_RESPONSE_BYTES) {
    throw new OrcaRouterRequestError("invalid_response", "OrcaRouter response was too large");
  }
  if (!response.ok) {
    if (response.status === 401) {
      throw new OrcaRouterRequestError(
        "auth",
        "OrcaRouter rejected the credential (401) — reconnect or paste a new key",
        401,
      );
    }
    if (response.status === 403) {
      throw new OrcaRouterRequestError(
        "auth",
        "This credential is not permitted for the requested model (403)",
        403,
      );
    }
    if (response.status === 429) {
      throw new OrcaRouterRequestError(
        "rate_limited",
        "OrcaRouter rate limited the request (429); retry shortly",
        429,
      );
    }
    throw new OrcaRouterRequestError(
      "http",
      `OrcaRouter returned HTTP ${response.status}`,
      response.status,
    );
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw new OrcaRouterRequestError("invalid_response", "OrcaRouter returned invalid JSON");
  }
}

export function createOrcaRouterClient(options: OrcaRouterClientOptions) {
  return {
    async embed(model: string, input: string): Promise<EmbeddingResult> {
      const payload = (await postJson(
        orcaRouterEmbeddingsUrl(options.origins),
        options.apiKey,
        { model, input },
        options,
      )) as { data?: { embedding?: unknown }[]; model?: unknown };
      const embedding = payload?.data?.[0]?.embedding;
      if (!Array.isArray(embedding) || embedding.length === 0) {
        throw new OrcaRouterRequestError(
          "invalid_response",
          "OrcaRouter embedding response had no vector",
        );
      }
      return {
        embedding: embedding as number[],
        model: typeof payload.model === "string" ? payload.model : model,
      };
    },

    async chat(
      model: string,
      messages: { role: "system" | "user" | "assistant"; content: string }[],
      maxTokens = 256,
    ): Promise<ChatResult> {
      const payload = (await postJson(
        orcaRouterChatCompletionsUrl(options.origins),
        options.apiKey,
        { model, messages, max_tokens: maxTokens },
        options,
      )) as {
        choices?: { message?: { content?: unknown } }[];
        model?: unknown;
        usage?: { prompt_tokens?: number; completion_tokens?: number };
      };
      const content = payload?.choices?.[0]?.message?.content;
      if (typeof content !== "string") {
        throw new OrcaRouterRequestError(
          "invalid_response",
          "OrcaRouter chat response had no message content",
        );
      }
      return {
        content,
        model: typeof payload.model === "string" ? payload.model : model,
        usage: payload.usage
          ? {
              input: payload.usage.prompt_tokens ?? 0,
              output: payload.usage.completion_tokens ?? 0,
            }
          : null,
      };
    },
  };
}

export type OrcaRouterClient = ReturnType<typeof createOrcaRouterClient>;
