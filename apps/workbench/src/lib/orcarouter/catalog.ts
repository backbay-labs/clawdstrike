/**
 * OrcaRouter model catalogue: live discovery, capability filtering and a
 * small verified cold-start seed.
 *
 * Source of truth: `GET <api-base>/models` on the configured origin
 * (`https://api.orcarouter.ai/v1/models` by default) with the user's key.
 *
 * Design rules:
 *   - live discovery is authoritative when it succeeds;
 *   - a bounded, verified seed keeps a fresh install usable during an outage;
 *   - filtering is driven by catalogue metadata only — never by model names;
 *   - anything whose capabilities are not declared fails closed (it is not
 *     offered for an entry that needs that capability).
 */

import {
  isOrcaRouterCyberModel,
  normalizeCyberModelId,
  ORCAROUTER_CYBER_TIER_ORDER,
  orcaRouterModelsUrl,
  ORCAROUTER_DEFAULT_MODEL,
  ORCAROUTER_FALLBACK_MODEL,
  type OrcaRouterOrigins,
} from "./provider";

export type OrcaRouterCapability =
  | "chat"
  | "embedding"
  | "image"
  | "video"
  | "rerank";

export type OrcaRouterInputModality = "text" | "image" | "audio" | "video" | "file";

export type OrcaRouterReasoningEffort = "low" | "medium" | "high" | "xhigh";

export interface OrcaRouterModel {
  /** Vendor-qualified id, preserved verbatim (e.g. `orcarouter/auto`). */
  id: string;
  name: string;
  capabilities: OrcaRouterCapability[];
  inputModalities: OrcaRouterInputModality[];
  /** Endpoint wire types the catalogue advertises for this model. */
  endpointTypes: string[];
  contextLength: number | null;
  reasoningEfforts: OrcaRouterReasoningEffort[];
  /** True only when the record names chat as a capability itself. */
  explicitChat: boolean;
}

export type OrcaRouterCatalogSource = "live" | "seed" | "last-known-good";
export type OrcaRouterCatalogStatus = "loading" | "ready" | "degraded" | "error";

export interface OrcaRouterCatalog {
  models: OrcaRouterModel[];
  source: OrcaRouterCatalogSource;
  fetchedAt: number;
  /** Human-readable reason shown in the UI when `status === "degraded"`. */
  note?: string;
}

export interface CatalogRequirement {
  capability: OrcaRouterCapability;
  /** Non-text modalities the entry will upload. Empty for text-only entries. */
  modalities?: OrcaRouterInputModality[];
}

const CHAT_ENDPOINT_TYPES = new Set(["openai", "anthropic", "gemini", "openai-response"]);
const CHAT_EXCLUDED_ENDPOINT_TYPES = new Set([
  "embeddings",
  "image-generation",
  "openai-video",
  "jina-rerank",
]);

const ALL_CAPABILITIES: OrcaRouterCapability[] = [
  "chat",
  "embedding",
  "image",
  "video",
  "rerank",
];

const KNOWN_BUILTIN_CAPABILITY_WORDS: Record<string, OrcaRouterCapability> = {
  chat: "chat",
  completion: "chat",
  "chat-completions": "chat",
  embedding: "embedding",
  embeddings: "embedding",
  image: "image",
  "image-generation": "image",
  video: "video",
  "openai-video": "video",
  rerank: "rerank",
  "jina-rerank": "rerank",
};

/**
 * Verified cold-start seed. IDs are OrcaRouter-branded or vendor-namespaced
 * and every entry carries the metadata the selectors filter on. Reasoning
 * ladders are kept exactly as verified for `openai/gpt-5.5`.
 */
export const ORCAROUTER_VERIFIED_SEED: OrcaRouterModel[] = [
  {
    id: "orcarouter/auto",
    name: "OrcaRouter Auto",
    capabilities: ["chat"],
    inputModalities: [],
    endpointTypes: ["openai", "openai-response", "anthropic", "gemini"],
    contextLength: null,
    reasoningEfforts: [],
    explicitChat: true,
  },
  {
    id: "openai/gpt-5.5",
    name: "OpenAI GPT-5.5",
    capabilities: ["chat"],
    inputModalities: ["text", "image", "file"],
    endpointTypes: ["openai", "openai-response"],
    contextLength: null,
    reasoningEfforts: ["low", "medium", "high", "xhigh"],
    explicitChat: true,
  },
  {
    id: "anthropic/claude-opus-4.8",
    name: "Anthropic Claude Opus 4.8",
    capabilities: ["chat"],
    inputModalities: ["text", "image", "file"],
    endpointTypes: ["openai", "anthropic", "openai-response"],
    contextLength: 1_000_000,
    reasoningEfforts: [],
    explicitChat: true,
  },
  {
    id: "google/gemini-3.5-flash",
    name: "Google Gemini 3.5 Flash",
    capabilities: ["chat"],
    inputModalities: ["text", "image", "audio", "video", "file"],
    endpointTypes: ["openai", "gemini"],
    contextLength: 1_048_576,
    reasoningEfforts: [],
    explicitChat: true,
  },
  {
    id: "deepseek/deepseek-v4-pro",
    name: "DeepSeek V4 Pro",
    capabilities: ["chat"],
    inputModalities: ["text"],
    endpointTypes: ["openai", "openai-response"],
    contextLength: 1_048_576,
    reasoningEfforts: [],
    explicitChat: true,
  },
  {
    id: "orca/orcacyber-ultra-1.0",
    name: "OrcaCyber Ultra",
    capabilities: ["chat"],
    inputModalities: ["text"],
    endpointTypes: ["openai"],
    contextLength: 1_048_576,
    reasoningEfforts: [],
    explicitChat: true,
  },
  {
    id: "orca/orcacyber-zero-1.5",
    name: "OrcaCyber Zero",
    capabilities: ["chat"],
    inputModalities: ["text"],
    endpointTypes: ["openai"],
    contextLength: 1_000_000,
    reasoningEfforts: [],
    explicitChat: true,
  },
  {
    id: "orca/orcacyber-zero-1.0",
    name: "OrcaCyber Zero 1.0",
    capabilities: ["chat"],
    inputModalities: ["text"],
    endpointTypes: ["openai"],
    contextLength: 1_000_000,
    reasoningEfforts: [],
    explicitChat: true,
  },
  {
    id: "orcarouter/fusion",
    name: "OrcaRouter Fusion",
    capabilities: ["chat"],
    inputModalities: [],
    endpointTypes: ["openai", "openai-response", "anthropic", "gemini"],
    contextLength: 1_000_000,
    reasoningEfforts: [],
    explicitChat: true,
  },
  {
    // Embedding entry for the cold-start path. The catalogue replaces this as
    // soon as discovery succeeds.
    id: "orcarouter/auto",
    name: "OrcaRouter Auto",
    capabilities: ["embedding"],
    inputModalities: ["text"],
    endpointTypes: ["openai"],
    contextLength: null,
    reasoningEfforts: [],
    explicitChat: false,
  },
];

export interface FetchCatalogOptions {
  origins: OrcaRouterOrigins;
  apiKey: string;
  fetchFn?: typeof fetch;
  signal?: AbortSignal;
  timeoutMs?: number;
  maxBytes?: number;
  maxItems?: number;
  now?: () => number;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_ITEMS = 2_000;

function asStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function normalizeCapability(word: string): OrcaRouterCapability | null {
  const key = word.trim().toLowerCase();
  return KNOWN_BUILTIN_CAPABILITY_WORDS[key] ?? null;
}

function endpointTypesOf(record: Record<string, unknown>): string[] {
  const direct = asStringArray(record.supported_endpoint_types).map((v) => v.toLowerCase());
  if (direct.length > 0) return direct;
  const endpoints = record.endpoints;
  if (Array.isArray(endpoints)) {
    const types: string[] = [];
    for (const endpoint of endpoints) {
      if (typeof endpoint === "string") {
        types.push(endpoint.toLowerCase());
      } else if (endpoint && typeof endpoint === "object") {
        const entry = endpoint as Record<string, unknown>;
        const type = entry.type ?? entry.endpoint_type ?? entry.endpoint;
        if (typeof type === "string") types.push(type.toLowerCase());
      }
    }
    return types;
  }
  return [];
}

function capabilitiesOf(
  record: Record<string, unknown>,
  endpointTypes: string[],
): { capabilities: OrcaRouterCapability[]; explicitChat: boolean } {
  const found = new Set<OrcaRouterCapability>();
  let explicitChat = false;
  const declared = asStringArray(record.capabilities);
  for (const raw of declared) {
    const capability = normalizeCapability(raw);
    if (capability) found.add(capability);
    if (capability === "chat") explicitChat = true;
  }
  for (const type of endpointTypes) {
    const capability = normalizeCapability(type);
    if (capability) found.add(capability);
  }
  // A model with a conversational endpoint type is a chat model even when the
  // catalogue does not spell out a capability array.
  if (endpointTypes.some((type) => CHAT_ENDPOINT_TYPES.has(type))) found.add("chat");
  if (found.size === 0) {
    for (const capability of ALL_CAPABILITIES) {
      if (record[capability] === true) {
        found.add(capability);
        if (capability === "chat") explicitChat = true;
      }
    }
  }
  return {
    capabilities: ALL_CAPABILITIES.filter((capability) => found.has(capability)),
    explicitChat,
  };
}

function inputModalitiesOf(record: Record<string, unknown>): OrcaRouterInputModality[] {
  const architecture =
    record.architecture && typeof record.architecture === "object"
      ? (record.architecture as Record<string, unknown>)
      : null;
  const declared = asStringArray(architecture?.input_modalities ?? record.input_modalities);
  const allowed = new Set<OrcaRouterInputModality>(["text", "image", "audio", "video", "file"]);
  return declared
    .map((value) => value.trim().toLowerCase())
    .filter((value): value is OrcaRouterInputModality =>
      allowed.has(value as OrcaRouterInputModality),
    );
}

function reasoningEffortsOf(record: Record<string, unknown>): OrcaRouterReasoningEffort[] {
  const ladder = asStringArray(record.reasoning_efforts).map((value) => value.toLowerCase());
  const allowed: OrcaRouterReasoningEffort[] = ["low", "medium", "high", "xhigh"];
  const result = allowed.filter((effort) => ladder.includes(effort));
  if (result.length > 0) return result;
  const supported = asStringArray(record.supported_parameters).map((v) => v.toLowerCase());
  if (supported.includes("reasoning") || supported.includes("reasoning_effort")) {
    return ["low", "medium", "high", "xhigh"];
  }
  return [];
}

export function parseOrcaRouterModel(raw: unknown): OrcaRouterModel | null {
  if (!raw || typeof raw !== "object") return null;
  const record = raw as Record<string, unknown>;
  const id = typeof record.id === "string" ? record.id.trim() : "";
  if (id.length === 0) return null;
  const endpointTypes = endpointTypesOf(record);
  const { capabilities, explicitChat } = capabilitiesOf(record, endpointTypes);
  if (capabilities.length === 0) return null;
  const contextRaw = record.context_length ?? record.context_window;
  const contextLength =
    typeof contextRaw === "number" && Number.isFinite(contextRaw) && contextRaw > 0
      ? contextRaw
      : null;
  return {
    id,
    name: typeof record.name === "string" && record.name.trim().length > 0 ? record.name : id,
    capabilities,
    inputModalities: inputModalitiesOf(record),
    endpointTypes,
    contextLength,
    reasoningEfforts: reasoningEffortsOf(record),
    explicitChat,
  };
}

/** Filter for one entry's requirement. Metadata must prove compatibility. */
export function filterModels(
  models: OrcaRouterModel[],
  requirement: CatalogRequirement,
): OrcaRouterModel[] {
  const wantedModalities = (requirement.modalities ?? []).filter(
    (modality) => modality !== "text",
  );
  const seen = new Set<string>();
  const result: OrcaRouterModel[] = [];
  for (const model of models) {
    if (seen.has(model.id)) continue;
    if (!model.capabilities.includes(requirement.capability)) continue;

    if (requirement.capability === "chat") {
      const hasChatEndpoint = model.endpointTypes.some((type) => CHAT_ENDPOINT_TYPES.has(type));
      const onlyExcluded =
        model.endpointTypes.length > 0 &&
        model.endpointTypes.every((type) => CHAT_EXCLUDED_ENDPOINT_TYPES.has(type));
      // A model advertised purely through a non-chat endpoint (embeddings,
      // image/video generation, rerank) is not a chat model, even when it also
      // lists the generic `openai` wire type.
      const dedicatedToOtherWorkload =
        model.endpointTypes.some((type) => CHAT_EXCLUDED_ENDPOINT_TYPES.has(type)) &&
        !model.explicitChat;
      if (!hasChatEndpoint || onlyExcluded || dedicatedToOtherWorkload) continue;
      // Fail closed: a model that does not declare a modality is not offered
      // for an entry that uploads it.
      const missing = wantedModalities.filter(
        (modality) => !model.inputModalities.includes(modality),
      );
      if (missing.length > 0) continue;
    }

    seen.add(model.id);
    result.push(model);
  }
  return result;
}

function dedupe(models: OrcaRouterModel[]): OrcaRouterModel[] {
  const byId = new Map<string, OrcaRouterModel>();
  for (const model of models) {
    const existing = byId.get(model.id);
    if (!existing) {
      byId.set(model.id, { ...model });
      continue;
    }
    byId.set(model.id, {
      ...existing,
      capabilities: ALL_CAPABILITIES.filter(
        (capability) =>
          existing.capabilities.includes(capability) || model.capabilities.includes(capability),
      ),
      inputModalities: Array.from(
        new Set([...existing.inputModalities, ...model.inputModalities]),
      ),
      endpointTypes: Array.from(new Set([...existing.endpointTypes, ...model.endpointTypes])),
      reasoningEfforts:
        existing.reasoningEfforts.length > 0
          ? existing.reasoningEfforts
          : model.reasoningEfforts,
      explicitChat: existing.explicitChat || model.explicitChat,
    });
  }
  return [...byId.values()];
}

export interface CatalogFetchResult {
  catalog: OrcaRouterCatalog;
  status: OrcaRouterCatalogStatus;
}

/**
 * Fetch and parse the live catalogue. Never throws: a failure returns the
 * verified seed with `source: "seed"` (or the caller's last-known-good).
 */
export async function fetchOrcaRouterCatalog(
  options: FetchCatalogOptions & { lastKnownGood?: OrcaRouterModel[] },
): Promise<CatalogFetchResult> {
  const {
    origins,
    apiKey,
    fetchFn = fetch,
    signal,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxBytes = DEFAULT_MAX_BYTES,
    maxItems = DEFAULT_MAX_ITEMS,
    now = () => Date.now(),
    lastKnownGood,
  } = options;

  const fallback = (note: string): CatalogFetchResult => ({
    status: "degraded",
    catalog: {
      models: dedupe(lastKnownGood ?? ORCAROUTER_VERIFIED_SEED),
      source: lastKnownGood ? "last-known-good" : "seed",
      fetchedAt: now(),
      note,
    },
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const onAbort = () => controller.abort();
  signal?.addEventListener("abort", onAbort, { once: true });

  try {
    const response = await fetchFn(orcaRouterModelsUrl(origins), {
      method: "GET",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        accept: "application/json",
      },
      signal: controller.signal,
    });

    if (!response.ok) {
      return fallback(
        response.status === 401
          ? "OrcaRouter rejected the API key (401); showing the verified model seed"
          : `Model catalogue unavailable (HTTP ${response.status}); showing the verified model seed`,
      );
    }

    const text = await response.text();
    if (text.length > maxBytes) {
      return fallback("Model catalogue response was too large; showing the verified model seed");
    }

    let payload: unknown;
    try {
      payload = JSON.parse(text);
    } catch {
      return fallback("Model catalogue response was not valid JSON; showing the verified model seed");
    }

    const rawItems = Array.isArray(payload)
      ? payload
      : payload && typeof payload === "object" && Array.isArray((payload as { data?: unknown }).data)
        ? ((payload as { data: unknown[] }).data)
        : null;
    if (!rawItems) {
      return fallback("Model catalogue response had an unexpected shape; showing the verified model seed");
    }

    const models: OrcaRouterModel[] = [];
    for (const item of rawItems.slice(0, maxItems)) {
      const parsed = parseOrcaRouterModel(item);
      if (parsed) models.push(parsed);
    }

    if (models.length === 0) {
      return fallback("Model catalogue returned no usable models; showing the verified model seed");
    }

    return {
      status: "ready",
      catalog: {
        models: dedupe(models),
        source: "live",
        fetchedAt: now(),
      },
    };
  } catch (err) {
    const aborted = err instanceof Error && err.name === "AbortError";
    return fallback(
      aborted
        ? "Model catalogue request timed out; showing the verified model seed"
        : "Model catalogue request failed; showing the verified model seed",
    );
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}

/** Models for one entry, filtered by that entry's capability requirement. */
export function modelsFor(
  catalog: OrcaRouterCatalog | null,
  requirement: CatalogRequirement,
): OrcaRouterModel[] {
  const models = catalog?.models ?? ORCAROUTER_VERIFIED_SEED;
  return filterModels(models, requirement);
}

/**
 * Keep a previously selected model only while it is still compatible with the
 * current requirement. Callers must clear and prompt otherwise.
 */
export function reconcileSelection(
  selected: string | null,
  options: OrcaRouterModel[],
): { selected: string | null; cleared: boolean } {
  if (!selected) return { selected: null, cleared: false };
  const stillValid = options.some((model) => model.id === selected);
  return stillValid ? { selected, cleared: false } : { selected: null, cleared: true };
}

/** Default model for a chat selector: branded auto, else first compatible. */
export function defaultChatModel(options: OrcaRouterModel[]): string {
  if (options.some((model) => model.id === ORCAROUTER_DEFAULT_MODEL)) {
    return ORCAROUTER_DEFAULT_MODEL;
  }
  return options[0]?.id ?? "";
}

/** Recommended dedicated cyber models present in the catalogue, in order. */
export function recommendedCyberModels(options: OrcaRouterModel[]): OrcaRouterModel[] {
  const byTier = new Map<string, OrcaRouterModel>();
  for (const model of options) {
    if (!isOrcaRouterCyberModel(model.id)) continue;
    const tier = normalizeCyberModelId(model.id);
    if (!byTier.has(tier)) byTier.set(tier, model);
  }
  return ORCAROUTER_CYBER_TIER_ORDER.map((tier) => byTier.get(tier)).filter(
    (model): model is OrcaRouterModel => Boolean(model),
  );
}

/**
 * Order a chat selector by tier: the branded default first, then the
 * dedicated cyber models in their fixed order, then everything else, with the
 * general fallback last. The order is stable within each group.
 */
export function sortChatModels(models: OrcaRouterModel[]): OrcaRouterModel[] {
  const rank = (model: OrcaRouterModel): number => {
    if (model.id === ORCAROUTER_DEFAULT_MODEL) return 0;
    if (isOrcaRouterCyberModel(model.id)) {
      const tier = normalizeCyberModelId(model.id);
      return 1 + (ORCAROUTER_CYBER_TIER_ORDER as readonly string[]).indexOf(tier);
    }
    if (model.id === ORCAROUTER_FALLBACK_MODEL) return 10_000;
    return 100;
  };
  return models
    .map((model, index) => ({ model, index, rank: rank(model) }))
    .sort((a, b) => a.rank - b.rank || a.index - b.index)
    .map(({ model }) => model);
}
