/**
 * OrcaRouter Cyber Inference — first-class provider definition.
 *
 * OrcaRouter is an OpenAI-compatible AI gateway for security teams: one
 * endpoint routes chat and embedding requests to many upstream models, and
 * exposes a live model catalogue at `GET /v1/models`.
 *
 * Two public origins are involved and they are deliberately independent:
 *
 *   auth:      https://www.orcarouter.ai        (consent + key exchange)
 *   inference: https://api.orcarouter.ai/v1     (chat, embeddings, catalogue)
 *
 * `https://api.orcarouter.ai/v1/auth/keys` is a 404; never derive one origin
 * from the other by host substitution.
 */

export const ORCAROUTER_PROVIDER_ID = "orcarouter";
export const ORCAROUTER_DISPLAY_NAME = "OrcaRouter Cyber Inference";
export const ORCAROUTER_PROVIDER_PAGE_URL = "https://www.orcarouter.ai/cyber";
export const ORCAROUTER_CYBER_MODELS_URL =
  "https://www.orcarouter.ai/models?tier=cyber";
export const ORCAROUTER_KEY_DASHBOARD_URL =
  "https://www.orcarouter.ai/console/authorized-apps";

/** Public auth origin. */
export const ORCAROUTER_DEFAULT_AUTH_BASE_URL = "https://www.orcarouter.ai";
/** Public inference origin, including the `/v1` prefix. */
export const ORCAROUTER_DEFAULT_API_BASE_URL = "https://api.orcarouter.ai/v1";

/**
 * Model tiering shown in the provider panel. Every entry is a branded
 * OrcaRouter model id; the catalogue is the source of truth at runtime and
 * these ids are only the cold-start recommendation.
 *
 * The live catalogue publishes the cyber tier under the `orca/` namespace
 * (`orca/orcacyber-ultra-1.0`); both the namespaced and bare forms are accepted
 * so a workspace that lists either one is recognised.
 */
export const ORCAROUTER_DEFAULT_MODEL = "orcarouter/auto";
export const ORCAROUTER_FALLBACK_MODEL = "orcarouter/fusion";
export const ORCAROUTER_CYBER_MODEL_IDS = [
  "orca/orcacyber-ultra-1.0",
  "orcacyber-ultra-1.0",
  "orca/orcacyber-zero-1.5",
  "orcacyber-zero-1.5",
  "orca/orcacyber-zero-1.0",
  "orcacyber-zero-1.0",
] as const;

/** Canonical tier order used for badges and selector ordering. */
export const ORCAROUTER_CYBER_TIER_ORDER = [
  "orcacyber-ultra-1.0",
  "orcacyber-zero-1.5",
  "orcacyber-zero-1.0",
] as const;

/** Strip the optional `orca/` vendor namespace from a cyber model id. */
export function normalizeCyberModelId(modelId: string): string {
  return modelId.trim().toLowerCase().replace(/^orca\//, "");
}

/** True when the model belongs to the dedicated OrcaRouter cyber tier. */
export function isOrcaRouterCyberModel(modelId: string): boolean {
  return (ORCAROUTER_CYBER_TIER_ORDER as readonly string[]).includes(
    normalizeCyberModelId(modelId),
  );
}

export interface OrcaRouterOrigins {
  authBaseUrl: string;
  apiBaseUrl: string;
}

export interface OrcaRouterOriginOverrides {
  /** Explicit auth origin; wins over every shared fallback. */
  authBaseUrl?: string;
  /** Explicit inference origin; wins over every shared fallback. */
  apiBaseUrl?: string;
  /** Shared self-hosted origin used when an explicit override is absent. */
  sharedBaseUrl?: string;
}

function readEnv(name: string): string | undefined {
  const g = globalThis as {
    process?: { env?: Record<string, string | undefined> };
  };
  const fromProcess = g.process?.env?.[name];
  if (typeof fromProcess === "string" && fromProcess.length > 0) {
    return fromProcess;
  }
  return undefined;
}

function isLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "[::1]" ||
    host === "::1" ||
    host.endsWith(".localhost")
  );
}

/**
 * Validate a configured origin. Remote origins must be HTTPS; plain HTTP is
 * tolerated only for loopback development, matching the repo's fleet URL
 * policy.
 */
export function normalizeOrcaRouterOrigin(raw: string, label: string): string {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    throw new Error(`${label} must not be empty`);
  }
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new Error(`${label} must be an absolute URL`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(`${label} must use https (http is allowed for loopback only)`);
  }
  if (url.protocol === "http:" && !isLoopbackHost(url.hostname)) {
    throw new Error(`${label} must use https unless it targets loopback`);
  }
  if (url.username || url.password) {
    throw new Error(`${label} must not embed credentials`);
  }
  return trimmed.replace(/\/+$/, "");
}

/**
 * Resolve both origins from explicit overrides first, then the shared
 * self-hosted base, then the public defaults.
 */
export function resolveOrcaRouterOrigins(
  overrides: OrcaRouterOriginOverrides = {},
): OrcaRouterOrigins {
  const envShared = readEnv("ORCA_BASE_URL");
  const envAuth = readEnv("ORCA_AUTH_BASE_URL");
  const envApi = readEnv("ORCA_API_BASE_URL");

  const shared = overrides.sharedBaseUrl ?? envShared;
  const authRaw =
    overrides.authBaseUrl ?? envAuth ?? shared ?? ORCAROUTER_DEFAULT_AUTH_BASE_URL;
  const apiRaw =
    overrides.apiBaseUrl ?? envApi ?? shared ?? ORCAROUTER_DEFAULT_API_BASE_URL;

  let apiBaseUrl = normalizeOrcaRouterOrigin(apiRaw, "OrcaRouter API base URL");
  // A shared self-hosted base may be given without the `/v1` suffix; only add
  // it when the caller did not supply an explicit inference origin.
  const apiIsExplicit = overrides.apiBaseUrl !== undefined || envApi !== undefined;
  if (!apiIsExplicit && !/\/v\d+$/.test(apiBaseUrl)) {
    apiBaseUrl = `${apiBaseUrl}/v1`;
  }

  return {
    authBaseUrl: normalizeOrcaRouterOrigin(authRaw, "OrcaRouter auth base URL"),
    apiBaseUrl,
  };
}

/** Consent screen URL. The authorize path is fixed at `/auth`. */
export function orcaRouterAuthorizeUrl(origins: OrcaRouterOrigins): string {
  return `${origins.authBaseUrl}/auth`;
}

/** Key exchange URL. Note the `/api/v1` prefix, not `/v1`. */
export function orcaRouterExchangeUrl(origins: OrcaRouterOrigins): string {
  return `${origins.authBaseUrl}/api/v1/auth/keys`;
}

export function orcaRouterModelsUrl(
  origins: OrcaRouterOrigins,
  capability?: string,
): string {
  const base = `${origins.apiBaseUrl}/models`;
  return capability ? `${base}?capability=${encodeURIComponent(capability)}` : base;
}

export function orcaRouterEmbeddingsUrl(origins: OrcaRouterOrigins): string {
  return `${origins.apiBaseUrl}/embeddings`;
}

export function orcaRouterChatCompletionsUrl(origins: OrcaRouterOrigins): string {
  return `${origins.apiBaseUrl}/chat/completions`;
}

/** True when a user-configured inference URL already points at OrcaRouter. */
export function isOrcaRouterUrl(url: string | undefined | null): boolean {
  if (!url) return false;
  try {
    return new URL(url).hostname.toLowerCase().endsWith("orcarouter.ai");
  } catch {
    return false;
  }
}

/** Lightweight format check only; never presented as proof of validity. */
export function looksLikeOrcaRouterKey(value: string): boolean {
  return /^sk-orca-[A-Za-z0-9_-]{8,}$/.test(value.trim());
}

export function redactOrcaRouterKey(value: string | undefined | null): string {
  if (!value) return "";
  const trimmed = value.trim();
  if (trimmed.length <= 8) return "••••";
  return `${trimmed.slice(0, 4)}…${trimmed.slice(-4)}`;
}
