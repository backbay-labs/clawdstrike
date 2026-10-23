/**
 * OrcaRouter OAuth 2.0 + PKCE (Flow B — out-of-band code).
 *
 * The workbench runs as a browser renderer (served by Vite, or inside Tauri),
 * so it cannot reliably receive a loopback redirect: the install address
 * differs per deployment and hosted instances have no listener at all. Flow B
 * is the flow the OrcaRouter guide prescribes for exactly that shape — the
 * consent screen shows a short code and the operator pastes it back.
 *
 * S256 is mandatory here because the code is handled by a human.
 *
 * Invariants enforced below:
 *   - verifier and state are fresh cryptographic randomness per attempt;
 *   - the verifier never appears in a URL, log, error or telemetry payload;
 *   - the exchange posts to `<auth>/api/v1/auth/keys`, never `<api>/v1/...`;
 *   - the granted scope is read back and a downgrade is surfaced, not assumed;
 *   - auth codes are single use with a 10 minute TTL (403 on reuse/expiry).
 */

import { orcaRouterAuthorizeUrl, orcaRouterExchangeUrl } from "./provider";
import type { OrcaRouterOrigins } from "./provider";

export const ORCAROUTER_APP_NAME = "ClawdStrike Trustprint";
export const ORCAROUTER_PKCE_METHOD = "S256" as const;

export interface PkceAttempt {
  /** Monotonic attempt identifier used to discard stale completions. */
  id: string;
  verifier: string;
  challenge: string;
  state: string;
  createdAt: number;
  /** Whether the user has already redeemed this attempt. */
  consumed: boolean;
}

export interface OrcaRouterKeyGrant {
  apiKey: string;
  userId: string | null;
  /** Scope that was granted (not the scope that was requested). */
  scope: string;
}

export type OrcaRouterAuthErrorCode =
  | "access_denied"
  | "state_mismatch"
  | "code_expired_or_used"
  | "invalid_request"
  | "scope_downgrade"
  | "rate_limited"
  | "network"
  | "invalid_response";

export class OrcaRouterAuthError extends Error {
  readonly code: OrcaRouterAuthErrorCode;
  readonly status: number | null;

  constructor(code: OrcaRouterAuthErrorCode, message: string, status: number | null = null) {
    super(message);
    this.name = "OrcaRouterAuthError";
    this.code = code;
    this.status = status;
  }
}

function getWebCrypto(): Crypto {
  const c = globalThis.crypto;
  if (!c || typeof c.getRandomValues !== "function") {
    throw new OrcaRouterAuthError(
      "invalid_response",
      "Web Crypto is unavailable; cannot start an authorization attempt",
    );
  }
  return c;
}

function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256Base64url(value: string): Promise<string> {
  const subtle = getWebCrypto().subtle;
  if (!subtle) {
    throw new OrcaRouterAuthError(
      "invalid_response",
      "Web Crypto subtle digest is unavailable; cannot build an S256 challenge",
    );
  }
  const digest = await subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64url(new Uint8Array(digest));
}

/** Constant-time comparison for the OAuth `state` value. */
export function constantTimeEqual(a: string, b: string): boolean {
  const left = new TextEncoder().encode(a ?? "");
  const right = new TextEncoder().encode(b ?? "");
  const length = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;
  for (let i = 0; i < length; i += 1) {
    diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  }
  return diff === 0;
}

/** Create a fresh PKCE attempt. Never reuse a verifier across attempts. */
export async function createPkceAttempt(now: number = Date.now()): Promise<PkceAttempt> {
  const webCrypto = getWebCrypto();
  const verifier = base64url(webCrypto.getRandomValues(new Uint8Array(32)));
  const state = base64url(webCrypto.getRandomValues(new Uint8Array(16)));
  const challenge = await sha256Base64url(verifier);
  return {
    id: base64url(webCrypto.getRandomValues(new Uint8Array(12))),
    verifier,
    challenge,
    state,
    createdAt: now,
    consumed: false,
  };
}

export interface AuthorizeUrlOptions {
  origins: OrcaRouterOrigins;
  attempt: PkceAttempt;
  appName?: string;
  scope?: "api";
}

/**
 * Build the consent URL. `callback_url=oob` asks for the out-of-band code
 * rather than a redirect we cannot receive.
 */
export function buildAuthorizeUrl({
  origins,
  attempt,
  appName = ORCAROUTER_APP_NAME,
  scope = "api",
}: AuthorizeUrlOptions): string {
  const url = new URL(orcaRouterAuthorizeUrl(origins));
  url.searchParams.set("callback_url", "oob");
  url.searchParams.set("code_challenge", attempt.challenge);
  url.searchParams.set("code_challenge_method", ORCAROUTER_PKCE_METHOD);
  url.searchParams.set("state", attempt.state);
  url.searchParams.set("app_name", appName);
  url.searchParams.set("scope", scope);
  return url.toString();
}

/**
 * Parse what the operator pasted. Accepts a bare code or a full callback URL
 * (handy when a browser delivered the code as a link).
 */
export function extractAuthorizationCode(input: string): { code: string; state: string | null } {
  const trimmed = input.trim();
  if (trimmed.length === 0) {
    throw new OrcaRouterAuthError("invalid_request", "Enter the authorization code");
  }
  if (trimmed.includes("://") || trimmed.includes("code=")) {
    let parsed: URL | null = null;
    try {
      parsed = new URL(trimmed, "https://callback.invalid");
    } catch {
      parsed = null;
    }
    if (parsed) {
      const error = parsed.searchParams.get("error");
      if (error) {
        throw new OrcaRouterAuthError(
          error === "access_denied" ? "access_denied" : "invalid_request",
          error === "access_denied"
            ? "Authorization was denied"
            : `Authorization failed: ${error}`,
        );
      }
      const code = parsed.searchParams.get("code");
      if (code) {
        return { code, state: parsed.searchParams.get("state") };
      }
    }
    throw new OrcaRouterAuthError("invalid_request", "That link does not contain a code");
  }
  return { code: trimmed, state: null };
}

export interface ExchangeOptions {
  origins: OrcaRouterOrigins;
  attempt: PkceAttempt;
  /** Raw user input: a bare code or a callback URL. */
  userInput: string;
  fetchFn?: typeof fetch;
  signal?: AbortSignal;
  timeoutMs?: number;
}

const DEFAULT_EXCHANGE_TIMEOUT_MS = 15_000;
const MAX_EXCHANGE_BODY_BYTES = 64 * 1024;

/**
 * Redeem an authorization code for a durable OrcaRouter API key.
 *
 * The returned key is a normal `sk-orca-…` credential — not a refresh token.
 */
export async function exchangeAuthorizationCode({
  origins,
  attempt,
  userInput,
  fetchFn = fetch,
  signal,
  timeoutMs = DEFAULT_EXCHANGE_TIMEOUT_MS,
}: ExchangeOptions): Promise<OrcaRouterKeyGrant> {
  if (attempt.consumed) {
    throw new OrcaRouterAuthError(
      "code_expired_or_used",
      "This authorization attempt was already redeemed; start a new one",
    );
  }

  const { code, state } = extractAuthorizationCode(userInput);

  // Flow A-style callbacks can also be pasted; verify state before use.
  if (state !== null && !constantTimeEqual(state, attempt.state)) {
    throw new OrcaRouterAuthError(
      "state_mismatch",
      "Authorization state did not match this attempt; start a new one",
    );
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const onAbort = () => controller.abort();
  signal?.addEventListener("abort", onAbort, { once: true });

  let response: Response;
  try {
    response = await fetchFn(orcaRouterExchangeUrl(origins), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        code,
        code_verifier: attempt.verifier,
        code_challenge_method: ORCAROUTER_PKCE_METHOD,
      }),
      signal: controller.signal,
    });
  } catch (err) {
    const aborted = err instanceof Error && err.name === "AbortError";
    throw new OrcaRouterAuthError(
      "network",
      aborted
        ? "The key exchange timed out; try connecting again"
        : "Could not reach the OrcaRouter auth service",
    );
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }

  const raw = await response.text().catch(() => "");
  if (raw.length > MAX_EXCHANGE_BODY_BYTES) {
    throw new OrcaRouterAuthError("invalid_response", "Auth response was unexpectedly large");
  }

  if (!response.ok) {
    // Error strings never include the code or verifier.
    if (response.status === 403) {
      throw new OrcaRouterAuthError(
        "code_expired_or_used",
        "That code is unknown, expired, already used, or not bound to this attempt",
        403,
      );
    }
    if (response.status === 400) {
      throw new OrcaRouterAuthError(
        "invalid_request",
        "The authorization request was rejected (challenge method mismatch)",
        400,
      );
    }
    if (response.status === 429) {
      throw new OrcaRouterAuthError(
        "rate_limited",
        "Too many authorization requests; wait before connecting again",
        429,
      );
    }
    throw new OrcaRouterAuthError(
      "invalid_response",
      `Authorization failed with HTTP ${response.status}`,
      response.status,
    );
  }

  let payload: unknown;
  try {
    payload = JSON.parse(raw);
  } catch {
    throw new OrcaRouterAuthError("invalid_response", "Auth response was not valid JSON");
  }

  const record = payload as { key?: unknown; user_id?: unknown; scope?: unknown };
  const apiKey = typeof record.key === "string" ? record.key.trim() : "";
  if (!apiKey) {
    throw new OrcaRouterAuthError("invalid_response", "Auth response did not include a key");
  }
  const scope = typeof record.scope === "string" ? record.scope : "";
  if (scope !== "api") {
    throw new OrcaRouterAuthError(
      "scope_downgrade",
      `OrcaRouter granted scope "${scope || "unknown"}" instead of "api"`,
    );
  }

  attempt.consumed = true;
  return {
    apiKey,
    userId: typeof record.user_id === "string" ? record.user_id : null,
    scope,
  };
}
