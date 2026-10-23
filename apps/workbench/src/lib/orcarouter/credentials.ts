/**
 * Credential seam for the OrcaRouter Cyber Inference provider.
 *
 * Getting a credential is one interface with two adapters:
 *
 *   - `ApiKeyCredentialAdapter`  : the operator pastes an existing sk-orca-… key
 *   - `PkceCredentialAdapter`    : the operator authorizes in a browser (Flow B)
 *
 * Both adapters produce the *same* `OrcaRouterCredential`, and nothing
 * downstream (provider requests, model discovery, guard config) knows or cares
 * which one produced it.
 *
 * Lifecycle rules:
 *   - the key is persisted through the workbench `secureStore` (Stronghold on
 *     desktop, never sessionStorage/localStorage for secrets in web mode);
 *   - a PKCE-issued key is durable, **not** a refresh token: we never refresh
 *     it proactively and never invent a refresh grant;
 *   - a relay `401` marks exactly the account + credential generation that made
 *     the rejected request as `needsReauth`; a late failure from an older
 *     generation cannot poison a freshly re-authorized credential;
 *   - the old secret is not deleted until a new login succeeds.
 */

import { secureStore } from "@/features/settings/secure-store";
import {
  buildAuthorizeUrl,
  createPkceAttempt,
  exchangeAuthorizationCode,
  OrcaRouterAuthError,
  type OrcaRouterKeyGrant,
  type PkceAttempt,
} from "./pkce";
import {
  looksLikeOrcaRouterKey,
  type OrcaRouterOrigins,
} from "./provider";

export type OrcaRouterCredentialSource = "api_key" | "pkce";
export type OrcaRouterCredentialStatus = "active" | "needsReauth";

export interface OrcaRouterCredential {
  /** The `sk-orca-…` value. Never log or serialize this field. */
  apiKey: string;
  source: OrcaRouterCredentialSource;
  /** Monotonic generation; bumped on every successful acquisition. */
  generation: number;
  status: OrcaRouterCredentialStatus;
  userId: string | null;
  scope: string | null;
  issuedAt: number;
}

export interface OrcaRouterCredentialPersistence {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}

export const ORCAROUTER_SECRET_KEY = "orcarouter_api_key";
export const ORCAROUTER_META_KEY = "orcarouter_credential_meta";

/** Production persistence: the workbench secure store. */
export const secureStorePersistence: OrcaRouterCredentialPersistence = {
  get: (key) => secureStore.get(key),
  set: (key, value) => secureStore.set(key, value),
  delete: (key) => secureStore.delete(key),
};

/** In-memory persistence for tests and for degraded browser mode. */
export function createMemoryPersistence(): OrcaRouterCredentialPersistence {
  const map = new Map<string, string>();
  return {
    async get(key) {
      return map.get(key) ?? null;
    },
    async set(key, value) {
      map.set(key, value);
    },
    async delete(key) {
      map.delete(key);
    },
  };
}

interface PersistedMeta {
  source: OrcaRouterCredentialSource;
  generation: number;
  status: OrcaRouterCredentialStatus;
  userId: string | null;
  scope: string | null;
  issuedAt: number;
}

export interface CredentialAcquisition {
  apiKey: string;
  source: OrcaRouterCredentialSource;
  userId?: string | null;
  scope?: string | null;
}

/** A way to obtain a credential. Both adapters implement this. */
export interface CredentialAdapter {
  readonly source: OrcaRouterCredentialSource;
  acquire(): Promise<CredentialAcquisition>;
}

/** Adapter for an operator-supplied API key. */
export class ApiKeyCredentialAdapter implements CredentialAdapter {
  readonly source = "api_key" as const;

  constructor(private readonly rawKey: string) {}

  async acquire(): Promise<CredentialAcquisition> {
    const apiKey = this.rawKey.trim();
    if (apiKey.length === 0) {
      throw new OrcaRouterAuthError("invalid_request", "Enter an OrcaRouter API key");
    }
    if (!looksLikeOrcaRouterKey(apiKey)) {
      // Format guidance only; the first real request establishes validity.
      throw new OrcaRouterAuthError(
        "invalid_request",
        "That does not look like an OrcaRouter key (expected sk-orca-…)",
      );
    }
    return { apiKey, source: this.source, userId: null, scope: null };
  }
}

export type PkcePhase =
  | { phase: "authorizing"; attemptId: string; authorizeUrl: string }
  | { phase: "exchanging"; attemptId: string };

export interface PkceAuthorizeResult {
  attemptId: string;
  authorizeUrl: string;
}

/**
 * Adapter for the OAuth 2.0 + PKCE (out-of-band) flow. `complete()` must be
 * called with the attempt id that `begin()` returned; a stale attempt id is
 * rejected so an older browser tab cannot overwrite a newer login.
 */
export class PkceCredentialAdapter implements CredentialAdapter {
  readonly source = "pkce" as const;

  private attempt: PkceAttempt | null = null;

  constructor(
    private readonly options: {
      origins: OrcaRouterOrigins;
      appName?: string;
      fetchFn?: typeof fetch;
      now?: () => number;
    },
  ) {}

  /** Start a fresh attempt and return the consent URL to open. */
  async begin(): Promise<PkceAuthorizeResult> {
    const now = this.options.now?.() ?? Date.now();
    const attempt = await createPkceAttempt(now);
    this.attempt = attempt;
    return {
      attemptId: attempt.id,
      authorizeUrl: buildAuthorizeUrl({
        origins: this.options.origins,
        attempt,
        appName: this.options.appName,
      }),
    };
  }

  async complete(attemptId: string, userInput: string): Promise<CredentialAcquisition> {
    const attempt = this.attempt;
    if (!attempt || attempt.id !== attemptId) {
      throw new OrcaRouterAuthError(
        "state_mismatch",
        "This authorization attempt is no longer current; start again",
      );
    }
    const grant: OrcaRouterKeyGrant = await exchangeAuthorizationCode({
      origins: this.options.origins,
      attempt,
      userInput,
      fetchFn: this.options.fetchFn,
    });
    this.attempt = null;
    return {
      apiKey: grant.apiKey,
      source: this.source,
      userId: grant.userId,
      scope: grant.scope,
    };
  }

  cancel(): void {
    this.attempt = null;
  }

  async acquire(): Promise<CredentialAcquisition> {
    throw new OrcaRouterAuthError(
      "invalid_request",
      "PKCE requires begin()/complete(); there is no silent acquisition",
    );
  }
}

export interface CredentialManagerOptions {
  persistence?: OrcaRouterCredentialPersistence;
  origins: OrcaRouterOrigins;
  now?: () => number;
  fetchFn?: typeof fetch;
}

/**
 * Owns the current credential, its generation counter and persistence.
 */
export class OrcaRouterCredentialManager {
  private readonly persistence: OrcaRouterCredentialPersistence;
  private readonly now: () => number;
  private credential: OrcaRouterCredential | null = null;
  private generation = 0;
  private listeners = new Set<(credential: OrcaRouterCredential | null) => void>();

  constructor(private readonly options: CredentialManagerOptions) {
    this.persistence = options.persistence ?? secureStorePersistence;
    this.now = options.now ?? (() => Date.now());
  }

  subscribe(listener: (credential: OrcaRouterCredential | null) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private emit(): void {
    for (const listener of this.listeners) listener(this.credential);
  }

  getCurrent(): OrcaRouterCredential | null {
    return this.credential;
  }

  /** Restore a previously stored credential, if any. */
  async load(): Promise<OrcaRouterCredential | null> {
    const apiKey = await this.persistence.get(ORCAROUTER_SECRET_KEY);
    if (!apiKey) {
      this.credential = null;
      this.emit();
      return null;
    }
    let meta: Partial<PersistedMeta> = {};
    const rawMeta = await this.persistence.get(ORCAROUTER_META_KEY);
    if (rawMeta) {
      try {
        meta = JSON.parse(rawMeta) as Partial<PersistedMeta>;
      } catch {
        meta = {};
      }
    }
    this.generation = Math.max(this.generation, Number(meta.generation ?? 0));
    this.credential = {
      apiKey,
      source: meta.source === "pkce" ? "pkce" : "api_key",
      generation: this.generation,
      status: meta.status === "needsReauth" ? "needsReauth" : "active",
      userId: typeof meta.userId === "string" ? meta.userId : null,
      scope: typeof meta.scope === "string" ? meta.scope : null,
      issuedAt: Number(meta.issuedAt ?? 0),
    };
    this.emit();
    return this.credential;
  }

  /** Acquire through an adapter (API key or, eventually, a completed PKCE flow). */
  async connect(adapter: CredentialAdapter): Promise<OrcaRouterCredential> {
    const acquisition = await adapter.acquire();
    return this.persist(acquisition);
  }

  /** Persist a credential produced by any adapter. */
  async persist(acquisition: CredentialAcquisition): Promise<OrcaRouterCredential> {
    const generation = this.generation + 1;
    const credential: OrcaRouterCredential = {
      apiKey: acquisition.apiKey,
      source: acquisition.source,
      generation,
      status: "active",
      userId: acquisition.userId ?? null,
      scope: acquisition.scope ?? null,
      issuedAt: this.now(),
    };

    // Write the secret first; only advance in-memory state after it lands, so
    // a failed write cannot leave a credential that looks saved.
    await this.persistence.set(ORCAROUTER_SECRET_KEY, credential.apiKey);
    await this.persistence.set(
      ORCAROUTER_META_KEY,
      JSON.stringify({
        source: credential.source,
        generation: credential.generation,
        status: credential.status,
        userId: credential.userId,
        scope: credential.scope,
        issuedAt: credential.issuedAt,
      } satisfies PersistedMeta),
    );

    this.generation = generation;
    this.credential = credential;
    this.emit();
    return credential;
  }

  /**
   * Mark a credential as requiring re-authentication after a relay `401`.
   * Only the exact generation that made the rejected request is affected.
   * There is no refresh: OrcaRouter keys are durable until revoked.
   */
  async markUnauthorized(generation: number): Promise<boolean> {
    const current = this.credential;
    if (!current || current.generation !== generation) {
      // A late failure from an older request must not touch a newer login.
      return false;
    }
    if (current.status === "needsReauth") return false;
    const next: OrcaRouterCredential = { ...current, status: "needsReauth" };
    this.credential = next;
    await this.persistence.set(
      ORCAROUTER_META_KEY,
      JSON.stringify({
        source: next.source,
        generation: next.generation,
        status: next.status,
        userId: next.userId,
        scope: next.scope,
        issuedAt: next.issuedAt,
      } satisfies PersistedMeta),
    );
    this.emit();
    return true;
  }

  /** True when a request returned 401 and no newer login has replaced it. */
  requiresReauth(): boolean {
    return this.credential?.status === "needsReauth";
  }

  /** Remove the stored credential. */
  async clear(): Promise<void> {
    await this.persistence.delete(ORCAROUTER_SECRET_KEY);
    await this.persistence.delete(ORCAROUTER_META_KEY);
    this.credential = null;
    this.emit();
  }
}

/** Create a PKCE adapter bound to this manager's origin configuration. */
export function createPkceAdapter(options: CredentialManagerOptions): PkceCredentialAdapter {
  return new PkceCredentialAdapter({
    origins: options.origins,
    fetchFn: options.fetchFn,
    now: options.now,
  });
}
