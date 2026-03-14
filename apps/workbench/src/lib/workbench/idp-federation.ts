// IdP Federation — OIDC integration with PKCE for operator identity binding.
//
// Structural implementation: types, PKCE challenge generation, OIDC discovery,
// authorization URL construction, token exchange, and IdP binding proofs.

import { validateFleetUrl } from "./fleet-url-policy";

/** Maximum OIDC discovery / token response body size (1 MB). */
const MAX_OIDC_RESPONSE_BYTES = 1_048_576;

export interface IdpConfig {
  issuer: string;
  clientId: string;
  redirectUri: string;
  scopes: string[];
}

export interface PkceChallenge {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
}

export interface TokenResponse {
  accessToken: string;
  idToken: string;
  refreshToken: string | null;
  expiresIn: number;
  tokenType: string;
}

export interface OidcDiscovery {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  issuer: string;
}


function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...Array.from(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}


export async function generatePkceChallenge(): Promise<PkceChallenge> {
  const verifierBytes = crypto.getRandomValues(new Uint8Array(32));
  const codeVerifier = base64url(verifierBytes);
  const encoded = new TextEncoder().encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", encoded.buffer as ArrayBuffer);
  const codeChallenge = base64url(new Uint8Array(digest));
  return { codeVerifier, codeChallenge, codeChallengeMethod: "S256" };
}


export async function discoverEndpoints(
  issuerUrl: string,
): Promise<OidcDiscovery> {
  const url = `${issuerUrl.replace(/\/$/, "")}/.well-known/openid-configuration`;

  // Finding M5: validate the issuer URL to prevent SSRF
  const validation = validateFleetUrl(url);
  if (!validation.valid) {
    throw new Error(`Invalid OIDC issuer URL: ${validation.reason}`);
  }

  // Finding M5 + M6: block redirects, enforce timeout, and limit response size
  const res = await fetch(url, {
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`OIDC discovery failed: ${res.status}`);

  const contentLength = res.headers.get("Content-Length");
  if (contentLength && parseInt(contentLength, 10) > MAX_OIDC_RESPONSE_BYTES) {
    throw new Error(`OIDC discovery response too large (${contentLength} bytes)`);
  }

  const text = await res.text();
  if (text.length > MAX_OIDC_RESPONSE_BYTES) {
    throw new Error(`OIDC discovery response too large (${text.length} bytes)`);
  }

  return JSON.parse(text);
}


export function buildAuthorizationUrl(
  config: IdpConfig,
  discovery: OidcDiscovery,
  challenge: PkceChallenge,
  state: string,
): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scopes.join(" "),
    code_challenge: challenge.codeChallenge,
    code_challenge_method: challenge.codeChallengeMethod,
    state,
  });
  return `${discovery.authorization_endpoint}?${params}`;
}


export async function exchangeCodeForTokens(
  code: string,
  verifier: string,
  config: IdpConfig,
  discovery: OidcDiscovery,
): Promise<TokenResponse> {
  // Finding M6: block redirects and enforce timeout on token endpoint
  const res = await fetch(discovery.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: config.redirectUri,
      client_id: config.clientId,
      code_verifier: verifier,
    }),
  });
  if (!res.ok) throw new Error(`Token exchange failed: ${res.status}`);
  const data = await res.json();
  return {
    accessToken: data.access_token,
    idToken: data.id_token,
    refreshToken: data.refresh_token ?? null,
    expiresIn: data.expires_in,
    tokenType: data.token_type,
  };
}


export async function createIdpBinding(
  sub: string,
  fingerprint: string,
  operatorSecretKey: string,
): Promise<string> {
  const { signData } = await import("./operator-crypto");
  const message = `clawdstrike:idp-bind|${sub}|${fingerprint}|${Date.now()}`;
  return signData(new TextEncoder().encode(message), operatorSecretKey);
}


export async function refreshTokens(
  refreshToken: string,
  config: IdpConfig,
  discovery: OidcDiscovery,
): Promise<TokenResponse> {
  // Finding M6: block redirects and enforce timeout on token endpoint
  const res = await fetch(discovery.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: config.clientId,
    }),
  });
  if (!res.ok) throw new Error(`Token refresh failed: ${res.status}`);
  const data = await res.json();
  return {
    accessToken: data.access_token,
    idToken: data.id_token,
    refreshToken: data.refresh_token ?? refreshToken,
    expiresIn: data.expires_in,
    tokenType: data.token_type,
  };
}
