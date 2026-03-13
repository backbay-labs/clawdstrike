// ---------------------------------------------------------------------------
// IdP Federation — OIDC integration with PKCE for operator identity binding.
//
// Structural implementation: types, PKCE challenge generation, OIDC discovery,
// authorization URL construction, token exchange, and IdP binding proofs.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Base64url encoding
// ---------------------------------------------------------------------------

function base64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...Array.from(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

export async function generatePkceChallenge(): Promise<PkceChallenge> {
  const verifierBytes = crypto.getRandomValues(new Uint8Array(32));
  const codeVerifier = base64url(verifierBytes);
  const encoded = new TextEncoder().encode(codeVerifier);
  const digest = await crypto.subtle.digest("SHA-256", encoded.buffer as ArrayBuffer);
  const codeChallenge = base64url(new Uint8Array(digest));
  return { codeVerifier, codeChallenge, codeChallengeMethod: "S256" };
}

// ---------------------------------------------------------------------------
// OIDC Discovery
// ---------------------------------------------------------------------------

export async function discoverEndpoints(
  issuerUrl: string,
): Promise<OidcDiscovery> {
  const url = `${issuerUrl.replace(/\/$/, "")}/.well-known/openid-configuration`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`OIDC discovery failed: ${res.status}`);
  return res.json();
}

// ---------------------------------------------------------------------------
// Authorization URL
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Token Exchange
// ---------------------------------------------------------------------------

export async function exchangeCodeForTokens(
  code: string,
  verifier: string,
  config: IdpConfig,
  discovery: OidcDiscovery,
): Promise<TokenResponse> {
  const res = await fetch(discovery.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
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

// ---------------------------------------------------------------------------
// IdP Binding Proof
// ---------------------------------------------------------------------------

export async function createIdpBinding(
  sub: string,
  fingerprint: string,
  operatorSecretKey: string,
): Promise<string> {
  const { signData } = await import("./operator-crypto");
  const message = `clawdstrike:idp-bind|${sub}|${fingerprint}|${Date.now()}`;
  return signData(new TextEncoder().encode(message), operatorSecretKey);
}

// ---------------------------------------------------------------------------
// Token Refresh
// ---------------------------------------------------------------------------

export async function refreshTokens(
  refreshToken: string,
  config: IdpConfig,
  discovery: OidcDiscovery,
): Promise<TokenResponse> {
  const res = await fetch(discovery.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
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
