import { describe, expect, it, vi } from "vitest";
import {
  buildAuthorizeUrl,
  constantTimeEqual,
  createPkceAttempt,
  exchangeAuthorizationCode,
  extractAuthorizationCode,
  OrcaRouterAuthError,
} from "../pkce";
import { resolveOrcaRouterOrigins } from "../provider";

const origins = resolveOrcaRouterOrigins();

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("PKCE attempt", () => {
  it("generates a fresh verifier and state per attempt", async () => {
    const first = await createPkceAttempt();
    const second = await createPkceAttempt();
    expect(first.verifier).not.toBe(second.verifier);
    expect(first.state).not.toBe(second.state);
    expect(first.verifier.length).toBeGreaterThanOrEqual(43);
  });

  it("derives an unpadded base64url S256 challenge from the verifier", async () => {
    const attempt = await createPkceAttempt();
    expect(attempt.challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(attempt.challenge).not.toContain("=");

    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(attempt.verifier),
    );
    const expected = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
    expect(attempt.challenge).toBe(expected);
  });

  it("builds an out-of-band consent URL carrying only the challenge", async () => {
    const attempt = await createPkceAttempt();
    const url = new URL(buildAuthorizeUrl({ origins, attempt }));

    expect(url.origin).toBe("https://www.orcarouter.ai");
    expect(url.pathname).toBe("/auth");
    expect(url.searchParams.get("callback_url")).toBe("oob");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("code_challenge")).toBe(attempt.challenge);
    expect(url.searchParams.get("state")).toBe(attempt.state);
    expect(url.searchParams.get("scope")).toBe("api");
    expect(url.searchParams.get("app_name")).toContain("ClawdStrike");
    // The verifier must never ride on the URL.
    expect(url.toString()).not.toContain(attempt.verifier);
  });
});

describe("state handling", () => {
  it("compares state in constant time", () => {
    expect(constantTimeEqual("abc", "abc")).toBe(true);
    expect(constantTimeEqual("abc", "abd")).toBe(false);
    expect(constantTimeEqual("abc", "abcd")).toBe(false);
    expect(constantTimeEqual("", "")).toBe(true);
  });

  it("rejects a pasted callback whose state does not match", async () => {
    const attempt = await createPkceAttempt();
    const fetchFn = vi.fn<typeof fetch>();

    await expect(
      exchangeAuthorizationCode({
        origins,
        attempt,
        userInput: "http://127.0.0.1:1234/cb?code=abc&state=not-the-state",
        fetchFn,
      }),
    ).rejects.toMatchObject({ code: "state_mismatch" });
    expect(fetchFn).not.toHaveBeenCalled();
  });

  it("accepts a pasted callback whose state matches", async () => {
    const attempt = await createPkceAttempt();
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse({ key: "sk-orca-testkey123456", user_id: "42", scope: "api" }),
    );
    const grant = await exchangeAuthorizationCode({
      origins,
      attempt,
      userInput: `http://127.0.0.1:1234/cb?code=the-code&state=${attempt.state}`,
      fetchFn,
    });
    expect(grant.apiKey).toBe("sk-orca-testkey123456");
  });

  it("surfaces a denial as access_denied", () => {
    expect(() =>
      extractAuthorizationCode("http://127.0.0.1:1234/cb?error=access_denied"),
    ).toThrow(expect.objectContaining({ code: "access_denied" }));
  });
});

describe("code exchange", () => {
  it("posts the verifier and S256 method to the auth origin, not the inference origin", async () => {
    const attempt = await createPkceAttempt();
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(
      jsonResponse({ key: "sk-orca-testkey123456", user_id: "7", scope: "api" }),
    );

    await exchangeAuthorizationCode({ origins, attempt, userInput: "abc123", fetchFn });

    expect(fetchFn).toHaveBeenCalledTimes(1);
    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe("https://www.orcarouter.ai/api/v1/auth/keys");
    expect(String(url)).not.toContain("api.orcarouter.ai");
    expect(init?.method).toBe("POST");
    const body = JSON.parse(String(init?.body));
    expect(body).toEqual({
      code: "abc123",
      code_verifier: attempt.verifier,
      code_challenge_method: "S256",
    });
  });

  it("returns the granted scope and user", async () => {
    const attempt = await createPkceAttempt();
    const fetchFn = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse({ key: "sk-orca-key00000001", user_id: "99", scope: "api" }));
    const grant = await exchangeAuthorizationCode({ origins, attempt, userInput: "c", fetchFn });
    expect(grant).toEqual({ apiKey: "sk-orca-key00000001", userId: "99", scope: "api" });
  });

  it("rejects a scope downgrade instead of assuming the requested scope", async () => {
    const attempt = await createPkceAttempt();
    const fetchFn = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse({ key: "sk-orca-key00000001", scope: "readonly" }));
    await expect(
      exchangeAuthorizationCode({ origins, attempt, userInput: "c", fetchFn }),
    ).rejects.toMatchObject({ code: "scope_downgrade" });
  });

  it("maps 403 to a terminal expired/used code error", async () => {
    const attempt = await createPkceAttempt();
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(new Response("", { status: 403 }));
    await expect(
      exchangeAuthorizationCode({ origins, attempt, userInput: "c", fetchFn }),
    ).rejects.toMatchObject({ code: "code_expired_or_used", status: 403 });
  });

  it("maps 400 to an invalid request (challenge downgrade defence)", async () => {
    const attempt = await createPkceAttempt();
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(new Response("", { status: 400 }));
    await expect(
      exchangeAuthorizationCode({ origins, attempt, userInput: "c", fetchFn }),
    ).rejects.toMatchObject({ code: "invalid_request", status: 400 });
  });

  it("maps 429 to a rate-limit error", async () => {
    const attempt = await createPkceAttempt();
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(new Response("", { status: 429 }));
    await expect(
      exchangeAuthorizationCode({ origins, attempt, userInput: "c", fetchFn }),
    ).rejects.toMatchObject({ code: "rate_limited" });
  });

  it("maps a network failure without leaking the verifier or code", async () => {
    const attempt = await createPkceAttempt();
    const fetchFn = vi.fn<typeof fetch>().mockRejectedValue(new Error("socket closed"));
    const error = await exchangeAuthorizationCode({
      origins,
      attempt,
      userInput: "secret-code-value",
      fetchFn,
    }).catch((err: unknown) => err as OrcaRouterAuthError);

    expect(error).toBeInstanceOf(OrcaRouterAuthError);
    const authError = error as OrcaRouterAuthError;
    expect(authError.code).toBe("network");
    expect(authError.message).not.toContain(attempt.verifier);
    expect(authError.message).not.toContain("secret-code-value");
  });

  it("refuses to redeem the same attempt twice", async () => {
    const attempt = await createPkceAttempt();
    const fetchFn = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse({ key: "sk-orca-key00000001", scope: "api" }));
    await exchangeAuthorizationCode({ origins, attempt, userInput: "c", fetchFn });
    await expect(
      exchangeAuthorizationCode({ origins, attempt, userInput: "c", fetchFn }),
    ).rejects.toMatchObject({ code: "code_expired_or_used" });
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it("rejects an auth response without a key", async () => {
    const attempt = await createPkceAttempt();
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(jsonResponse({ scope: "api" }));
    await expect(
      exchangeAuthorizationCode({ origins, attempt, userInput: "c", fetchFn }),
    ).rejects.toMatchObject({ code: "invalid_response" });
  });
});
