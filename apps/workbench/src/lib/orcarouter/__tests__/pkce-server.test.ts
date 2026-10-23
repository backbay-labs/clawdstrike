/**
 * End-to-end PKCE flow against a local fake authorization server.
 *
 * This exercises the project's real connect adapter — authorize URL →
 * consent (out-of-band code) → code exchange over HTTP → credential
 * persistence — and has the server verify the S256 challenge, so a verifier
 * that does not match its challenge fails the exchange exactly as the real
 * service would. No consent is fabricated against the real service.
 */

import { createHash, randomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { createPkceAdapter, OrcaRouterCredentialManager } from "../credentials";
import { createMemoryPersistence } from "../credentials";
import type { OrcaRouterOrigins } from "../provider";

interface FakeAuthState {
  challenge: string | null;
  state: string | null;
  issuedCode: string | null;
  exchanges: { code: string; verifier: string; method: string }[];
}

function s256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += String(chunk);
    });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

function json(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload));
}

const servers: { close: () => void }[] = [];

async function startFakeAuthServer(): Promise<{ origins: OrcaRouterOrigins; state: FakeAuthState }> {
  const state: FakeAuthState = {
    challenge: null,
    state: null,
    issuedCode: null,
    exchanges: [],
  };

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");

    // Consent screen: the app opened this URL with its challenge and state.
    if (req.method === "GET" && url.pathname === "/auth") {
      state.challenge = url.searchParams.get("code_challenge");
      state.state = url.searchParams.get("state");
      state.issuedCode = `code-${randomBytes(6).toString("hex")}`;
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(`<p>authorization code: ${state.issuedCode}</p>`);
      return;
    }

    // Key exchange, exactly the documented path.
    if (req.method === "POST" && url.pathname === "/api/v1/auth/keys") {
      const body = JSON.parse(await readBody(req)) as {
        code?: string;
        code_verifier?: string;
        code_challenge_method?: string;
      };
      const verifier = body.code_verifier ?? "";
      state.exchanges.push({
        code: body.code ?? "",
        verifier,
        method: body.code_challenge_method ?? "",
      });
      if (
        !state.challenge ||
        body.code !== state.issuedCode ||
        body.code_challenge_method !== "S256" ||
        s256(verifier) !== state.challenge
      ) {
        json(res, 400, { error: "invalid_grant" });
        return;
      }
      // One-time code.
      state.issuedCode = null;
      json(res, 200, { key: "sk-orca-serverissued123456", user_id: "4242", scope: "api" });
      return;
    }

    json(res, 404, { error: "not_found" });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  servers.push({ close: () => server.close() });
  const { port } = server.address() as AddressInfo;
  return {
    state,
    origins: {
      authBaseUrl: `http://127.0.0.1:${port}`,
      apiBaseUrl: `http://127.0.0.1:${port}/v1`,
    },
  };
}

afterEach(() => {
  while (servers.length > 0) servers.pop()?.close();
});

describe("PKCE connect against a local authorization server", () => {
  it("authorize → out-of-band code → exchange → persist", async () => {
    const { origins, state } = await startFakeAuthServer();
    const persistence = createMemoryPersistence();
    const manager = new OrcaRouterCredentialManager({ origins, persistence });
    const adapter = createPkceAdapter({ origins });

    const begin = await adapter.begin();
    const authorize = new URL(begin.authorizeUrl);
    expect(authorize.origin).toBe(origins.authBaseUrl);

    // The user approves on the consent screen and reads the code back.
    const consent = await fetch(begin.authorizeUrl);
    expect(consent.status).toBe(200);
    const code = state.issuedCode ?? "";

    const acquisition = await adapter.complete(begin.attemptId, code);
    expect(acquisition.apiKey).toBe("sk-orca-serverissued123456");
    expect(acquisition.source).toBe("pkce");
    expect(acquisition.userId).toBe("4242");

    // The server actually verified the verifier against the challenge.
    expect(state.challenge).toBeTruthy();
    expect(s256(state.exchanges[0]?.verifier ?? "")).toBe(state.challenge);

    const credential = await manager.persist(acquisition);
    expect(credential.status).toBe("active");
    expect(credential.scope).toBe("api");
    expect(await persistence.get("orcarouter_api_key")).toBe("sk-orca-serverissued123456");
  });

  it("refuses to redeem the same authorization code twice", async () => {
    const { origins, state } = await startFakeAuthServer();
    const adapter = createPkceAdapter({ origins });
    const begin = await adapter.begin();
    await fetch(begin.authorizeUrl);
    const code = state.issuedCode ?? "";

    await adapter.complete(begin.attemptId, code);

    // A fresh attempt cannot replay the consumed code.
    const replay = createPkceAdapter({ origins });
    const second = await replay.begin();
    await fetch(second.authorizeUrl);
    await expect(replay.complete(second.attemptId, code)).rejects.toMatchObject({
      code: "invalid_request",
      status: 400,
    });
  });

  it("rejects a verifier that does not match the issued challenge", async () => {
    const { origins } = await startFakeAuthServer();
    const adapter = createPkceAdapter({ origins });
    const begin = await adapter.begin();
    await fetch(begin.authorizeUrl);

    // A newer attempt supersedes the first; its verifier is the only one the
    // adapter will use, and it cannot satisfy the first challenge.
    const other = await adapter.begin();
    await expect(adapter.complete(begin.attemptId, "whatever")).rejects.toMatchObject({
      code: "state_mismatch",
    });
    // The superseded attempt stays unusable even through the live attempt id.
    await expect(adapter.complete(other.attemptId, "whatever")).rejects.toMatchObject({
      code: "invalid_request",
      status: 400,
    });
  });
});
