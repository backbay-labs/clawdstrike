import { describe, expect, it, vi } from "vitest";
import {
  ApiKeyCredentialAdapter,
  createMemoryPersistence,
  createPkceAdapter,
  OrcaRouterCredentialManager,
  ORCAROUTER_SECRET_KEY,
} from "../credentials";
import { resolveOrcaRouterOrigins } from "../provider";

const origins = resolveOrcaRouterOrigins();
const TEST_KEY = "sk-orca-testkey123456";

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function manager(persistence = createMemoryPersistence()) {
  return {
    persistence,
    manager: new OrcaRouterCredentialManager({ origins, persistence }),
  };
}

describe("API key adapter", () => {
  it("produces an api_key credential", async () => {
    const acquisition = await new ApiKeyCredentialAdapter(`  ${TEST_KEY}  `).acquire();
    expect(acquisition).toEqual({
      apiKey: TEST_KEY,
      source: "api_key",
      userId: null,
      scope: null,
    });
  });

  it("rejects an empty key", async () => {
    await expect(new ApiKeyCredentialAdapter("   ").acquire()).rejects.toMatchObject({
      code: "invalid_request",
    });
  });

  it("rejects a key without the sk-orca prefix as a format hint", async () => {
    await expect(new ApiKeyCredentialAdapter("sk-proj-nope").acquire()).rejects.toMatchObject({
      code: "invalid_request",
    });
  });
});

describe("credential lifecycle", () => {
  it("saves, reloads and clears a key through the project store", async () => {
    const { persistence, manager: mgr } = manager();

    const saved = await mgr.connect(new ApiKeyCredentialAdapter(TEST_KEY));
    expect(saved.generation).toBe(1);
    expect(await persistence.get(ORCAROUTER_SECRET_KEY)).toBe(TEST_KEY);

    const reloaded = new OrcaRouterCredentialManager({ origins, persistence });
    const restored = await reloaded.load();
    expect(restored?.apiKey).toBe(TEST_KEY);
    expect(restored?.status).toBe("active");
    expect(restored?.source).toBe("api_key");

    await reloaded.clear();
    expect(await persistence.get(ORCAROUTER_SECRET_KEY)).toBeNull();
    expect(await reloaded.load()).toBeNull();
  });

  it("persists the metadata but keeps the key out of it", async () => {
    const { persistence, manager: mgr } = manager();
    await mgr.connect(new ApiKeyCredentialAdapter(TEST_KEY));
    const meta = await persistence.get("orcarouter_credential_meta");
    expect(meta).toContain('"generation":1');
    expect(meta).not.toContain(TEST_KEY);
  });

  it("never writes the key into logs or thrown errors", async () => {
    const { manager: mgr } = manager();
    const debugSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await mgr.connect(new ApiKeyCredentialAdapter(TEST_KEY));
    await expect(mgr.connect(new ApiKeyCredentialAdapter("bad-key"))).rejects.toSatisfy(
      (err: unknown) => !String((err as Error).message).includes(TEST_KEY),
    );

    for (const spy of [debugSpy, errorSpy]) {
      for (const call of spy.mock.calls) {
        expect(JSON.stringify(call)).not.toContain(TEST_KEY);
      }
    }
    debugSpy.mockRestore();
    errorSpy.mockRestore();
  });
});

describe("two adapters, one credential", () => {
  it("PKCE and API-key adapters yield the same downstream credential shape", async () => {
    const fetchFn = vi
      .fn<typeof fetch>()
      .mockResolvedValue(jsonResponse({ key: TEST_KEY, user_id: "5", scope: "api" }));
    const pkce = createPkceAdapter({ origins, fetchFn });

    const begin = await pkce.begin();
    const pkceAcquisition = await pkce.complete(begin.attemptId, "the-code");

    const keyAcquisition = await new ApiKeyCredentialAdapter(TEST_KEY).acquire();

    const { manager: mgrA } = manager();
    const fromPkce = await mgrA.persist(pkceAcquisition);
    const { manager: mgrB } = manager();
    const fromKey = await mgrB.persist(keyAcquisition);

    // Downstream consumers only see these fields.
    expect(Object.keys(fromPkce).sort()).toEqual(Object.keys(fromKey).sort());
    expect(fromPkce.apiKey).toBe(fromKey.apiKey);
    expect(fromPkce.status).toBe("active");
    expect(fromKey.status).toBe("active");
    expect(fromPkce.source).toBe("pkce");
    expect(fromKey.source).toBe("api_key");
  });

  it("rejects a stale PKCE attempt id", async () => {
    const fetchFn = vi.fn<typeof fetch>();
    const pkce = createPkceAdapter({ origins, fetchFn });
    const first = await pkce.begin();
    await pkce.begin(); // a newer attempt supersedes the first
    await expect(pkce.complete(first.attemptId, "code")).rejects.toMatchObject({
      code: "state_mismatch",
    });
    expect(fetchFn).not.toHaveBeenCalled();
  });
});

describe("401 handling is generation-safe", () => {
  it("marks only the rejected generation as needsReauth", async () => {
    const { manager: mgr } = manager();
    const first = await mgr.connect(new ApiKeyCredentialAdapter(TEST_KEY));
    const marked = await mgr.markUnauthorized(first.generation);
    expect(marked).toBe(true);
    expect(mgr.getCurrent()?.status).toBe("needsReauth");
    expect(mgr.requiresReauth()).toBe(true);
  });

  it("ignores a late 401 from an older generation", async () => {
    const { manager: mgr } = manager();
    const first = await mgr.connect(new ApiKeyCredentialAdapter(TEST_KEY));
    const second = await mgr.connect(new ApiKeyCredentialAdapter("sk-orca-secondkey9999"));

    const applied = await mgr.markUnauthorized(first.generation);
    expect(applied).toBe(false);
    expect(mgr.getCurrent()?.generation).toBe(second.generation);
    expect(mgr.getCurrent()?.status).toBe("active");
  });

  it("does not attempt a refresh after a revoked key", async () => {
    const fetchFn = vi.fn<typeof fetch>();
    const { manager: mgr } = manager();
    const credential = await mgr.persist({
      apiKey: TEST_KEY,
      source: "pkce",
      userId: "1",
      scope: "api",
    });
    await mgr.markUnauthorized(credential.generation);
    expect(fetchFn).not.toHaveBeenCalled();
    // The durable key is kept until a new login replaces it.
    expect(mgr.getCurrent()?.apiKey).toBe(TEST_KEY);
  });
});
