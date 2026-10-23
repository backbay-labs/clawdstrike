import { describe, expect, it, vi } from "vitest";
import {
  defaultChatModel,
  fetchOrcaRouterCatalog,
  filterModels,
  modelsFor,
  parseOrcaRouterModel,
  reconcileSelection,
  recommendedCyberModels,
  sortChatModels,
  ORCAROUTER_VERIFIED_SEED,
  type OrcaRouterCatalog,
  type OrcaRouterModel,
} from "../catalog";
import { resolveOrcaRouterOrigins } from "../provider";

const origins = resolveOrcaRouterOrigins();

const CATALOG_FIXTURE = {
  data: [
    {
      id: "orcarouter/auto",
      name: "OrcaRouter Auto",
      supported_endpoint_types: ["openai"],
      architecture: { input_modalities: ["text", "image"] },
      context_length: 200000,
    },
    {
      id: "orcacyber-ultra-1.0",
      name: "OrcaCyber Ultra",
      supported_endpoint_types: ["openai", "openai-response"],
      architecture: { input_modalities: ["text"] },
      context_length: 400000,
    },
    {
      id: "text-embedding-3-small",
      supported_endpoint_types: ["openai", "embeddings"],
      architecture: { input_modalities: ["text"] },
    },
    {
      id: "openai/gpt-image-1",
      supported_endpoint_types: ["image-generation"],
      architecture: { input_modalities: ["text"], output_modalities: ["image"] },
    },
    {
      id: "acme/video-model",
      supported_endpoint_types: ["openai-video"],
      architecture: { input_modalities: ["text", "image"] },
    },
    {
      id: "acme/reranker",
      supported_endpoint_types: ["jina-rerank"],
      architecture: { input_modalities: ["text"] },
    },
    {
      // Declares chat but no modalities: must fail closed for image entries.
      id: "acme/undeclared-modalities",
      supported_endpoint_types: ["openai"],
    },
  ],
};

function liveCatalog(): OrcaRouterCatalog {
  return {
    models: CATALOG_FIXTURE.data
      .map((raw) => parseOrcaRouterModel(raw))
      .filter((model): model is OrcaRouterModel => model !== null),
    source: "live",
    fetchedAt: 1,
  };
}

describe("catalogue parsing", () => {
  it("preserves vendor-qualified model ids verbatim", () => {
    const parsed = parseOrcaRouterModel(CATALOG_FIXTURE.data[1]);
    expect(parsed?.id).toBe("orcacyber-ultra-1.0");
  });

  it("reads capabilities from endpoint types and modalities from architecture", () => {
    const parsed = parseOrcaRouterModel(CATALOG_FIXTURE.data[0]);
    expect(parsed?.capabilities).toContain("chat");
    expect(parsed?.inputModalities).toEqual(["text", "image"]);
    expect(parsed?.contextLength).toBe(200000);
  });

  it("drops records with no id or no discoverable capability", () => {
    expect(parseOrcaRouterModel({})).toBeNull();
    expect(parseOrcaRouterModel({ id: "" })).toBeNull();
    expect(parseOrcaRouterModel({ id: "x/y", supported_endpoint_types: [] })).toBeNull();
  });

  it("keeps the verified reasoning ladder for openai/gpt-5.5", () => {
    const gpt = ORCAROUTER_VERIFIED_SEED.find((model) => model.id === "openai/gpt-5.5");
    expect(gpt?.reasoningEfforts).toEqual(["low", "medium", "high", "xhigh"]);
  });
});

describe("capability filtering", () => {
  const catalog = liveCatalog();

  it("offers only chat-capable text models for a text entry", () => {
    const ids = filterModels(catalog.models, { capability: "chat", modalities: [] }).map(
      (model) => model.id,
    );
    expect(ids).toContain("orcarouter/auto");
    expect(ids).toContain("orcacyber-ultra-1.0");
    expect(ids).not.toContain("text-embedding-3-small");
    expect(ids).not.toContain("openai/gpt-image-1");
    expect(ids).not.toContain("acme/video-model");
    expect(ids).not.toContain("acme/reranker");
  });

  it("drops a chat model that does not declare the uploaded modality", () => {
    const ids = filterModels(catalog.models, {
      capability: "chat",
      modalities: ["image"],
    }).map((model) => model.id);

    expect(ids).toContain("orcarouter/auto");
    expect(ids).not.toContain("orcacyber-ultra-1.0"); // text-only
    expect(ids).not.toContain("acme/undeclared-modalities"); // fail closed
  });

  it("offers only embedding models for the embedding entry", () => {
    const ids = filterModels(catalog.models, { capability: "embedding" }).map((m) => m.id);
    expect(ids).toContain("text-embedding-3-small");
    expect(ids).not.toContain("orcarouter/auto");
    expect(ids).not.toContain("openai/gpt-image-1");
  });

  it("keeps image, video and rerank models out of the chat list but visible per capability", () => {
    expect(filterModels(catalog.models, { capability: "image" }).map((m) => m.id)).toEqual([
      "openai/gpt-image-1",
    ]);
    expect(filterModels(catalog.models, { capability: "video" }).map((m) => m.id)).toEqual([
      "acme/video-model",
    ]);
    expect(filterModels(catalog.models, { capability: "rerank" }).map((m) => m.id)).toEqual([
      "acme/reranker",
    ]);
  });

  it("recommends branded cyber models in a fixed order when present", () => {
    const cyber = recommendedCyberModels(catalog.models).map((model) => model.id);
    expect(cyber).toEqual(["orcacyber-ultra-1.0"]);
    expect(defaultChatModel(catalog.models)).toBe("orcarouter/auto");
  });

  it("recognises the live `orca/` namespaced cyber ids and keeps tier order", () => {
    const namespaced = [
      "orcarouter/auto",
      "orca/orcacyber-zero-1.0",
      "orca/orcacyber-zero-1.5",
      "orca/orcacyber-ultra-1.0",
      "orcarouter/fusion",
    ].map(
      (id) =>
        ({
          id,
          name: id,
          capabilities: ["chat"],
          inputModalities: ["text"],
          endpointTypes: ["openai"],
          contextLength: null,
          reasoningEfforts: [],
          explicitChat: true,
        }) satisfies OrcaRouterModel,
    );

    expect(recommendedCyberModels(namespaced).map((model) => model.id)).toEqual([
      "orca/orcacyber-ultra-1.0",
      "orca/orcacyber-zero-1.5",
      "orca/orcacyber-zero-1.0",
    ]);
  });

  it("orders a chat selector default → cyber tiers → others → fallback", () => {
    const models = [
      "acme/other",
      "orcarouter/fusion",
      "orca/orcacyber-zero-1.5",
      "orcarouter/auto",
      "orca/orcacyber-ultra-1.0",
      "deepseek/deepseek-v4-pro",
    ].map(
      (id) =>
        ({
          id,
          name: id,
          capabilities: ["chat"],
          inputModalities: ["text"],
          endpointTypes: ["openai"],
          contextLength: null,
          reasoningEfforts: [],
          explicitChat: true,
        }) satisfies OrcaRouterModel,
    );

    expect(sortChatModels(models).map((model) => model.id)).toEqual([
      "orcarouter/auto",
      "orca/orcacyber-ultra-1.0",
      "orca/orcacyber-zero-1.5",
      "acme/other",
      "deepseek/deepseek-v4-pro",
      "orcarouter/fusion",
    ]);
  });
});

describe("live discovery", () => {
  it("treats a successful live response as authoritative (no seed mixed in)", async () => {
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify(CATALOG_FIXTURE), { status: 200 }),
    );
    const result = await fetchOrcaRouterCatalog({ origins, apiKey: "sk-orca-x1234567", fetchFn });

    expect(result.status).toBe("ready");
    expect(result.catalog.source).toBe("live");
    const ids = result.catalog.models.map((model) => model.id);
    expect(ids).toContain("orcacyber-ultra-1.0");
    // Seed-only models must not be injected into a live result.
    expect(ids).not.toContain("anthropic/claude-opus-4.8");
    expect(result.catalog.models.some((model) => !ids.includes(model.id))).toBe(false);

    const [url, init] = fetchFn.mock.calls[0];
    expect(url).toBe("https://api.orcarouter.ai/v1/models");
    expect((init?.headers as Record<string, string>).Authorization).toBe("Bearer sk-orca-x1234567");
  });

  it("falls back to the verified seed on HTTP failure", async () => {
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(new Response("", { status: 500 }));
    const result = await fetchOrcaRouterCatalog({ origins, apiKey: "sk-orca-x1234567", fetchFn });

    expect(result.status).toBe("degraded");
    expect(result.catalog.source).toBe("seed");
    expect(result.catalog.note).toMatch(/verified model seed/);
    expect(result.catalog.models.map((m) => m.id)).toContain("openai/gpt-5.5");
  });

  it("reports a 401 as a degraded catalogue rather than throwing", async () => {
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(new Response("", { status: 401 }));
    const result = await fetchOrcaRouterCatalog({ origins, apiKey: "sk-orca-x1234567", fetchFn });
    expect(result.status).toBe("degraded");
    expect(result.catalog.note).toMatch(/401/);
  });

  it("keeps last-known-good models when discovery fails later", async () => {
    const lastKnownGood = liveCatalog().models;
    const fetchFn = vi.fn<typeof fetch>().mockRejectedValue(new Error("offline"));
    const result = await fetchOrcaRouterCatalog({
      origins,
      apiKey: "sk-orca-x1234567",
      fetchFn,
      lastKnownGood,
    });
    expect(result.catalog.source).toBe("last-known-good");
    expect(result.catalog.models.map((m) => m.id)).toContain("orcacyber-ultra-1.0");
  });

  it("rejects an oversized catalogue instead of buffering it", async () => {
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(
      new Response("{}", { status: 200 }),
    );
    const result = await fetchOrcaRouterCatalog({
      origins,
      apiKey: "sk-orca-x1234567",
      fetchFn,
      maxBytes: 1,
    });
    expect(result.status).toBe("degraded");
    expect(result.catalog.note).toMatch(/too large/);
  });

  it("caps the number of parsed items", async () => {
    const fetchFn = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify(CATALOG_FIXTURE), { status: 200 }),
    );
    const result = await fetchOrcaRouterCatalog({
      origins,
      apiKey: "sk-orca-x1234567",
      fetchFn,
      maxItems: 2,
    });
    expect(result.catalog.models.length).toBeLessThanOrEqual(2);
  });
});

describe("selection reconciliation", () => {
  it("clears a selection that the new capability set no longer offers", () => {
    const options = liveCatalog().models.filter((m) => m.capabilities.includes("embedding"));
    expect(reconcileSelection("orcacyber-ultra-1.0", options)).toEqual({
      selected: null,
      cleared: true,
    });
    expect(reconcileSelection("text-embedding-3-small", options)).toEqual({
      selected: "text-embedding-3-small",
      cleared: false,
    });
  });

  it("recomputes options when the provider requirement changes", () => {
    const catalog = liveCatalog();
    const chat = modelsFor(catalog, { capability: "chat" }).map((m) => m.id);
    const embedding = modelsFor(catalog, { capability: "embedding" }).map((m) => m.id);
    expect(chat).not.toEqual(embedding);
    expect(embedding).not.toContain("orcarouter/auto");
  });

  it("uses the verified seed when no catalogue is loaded yet", () => {
    const ids = modelsFor(null, { capability: "chat" }).map((m) => m.id);
    expect(ids).toContain("orcarouter/auto");
    expect(ids).toContain("openai/gpt-5.5");
    expect(ids).not.toContain("acme/reranker");
  });
});
