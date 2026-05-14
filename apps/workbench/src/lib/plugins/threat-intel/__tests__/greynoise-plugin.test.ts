import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { EnrichmentResult, Indicator } from "@clawdstrike/plugin-sdk";
import {
  createGreyNoiseSource,
  GREYNOISE_MANIFEST,
} from "../greynoise-plugin";

// ---- Mock fetch ----

const mockFetch = vi.fn<
  (input: string | URL | Request, init?: RequestInit) => Promise<Response>
>();

beforeEach(() => {
  mockFetch.mockReset();
  vi.stubGlobal("fetch", mockFetch);
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---- GreyNoise community API response helpers ----

function makeGnResponse(overrides: Partial<{
  ip: string;
  noise: boolean;
  riot: boolean;
  classification: string;
  name: string;
  link: string;
  last_seen: string;
  message: string;
}> = {}) {
  return {
    ip: "1.2.3.4",
    noise: true,
    riot: false,
    classification: "unknown",
    name: "Unknown",
    link: "https://viz.greynoise.io/ip/1.2.3.4",
    last_seen: "2026-03-20",
    message: "IP found",
    ...overrides,
  };
}

function okResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });
}

function errorResponse(status: number, body: unknown = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

// ---- Manifest tests ----

describe("GREYNOISE_MANIFEST", () => {
  it("has correct id, trust, and category", () => {
    expect(GREYNOISE_MANIFEST.id).toBe("clawdstrike.greynoise");
    expect(GREYNOISE_MANIFEST.trust).toBe("internal");
    expect(GREYNOISE_MANIFEST.categories).toContain("intel");
  });

  it("declares threatIntelSources contribution", () => {
    const sources = GREYNOISE_MANIFEST.contributions?.threatIntelSources;
    expect(sources).toBeDefined();
    expect(sources).toHaveLength(1);
    expect(sources![0].id).toBe("greynoise");
    expect(sources![0].name).toBe("GreyNoise");
  });
});

// ---- Source metadata tests ----

describe("createGreyNoiseSource", () => {
  const source = createGreyNoiseSource("test-api-key");

  it("has supportedIndicatorTypes of ip only", () => {
    expect(source.supportedIndicatorTypes).toEqual(["ip"]);
  });

  it("has community tier rate limit", () => {
    expect(source.rateLimit).toEqual({ maxPerMinute: 10 });
  });

  it("has correct id and name", () => {
    expect(source.id).toBe("greynoise");
    expect(source.name).toBe("GreyNoise");
  });
});

// ---- Endpoint routing tests ----

describe("enrich() endpoint routing", () => {
  let source: ReturnType<typeof createGreyNoiseSource>;

  beforeEach(() => {
    source = createGreyNoiseSource("test-api-key");
  });

  it("calls /v3/community/{ip} with key header for IP indicator", async () => {
    mockFetch.mockResolvedValue(okResponse(makeGnResponse()));

    await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(mockFetch).toHaveBeenCalledOnce();
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe("https://api.greynoise.io/v3/community/1.2.3.4");
    const init = mockFetch.mock.calls[0][1] as RequestInit;
    expect(init.headers).toEqual(
      expect.objectContaining({ key: "test-api-key" }),
    );
  });

  it("returns unsupported for non-IP indicator types without calling fetch", async () => {
    const domainResult = await source.enrich({ type: "domain", value: "evil.com" });
    const hashResult = await source.enrich({ type: "hash", value: "abc123" });

    expect(mockFetch).not.toHaveBeenCalled();
    expect(domainResult.verdict.classification).toBe("unknown");
    expect(domainResult.verdict.summary).toMatch(/unsupported indicator type/i);
    expect(hashResult.verdict.classification).toBe("unknown");
    expect(hashResult.verdict.summary).toMatch(/unsupported indicator type/i);
  });
});

// ---- Response normalization tests ----

describe("enrich() response normalization", () => {
  let source: ReturnType<typeof createGreyNoiseSource>;

  beforeEach(() => {
    source = createGreyNoiseSource("test-api-key");
  });

  it("normalizes malicious classification with confidence 0.85", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeGnResponse({ classification: "malicious", name: "Mirai" })),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("malicious");
    expect(result.verdict.confidence).toBe(0.85);
  });

  it("normalizes benign classification with confidence 0.9", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeGnResponse({ classification: "benign", riot: false })),
    );

    const result = await source.enrich({ type: "ip", value: "8.8.8.8" });

    expect(result.verdict.classification).toBe("benign");
    expect(result.verdict.confidence).toBe(0.9);
  });

  it("bumps benign confidence to 0.95 when RIOT is true", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeGnResponse({ classification: "benign", riot: true, name: "Google DNS" })),
    );

    const result = await source.enrich({ type: "ip", value: "8.8.8.8" });

    expect(result.verdict.classification).toBe("benign");
    expect(result.verdict.confidence).toBe(0.95);
    expect(result.verdict.summary).toContain("RIOT");
  });

  it("normalizes unknown classification with confidence 0.5", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeGnResponse({ classification: "unknown" })),
    );

    const result = await source.enrich({ type: "ip", value: "10.0.0.1" });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.confidence).toBe(0.5);
  });

  it("includes name in summary when present", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeGnResponse({ classification: "malicious", name: "Mirai" })),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.summary).toContain("Mirai");
  });

  it("includes RIOT label in summary when riot is true", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeGnResponse({ classification: "benign", riot: true })),
    );

    const result = await source.enrich({ type: "ip", value: "8.8.8.8" });

    expect(result.verdict.summary).toMatch(/RIOT/);
    expect(result.verdict.summary).toMatch(/Rule It Out/);
  });

  it("sets permalink from response link field", async () => {
    const link = "https://viz.greynoise.io/ip/1.2.3.4";
    mockFetch.mockResolvedValue(
      okResponse(makeGnResponse({ link })),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.permalink).toBe(link);
  });

  it("constructs fallback permalink when link missing", async () => {
    const resp = makeGnResponse();
    // @ts-expect-error -- simulate missing link field
    delete resp.link;
    mockFetch.mockResolvedValue(okResponse(resp));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.permalink).toBe("https://viz.greynoise.io/ip/1.2.3.4");
  });

  it("includes noise, riot, classification, name, last_seen in rawData", async () => {
    mockFetch.mockResolvedValue(
      okResponse(
        makeGnResponse({
          noise: true,
          riot: false,
          classification: "malicious",
          name: "Scanner",
          last_seen: "2026-03-20",
        }),
      ),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.rawData).toEqual(
      expect.objectContaining({
        noise: true,
        riot: false,
        classification: "malicious",
        name: "Scanner",
        last_seen: "2026-03-20",
      }),
    );
  });

  it("sets cacheTtlMs to 600000 (10 minutes)", async () => {
    mockFetch.mockResolvedValue(okResponse(makeGnResponse()));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.cacheTtlMs).toBe(600_000);
  });

  it("sets sourceId and sourceName", async () => {
    mockFetch.mockResolvedValue(okResponse(makeGnResponse()));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.sourceId).toBe("greynoise");
    expect(result.sourceName).toBe("GreyNoise");
  });
});

// ---- Error handling tests ----

describe("enrich() error handling", () => {
  let source: ReturnType<typeof createGreyNoiseSource>;

  beforeEach(() => {
    source = createGreyNoiseSource("test-api-key");
  });

  it("returns classification:unknown on 401 unauthorized", async () => {
    mockFetch.mockResolvedValue(
      errorResponse(401, { message: "Unauthorized" }),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.confidence).toBe(0);
  });

  it("returns classification:unknown on 429 rate limited", async () => {
    mockFetch.mockResolvedValue(
      errorResponse(429, { message: "Rate limit exceeded" }),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.confidence).toBe(0);
    expect(result.verdict.summary).toMatch(/rate limit/i);
  });

  it("returns classification:unknown on network error", async () => {
    mockFetch.mockRejectedValue(new TypeError("Failed to fetch"));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.confidence).toBe(0);
  });

  it("never throws -- always returns EnrichmentResult", async () => {
    mockFetch.mockRejectedValue(new Error("Unexpected error"));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result).toBeDefined();
    expect(result.sourceId).toBe("greynoise");
    expect(result.verdict.classification).toBe("unknown");
  });
});

// ---- API response validation ----

describe("enrich() API response validation", () => {
  let source: ReturnType<typeof createGreyNoiseSource>;

  beforeEach(() => {
    source = createGreyNoiseSource("test-api-key");
  });

  it("handles malformed JSON response ({ unexpected: 'data' }) with classification:unknown", async () => {
    mockFetch.mockResolvedValue(okResponse({ unexpected: "data" }));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.confidence).toBe(0);
  });

  it("handles non-JSON response (HTTP 500 with HTML)", async () => {
    mockFetch.mockResolvedValue(
      new Response("<html>500 Internal Server Error</html>", {
        status: 500,
        headers: { "content-type": "text/html" },
      }),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.confidence).toBe(0);
  });

  it("handles null body response", async () => {
    mockFetch.mockResolvedValue(
      new Response(null, {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result).toBeDefined();
    expect(result.verdict.classification).toBe("unknown");
  });
});
