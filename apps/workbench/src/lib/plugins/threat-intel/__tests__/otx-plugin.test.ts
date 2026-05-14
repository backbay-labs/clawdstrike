import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { EnrichmentResult, Indicator } from "@clawdstrike/plugin-sdk";
import {
  createOtxSource,
  OTX_MANIFEST,
} from "../otx-plugin";

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

// ---- OTX API response helpers ----

function makeOtxGeneralResponse(overrides: Partial<{
  pulse_info: {
    count: number;
    pulses: Array<{
      id: string;
      name: string;
      indicator_type_counts?: Record<string, number>;
      references?: string[];
    }>;
  };
  reputation: number;
  country_name: string;
  asn: string;
  type_title: string;
}> = {}) {
  return {
    pulse_info: {
      count: 0,
      pulses: [],
    },
    reputation: 0,
    country_name: "United States",
    asn: "AS15169",
    type_title: "IPv4",
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

describe("OTX_MANIFEST", () => {
  it("has id clawdstrike.otx, trust internal, category intel", () => {
    expect(OTX_MANIFEST.id).toBe("clawdstrike.otx");
    expect(OTX_MANIFEST.trust).toBe("internal");
    expect(OTX_MANIFEST.categories).toContain("intel");
  });

  it("declares threatIntelSources contribution", () => {
    const sources = OTX_MANIFEST.contributions?.threatIntelSources;
    expect(sources).toBeDefined();
    expect(sources).toHaveLength(1);
    expect(sources![0].id).toBe("otx");
    expect(sources![0].name).toBe("AlienVault OTX");
  });

  it("declares requiredSecrets with api_key entry", () => {
    const secrets = OTX_MANIFEST.requiredSecrets ?? [];
    expect(secrets).toBeDefined();
    expect(secrets.length).toBeGreaterThanOrEqual(1);
    expect(secrets.some((s) => s.key === "api_key")).toBe(true);
  });
});

// ---- Source metadata tests ----

describe("createOtxSource", () => {
  const source = createOtxSource("test-api-key");

  it("declares supportedIndicatorTypes [ip, domain, url, hash]", () => {
    expect(source.supportedIndicatorTypes).toEqual(
      expect.arrayContaining(["ip", "domain", "url", "hash"]),
    );
    expect(source.supportedIndicatorTypes).toHaveLength(4);
  });

  it("has correct id and name", () => {
    expect(source.id).toBe("otx");
    expect(source.name).toBe("AlienVault OTX");
  });
});

// ---- Endpoint routing tests ----

describe("enrich() endpoint routing", () => {
  let source: ReturnType<typeof createOtxSource>;

  beforeEach(() => {
    source = createOtxSource("test-api-key");
    mockFetch.mockResolvedValue(okResponse(makeOtxGeneralResponse()));
  });

  it("calls /indicators/IPv4/{ip}/general with X-OTX-API-KEY header for IP", async () => {
    await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(mockFetch).toHaveBeenCalledOnce();
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe(
      "https://otx.alienvault.com/api/v1/indicators/IPv4/1.2.3.4/general",
    );
    const init = mockFetch.mock.calls[0][1] as RequestInit;
    expect(init.headers).toEqual(
      expect.objectContaining({ "X-OTX-API-KEY": "test-api-key" }),
    );
  });

  it("calls /indicators/domain/{domain}/general for domain", async () => {
    await source.enrich({ type: "domain", value: "evil.com" });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe(
      "https://otx.alienvault.com/api/v1/indicators/domain/evil.com/general",
    );
  });

  it("calls /indicators/url/{url}/general for URL", async () => {
    await source.enrich({ type: "url", value: "https://evil.com/malware" });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe(
      "https://otx.alienvault.com/api/v1/indicators/url/https://evil.com/malware/general",
    );
  });

  it("calls /indicators/file/{hash}/general for hash", async () => {
    const hash = "a".repeat(64);
    await source.enrich({ type: "hash", value: hash });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe(
      `https://otx.alienvault.com/api/v1/indicators/file/${hash}/general`,
    );
  });
});

// ---- Response normalization tests ----

describe("enrich() response normalization", () => {
  let source: ReturnType<typeof createOtxSource>;

  beforeEach(() => {
    source = createOtxSource("test-api-key");
  });

  it("maps pulse_info.count > 5 to malicious", async () => {
    mockFetch.mockResolvedValue(
      okResponse(
        makeOtxGeneralResponse({
          pulse_info: {
            count: 8,
            pulses: Array.from({ length: 8 }, (_, i) => ({
              id: `pulse-${i}`,
              name: `Pulse ${i}`,
            })),
          },
        }),
      ),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("malicious");
  });

  it("maps pulse_info.count 1-5 to suspicious", async () => {
    mockFetch.mockResolvedValue(
      okResponse(
        makeOtxGeneralResponse({
          pulse_info: {
            count: 3,
            pulses: [
              { id: "pulse-1", name: "Pulse 1" },
              { id: "pulse-2", name: "Pulse 2" },
              { id: "pulse-3", name: "Pulse 3" },
            ],
          },
        }),
      ),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("suspicious");
  });

  it("maps pulse_info.count 0 to benign", async () => {
    mockFetch.mockResolvedValue(
      okResponse(
        makeOtxGeneralResponse({
          pulse_info: { count: 0, pulses: [] },
        }),
      ),
    );

    const result = await source.enrich({ type: "ip", value: "8.8.8.8" });

    expect(result.verdict.classification).toBe("benign");
  });

  it("returns rawData with pulseCount, reputation, country, asn", async () => {
    mockFetch.mockResolvedValue(
      okResponse(
        makeOtxGeneralResponse({
          pulse_info: { count: 2, pulses: [] },
          reputation: 42,
          country_name: "Germany",
          asn: "AS1234",
          type_title: "IPv4",
        }),
      ),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.rawData).toEqual(
      expect.objectContaining({
        pulseCount: 2,
        reputation: 42,
        country: "Germany",
        asn: "AS1234",
      }),
    );
  });

  it("returns relatedIndicators from pulse references when available", async () => {
    mockFetch.mockResolvedValue(
      okResponse(
        makeOtxGeneralResponse({
          pulse_info: {
            count: 1,
            pulses: [
              {
                id: "pulse-1",
                name: "Malware Campaign",
                references: ["https://evil.com/c2", "https://bad.org/payload"],
              },
            ],
          },
        }),
      ),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.relatedIndicators).toBeDefined();
    expect(result.relatedIndicators!.length).toBeGreaterThan(0);
  });

  it("sets permalink to OTX indicator URL", async () => {
    mockFetch.mockResolvedValue(okResponse(makeOtxGeneralResponse()));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.permalink).toBe(
      "https://otx.alienvault.com/indicator/IPv4/1.2.3.4",
    );
  });

  it("sets cacheTtlMs to 1800000 (30 min)", async () => {
    mockFetch.mockResolvedValue(okResponse(makeOtxGeneralResponse()));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.cacheTtlMs).toBe(1_800_000);
  });

  it("includes verdict summary with pulse count", async () => {
    mockFetch.mockResolvedValue(
      okResponse(
        makeOtxGeneralResponse({
          pulse_info: { count: 3, pulses: [] },
        }),
      ),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.summary).toMatch(/3.*pulse/i);
  });

  it("includes verdict summary for zero pulses", async () => {
    mockFetch.mockResolvedValue(
      okResponse(
        makeOtxGeneralResponse({
          pulse_info: { count: 0, pulses: [] },
        }),
      ),
    );

    const result = await source.enrich({ type: "ip", value: "8.8.8.8" });

    expect(result.verdict.summary).toMatch(/no.*pulse/i);
  });
});

// ---- Health check tests ----

describe("healthCheck()", () => {
  it("returns healthy:true on 200 from /api/v1/user/me", async () => {
    const source = createOtxSource("test-api-key");
    mockFetch.mockResolvedValue(okResponse({ username: "test-user" }));

    const result = await source.healthCheck!();

    expect(result.healthy).toBe(true);
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe("https://otx.alienvault.com/api/v1/user/me");
  });

  it("returns healthy:false on error", async () => {
    const source = createOtxSource("test-api-key");
    mockFetch.mockResolvedValue(errorResponse(401));

    const result = await source.healthCheck!();

    expect(result.healthy).toBe(false);
  });
});

// ---- Error handling tests ----

describe("enrich() error handling", () => {
  let source: ReturnType<typeof createOtxSource>;

  beforeEach(() => {
    source = createOtxSource("test-api-key");
  });

  it("returns classification:unknown on API error", async () => {
    mockFetch.mockResolvedValue(errorResponse(500));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.confidence).toBe(0);
  });

  it("never throws -- always returns EnrichmentResult", async () => {
    mockFetch.mockRejectedValue(new Error("Unexpected error"));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result).toBeDefined();
    expect(result.sourceId).toBe("otx");
    expect(result.verdict.classification).toBe("unknown");
  });
});

// ---- API response validation ----

describe("enrich() API response validation", () => {
  let source: ReturnType<typeof createOtxSource>;

  beforeEach(() => {
    source = createOtxSource("test-api-key");
  });

  it("handles malformed JSON response ({ unexpected: 'data' }) gracefully", async () => {
    mockFetch.mockResolvedValue(okResponse({ unexpected: "data" }));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    // OTX validates `typeof data === 'object'` which passes, then uses
    // data.pulse_info?.count ?? 0 which yields 0 => benign
    expect(result.verdict.classification).toBe("benign");
    expect(result).toBeDefined();
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
