import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { EnrichmentResult, Indicator } from "@clawdstrike/plugin-sdk";
import {
  createAbuseIPDBSource,
  ABUSEIPDB_MANIFEST,
} from "../abuseipdb-plugin";

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

// ---- AbuseIPDB response helpers ----

function makeAbuseIPDBResponse(overrides: Partial<{
  ipAddress: string;
  isPublic: boolean;
  abuseConfidenceScore: number;
  totalReports: number;
  lastReportedAt: string | null;
  usageType: string;
  isp: string;
  countryCode: string;
  domain: string;
  isWhitelisted: boolean | null;
}> = {}) {
  return {
    data: {
      ipAddress: "1.2.3.4",
      isPublic: true,
      abuseConfidenceScore: 50,
      totalReports: 10,
      lastReportedAt: "2026-03-15T12:00:00+00:00",
      usageType: "Data Center/Web Hosting/Transit",
      isp: "Example ISP",
      countryCode: "US",
      domain: "example.com",
      isWhitelisted: false,
      ...overrides,
    },
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

describe("ABUSEIPDB_MANIFEST", () => {
  it("has correct id, trust, and category", () => {
    expect(ABUSEIPDB_MANIFEST.id).toBe("clawdstrike.abuseipdb");
    expect(ABUSEIPDB_MANIFEST.trust).toBe("internal");
    expect(ABUSEIPDB_MANIFEST.categories).toContain("intel");
  });

  it("declares threatIntelSources contribution", () => {
    const sources = ABUSEIPDB_MANIFEST.contributions?.threatIntelSources;
    expect(sources).toBeDefined();
    expect(sources).toHaveLength(1);
    expect(sources![0].id).toBe("abuseipdb");
    expect(sources![0].name).toBe("AbuseIPDB");
  });

  it("declares requiredSecrets with api_key entry", () => {
    expect(ABUSEIPDB_MANIFEST.requiredSecrets).toBeDefined();
    expect(ABUSEIPDB_MANIFEST.requiredSecrets).toHaveLength(1);
    expect(ABUSEIPDB_MANIFEST.requiredSecrets![0].key).toBe("api_key");
    expect(ABUSEIPDB_MANIFEST.requiredSecrets![0].label).toMatch(/AbuseIPDB/i);
  });
});

// ---- Source metadata tests ----

describe("createAbuseIPDBSource", () => {
  const source = createAbuseIPDBSource("test-api-key");

  it("has supportedIndicatorTypes of ip only", () => {
    expect(source.supportedIndicatorTypes).toEqual(["ip"]);
  });

  it("has conservative rate limit of 17 req/min", () => {
    expect(source.rateLimit).toEqual({ maxPerMinute: 17 });
  });

  it("has correct id and name", () => {
    expect(source.id).toBe("abuseipdb");
    expect(source.name).toBe("AbuseIPDB");
  });
});

// ---- Endpoint routing tests ----

describe("enrich() endpoint routing", () => {
  let source: ReturnType<typeof createAbuseIPDBSource>;

  beforeEach(() => {
    source = createAbuseIPDBSource("test-api-key");
  });

  it("calls /api/v2/check with Key header and query params for IP indicator", async () => {
    mockFetch.mockResolvedValue(okResponse(makeAbuseIPDBResponse()));

    await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(mockFetch).toHaveBeenCalledOnce();
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("https://api.abuseipdb.com/api/v2/check");
    expect(url).toContain("ipAddress=1.2.3.4");
    expect(url).toContain("maxAgeInDays=90");
    expect(url).toContain("verbose");
    const init = mockFetch.mock.calls[0][1] as RequestInit;
    expect(init.headers).toEqual(
      expect.objectContaining({ Key: "test-api-key" }),
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
  let source: ReturnType<typeof createAbuseIPDBSource>;

  beforeEach(() => {
    source = createAbuseIPDBSource("test-api-key");
  });

  it("classifies score 0-25 as benign", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeAbuseIPDBResponse({ abuseConfidenceScore: 10, totalReports: 2 })),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("benign");
  });

  it("classifies score 26-75 as suspicious", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeAbuseIPDBResponse({ abuseConfidenceScore: 50, totalReports: 10 })),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("suspicious");
  });

  it("classifies score 76-100 as malicious", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeAbuseIPDBResponse({ abuseConfidenceScore: 90, totalReports: 100 })),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("malicious");
  });

  it("classifies score 0 with 0 reports as unknown", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeAbuseIPDBResponse({ abuseConfidenceScore: 0, totalReports: 0 })),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("unknown");
  });

  it("returns confidence = abuseConfidenceScore / 100", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeAbuseIPDBResponse({ abuseConfidenceScore: 75 })),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.confidence).toBe(0.75);
  });

  it("returns rawData with totalReports, lastReportedAt, usageType, isp, countryCode", async () => {
    mockFetch.mockResolvedValue(
      okResponse(
        makeAbuseIPDBResponse({
          totalReports: 42,
          lastReportedAt: "2026-03-15T12:00:00+00:00",
          usageType: "Data Center/Web Hosting/Transit",
          isp: "Example ISP",
          countryCode: "US",
          domain: "example.com",
          isWhitelisted: false,
        }),
      ),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.rawData).toEqual(
      expect.objectContaining({
        abuseConfidenceScore: 50,
        totalReports: 42,
        lastReportedAt: "2026-03-15T12:00:00+00:00",
        usageType: "Data Center/Web Hosting/Transit",
        isp: "Example ISP",
        countryCode: "US",
        domain: "example.com",
        isWhitelisted: false,
      }),
    );
  });

  it("includes summary with abuse confidence and report count", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeAbuseIPDBResponse({ abuseConfidenceScore: 75, totalReports: 42 })),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.summary).toMatch(/75%/);
    expect(result.verdict.summary).toMatch(/42 reports/);
  });

  it("constructs permalink for IP indicators", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeAbuseIPDBResponse()),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.permalink).toBe("https://www.abuseipdb.com/check/1.2.3.4");
  });

  it("sets cacheTtlMs to 1800000 (30 minutes)", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeAbuseIPDBResponse()),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.cacheTtlMs).toBe(1_800_000);
  });

  it("sets sourceId and sourceName", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeAbuseIPDBResponse()),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.sourceId).toBe("abuseipdb");
    expect(result.sourceName).toBe("AbuseIPDB");
  });
});

// ---- Health check tests ----

describe("healthCheck()", () => {
  let source: ReturnType<typeof createAbuseIPDBSource>;

  beforeEach(() => {
    source = createAbuseIPDBSource("test-api-key");
  });

  it("makes a lightweight check request and returns healthy on 200", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeAbuseIPDBResponse({ ipAddress: "8.8.8.8", abuseConfidenceScore: 0 })),
    );

    const result = await source.healthCheck!();

    expect(mockFetch).toHaveBeenCalledOnce();
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("api.abuseipdb.com/api/v2/check");
    expect(url).toContain("8.8.8.8");
    expect(result.healthy).toBe(true);
  });

  it("returns unhealthy on non-200 response", async () => {
    mockFetch.mockResolvedValue(errorResponse(401, {}));

    const result = await source.healthCheck!();

    expect(result.healthy).toBe(false);
  });

  it("returns unhealthy on network error", async () => {
    mockFetch.mockRejectedValue(new TypeError("Failed to fetch"));

    const result = await source.healthCheck!();

    expect(result.healthy).toBe(false);
  });
});

// ---- Error handling tests ----

describe("enrich() error handling", () => {
  let source: ReturnType<typeof createAbuseIPDBSource>;

  beforeEach(() => {
    source = createAbuseIPDBSource("test-api-key");
  });

  it("returns classification:unknown on 401 unauthorized", async () => {
    mockFetch.mockResolvedValue(
      errorResponse(401, { errors: [{ detail: "Authentication failed" }] }),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.confidence).toBe(0);
  });

  it("returns classification:unknown on 429 rate limited", async () => {
    mockFetch.mockResolvedValue(
      errorResponse(429, { errors: [{ detail: "Daily rate limit exceeded" }] }),
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
    expect(result.sourceId).toBe("abuseipdb");
    expect(result.verdict.classification).toBe("unknown");
  });
});

// ---- API response validation ----

describe("enrich() API response validation", () => {
  let source: ReturnType<typeof createAbuseIPDBSource>;

  beforeEach(() => {
    source = createAbuseIPDBSource("test-api-key");
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

  it("handles response with data but missing abuseConfidenceScore", async () => {
    mockFetch.mockResolvedValue(
      okResponse({ data: { ipAddress: "1.2.3.4" } }),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.summary).toMatch(/unexpected/i);
  });
});
