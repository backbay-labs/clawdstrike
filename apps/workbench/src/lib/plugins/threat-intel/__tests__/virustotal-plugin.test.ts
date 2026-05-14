import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { EnrichmentResult, Indicator } from "@clawdstrike/plugin-sdk";
import {
  createVirusTotalSource,
  VIRUSTOTAL_MANIFEST,
} from "../virustotal-plugin";

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

// ---- VT v3 response helpers ----

function makeVtAnalysisStats(overrides: Partial<Record<string, number>> = {}) {
  return {
    malicious: 0,
    suspicious: 0,
    undetected: 10,
    harmless: 50,
    timeout: 0,
    "confirmed-timeout": 0,
    failure: 0,
    "type-unsupported": 0,
    ...overrides,
  };
}

function makeVtResponse(stats: Record<string, number>, extra: Record<string, unknown> = {}) {
  return {
    data: {
      attributes: {
        last_analysis_stats: stats,
        ...extra,
      },
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

describe("VIRUSTOTAL_MANIFEST", () => {
  it("has correct id, trust, and category", () => {
    expect(VIRUSTOTAL_MANIFEST.id).toBe("clawdstrike.virustotal");
    expect(VIRUSTOTAL_MANIFEST.trust).toBe("internal");
    expect(VIRUSTOTAL_MANIFEST.categories).toContain("intel");
  });

  it("declares threatIntelSources contribution", () => {
    const sources = VIRUSTOTAL_MANIFEST.contributions?.threatIntelSources;
    expect(sources).toBeDefined();
    expect(sources).toHaveLength(1);
    expect(sources![0].id).toBe("virustotal");
    expect(sources![0].name).toBe("VirusTotal");
  });
});

// ---- Source metadata tests ----

describe("createVirusTotalSource", () => {
  const source = createVirusTotalSource("test-api-key");

  it("has correct supportedIndicatorTypes", () => {
    expect(source.supportedIndicatorTypes).toEqual(
      expect.arrayContaining(["hash", "ip", "domain", "url"]),
    );
    expect(source.supportedIndicatorTypes).toHaveLength(4);
  });

  it("has free tier rate limit", () => {
    expect(source.rateLimit).toEqual({ maxPerMinute: 4 });
  });

  it("has correct id and name", () => {
    expect(source.id).toBe("virustotal");
    expect(source.name).toBe("VirusTotal");
  });
});

// ---- Endpoint routing tests ----

describe("enrich() endpoint routing", () => {
  let source: ReturnType<typeof createVirusTotalSource>;

  beforeEach(() => {
    source = createVirusTotalSource("test-api-key");
    mockFetch.mockResolvedValue(
      okResponse(makeVtResponse(makeVtAnalysisStats())),
    );
  });

  it("calls /files/{hash} for SHA-256 hash indicator", async () => {
    const indicator: Indicator = {
      type: "hash",
      value: "a" .repeat(64),
      hashAlgorithm: "sha256",
    };
    await source.enrich(indicator);

    expect(mockFetch).toHaveBeenCalledOnce();
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe(
      `https://www.virustotal.com/api/v3/files/${"a".repeat(64)}`,
    );
    const init = mockFetch.mock.calls[0][1] as RequestInit;
    expect(init.headers).toEqual(
      expect.objectContaining({ "x-apikey": "test-api-key" }),
    );
  });

  it("calls /files/{hash} for MD5 hash indicator", async () => {
    const indicator: Indicator = {
      type: "hash",
      value: "d41d8cd98f00b204e9800998ecf8427e",
      hashAlgorithm: "md5",
    };
    await source.enrich(indicator);

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("/api/v3/files/");
  });

  it("calls /domains/{domain} for domain indicator", async () => {
    const indicator: Indicator = { type: "domain", value: "evil.com" };
    await source.enrich(indicator);

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe("https://www.virustotal.com/api/v3/domains/evil.com");
  });

  it("calls /ip_addresses/{ip} for IP indicator", async () => {
    const indicator: Indicator = { type: "ip", value: "1.2.3.4" };
    await source.enrich(indicator);

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe("https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4");
  });

  it("calls /urls/{base64url} for URL indicator", async () => {
    const indicator: Indicator = {
      type: "url",
      value: "https://evil.com/malware",
    };
    await source.enrich(indicator);

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toContain("/api/v3/urls/");
    // Should contain base64url-encoded value
    expect(url).not.toContain("https://evil.com/malware");
  });
});

// ---- Response normalization tests ----

describe("enrich() response normalization", () => {
  let source: ReturnType<typeof createVirusTotalSource>;

  beforeEach(() => {
    source = createVirusTotalSource("test-api-key");
  });

  it("normalizes high malicious detections to classification:malicious with confidence > 0.7", async () => {
    // 50 malicious out of 60 total = 0.833 confidence
    const stats = makeVtAnalysisStats({ malicious: 50, harmless: 5, undetected: 5, suspicious: 0, timeout: 0 });
    mockFetch.mockResolvedValue(okResponse(makeVtResponse(stats)));

    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

    expect(result.verdict.classification).toBe("malicious");
    expect(result.verdict.confidence).toBeGreaterThan(0.7);
  });

  it("normalizes zero detections to classification:benign", async () => {
    const stats = makeVtAnalysisStats({ malicious: 0, harmless: 55, undetected: 5 });
    mockFetch.mockResolvedValue(okResponse(makeVtResponse(stats)));

    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

    expect(result.verdict.classification).toBe("benign");
  });

  it("normalizes mixed results (1-5 malicious) to classification:suspicious", async () => {
    const stats = makeVtAnalysisStats({ malicious: 3, harmless: 50, undetected: 10 });
    mockFetch.mockResolvedValue(okResponse(makeVtResponse(stats)));

    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

    expect(result.verdict.classification).toBe("suspicious");
  });

  it("includes summary with detection ratio", async () => {
    const stats = makeVtAnalysisStats({ malicious: 10, harmless: 40, undetected: 20 });
    mockFetch.mockResolvedValue(okResponse(makeVtResponse(stats)));

    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

    expect(result.verdict.summary).toMatch(/10\/\d+ engines detected as malicious/);
  });

  it("constructs permalink for hash indicators", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeVtResponse(makeVtAnalysisStats())),
    );
    const hash = "a".repeat(64);
    const result = await source.enrich({ type: "hash", value: hash });

    expect(result.permalink).toBe(
      `https://www.virustotal.com/gui/file/${hash}`,
    );
  });

  it("constructs permalink for domain indicators", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeVtResponse(makeVtAnalysisStats())),
    );
    const result = await source.enrich({ type: "domain", value: "evil.com" });

    expect(result.permalink).toBe(
      "https://www.virustotal.com/gui/domain/evil.com",
    );
  });

  it("constructs permalink for IP indicators", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeVtResponse(makeVtAnalysisStats())),
    );
    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.permalink).toBe(
      "https://www.virustotal.com/gui/ip-address/1.2.3.4",
    );
  });

  it("sets cacheTtlMs to 300000 (5 minutes)", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeVtResponse(makeVtAnalysisStats())),
    );
    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

    expect(result.cacheTtlMs).toBe(300_000);
  });

  it("sets sourceId and sourceName", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeVtResponse(makeVtAnalysisStats())),
    );
    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

    expect(result.sourceId).toBe("virustotal");
    expect(result.sourceName).toBe("VirusTotal");
  });
});

// ---- Error handling tests ----

describe("enrich() error handling", () => {
  let source: ReturnType<typeof createVirusTotalSource>;

  beforeEach(() => {
    source = createVirusTotalSource("test-api-key");
  });

  it("returns classification:unknown on 403 forbidden", async () => {
    mockFetch.mockResolvedValue(
      errorResponse(403, { error: { code: "ForbiddenError" } }),
    );

    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.confidence).toBe(0);
    expect(result.verdict.summary).toMatch(/forbidden|api key/i);
  });

  it("returns classification:unknown on 429 rate limited", async () => {
    mockFetch.mockResolvedValue(
      errorResponse(429, { error: { code: "QuotaExceededError" } }),
    );

    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.confidence).toBe(0);
    expect(result.verdict.summary).toMatch(/rate limit/i);
  });

  it("returns classification:unknown on network timeout", async () => {
    mockFetch.mockRejectedValue(new DOMException("The operation timed out", "AbortError"));

    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.confidence).toBe(0);
    expect(result.verdict.summary).toMatch(/timeout|network/i);
  });

  it("returns classification:unknown on network error", async () => {
    mockFetch.mockRejectedValue(new TypeError("Failed to fetch"));

    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.confidence).toBe(0);
  });

  it("never throws -- always returns EnrichmentResult", async () => {
    mockFetch.mockRejectedValue(new Error("Unexpected error"));

    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

    expect(result).toBeDefined();
    expect(result.sourceId).toBe("virustotal");
    expect(result.verdict.classification).toBe("unknown");
  });
});

// ---- API response validation ----

describe("enrich() API response validation", () => {
  let source: ReturnType<typeof createVirusTotalSource>;

  beforeEach(() => {
    source = createVirusTotalSource("test-api-key");
  });

  it("handles malformed JSON response ({ unexpected: 'data' }) with classification:unknown", async () => {
    mockFetch.mockResolvedValue(okResponse({ unexpected: "data" }));

    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

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

    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

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

    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

    expect(result).toBeDefined();
    expect(result.verdict.classification).toBe("unknown");
  });

  it("handles response missing last_analysis_stats", async () => {
    mockFetch.mockResolvedValue(
      okResponse({ data: { attributes: {} } }),
    );

    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.summary).toMatch(/missing analysis stats/i);
  });
});

// ---- Fetch timeout behavior ----

describe("enrich() timeout behavior", () => {
  let source: ReturnType<typeof createVirusTotalSource>;

  beforeEach(() => {
    source = createVirusTotalSource("test-api-key");
  });

  it("returns timeout error when fetch is aborted via AbortController", async () => {
    mockFetch.mockRejectedValue(
      new DOMException("The operation was aborted", "AbortError"),
    );

    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.summary).toMatch(/timeout/i);
  });

  it("handles non-AbortError DOMException gracefully", async () => {
    mockFetch.mockRejectedValue(
      new DOMException("Network error", "NetworkError"),
    );

    const result = await source.enrich({ type: "hash", value: "a".repeat(64) });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.confidence).toBe(0);
  });
});
