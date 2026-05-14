import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { EnrichmentResult, Indicator } from "@clawdstrike/plugin-sdk";
import {
  createShodanSource,
  SHODAN_MANIFEST,
} from "../shodan-plugin";

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

// ---- Shodan response helpers ----

function makeShodanHostResponse(overrides: Partial<{
  ip_str: string;
  ports: number[];
  vulns: string[];
  org: string;
  isp: string;
  country_name: string;
  city: string;
  os: string;
}> = {}) {
  return {
    ip_str: "1.2.3.4",
    ports: [22, 80, 443],
    org: "Example Corp",
    isp: "Example ISP",
    country_name: "United States",
    city: "New York",
    os: "Linux",
    ...overrides,
  };
}

function makeShodanDnsResponse(domain: string, ip: string) {
  return { [domain]: ip };
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

describe("SHODAN_MANIFEST", () => {
  it("has correct id, trust, and category", () => {
    expect(SHODAN_MANIFEST.id).toBe("clawdstrike.shodan");
    expect(SHODAN_MANIFEST.trust).toBe("internal");
    expect(SHODAN_MANIFEST.categories).toContain("intel");
  });

  it("declares threatIntelSources contribution", () => {
    const sources = SHODAN_MANIFEST.contributions?.threatIntelSources;
    expect(sources).toBeDefined();
    expect(sources).toHaveLength(1);
    expect(sources![0].id).toBe("shodan");
    expect(sources![0].name).toBe("Shodan");
  });

  it("declares requiredSecrets with api_key entry", () => {
    expect(SHODAN_MANIFEST.requiredSecrets).toBeDefined();
    expect(SHODAN_MANIFEST.requiredSecrets).toHaveLength(1);
    expect(SHODAN_MANIFEST.requiredSecrets![0].key).toBe("api_key");
    expect(SHODAN_MANIFEST.requiredSecrets![0].label).toMatch(/Shodan/i);
  });
});

// ---- Source metadata tests ----

describe("createShodanSource", () => {
  const source = createShodanSource("test-api-key");

  it("has supportedIndicatorTypes of ip and domain", () => {
    expect(source.supportedIndicatorTypes).toEqual(
      expect.arrayContaining(["ip", "domain"]),
    );
    expect(source.supportedIndicatorTypes).toHaveLength(2);
  });

  it("has rate limit of 60 req/min", () => {
    expect(source.rateLimit).toEqual({ maxPerMinute: 60 });
  });

  it("has correct id and name", () => {
    expect(source.id).toBe("shodan");
    expect(source.name).toBe("Shodan");
  });
});

// ---- Endpoint routing tests ----

describe("enrich() endpoint routing", () => {
  let source: ReturnType<typeof createShodanSource>;

  beforeEach(() => {
    source = createShodanSource("test-api-key");
  });

  it("calls /shodan/host/{ip}?key={apiKey} for IP indicator", async () => {
    mockFetch.mockResolvedValue(okResponse(makeShodanHostResponse()));

    await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(mockFetch).toHaveBeenCalledOnce();
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe(
      "https://api.shodan.io/shodan/host/1.2.3.4?key=test-api-key",
    );
  });

  it("calls /dns/resolve then /shodan/host for domain indicator", async () => {
    // First call: DNS resolution
    mockFetch.mockResolvedValueOnce(
      okResponse(makeShodanDnsResponse("evil.com", "5.6.7.8")),
    );
    // Second call: host lookup on resolved IP
    mockFetch.mockResolvedValueOnce(
      okResponse(makeShodanHostResponse({ ip_str: "5.6.7.8" })),
    );

    await source.enrich({ type: "domain", value: "evil.com" });

    expect(mockFetch).toHaveBeenCalledTimes(2);
    const dnsUrl = mockFetch.mock.calls[0][0] as string;
    expect(dnsUrl).toBe(
      "https://api.shodan.io/dns/resolve?hostnames=evil.com&key=test-api-key",
    );
    const hostUrl = mockFetch.mock.calls[1][0] as string;
    expect(hostUrl).toBe(
      "https://api.shodan.io/shodan/host/5.6.7.8?key=test-api-key",
    );
  });
});

// ---- Response normalization tests ----

describe("enrich() response normalization", () => {
  let source: ReturnType<typeof createShodanSource>;

  beforeEach(() => {
    source = createShodanSource("test-api-key");
  });

  it("classifies as suspicious when vulns are present", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeShodanHostResponse({ vulns: ["CVE-2021-44228", "CVE-2023-1234"] })),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("suspicious");
    expect(result.verdict.confidence).toBeGreaterThan(0);
  });

  it("classifies as benign when no vulns are present", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeShodanHostResponse()),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("benign");
  });

  it("returns confidence 0.3 for 0 vulns", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeShodanHostResponse()),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.confidence).toBe(0.3);
  });

  it("returns confidence 0.5 for 1-5 vulns", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeShodanHostResponse({ vulns: ["CVE-2021-44228", "CVE-2023-1234"] })),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.confidence).toBe(0.5);
  });

  it("returns confidence 0.7 for 6+ vulns", async () => {
    const vulns = Array.from({ length: 7 }, (_, i) => `CVE-2021-${i + 1}`);
    mockFetch.mockResolvedValue(
      okResponse(makeShodanHostResponse({ vulns })),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.confidence).toBe(0.7);
  });

  it("includes ports, vulns, org, isp, country in rawData", async () => {
    mockFetch.mockResolvedValue(
      okResponse(
        makeShodanHostResponse({
          ports: [22, 80, 443],
          org: "Example Corp",
          isp: "Example ISP",
          country_name: "United States",
          city: "New York",
          os: "Linux",
        }),
      ),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.rawData).toEqual(
      expect.objectContaining({
        ports: [22, 80, 443],
        org: "Example Corp",
        isp: "Example ISP",
        country_name: "United States",
        city: "New York",
        os: "Linux",
      }),
    );
  });

  it("includes summary with port/vuln counts", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeShodanHostResponse({ ports: [22, 80], vulns: ["CVE-2021-1"] })),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.summary).toMatch(/2 open ports/);
    expect(result.verdict.summary).toMatch(/1 known vulnerabilit/);
  });

  it("returns relatedIndicators for domain lookups", async () => {
    mockFetch.mockResolvedValueOnce(
      okResponse(makeShodanDnsResponse("evil.com", "5.6.7.8")),
    );
    mockFetch.mockResolvedValueOnce(
      okResponse(makeShodanHostResponse({ ip_str: "5.6.7.8" })),
    );

    const result = await source.enrich({ type: "domain", value: "evil.com" });

    expect(result.relatedIndicators).toBeDefined();
    expect(result.relatedIndicators).toHaveLength(1);
    expect(result.relatedIndicators![0]).toEqual(
      expect.objectContaining({ type: "ip", value: "5.6.7.8" }),
    );
  });

  it("returns unknown classification when API returns 404", async () => {
    mockFetch.mockResolvedValue(errorResponse(404, { error: "No information available" }));

    const result = await source.enrich({ type: "ip", value: "203.0.113.1" });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.summary).toMatch(/No data found|no information/i);
  });

  it("constructs permalink for IP indicators", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeShodanHostResponse()),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.permalink).toBe("https://www.shodan.io/host/1.2.3.4");
  });

  it("sets cacheTtlMs to 3600000 (1 hour)", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeShodanHostResponse()),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.cacheTtlMs).toBe(3_600_000);
  });

  it("sets sourceId and sourceName", async () => {
    mockFetch.mockResolvedValue(
      okResponse(makeShodanHostResponse()),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.sourceId).toBe("shodan");
    expect(result.sourceName).toBe("Shodan");
  });
});

// ---- Health check tests ----

describe("healthCheck()", () => {
  let source: ReturnType<typeof createShodanSource>;

  beforeEach(() => {
    source = createShodanSource("test-api-key");
  });

  it("calls /api-info?key={apiKey} and returns healthy on 200", async () => {
    mockFetch.mockResolvedValue(okResponse({ scan_credits: 100 }));

    const result = await source.healthCheck!();

    expect(mockFetch).toHaveBeenCalledOnce();
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe("https://api.shodan.io/api-info?key=test-api-key");
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
  let source: ReturnType<typeof createShodanSource>;

  beforeEach(() => {
    source = createShodanSource("test-api-key");
  });

  it("returns classification:unknown on 401 unauthorized", async () => {
    mockFetch.mockResolvedValue(
      errorResponse(401, { error: "Access denied" }),
    );

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.confidence).toBe(0);
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
    expect(result.sourceId).toBe("shodan");
    expect(result.verdict.classification).toBe("unknown");
  });
});

// ---- SSRF prevention: isPrivateOrReservedIP ----

describe("SSRF prevention: isPrivateOrReservedIP", () => {
  let source: ReturnType<typeof createShodanSource>;

  beforeEach(() => {
    source = createShodanSource("test-api-key");
  });

  describe("blocks private IPs (RFC 1918)", () => {
    it.each([
      "10.0.0.1",
      "10.255.255.255",
      "172.16.0.1",
      "172.31.255.255",
      "192.168.0.1",
      "192.168.255.255",
    ])("blocks %s", async (ip) => {
      const result = await source.enrich({ type: "ip", value: ip });

      expect(result.verdict.classification).toBe("unknown");
      expect(result.verdict.summary).toMatch(/private or reserved/i);
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe("blocks loopback addresses", () => {
    it.each(["127.0.0.1", "127.255.255.255"])("blocks %s", async (ip) => {
      const result = await source.enrich({ type: "ip", value: ip });

      expect(result.verdict.classification).toBe("unknown");
      expect(result.verdict.summary).toMatch(/private or reserved/i);
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe("blocks link-local addresses", () => {
    it.each(["169.254.0.1", "169.254.255.255"])("blocks %s", async (ip) => {
      const result = await source.enrich({ type: "ip", value: ip });

      expect(result.verdict.classification).toBe("unknown");
      expect(result.verdict.summary).toMatch(/private or reserved/i);
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe("blocks multicast and broadcast addresses", () => {
    it.each(["224.0.0.1", "239.255.255.255", "255.255.255.255"])(
      "blocks %s",
      async (ip) => {
        const result = await source.enrich({ type: "ip", value: ip });

        expect(result.verdict.classification).toBe("unknown");
        expect(result.verdict.summary).toMatch(/private or reserved/i);
        expect(mockFetch).not.toHaveBeenCalled();
      },
    );
  });

  describe("allows public IPs", () => {
    it.each(["8.8.8.8", "1.1.1.1", "93.184.216.34"])(
      "allows %s",
      async (ip) => {
        mockFetch.mockResolvedValue(
          okResponse(makeShodanHostResponse({ ip_str: ip })),
        );

        const result = await source.enrich({ type: "ip", value: ip });

        expect(result.verdict.classification).not.toBe("unknown");
        expect(mockFetch).toHaveBeenCalled();
      },
    );
  });

  describe("handles invalid IPs", () => {
    it("treats empty string as non-private (returns false from validator)", async () => {
      mockFetch.mockResolvedValue(
        okResponse(makeShodanHostResponse()),
      );
      // Empty string fails the parts.length !== 4 check so isPrivateOrReservedIP returns false.
      // The IP will be sent to Shodan API as-is (Shodan will reject it).
      await source.enrich({ type: "ip", value: "" });
      // fetch is called because the function does not detect it as private
      expect(mockFetch).toHaveBeenCalled();
    });

    it("treats 'not-an-ip' as non-private (passes to API)", async () => {
      mockFetch.mockResolvedValue(
        okResponse(makeShodanHostResponse()),
      );
      await source.enrich({ type: "ip", value: "not-an-ip" });
      expect(mockFetch).toHaveBeenCalled();
    });

    it("treats '999.999.999.999' as non-private (NaN octets fail validation)", async () => {
      mockFetch.mockResolvedValue(
        okResponse(makeShodanHostResponse()),
      );
      await source.enrich({ type: "ip", value: "999.999.999.999" });
      // Octets > 255 fail the validator, returning false, so fetch IS called
      expect(mockFetch).toHaveBeenCalled();
    });
  });

  describe("enrich() returns error result for private IPs without calling fetch", () => {
    it("returns error and does NOT call fetch for 10.0.0.1", async () => {
      const result = await source.enrich({
        type: "ip",
        value: "10.0.0.1",
      });

      expect(result.sourceId).toBe("shodan");
      expect(result.verdict.classification).toBe("unknown");
      expect(result.verdict.confidence).toBe(0);
      expect(result.verdict.summary).toMatch(/private or reserved/i);
      expect(mockFetch).not.toHaveBeenCalled();
    });
  });

  describe("SSRF via DNS rebinding for domain indicators", () => {
    it("blocks domain that resolves to private IP", async () => {
      // DNS resolves to private IP
      mockFetch.mockResolvedValueOnce(
        okResponse(makeShodanDnsResponse("evil.internal", "192.168.1.1")),
      );

      const result = await source.enrich({
        type: "domain",
        value: "evil.internal",
      });

      // Should block after DNS resolution
      expect(result.verdict.classification).toBe("unknown");
      expect(result.verdict.summary).toMatch(/private or reserved/i);
      // Only 1 fetch call (DNS resolution), host lookup should NOT happen
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });
  });
});

// ---- API response validation ----

describe("enrich() API response validation", () => {
  let source: ReturnType<typeof createShodanSource>;

  beforeEach(() => {
    source = createShodanSource("test-api-key");
  });

  it("handles malformed JSON response (missing ip_str)", async () => {
    mockFetch.mockResolvedValue(
      okResponse({ unexpected: "data" }),
    );

    const result = await source.enrich({ type: "ip", value: "8.8.8.8" });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.summary).toMatch(/unexpected/i);
  });

  it("handles non-JSON response (HTTP 500 with HTML)", async () => {
    mockFetch.mockResolvedValue(
      new Response("<html>500 Internal Server Error</html>", {
        status: 500,
        headers: { "content-type": "text/html" },
      }),
    );

    const result = await source.enrich({ type: "ip", value: "8.8.8.8" });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.confidence).toBe(0);
  });

  it("handles null body in response", async () => {
    // response.json() will throw on null body, caught by error handler
    mockFetch.mockResolvedValue(
      new Response(null, {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );

    const result = await source.enrich({ type: "ip", value: "8.8.8.8" });

    // Should not crash -- returns unknown classification
    expect(result).toBeDefined();
    expect(result.verdict.classification).toBe("unknown");
  });
});

// ---- Fetch timeout behavior ----

describe("enrich() timeout behavior", () => {
  let source: ReturnType<typeof createShodanSource>;

  beforeEach(() => {
    source = createShodanSource("test-api-key");
  });

  it("returns timeout error when fetch is aborted", async () => {
    mockFetch.mockRejectedValue(
      new DOMException("The operation was aborted", "AbortError"),
    );

    const result = await source.enrich({ type: "ip", value: "8.8.8.8" });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.summary).toMatch(/timeout/i);
  });
});
