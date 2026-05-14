import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { EnrichmentResult, Indicator } from "@clawdstrike/plugin-sdk";
import {
  createMispSource,
  MISP_MANIFEST,
} from "../misp-plugin";

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

// ---- MISP API response helpers ----

interface MispAttribute {
  id: string;
  event_id: string;
  type: string;
  category: string;
  value: string;
  Event?: {
    id: string;
    info: string;
    threat_level_id: string;
    Tag?: Array<{
      name: string;
    }>;
    Attribute?: Array<{
      type: string;
      value: string;
    }>;
  };
}

function makeMispResponse(attributes: MispAttribute[] = []) {
  return {
    response: {
      Attribute: attributes,
    },
  };
}

function makeAttribute(overrides: Partial<MispAttribute> = {}): MispAttribute {
  return {
    id: "1",
    event_id: "100",
    type: "ip-src",
    category: "Network activity",
    value: "1.2.3.4",
    Event: {
      id: "100",
      info: "Malware Campaign",
      threat_level_id: "1",
      Tag: [],
      Attribute: [],
    },
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

describe("MISP_MANIFEST", () => {
  it("has id clawdstrike.misp, trust internal, category intel", () => {
    expect(MISP_MANIFEST.id).toBe("clawdstrike.misp");
    expect(MISP_MANIFEST.trust).toBe("internal");
    expect(MISP_MANIFEST.categories).toContain("intel");
  });

  it("declares threatIntelSources contribution", () => {
    const sources = MISP_MANIFEST.contributions?.threatIntelSources;
    expect(sources).toBeDefined();
    expect(sources).toHaveLength(1);
    expect(sources![0].id).toBe("misp");
    expect(sources![0].name).toBe("MISP");
  });

  it("declares requiredSecrets with api_key AND base_url entries", () => {
    const secrets = MISP_MANIFEST.requiredSecrets ?? [];
    expect(secrets).toBeDefined();
    expect(secrets.length).toBeGreaterThanOrEqual(2);
    expect(secrets.some((s) => s.key === "api_key")).toBe(true);
    expect(secrets.some((s) => s.key === "base_url")).toBe(true);
  });
});

// ---- Source metadata tests ----

describe("createMispSource", () => {
  const source = createMispSource("test-api-key", "https://misp.example.com");

  it("declares supportedIndicatorTypes [ip, domain, url, hash, email]", () => {
    expect(source.supportedIndicatorTypes).toEqual(
      expect.arrayContaining(["ip", "domain", "url", "hash", "email"]),
    );
    expect(source.supportedIndicatorTypes).toHaveLength(5);
  });

  it("has correct id and name", () => {
    expect(source.id).toBe("misp");
    expect(source.name).toBe("MISP");
  });
});

// ---- Endpoint routing tests ----

describe("enrich() endpoint and auth", () => {
  let source: ReturnType<typeof createMispSource>;

  beforeEach(() => {
    source = createMispSource("test-api-key", "https://misp.example.com");
    mockFetch.mockResolvedValue(okResponse(makeMispResponse()));
  });

  it("calls POST to {baseUrl}/attributes/restSearch with Authorization header", async () => {
    await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(mockFetch).toHaveBeenCalledOnce();
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe("https://misp.example.com/attributes/restSearch");

    const init = mockFetch.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(init.headers).toEqual(
      expect.objectContaining({
        Authorization: "test-api-key",
        "Content-Type": "application/json",
      }),
    );
  });

  it("sends body with indicator value", async () => {
    await source.enrich({ type: "ip", value: "1.2.3.4" });

    const init = mockFetch.mock.calls[0][1] as RequestInit;
    const body = JSON.parse(init.body as string);
    expect(body.value).toBe("1.2.3.4");
    expect(body.returnFormat).toBe("json");
  });

  it("uses configurable base_url, not hardcoded", async () => {
    const customSource = createMispSource("key", "https://custom-misp.corp.net");
    mockFetch.mockResolvedValue(okResponse(makeMispResponse()));

    await customSource.enrich({ type: "domain", value: "evil.com" });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe("https://custom-misp.corp.net/attributes/restSearch");
  });

  it("strips trailing slash from base_url", async () => {
    const trailingSlashSource = createMispSource("key", "https://misp.example.com/");
    mockFetch.mockResolvedValue(okResponse(makeMispResponse()));

    await trailingSlashSource.enrich({ type: "ip", value: "1.2.3.4" });

    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe("https://misp.example.com/attributes/restSearch");
  });
});

// ---- Response normalization tests ----

describe("enrich() response normalization", () => {
  let source: ReturnType<typeof createMispSource>;

  beforeEach(() => {
    source = createMispSource("test-api-key", "https://misp.example.com");
  });

  it("maps attribute count > 3 events to malicious", async () => {
    // 4 attributes across 4 distinct events
    const attrs = [
      makeAttribute({ id: "1", event_id: "100", Event: { id: "100", info: "Campaign A", threat_level_id: "1", Tag: [] } }),
      makeAttribute({ id: "2", event_id: "101", Event: { id: "101", info: "Campaign B", threat_level_id: "2", Tag: [] } }),
      makeAttribute({ id: "3", event_id: "102", Event: { id: "102", info: "Campaign C", threat_level_id: "1", Tag: [] } }),
      makeAttribute({ id: "4", event_id: "103", Event: { id: "103", info: "Campaign D", threat_level_id: "3", Tag: [] } }),
    ];
    mockFetch.mockResolvedValue(okResponse(makeMispResponse(attrs)));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("malicious");
  });

  it("maps attribute count 1-3 events to suspicious", async () => {
    const attrs = [
      makeAttribute({ id: "1", event_id: "100" }),
      makeAttribute({ id: "2", event_id: "101", Event: { id: "101", info: "Another", threat_level_id: "2", Tag: [] } }),
    ];
    mockFetch.mockResolvedValue(okResponse(makeMispResponse(attrs)));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.classification).toBe("suspicious");
  });

  it("maps 0 matching attributes to unknown", async () => {
    mockFetch.mockResolvedValue(okResponse(makeMispResponse([])));

    const result = await source.enrich({ type: "ip", value: "8.8.8.8" });

    expect(result.verdict.classification).toBe("unknown");
  });

  it("returns unknown when no attributes match (empty response)", async () => {
    mockFetch.mockResolvedValue(okResponse(makeMispResponse([])));

    const result = await source.enrich({ type: "domain", value: "safe.org" });

    expect(result.verdict.classification).toBe("unknown");
    expect(result.verdict.summary).toMatch(/no matching/i);
  });

  it("extracts MITRE ATT&CK Galaxy clusters from event tags", async () => {
    const attrs = [
      makeAttribute({
        id: "1",
        event_id: "100",
        Event: {
          id: "100",
          info: "APT Campaign",
          threat_level_id: "1",
          Tag: [
            { name: 'misp-galaxy:mitre-attack-pattern="Command and Scripting Interpreter - T1059"' },
            { name: 'misp-galaxy:mitre-attack-pattern="Spearphishing Attachment - T1566.001"' },
            { name: "tlp:white" },
          ],
        },
      }),
    ];
    mockFetch.mockResolvedValue(okResponse(makeMispResponse(attrs)));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.mitreTechniques).toBeDefined();
    expect(result.mitreTechniques!.length).toBeGreaterThanOrEqual(1);
    // Should extract technique IDs like T1059, T1566.001
    const techniqueIds = result.mitreTechniques!.map((t) => t.techniqueId);
    expect(techniqueIds).toContain("T1059");
  });

  it("returns rawData with matchedAttributes, eventCount, categories, threatLevel", async () => {
    const attrs = [
      makeAttribute({
        id: "1",
        event_id: "100",
        category: "Network activity",
        Event: { id: "100", info: "Campaign", threat_level_id: "1", Tag: [] },
      }),
      makeAttribute({
        id: "2",
        event_id: "101",
        category: "Payload delivery",
        Event: { id: "101", info: "Malware", threat_level_id: "2", Tag: [] },
      }),
    ];
    mockFetch.mockResolvedValue(okResponse(makeMispResponse(attrs)));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.rawData).toEqual(
      expect.objectContaining({
        matchedAttributes: 2,
        eventCount: 2,
      }),
    );
    expect(result.rawData.categories).toBeDefined();
    expect(result.rawData.threatLevel).toBeDefined();
  });

  it("returns relatedIndicators from other attributes in matching events", async () => {
    const attrs = [
      makeAttribute({
        id: "1",
        event_id: "100",
        type: "ip-src",
        value: "1.2.3.4",
        Event: {
          id: "100",
          info: "Campaign",
          threat_level_id: "1",
          Tag: [],
          Attribute: [
            { type: "domain", value: "evil.com" },
            { type: "md5", value: "abc123" },
          ],
        },
      }),
    ];
    mockFetch.mockResolvedValue(okResponse(makeMispResponse(attrs)));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.relatedIndicators).toBeDefined();
    expect(result.relatedIndicators!.length).toBeGreaterThan(0);
  });

  it("sets cacheTtlMs to 900000 (15 min)", async () => {
    mockFetch.mockResolvedValue(okResponse(makeMispResponse()));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.cacheTtlMs).toBe(900_000);
  });

  it("includes summary with event/attribute counts", async () => {
    const attrs = [
      makeAttribute({ id: "1", event_id: "100" }),
      makeAttribute({ id: "2", event_id: "100" }),
    ];
    mockFetch.mockResolvedValue(okResponse(makeMispResponse(attrs)));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.summary).toMatch(/MISP/i);
    expect(result.verdict.summary).toMatch(/event/i);
  });

  it("caps confidence at 0.9", async () => {
    // 10 events should yield confidence = min(10/5, 0.9) = 0.9
    const attrs = Array.from({ length: 10 }, (_, i) =>
      makeAttribute({
        id: String(i),
        event_id: String(200 + i),
        Event: { id: String(200 + i), info: `E${i}`, threat_level_id: "1", Tag: [] },
      }),
    );
    mockFetch.mockResolvedValue(okResponse(makeMispResponse(attrs)));

    const result = await source.enrich({ type: "ip", value: "1.2.3.4" });

    expect(result.verdict.confidence).toBeLessThanOrEqual(0.9);
  });
});

// ---- Health check tests ----

describe("healthCheck()", () => {
  it("calls GET {baseUrl}/servers/getVersion and returns healthy:true on 200", async () => {
    const source = createMispSource("test-api-key", "https://misp.example.com");
    mockFetch.mockResolvedValue(okResponse({ version: "2.4.170" }));

    const result = await source.healthCheck!();

    expect(result.healthy).toBe(true);
    const url = mockFetch.mock.calls[0][0] as string;
    expect(url).toBe("https://misp.example.com/servers/getVersion");
  });

  it("returns healthy:false on error", async () => {
    const source = createMispSource("test-api-key", "https://misp.example.com");
    mockFetch.mockResolvedValue(errorResponse(401));

    const result = await source.healthCheck!();

    expect(result.healthy).toBe(false);
  });
});

// ---- Error handling tests ----

describe("enrich() error handling", () => {
  let source: ReturnType<typeof createMispSource>;

  beforeEach(() => {
    source = createMispSource("test-api-key", "https://misp.example.com");
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
    expect(result.sourceId).toBe("misp");
    expect(result.verdict.classification).toBe("unknown");
  });
});

// ---- API response validation ----

describe("enrich() API response validation", () => {
  let source: ReturnType<typeof createMispSource>;

  beforeEach(() => {
    source = createMispSource("test-api-key", "https://misp.example.com");
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
