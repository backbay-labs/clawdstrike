import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  reportToAbuseIPDB,
  reportToMisp,
  mapIocTypeToMispAttrType,
} from "../threat-reporting";
import type {
  AbuseIPDBReportPayload,
  MispEventPayload,
  ReportResult,
} from "../threat-reporting";

describe("threat-reporting", () => {
  let fetchSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ---- AbuseIPDB ----

  describe("reportToAbuseIPDB", () => {
    const validPayload: AbuseIPDBReportPayload = {
      ip: "192.168.1.100",
      categories: [14, 22],
      comment: "Brute force SSH detected by ClawdStrike",
    };
    const apiKey = "test-abuseipdb-key";

    it("sends POST to AbuseIPDB v2 report endpoint with correct headers", async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          data: { ipAddress: "192.168.1.100", abuseConfidenceScore: 85 },
        }),
      });

      await reportToAbuseIPDB(validPayload, apiKey);

      expect(fetchSpy).toHaveBeenCalledOnce();
      const [url, options] = fetchSpy.mock.calls[0];
      expect(url).toBe("https://api.abuseipdb.com/api/v2/report");
      expect(options.method).toBe("POST");
      expect(options.headers.Key).toBe(apiKey);
      expect(options.headers.Accept).toBe("application/json");
      expect(options.headers["Content-Type"]).toBe("application/json");
    });

    it("sends body with ip, categories (comma-joined), and comment", async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          data: { ipAddress: "192.168.1.100", abuseConfidenceScore: 85 },
        }),
      });

      await reportToAbuseIPDB(validPayload, apiKey);

      const body = JSON.parse(fetchSpy.mock.calls[0][1].body);
      expect(body.ip).toBe("192.168.1.100");
      expect(body.categories).toBe("14,22");
      expect(body.comment).toBe("Brute force SSH detected by ClawdStrike");
    });

    it("returns success with data on 200 response", async () => {
      const responseData = {
        ipAddress: "192.168.1.100",
        abuseConfidenceScore: 85,
      };
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: responseData }),
      });

      const result = await reportToAbuseIPDB(validPayload, apiKey);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data).toEqual({ data: responseData });
      }
    });

    it("returns failure with error message on non-200 response", async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: false,
        status: 429,
        statusText: "Too Many Requests",
        json: async () => ({ errors: [{ detail: "Rate limit exceeded" }] }),
      });

      const result = await reportToAbuseIPDB(validPayload, apiKey);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBeTruthy();
      }
    });

    it("returns failure with error message on network error", async () => {
      fetchSpy.mockRejectedValueOnce(new Error("Network failure"));

      const result = await reportToAbuseIPDB(validPayload, apiKey);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toContain("Network failure");
      }
    });
  });

  // ---- MISP ----

  describe("reportToMisp", () => {
    const validPayload: MispEventPayload = {
      indicator: "192.168.1.100",
      iocType: "ip",
      eventInfo: "Malicious IP detected by ClawdStrike",
      severity: "high",
    };
    const apiKey = "test-misp-key";
    const baseUrl = "https://misp.example.org";

    it("sends POST to MISP events/add endpoint with correct headers", async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ Event: { id: "42", info: "test" } }),
      });

      await reportToMisp(validPayload, apiKey, baseUrl);

      expect(fetchSpy).toHaveBeenCalledOnce();
      const [url, options] = fetchSpy.mock.calls[0];
      expect(url).toBe("https://misp.example.org/events/add");
      expect(options.method).toBe("POST");
      expect(options.headers.Authorization).toBe(apiKey);
      expect(options.headers.Accept).toBe("application/json");
      expect(options.headers["Content-Type"]).toBe("application/json");
    });

    it("sends body with Event object containing info, distribution=0, and attributes", async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ Event: { id: "42", info: "test" } }),
      });

      await reportToMisp(validPayload, apiKey, baseUrl);

      const body = JSON.parse(fetchSpy.mock.calls[0][1].body);
      expect(body.Event).toBeDefined();
      expect(body.Event.info).toBe("Malicious IP detected by ClawdStrike");
      expect(body.Event.distribution).toBe(0);
      expect(body.Event.analysis).toBe(2);
      expect(body.Event.Attribute).toBeInstanceOf(Array);
      expect(body.Event.Attribute.length).toBe(1);
      expect(body.Event.Attribute[0].value).toBe("192.168.1.100");
      expect(body.Event.Attribute[0].type).toBe("ip-dst");
    });

    it("maps severity to MISP threat_level_id (high=1, medium=2, low=3)", async () => {
      const severityTests: Array<{
        severity: MispEventPayload["severity"];
        expectedThreatLevel: number;
      }> = [
        { severity: "critical", expectedThreatLevel: 1 },
        { severity: "high", expectedThreatLevel: 1 },
        { severity: "medium", expectedThreatLevel: 2 },
        { severity: "low", expectedThreatLevel: 3 },
      ];

      for (const test of severityTests) {
        fetchSpy.mockResolvedValueOnce({
          ok: true,
          json: async () => ({ Event: { id: "42", info: "test" } }),
        });

        await reportToMisp(
          { ...validPayload, severity: test.severity },
          apiKey,
          baseUrl,
        );

        const latestCall = fetchSpy.mock.calls[fetchSpy.mock.calls.length - 1]!;
        const body = JSON.parse(latestCall[1].body);
        expect(body.Event.threat_level_id).toBe(test.expectedThreatLevel);
      }
    });

    it("returns success with eventId on 200 response", async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          Event: { id: "42", info: "Malicious IP" },
        }),
      });

      const result = await reportToMisp(validPayload, apiKey, baseUrl);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.eventId).toBe("42");
      }
    });

    it("returns failure with error message on non-200 response", async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: false,
        status: 403,
        statusText: "Forbidden",
        json: async () => ({ message: "Invalid API key" }),
      });

      const result = await reportToMisp(validPayload, apiKey, baseUrl);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBeTruthy();
      }
    });

    it("returns failure with error message on network error", async () => {
      fetchSpy.mockRejectedValueOnce(new Error("Connection refused"));

      const result = await reportToMisp(validPayload, apiKey, baseUrl);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toContain("Connection refused");
      }
    });
  });

  // ---- IOC Type Mapping ----

  describe("mapIocTypeToMispAttrType", () => {
    it('maps "ip" to "ip-dst"', () => {
      expect(mapIocTypeToMispAttrType("ip")).toBe("ip-dst");
    });

    it('maps "domain" to "domain"', () => {
      expect(mapIocTypeToMispAttrType("domain")).toBe("domain");
    });

    it('maps "sha256" to "sha256"', () => {
      expect(mapIocTypeToMispAttrType("sha256")).toBe("sha256");
    });

    it('maps "sha1" to "sha1"', () => {
      expect(mapIocTypeToMispAttrType("sha1")).toBe("sha1");
    });

    it('maps "md5" to "md5"', () => {
      expect(mapIocTypeToMispAttrType("md5")).toBe("md5");
    });

    it('maps "url" to "url"', () => {
      expect(mapIocTypeToMispAttrType("url")).toBe("url");
    });

    it('maps "email" to "email-src"', () => {
      expect(mapIocTypeToMispAttrType("email")).toBe("email-src");
    });

    it('maps unknown types to "text"', () => {
      expect(mapIocTypeToMispAttrType("unknown-type")).toBe("text");
      expect(mapIocTypeToMispAttrType("registry")).toBe("text");
    });
  });
});
