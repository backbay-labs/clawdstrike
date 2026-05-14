import type {
  PluginManifest,
  ThreatIntelSource,
  Indicator,
  EnrichmentResult,
  ThreatVerdict,
} from "@clawdstrike/plugin-sdk";
import { sanitizeErrorMessage } from "./sanitize-error";

const ABUSEIPDB_API_BASE = "https://api.abuseipdb.com/api/v2";
const CACHE_TTL_MS = 1_800_000; // 30 minutes
const RATE_LIMIT_MAX_PER_MINUTE = 17; // ~1000/day conservative

export const ABUSEIPDB_MANIFEST: PluginManifest = {
  id: "clawdstrike.abuseipdb",
  name: "abuseipdb-intel",
  displayName: "AbuseIPDB",
  description:
    "AbuseIPDB threat intelligence source. Enriches IP addresses with abuse confidence scores, report counts, and ISP/geolocation data via the AbuseIPDB v2 API.",
  version: "1.0.0",
  publisher: "clawdstrike",
  categories: ["intel"],
  trust: "internal",
  activationEvents: ["onStartup"],
  main: "./abuseipdb-plugin.ts",
  contributions: {
    threatIntelSources: [
      {
        id: "abuseipdb",
        name: "AbuseIPDB",
        description:
          "IP address abuse reporting and checking",
        entrypoint: "./abuseipdb-plugin.ts",
      },
    ],
  },
  requiredSecrets: [
    {
      key: "api_key",
      label: "AbuseIPDB API Key",
      description: "API key from abuseipdb.com",
    },
  ],
};

interface AbuseIPDBCheckData {
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
  [key: string]: unknown;
}

function normalizeVerdict(data: AbuseIPDBCheckData): ThreatVerdict {
  const score = data.abuseConfidenceScore;
  const totalReports = data.totalReports;

  const summary = `Abuse confidence: ${score}%, ${totalReports} reports in last 90 days`;

  if (score === 0 && totalReports === 0) {
    return {
      classification: "unknown",
      confidence: 0,
      summary,
    };
  }

  if (score >= 76) {
    return {
      classification: "malicious",
      confidence: score / 100,
      summary,
    };
  }

  if (score >= 26) {
    return {
      classification: "suspicious",
      confidence: score / 100,
      summary,
    };
  }

  return {
    classification: "benign",
    confidence: score / 100,
    summary,
  };
}

function errorResult(summaryText: string): EnrichmentResult {
  return {
    sourceId: "abuseipdb",
    sourceName: "AbuseIPDB",
    verdict: {
      classification: "unknown",
      confidence: 0,
      summary: summaryText,
    },
    rawData: {},
    fetchedAt: Date.now(),
    cacheTtlMs: CACHE_TTL_MS,
  };
}

export function createAbuseIPDBSource(apiKey: string): ThreatIntelSource {
  return {
    id: "abuseipdb",
    name: "AbuseIPDB",
    supportedIndicatorTypes: ["ip"],
    rateLimit: { maxPerMinute: RATE_LIMIT_MAX_PER_MINUTE },

    async enrich(indicator: Indicator): Promise<EnrichmentResult> {
      if (indicator.type !== "ip") {
        return errorResult(
          `Unsupported indicator type: ${indicator.type}. AbuseIPDB only supports IP indicators.`,
        );
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 30_000);
      try {
        const url = `${ABUSEIPDB_API_BASE}/check?ipAddress=${indicator.value}&maxAgeInDays=90&verbose`;
        const response = await fetch(url, {
          method: "GET",
          headers: {
            Key: apiKey,
            Accept: "application/json",
          },
          signal: controller.signal,
        });

        if (!response.ok) {
          if (response.status === 401) {
            return errorResult("AbuseIPDB API key unauthorized or invalid");
          }
          if (response.status === 429) {
            return errorResult("AbuseIPDB rate limit exceeded");
          }
          return errorResult(
            `AbuseIPDB API error: HTTP ${response.status}`,
          );
        }

        const responseData = (await response.json()) as {
          data: AbuseIPDBCheckData;
        };

        if (!responseData || typeof responseData !== "object" || !("data" in responseData) || typeof responseData.data?.abuseConfidenceScore !== "number") {
          return errorResult("Unexpected API response format");
        }

        const data = responseData.data;
        const verdict = normalizeVerdict(data);

        return {
          sourceId: "abuseipdb",
          sourceName: "AbuseIPDB",
          verdict,
          rawData: {
            abuseConfidenceScore: data.abuseConfidenceScore,
            totalReports: data.totalReports,
            lastReportedAt: data.lastReportedAt,
            usageType: data.usageType,
            isp: data.isp,
            countryCode: data.countryCode,
            domain: data.domain,
            isWhitelisted: data.isWhitelisted,
          },
          permalink: `https://www.abuseipdb.com/check/${indicator.value}`,
          fetchedAt: Date.now(),
          cacheTtlMs: CACHE_TTL_MS,
        };
      } catch (err: unknown) {
        if (
          err instanceof DOMException &&
          err.name === "AbortError"
        ) {
          return errorResult("AbuseIPDB request timeout");
        }
        if (err instanceof TypeError && /fetch/i.test(err.message)) {
          return errorResult("Network error contacting AbuseIPDB");
        }
        return errorResult(
          `AbuseIPDB error: ${sanitizeErrorMessage(err)}`,
        );
      } finally {
        clearTimeout(timeout);
      }
    },

    async healthCheck(): Promise<{ healthy: boolean; message?: string }> {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      try {
        // Check a well-known IP (Google DNS) with short window
        const response = await fetch(
          `${ABUSEIPDB_API_BASE}/check?ipAddress=8.8.8.8&maxAgeInDays=1&verbose`,
          {
            method: "GET",
            headers: {
              Key: apiKey,
              Accept: "application/json",
            },
            signal: controller.signal,
          },
        );
        if (response.ok) {
          return { healthy: true };
        }
        return {
          healthy: false,
          message: `AbuseIPDB health check failed: HTTP ${response.status}`,
        };
      } catch (err: unknown) {
        return {
          healthy: false,
          message: `AbuseIPDB health check error: ${sanitizeErrorMessage(err)}`,
        };
      } finally {
        clearTimeout(timeout);
      }
    },
  };
}
