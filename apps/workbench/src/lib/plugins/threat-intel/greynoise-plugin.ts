import type {
  PluginManifest,
  ThreatIntelSource,
  Indicator,
  EnrichmentResult,
  ThreatVerdict,
} from "@clawdstrike/plugin-sdk";
import { sanitizeErrorMessage } from "./sanitize-error";

const GN_API_BASE = "https://api.greynoise.io";
const GN_VIZ_BASE = "https://viz.greynoise.io";
const CACHE_TTL_MS = 600_000; // 10 minutes
const RATE_LIMIT_MAX_PER_MINUTE = 10; // Community tier

export const GREYNOISE_MANIFEST: PluginManifest = {
  id: "clawdstrike.greynoise",
  name: "greynoise",
  displayName: "GreyNoise",
  description:
    "GreyNoise threat intelligence source. Enriches IP addresses via the GreyNoise Community v3 API with noise and RIOT classification.",
  version: "1.0.0",
  publisher: "clawdstrike",
  categories: ["intel"],
  trust: "internal",
  activationEvents: ["onStartup"],
  main: "./greynoise-plugin.ts",
  contributions: {
    threatIntelSources: [
      {
        id: "greynoise",
        name: "GreyNoise",
        description:
          "IP noise classification and RIOT status via GreyNoise Community v3 API",
        entrypoint: "./greynoise-plugin.ts",
      },
    ],
  },
};

interface GnCommunityResponse {
  ip: string;
  noise: boolean;
  riot: boolean;
  classification: string;
  name: string;
  link?: string;
  last_seen: string;
  message: string;
}

function normalizeVerdict(data: GnCommunityResponse): ThreatVerdict {
  let summary = `GreyNoise: ${data.classification}`;
  if (data.riot) {
    summary += " (RIOT - Rule It Out)";
  }
  if (data.name && data.name !== "Unknown") {
    summary += ` - ${data.name}`;
  }

  switch (data.classification) {
    case "malicious":
      return { classification: "malicious", confidence: 0.85, summary };
    case "benign":
      return { classification: "benign", confidence: data.riot ? 0.95 : 0.9, summary };
    case "unknown":
    default:
      return { classification: "unknown", confidence: 0.5, summary };
  }
}

function errorResult(summaryText: string): EnrichmentResult {
  return {
    sourceId: "greynoise",
    sourceName: "GreyNoise",
    verdict: { classification: "unknown", confidence: 0, summary: summaryText },
    rawData: {},
    fetchedAt: Date.now(),
    cacheTtlMs: CACHE_TTL_MS,
  };
}

export function createGreyNoiseSource(apiKey: string): ThreatIntelSource {
  return {
    id: "greynoise",
    name: "GreyNoise",
    supportedIndicatorTypes: ["ip"],
    rateLimit: { maxPerMinute: RATE_LIMIT_MAX_PER_MINUTE },

    async enrich(indicator: Indicator): Promise<EnrichmentResult> {
      if (indicator.type !== "ip") {
        return errorResult(
          `Unsupported indicator type: ${indicator.type}. GreyNoise only supports IP indicators.`,
        );
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 30_000);
      try {
        const url = `${GN_API_BASE}/v3/community/${indicator.value}`;
        const response = await fetch(url, {
          method: "GET",
          headers: { key: apiKey, Accept: "application/json" },
          signal: controller.signal,
        });

        if (!response.ok) {
          if (response.status === 401) {
            return errorResult("GreyNoise API key unauthorized or invalid");
          }
          if (response.status === 429) {
            return errorResult("GreyNoise rate limit exceeded");
          }
          return errorResult(`GreyNoise API error: HTTP ${response.status}`);
        }

        const data = (await response.json()) as GnCommunityResponse;

        if (!data || typeof data !== "object" || !("ip" in data) || !("classification" in data)) {
          return errorResult("Unexpected API response format");
        }

        return {
          sourceId: "greynoise",
          sourceName: "GreyNoise",
          verdict: normalizeVerdict(data),
          rawData: {
            noise: data.noise,
            riot: data.riot,
            classification: data.classification,
            name: data.name,
            last_seen: data.last_seen,
          },
          permalink: data.link || `${GN_VIZ_BASE}/ip/${indicator.value}`,
          fetchedAt: Date.now(),
          cacheTtlMs: CACHE_TTL_MS,
        };
      } catch (err: unknown) {
        if (err instanceof DOMException && err.name === "AbortError") {
          return errorResult("GreyNoise request timeout");
        }
        if (err instanceof TypeError && /fetch/i.test(err.message)) {
          return errorResult("Network error contacting GreyNoise");
        }
        return errorResult(`GreyNoise error: ${sanitizeErrorMessage(err)}`);
      } finally {
        clearTimeout(timeout);
      }
    },

    async healthCheck(): Promise<{ healthy: boolean; message?: string }> {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      try {
        // Google DNS (8.8.8.8) as a known benign IP for health checks
        const response = await fetch(
          `${GN_API_BASE}/v3/community/8.8.8.8`,
          {
            method: "GET",
            headers: { key: apiKey, Accept: "application/json" },
            signal: controller.signal,
          },
        );
        if (response.ok) {
          return { healthy: true };
        }
        return {
          healthy: false,
          message: `GreyNoise health check failed: HTTP ${response.status}`,
        };
      } catch (err: unknown) {
        return {
          healthy: false,
          message: `GreyNoise health check error: ${sanitizeErrorMessage(err)}`,
        };
      } finally {
        clearTimeout(timeout);
      }
    },
  };
}
