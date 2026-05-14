import type {
  PluginManifest,
  ThreatIntelSource,
  Indicator,
  EnrichmentResult,
  ThreatVerdict,
} from "@clawdstrike/plugin-sdk";
import { sanitizeErrorMessage } from "./sanitize-error";

const OTX_API_BASE = "https://otx.alienvault.com/api/v1";
const CACHE_TTL_MS = 1_800_000; // 30 minutes
const RATE_LIMIT_MAX_PER_MINUTE = 100; // OTX generous free tier

export const OTX_MANIFEST: PluginManifest & {
  requiredSecrets: Array<{ key: string; label: string; description: string }>;
} = {
  id: "clawdstrike.otx",
  name: "otx-intel",
  displayName: "AlienVault OTX",
  description:
    "AlienVault OTX threat intelligence source. Enriches IPs, domains, URLs, and file hashes via the Open Threat Exchange community intelligence platform.",
  version: "1.0.0",
  publisher: "clawdstrike",
  categories: ["intel"],
  trust: "internal",
  activationEvents: ["onStartup"],
  main: "./otx-plugin.ts",
  contributions: {
    threatIntelSources: [
      {
        id: "otx",
        name: "AlienVault OTX",
        description:
          "Open Threat Exchange community intelligence",
        entrypoint: "./otx-plugin.ts",
      },
    ],
  },
  requiredSecrets: [
    {
      key: "api_key",
      label: "OTX API Key",
      description: "API key from otx.alienvault.com",
    },
  ],
};

function otxTypePath(type: string): string {
  switch (type) {
    case "ip":
      return "IPv4";
    case "domain":
      return "domain";
    case "url":
      return "url";
    case "hash":
      return "file";
    default:
      return "";
  }
}

function otxPermalinkType(type: string): string {
  switch (type) {
    case "ip":
      return "IPv4";
    case "domain":
      return "domain";
    case "url":
      return "url";
    case "hash":
      return "file";
    default:
      return type;
  }
}

interface OtxGeneralResponse {
  pulse_info?: {
    count: number;
    pulses?: Array<{
      id: string;
      name: string;
      references?: string[];
      indicator_type_counts?: Record<string, number>;
    }>;
  };
  reputation?: number;
  country_name?: string;
  asn?: string;
  type_title?: string;
}

function normalizeVerdict(pulseCount: number): ThreatVerdict {
  if (pulseCount > 5) {
    return {
      classification: "malicious",
      confidence: Math.min(pulseCount / 10, 1.0),
      summary: `Referenced in ${pulseCount} OTX pulses`,
    };
  }

  if (pulseCount >= 1) {
    return {
      classification: "suspicious",
      confidence: Math.min(pulseCount / 10, 1.0),
      summary: `Referenced in ${pulseCount} OTX pulses`,
    };
  }

  return {
    classification: "benign",
    confidence: 0.5,
    summary: "No threat pulses found",
  };
}

function extractRelatedIndicators(
  pulses: OtxGeneralResponse["pulse_info"],
): EnrichmentResult["relatedIndicators"] {
  if (!pulses?.pulses) return undefined;

  const related: EnrichmentResult["relatedIndicators"] = [];
  for (const pulse of pulses.pulses) {
    if (!pulse.references) continue;
    for (const ref of pulse.references) {
      if (related.length >= 10) break;
      // References are typically URLs
      if (ref.startsWith("http://") || ref.startsWith("https://")) {
        related.push({ type: "url", value: ref });
      }
    }
    if (related.length >= 10) break;
  }

  return related.length > 0 ? related : undefined;
}

function errorResult(summaryText: string): EnrichmentResult {
  return {
    sourceId: "otx",
    sourceName: "AlienVault OTX",
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

export function createOtxSource(apiKey: string): ThreatIntelSource {
  return {
    id: "otx",
    name: "AlienVault OTX",
    supportedIndicatorTypes: ["ip", "domain", "url", "hash"],
    rateLimit: { maxPerMinute: RATE_LIMIT_MAX_PER_MINUTE },

    async enrich(indicator: Indicator): Promise<EnrichmentResult> {
      const typePath = otxTypePath(indicator.type);
      if (!typePath) {
        return errorResult(`Unsupported indicator type: ${indicator.type}`);
      }

      const url = `${OTX_API_BASE}/indicators/${typePath}/${indicator.value}/general`;

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 30_000);
      try {
        const response = await fetch(url, {
          method: "GET",
          headers: {
            "X-OTX-API-KEY": apiKey,
            Accept: "application/json",
          },
          signal: controller.signal,
        });

        if (!response.ok) {
          if (response.status === 403) {
            return errorResult("OTX API key forbidden or invalid");
          }
          if (response.status === 429) {
            return errorResult("OTX rate limit exceeded");
          }
          return errorResult(`OTX API error: HTTP ${response.status}`);
        }

        const data = (await response.json()) as OtxGeneralResponse;

        if (!data || typeof data !== "object") {
          return errorResult("Unexpected API response format");
        }

        const pulseCount = data.pulse_info?.count ?? 0;
        const verdict = normalizeVerdict(pulseCount);
        const relatedIndicators = extractRelatedIndicators(data.pulse_info);
        const permalinkType = otxPermalinkType(indicator.type);

        return {
          sourceId: "otx",
          sourceName: "AlienVault OTX",
          verdict,
          rawData: {
            pulseCount,
            reputation: data.reputation ?? 0,
            country: data.country_name ?? null,
            asn: data.asn ?? null,
            typeTitle: data.type_title ?? null,
          },
          relatedIndicators,
          permalink: `https://otx.alienvault.com/indicator/${permalinkType}/${indicator.value}`,
          fetchedAt: Date.now(),
          cacheTtlMs: CACHE_TTL_MS,
        };
      } catch (err: unknown) {
        if (err instanceof DOMException && err.name === "AbortError") {
          return errorResult("OTX request timeout");
        }
        if (err instanceof TypeError && /fetch/i.test(err.message)) {
          return errorResult("Network error contacting OTX");
        }
        return errorResult(
          `OTX error: ${sanitizeErrorMessage(err)}`,
        );
      } finally {
        clearTimeout(timeout);
      }
    },

    async healthCheck(): Promise<{ healthy: boolean; message?: string }> {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      try {
        const response = await fetch(`${OTX_API_BASE}/user/me`, {
          method: "GET",
          headers: {
            "X-OTX-API-KEY": apiKey,
            Accept: "application/json",
          },
          signal: controller.signal,
        });
        if (response.ok) {
          return { healthy: true };
        }
        return {
          healthy: false,
          message: `OTX health check failed: HTTP ${response.status}`,
        };
      } catch (err: unknown) {
        return {
          healthy: false,
          message: `OTX health check error: ${sanitizeErrorMessage(err)}`,
        };
      } finally {
        clearTimeout(timeout);
      }
    },
  };
}
