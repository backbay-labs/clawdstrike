import type {
  PluginManifest,
  ThreatIntelSource,
  Indicator,
  EnrichmentResult,
  ThreatVerdict,
} from "@clawdstrike/plugin-sdk";
import { sanitizeErrorMessage } from "./sanitize-error";

const VT_API_BASE = "https://www.virustotal.com/api/v3";
const VT_GUI_BASE = "https://www.virustotal.com/gui";
const CACHE_TTL_MS = 300_000; // 5 minutes
const RATE_LIMIT_MAX_PER_MINUTE = 4; // VT free tier

export const VIRUSTOTAL_MANIFEST: PluginManifest = {
  id: "clawdstrike.virustotal",
  name: "virustotal",
  displayName: "VirusTotal",
  description:
    "VirusTotal threat intelligence source. Enriches file hashes, domains, IPs, and URLs via the VirusTotal v3 API.",
  version: "1.0.0",
  publisher: "clawdstrike",
  categories: ["intel"],
  trust: "internal",
  activationEvents: ["onStartup"],
  main: "./virustotal-plugin.ts",
  contributions: {
    threatIntelSources: [
      {
        id: "virustotal",
        name: "VirusTotal",
        description:
          "File hash, domain, IP, and URL reputation via VirusTotal v3 API",
        entrypoint: "./virustotal-plugin.ts",
      },
    ],
  },
};

function base64UrlEncode(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function buildApiUrl(indicator: Indicator): string {
  switch (indicator.type) {
    case "hash":
      return `${VT_API_BASE}/files/${indicator.value}`;
    case "domain":
      return `${VT_API_BASE}/domains/${indicator.value}`;
    case "ip":
      return `${VT_API_BASE}/ip_addresses/${indicator.value}`;
    case "url":
      return `${VT_API_BASE}/urls/${base64UrlEncode(indicator.value)}`;
    default:
      return "";
  }
}

function buildPermalink(indicator: Indicator): string {
  switch (indicator.type) {
    case "hash":
      return `${VT_GUI_BASE}/file/${indicator.value}`;
    case "domain":
      return `${VT_GUI_BASE}/domain/${indicator.value}`;
    case "ip":
      return `${VT_GUI_BASE}/ip-address/${indicator.value}`;
    case "url":
      return `${VT_GUI_BASE}/url/${indicator.value}`;
    default:
      return "";
  }
}

interface VtAnalysisStats {
  malicious: number;
  suspicious: number;
  undetected: number;
  harmless: number;
  timeout: number;
  [key: string]: number;
}

function normalizeVerdict(stats: VtAnalysisStats): ThreatVerdict {
  const total =
    stats.malicious +
    stats.suspicious +
    stats.undetected +
    stats.harmless +
    stats.timeout;

  if (total === 0) {
    return {
      classification: "unknown",
      confidence: 0,
      summary: "No analysis data available",
    };
  }

  const summary = `${stats.malicious}/${total} engines detected as malicious`;

  if (stats.malicious > 5) {
    return {
      classification: "malicious",
      confidence: stats.malicious / total,
      summary,
    };
  }

  if (stats.malicious > 0) {
    return {
      classification: "suspicious",
      confidence: 0.3 + (stats.malicious / total) * 0.4,
      summary,
    };
  }

  return {
    classification: "benign",
    confidence: total > 0 ? stats.harmless / total : 0,
    summary,
  };
}

function errorResult(summaryText: string): EnrichmentResult {
  return {
    sourceId: "virustotal",
    sourceName: "VirusTotal",
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

export function createVirusTotalSource(apiKey: string): ThreatIntelSource {
  return {
    id: "virustotal",
    name: "VirusTotal",
    supportedIndicatorTypes: ["hash", "ip", "domain", "url"],
    rateLimit: { maxPerMinute: RATE_LIMIT_MAX_PER_MINUTE },

    async enrich(indicator: Indicator): Promise<EnrichmentResult> {
      const url = buildApiUrl(indicator);
      if (!url) {
        return errorResult(`Unsupported indicator type: ${indicator.type}`);
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 30_000);
      try {
        const response = await fetch(url, {
          method: "GET",
          headers: {
            "x-apikey": apiKey,
            Accept: "application/json",
          },
          signal: controller.signal,
        });

        if (!response.ok) {
          if (response.status === 403) {
            return errorResult("VirusTotal API key forbidden or invalid");
          }
          if (response.status === 429) {
            return errorResult("VirusTotal rate limit exceeded");
          }
          return errorResult(
            `VirusTotal API error: HTTP ${response.status}`,
          );
        }

        const data = (await response.json()) as {
          data?: {
            attributes?: {
              last_analysis_stats?: VtAnalysisStats;
              [key: string]: unknown;
            };
          };
        };

        if (!data || typeof data !== "object" || !("data" in data)) {
          return errorResult("Unexpected API response format");
        }

        const stats = data?.data?.attributes?.last_analysis_stats;
        if (!stats) {
          return errorResult("VirusTotal response missing analysis stats");
        }

        const verdict = normalizeVerdict(stats);

        return {
          sourceId: "virustotal",
          sourceName: "VirusTotal",
          verdict,
          rawData: data as unknown as Record<string, unknown>,
          permalink: buildPermalink(indicator),
          fetchedAt: Date.now(),
          cacheTtlMs: CACHE_TTL_MS,
        };
      } catch (err: unknown) {
        if (
          err instanceof DOMException &&
          err.name === "AbortError"
        ) {
          return errorResult("VirusTotal request timeout");
        }
        if (err instanceof TypeError && /fetch/i.test(err.message)) {
          return errorResult("Network error contacting VirusTotal");
        }
        return errorResult(
          `VirusTotal error: ${sanitizeErrorMessage(err)}`,
        );
      } finally {
        clearTimeout(timeout);
      }
    },

    async healthCheck(): Promise<{ healthy: boolean; message?: string }> {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      try {
        const response = await fetch(`${VT_API_BASE}/users/me`, {
          method: "GET",
          headers: {
            "x-apikey": apiKey,
            Accept: "application/json",
          },
          signal: controller.signal,
        });
        if (response.ok) {
          return { healthy: true };
        }
        return {
          healthy: false,
          message: `VirusTotal health check failed: HTTP ${response.status}`,
        };
      } catch (err: unknown) {
        return {
          healthy: false,
          message: `VirusTotal health check error: ${sanitizeErrorMessage(err)}`,
        };
      } finally {
        clearTimeout(timeout);
      }
    },
  };
}
