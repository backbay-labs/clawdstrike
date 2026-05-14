import type {
  PluginManifest,
  ThreatIntelSource,
  Indicator,
  EnrichmentResult,
  ThreatVerdict,
} from "@clawdstrike/plugin-sdk";
import { sanitizeErrorMessage } from "./sanitize-error";

const SHODAN_API_BASE = "https://api.shodan.io";
const CACHE_TTL_MS = 3_600_000; // 1 hour
const RATE_LIMIT_MAX_PER_MINUTE = 60; // 1 req/sec

export const SHODAN_MANIFEST: PluginManifest = {
  id: "clawdstrike.shodan",
  name: "shodan-intel",
  displayName: "Shodan",
  description:
    "Shodan threat intelligence source. Enriches IP addresses and domains with open ports, services, vulnerabilities, and geolocation via the Shodan API.",
  version: "1.0.0",
  publisher: "clawdstrike",
  categories: ["intel"],
  trust: "internal",
  activationEvents: ["onStartup"],
  main: "./shodan-plugin.ts",
  contributions: {
    threatIntelSources: [
      {
        id: "shodan",
        name: "Shodan",
        description:
          "Internet-connected device search engine",
        entrypoint: "./shodan-plugin.ts",
      },
    ],
  },
  requiredSecrets: [
    {
      key: "api_key",
      label: "Shodan API Key",
      description: "API key from account.shodan.io",
    },
  ],
};

interface ShodanHostResponse {
  ip_str: string;
  ports?: number[];
  vulns?: string[];
  org?: string;
  isp?: string;
  country_name?: string;
  city?: string;
  os?: string;
  [key: string]: unknown;
}

function isPrivateOrReservedIP(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255))
    return false;
  return (
    parts[0] === 10 ||
    parts[0] === 127 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 169 && parts[1] === 254) ||
    parts[0] >= 224
  );
}

function normalizeVerdict(data: ShodanHostResponse): ThreatVerdict {
  const ports = data.ports ?? [];
  const vulns = data.vulns ?? [];
  const vulnCount = vulns.length;
  const portCount = ports.length;

  const vulnWord = vulnCount === 1 ? "vulnerability" : "vulnerabilities";
  const summary = `${portCount} open ports, ${vulnCount} known ${vulnWord}`;

  if (vulnCount > 0) {
    // Confidence scales with vuln count: 1-5 = 0.5, 6+ = 0.7
    const confidence = vulnCount >= 6 ? 0.7 : 0.5;
    return {
      classification: "suspicious",
      confidence,
      summary,
    };
  }

  return {
    classification: "benign",
    confidence: 0.3,
    summary,
  };
}

function errorResult(summaryText: string): EnrichmentResult {
  return {
    sourceId: "shodan",
    sourceName: "Shodan",
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

export function createShodanSource(apiKey: string): ThreatIntelSource {
  return {
    id: "shodan",
    name: "Shodan",
    supportedIndicatorTypes: ["ip", "domain"],
    rateLimit: { maxPerMinute: RATE_LIMIT_MAX_PER_MINUTE },

    async enrich(indicator: Indicator): Promise<EnrichmentResult> {
      if (indicator.type === "ip" && isPrivateOrReservedIP(indicator.value)) {
        return errorResult(
          "Refused to query private or reserved IP address",
        );
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 30_000);
      try {
        let targetIp: string;
        let relatedIndicators: Indicator[] | undefined;

        if (indicator.type === "domain") {
          const dnsUrl = `${SHODAN_API_BASE}/dns/resolve?hostnames=${indicator.value}&key=${apiKey}`;
          const dnsResponse = await fetch(dnsUrl, {
            method: "GET",
            headers: { Accept: "application/json" },
            signal: controller.signal,
          });

          if (!dnsResponse.ok) {
            return errorResult(
              `Shodan DNS resolution failed: HTTP ${dnsResponse.status}`,
            );
          }

          const dnsData = (await dnsResponse.json()) as Record<string, string | null>;
          const resolvedIp = dnsData[indicator.value];
          if (!resolvedIp) {
            return errorResult(
              `No DNS resolution for domain: ${indicator.value}`,
            );
          }

          if (isPrivateOrReservedIP(resolvedIp)) {
            return errorResult(
              "Refused to query private or reserved IP address (resolved from domain)",
            );
          }

          targetIp = resolvedIp;
          relatedIndicators = [{ type: "ip", value: resolvedIp }];
        } else if (indicator.type === "ip") {
          targetIp = indicator.value;
        } else {
          return errorResult(
            `Unsupported indicator type: ${indicator.type}. Shodan supports IP and domain indicators.`,
          );
        }

        const hostUrl = `${SHODAN_API_BASE}/shodan/host/${targetIp}?key=${apiKey}`;
        const response = await fetch(hostUrl, {
          method: "GET",
          headers: { Accept: "application/json" },
          signal: controller.signal,
        });

        if (!response.ok) {
          if (response.status === 404) {
            return errorResult("No data found for this IP");
          }
          if (response.status === 401) {
            return errorResult("Shodan API key unauthorized or invalid");
          }
          if (response.status === 429) {
            return errorResult("Shodan rate limit exceeded");
          }
          return errorResult(
            `Shodan API error: HTTP ${response.status}`,
          );
        }

        const data = (await response.json()) as ShodanHostResponse;

        if (!data || typeof data !== "object" || !("ip_str" in data)) {
          return errorResult("Unexpected API response format");
        }

        const verdict = normalizeVerdict(data);

        return {
          sourceId: "shodan",
          sourceName: "Shodan",
          verdict,
          rawData: {
            ports: data.ports ?? [],
            vulns: data.vulns ?? [],
            org: data.org ?? "",
            isp: data.isp ?? "",
            country_name: data.country_name ?? "",
            city: data.city ?? "",
            os: data.os ?? "",
          },
          relatedIndicators,
          permalink: `https://www.shodan.io/host/${targetIp}`,
          fetchedAt: Date.now(),
          cacheTtlMs: CACHE_TTL_MS,
        };
      } catch (err: unknown) {
        if (
          err instanceof DOMException &&
          err.name === "AbortError"
        ) {
          return errorResult("Shodan request timeout");
        }
        if (err instanceof TypeError && /fetch/i.test(err.message)) {
          return errorResult("Network error contacting Shodan");
        }
        return errorResult(
          `Shodan error: ${sanitizeErrorMessage(err)}`,
        );
      } finally {
        clearTimeout(timeout);
      }
    },

    async healthCheck(): Promise<{ healthy: boolean; message?: string }> {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      try {
        const response = await fetch(
          `${SHODAN_API_BASE}/api-info?key=${apiKey}`,
          {
            method: "GET",
            headers: { Accept: "application/json" },
            signal: controller.signal,
          },
        );
        if (response.ok) {
          return { healthy: true };
        }
        return {
          healthy: false,
          message: `Shodan health check failed: HTTP ${response.status}`,
        };
      } catch (err: unknown) {
        return {
          healthy: false,
          message: `Shodan health check error: ${sanitizeErrorMessage(err)}`,
        };
      } finally {
        clearTimeout(timeout);
      }
    },
  };
}
