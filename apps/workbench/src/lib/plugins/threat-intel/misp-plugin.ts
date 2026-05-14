import type {
  PluginManifest,
  ThreatIntelSource,
  Indicator,
  EnrichmentResult,
  ThreatVerdict,
} from "@clawdstrike/plugin-sdk";
import { sanitizeErrorMessage } from "./sanitize-error";

const CACHE_TTL_MS = 900_000; // 15 minutes
const RATE_LIMIT_MAX_PER_MINUTE = 30; // Conservative for self-hosted

export const MISP_MANIFEST: PluginManifest & {
  requiredSecrets: Array<{ key: string; label: string; description: string }>;
} = {
  id: "clawdstrike.misp",
  name: "misp-intel",
  displayName: "MISP",
  description:
    "MISP threat intelligence source. Enriches all indicator types by searching a configurable MISP instance's attribute database. Extracts MITRE ATT&CK techniques from Galaxy tags.",
  version: "1.0.0",
  publisher: "clawdstrike",
  categories: ["intel"],
  trust: "internal",
  activationEvents: ["onStartup"],
  main: "./misp-plugin.ts",
  contributions: {
    threatIntelSources: [
      {
        id: "misp",
        name: "MISP",
        description:
          "Malware Information Sharing Platform (self-hosted)",
        entrypoint: "./misp-plugin.ts",
      },
    ],
  },
  requiredSecrets: [
    {
      key: "api_key",
      label: "MISP API Key",
      description: "Authentication key from your MISP instance",
    },
    {
      key: "base_url",
      label: "MISP Instance URL",
      description:
        "Base URL of your MISP instance (e.g., https://misp.example.com)",
    },
  ],
};

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
    Tag?: Array<{ name: string }>;
    Attribute?: Array<{ type: string; value: string }>;
  };
}

interface MispSearchResponse {
  response?: {
    Attribute?: MispAttribute[];
  };
}

function normalizeBaseUrl(url: string): string {
  return url.replace(/\/+$/, "");
}

/** MITRE ATT&CK technique ID regex. Matches T1234 or T1234.001 format. */
const MITRE_TECHNIQUE_RE = /T\d{4}(?:\.\d{3})?/;

/**
 * Extract MITRE ATT&CK technique IDs from MISP Galaxy tags.
 * Galaxy tags follow the pattern: misp-galaxy:mitre-attack-pattern="Name - T1234"
 */
function extractMitreTechniques(
  attributes: MispAttribute[],
): EnrichmentResult["mitreTechniques"] {
  const seen = new Set<string>();
  const techniques: NonNullable<EnrichmentResult["mitreTechniques"]> = [];

  for (const attr of attributes) {
    if (!attr.Event?.Tag) continue;
    for (const tag of attr.Event.Tag) {
      if (!tag.name.includes("mitre-attack")) continue;
      const match = MITRE_TECHNIQUE_RE.exec(tag.name);
      if (match && !seen.has(match[0])) {
        seen.add(match[0]);

        // Extract technique name from the tag (between quotes before the dash-T)
        let techniqueName = match[0];
        const nameMatch = /"([^"]+)"/.exec(tag.name);
        if (nameMatch) {
          // Format: "Name - T1234", extract the name portion
          const parts = nameMatch[1].split(" - ");
          if (parts.length > 1) {
            techniqueName = parts.slice(0, -1).join(" - ");
          } else {
            techniqueName = nameMatch[1];
          }
        }

        // Extract tactic from the galaxy namespace if present
        const tactic = tag.name.includes("mitre-attack-pattern")
          ? "attack-pattern"
          : "unknown";

        techniques.push({
          techniqueId: match[0],
          techniqueName,
          tactic,
        });
      }
    }
  }

  return techniques.length > 0 ? techniques : undefined;
}

function countDistinctEvents(attributes: MispAttribute[]): number {
  const eventIds = new Set<string>();
  for (const attr of attributes) {
    eventIds.add(attr.event_id);
  }
  return eventIds.size;
}

function highestThreatLevel(attributes: MispAttribute[]): string {
  let highest = "4"; // undefined in MISP
  for (const attr of attributes) {
    const level = attr.Event?.threat_level_id ?? "4";
    // MISP threat levels: 1=High, 2=Medium, 3=Low, 4=Undefined
    if (parseInt(level, 10) < parseInt(highest, 10)) {
      highest = level;
    }
  }
  return highest;
}

function collectCategories(attributes: MispAttribute[]): string[] {
  const categories = new Set<string>();
  for (const attr of attributes) {
    if (attr.category) {
      categories.add(attr.category);
    }
  }
  return Array.from(categories);
}

function mispTypeToIndicatorType(mispType: string): string | null {
  if (mispType.includes("ip") || mispType === "ip-src" || mispType === "ip-dst") {
    return "ip";
  }
  if (mispType === "domain" || mispType === "hostname") {
    return "domain";
  }
  if (mispType === "url" || mispType === "uri") {
    return "url";
  }
  if (
    mispType === "md5" ||
    mispType === "sha1" ||
    mispType === "sha256" ||
    mispType === "filename|md5" ||
    mispType === "filename|sha1" ||
    mispType === "filename|sha256"
  ) {
    return "hash";
  }
  if (mispType === "email-src" || mispType === "email-dst" || mispType === "email") {
    return "email";
  }
  return null;
}

function extractRelatedIndicators(
  attributes: MispAttribute[],
  queryValue: string,
): EnrichmentResult["relatedIndicators"] {
  const related: NonNullable<EnrichmentResult["relatedIndicators"]> = [];
  const seen = new Set<string>();

  for (const attr of attributes) {
    if (!attr.Event?.Attribute) continue;
    for (const otherAttr of attr.Event.Attribute) {
      if (related.length >= 10) break;
      if (otherAttr.value === queryValue) continue;
      const key = `${otherAttr.type}:${otherAttr.value}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const indicatorType = mispTypeToIndicatorType(otherAttr.type);
      if (indicatorType) {
        related.push({
          type: indicatorType as "ip" | "domain" | "url" | "hash" | "email",
          value: otherAttr.value,
        });
      }
    }
    if (related.length >= 10) break;
  }

  return related.length > 0 ? related : undefined;
}

function normalizeVerdict(
  eventCount: number,
  attributeCount: number,
): ThreatVerdict {
  if (eventCount > 3) {
    return {
      classification: "malicious",
      confidence: Math.min(eventCount / 5, 0.9),
      summary: `Found in ${eventCount} MISP events across ${attributeCount} attributes`,
    };
  }

  if (eventCount >= 1) {
    return {
      classification: "suspicious",
      confidence: Math.min(eventCount / 5, 0.9),
      summary: `Found in ${eventCount} MISP events across ${attributeCount} attributes`,
    };
  }

  return {
    classification: "unknown",
    confidence: 0,
    summary: "No matching attributes",
  };
}

function errorResult(summaryText: string): EnrichmentResult {
  return {
    sourceId: "misp",
    sourceName: "MISP",
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

export function createMispSource(
  apiKey: string,
  baseUrl: string,
): ThreatIntelSource {
  const normalizedBaseUrl = normalizeBaseUrl(baseUrl);

  return {
    id: "misp",
    name: "MISP",
    supportedIndicatorTypes: ["ip", "domain", "url", "hash", "email"],
    rateLimit: { maxPerMinute: RATE_LIMIT_MAX_PER_MINUTE },

    async enrich(indicator: Indicator): Promise<EnrichmentResult> {
      const url = `${normalizedBaseUrl}/attributes/restSearch`;

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 30_000);
      try {
        const response = await fetch(url, {
          method: "POST",
          headers: {
            Authorization: apiKey,
            "Content-Type": "application/json",
            Accept: "application/json",
          },
          body: JSON.stringify({
            value: indicator.value,
            returnFormat: "json",
          }),
          signal: controller.signal,
        });

        if (!response.ok) {
          if (response.status === 403) {
            return errorResult("MISP API key forbidden or invalid");
          }
          if (response.status === 429) {
            return errorResult("MISP rate limit exceeded");
          }
          return errorResult(`MISP API error: HTTP ${response.status}`);
        }

        const data = (await response.json()) as MispSearchResponse;

        if (!data || typeof data !== "object" || !("response" in data)) {
          return errorResult("Unexpected API response format");
        }

        const attributes = data?.response?.Attribute ?? [];

        if (attributes.length === 0) {
          return {
            sourceId: "misp",
            sourceName: "MISP",
            verdict: normalizeVerdict(0, 0),
            rawData: {
              matchedAttributes: 0,
              eventCount: 0,
              categories: [],
              threatLevel: null,
            },
            fetchedAt: Date.now(),
            cacheTtlMs: CACHE_TTL_MS,
          };
        }

        const eventCount = countDistinctEvents(attributes);
        const verdict = normalizeVerdict(eventCount, attributes.length);
        const mitreTechniques = extractMitreTechniques(attributes);
        const relatedIndicators = extractRelatedIndicators(
          attributes,
          indicator.value,
        );
        const categories = collectCategories(attributes);
        const threatLevel = highestThreatLevel(attributes);

        return {
          sourceId: "misp",
          sourceName: "MISP",
          verdict,
          rawData: {
            matchedAttributes: attributes.length,
            eventCount,
            categories,
            threatLevel,
          },
          mitreTechniques,
          relatedIndicators,
          fetchedAt: Date.now(),
          cacheTtlMs: CACHE_TTL_MS,
        };
      } catch (err: unknown) {
        if (err instanceof DOMException && err.name === "AbortError") {
          return errorResult("MISP request timeout");
        }
        if (err instanceof TypeError && /fetch/i.test(err.message)) {
          return errorResult("Network error contacting MISP");
        }
        return errorResult(
          `MISP error: ${sanitizeErrorMessage(err)}`,
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
          `${normalizedBaseUrl}/servers/getVersion`,
          {
            method: "GET",
            headers: {
              Authorization: apiKey,
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
          message: `MISP health check failed: HTTP ${response.status}`,
        };
      } catch (err: unknown) {
        return {
          healthy: false,
          message: `MISP health check error: ${sanitizeErrorMessage(err)}`,
        };
      } finally {
        clearTimeout(timeout);
      }
    },
  };
}
