import type { ParsedIndicator, StixIndicator } from "./types";

export class StixPatternParser {
  parse(pattern: string): { type: ParsedIndicator["type"]; value: string } | null {
    const match = pattern.match(/\[(\w+-?\w+):(\w+(?:\.\w+)*)\s*=\s*'([^']+)'\]/);
    if (!match) {
      return null;
    }

    const [, objectType, property, rawValue] = match;
    return this.mapToIndicatorType(objectType, property, rawValue);
  }

  private mapToIndicatorType(
    objectType: string,
    property: string,
    value: string
  ): { type: ParsedIndicator["type"]; value: string } | null {
    switch (objectType) {
      case "domain-name":
        return property === "value" ? { type: "domain", value } : null;
      case "ipv4-addr":
        return property === "value" ? { type: "ipv4", value } : null;
      case "ipv6-addr":
        return property === "value" ? { type: "ipv6", value } : null;
      case "url":
        if (property !== "value") {
          return null;
        }
        return { type: "url", value };
      case "file":
        if (property.startsWith("hashes.")) {
          return { type: "file_hash", value };
        }
        if (property === "name") {
          return { type: "file_name", value };
        }
        return null;
      default:
        return null;
    }
  }

  extractIndicators(indicator: StixIndicator, source: string): ParsedIndicator[] {
    const parsed = this.parse(indicator.pattern);
    if (!parsed) {
      return [];
    }

    const normalized = normalizeParsedIndicator(parsed);
    return [
      {
        id: indicator.id,
        type: normalized.type,
        value: normalized.value,
        confidence: indicator.confidence ?? 50,
        validFrom: new Date(indicator.valid_from),
        validUntil: indicator.valid_until ? new Date(indicator.valid_until) : undefined,
        source,
        context: {
          name: indicator.name,
          description: indicator.description,
          labels: indicator.labels,
          externalRefs: indicator.external_references,
        },
      },
    ];
  }
}

function normalizeParsedIndicator(input: { type: ParsedIndicator["type"]; value: string }): {
  type: ParsedIndicator["type"];
  value: string;
} {
  if (input.type === "url") {
    const host = extractHostFromUrl(input.value);
    if (host) {
      return { type: "domain", value: host };
    }
  }
  if (input.type === "domain") {
    return { type: "domain", value: input.value.trim().replace(/\.$/, "").toLowerCase() };
  }
  if (input.type === "ipv4" || input.type === "ipv6") {
    return { type: input.type, value: input.value.trim() };
  }
  if (input.type === "file_name") {
    return { type: "file_name", value: input.value.trim() };
  }
  if (input.type === "file_hash") {
    return { type: "file_hash", value: input.value.trim().toLowerCase() };
  }
  return input;
}

function extractHostFromUrl(url: string): string | null {
  try {
    const u = new URL(url);
    return u.hostname.trim().replace(/\.$/, "").toLowerCase();
  } catch {
    // Minimal fallback: strip scheme and path.
    const afterScheme = url.split("://").slice(1).join("://") || url;
    const hostPort = afterScheme.split("/")[0] ?? "";
    const host = hostPort.split("@").pop() ?? "";
    const hostname = host.split(":")[0] ?? "";
    const out = hostname.trim().replace(/\.$/, "").toLowerCase();
    return out ? out : null;
  }
}

