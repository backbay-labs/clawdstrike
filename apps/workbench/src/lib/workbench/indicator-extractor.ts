import type { Finding, Signal } from "./sentinel-types";
import type { Indicator, IndicatorType } from "@clawdstrike/plugin-sdk";

const IPV4_RE =
  /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;

const DOMAIN_RE =
  /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;

const SHA256_RE = /\b[a-f0-9]{64}\b/gi;
const SHA1_RE = /\b[a-f0-9]{40}\b/gi;
const MD5_RE = /\b[a-f0-9]{32}\b/gi;

// Common false-positive domains to exclude from domain extraction
const DOMAIN_FALSE_POSITIVES = new Set([
  "example.com",
  "localhost.localdomain",
  "test.local",
]);

function hashAlgorithmFromLength(
  length: number,
): "md5" | "sha1" | "sha256" | null {
  switch (length) {
    case 32:
      return "md5";
    case 40:
      return "sha1";
    case 64:
      return "sha256";
    default:
      return null;
  }
}

function extractIpsFromString(text: string): string[] {
  return Array.from(text.matchAll(IPV4_RE), (m) => m[0]);
}

function extractDomainsFromString(text: string): string[] {
  const matches = Array.from(text.matchAll(DOMAIN_RE), (m) => m[0].toLowerCase());
  // Filter out domains that look like IPs and common false positives
  return matches.filter((d) => {
    if (DOMAIN_FALSE_POSITIVES.has(d)) return false;
    // If it matches the IPv4 pattern fully, it's an IP not a domain
    if (/^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/.test(d)) {
      return false;
    }
    return true;
  });
}

function extractHashesFromString(
  text: string,
): Array<{ value: string; algorithm: "md5" | "sha1" | "sha256" }> {
  const results: Array<{ value: string; algorithm: "md5" | "sha1" | "sha256" }> = [];
  const seen = new Set<string>();

  // Extract in order of longest first so SHA-256 is matched before
  // being misidentified as containing shorter hashes
  for (const match of text.matchAll(SHA256_RE)) {
    const val = match[0].toLowerCase();
    if (!seen.has(val)) {
      seen.add(val);
      results.push({ value: val, algorithm: "sha256" });
    }
  }

  for (const match of text.matchAll(SHA1_RE)) {
    const val = match[0].toLowerCase();
    // Skip if this is a substring of an already-found SHA-256
    if (!seen.has(val) && !isSubstringOfExisting(val, seen)) {
      seen.add(val);
      results.push({ value: val, algorithm: "sha1" });
    }
  }

  for (const match of text.matchAll(MD5_RE)) {
    const val = match[0].toLowerCase();
    if (!seen.has(val) && !isSubstringOfExisting(val, seen)) {
      seen.add(val);
      results.push({ value: val, algorithm: "md5" });
    }
  }

  return results;
}

function isSubstringOfExisting(candidate: string, existing: Set<string>): boolean {
  for (const val of existing) {
    if (val.length > candidate.length && val.includes(candidate)) {
      return true;
    }
  }
  return false;
}

interface IndicatorAccumulator {
  key: string; // "${type}:${value}"
  type: IndicatorType;
  value: string;
  hashAlgorithm?: "md5" | "sha1" | "sha256";
  signalIds: Set<string>;
}

/**
 * Extract indicators (IOCs) from a finding and its contributing signals.
 *
 * Parses IPs from egress guard violations, domains from DNS-related signals,
 * hashes from file access signals, and passes through SignalDataIndicator values.
 * Results are deduplicated by (type, value) tuple.
 *
 * @param finding - The finding to extract indicators from.
 * @param signals - The signals contributing to this finding.
 * @returns Deduplicated array of Indicator objects with context linking.
 */
export function extractIndicators(
  finding: Pick<Finding, "id">,
  signals: Signal[],
): Indicator[] {
  const accumulators = new Map<string, IndicatorAccumulator>();

  for (const signal of signals) {
    const data = signal.data;

    switch (data.kind) {
      case "indicator":
        if (data.indicatorType !== "other") {
          addIndicator(accumulators, signal.id, data.indicatorType as IndicatorType, data.value);
        }
        break;

      case "detection":
        // Extract from guard results
        for (const gr of data.guardResults) {
          extractFromGuardResult(accumulators, signal.id, gr);
        }
        break;

      case "policy_violation":
        // Extract from guard results
        for (const gr of data.guardResults) {
          extractFromGuardResult(accumulators, signal.id, gr);
        }
        extractFromText(accumulators, signal.id, data.target);
        break;

      default:
        break;
    }
  }

  return Array.from(accumulators.values()).map((acc) => {
    const indicator: Indicator = {
      type: acc.type,
      value: acc.value,
      context: {
        findingId: finding.id,
        signalIds: Array.from(acc.signalIds),
      },
    };
    if (acc.hashAlgorithm) {
      indicator.hashAlgorithm = acc.hashAlgorithm;
    }
    return indicator;
  });
}

function addIndicator(
  accumulators: Map<string, IndicatorAccumulator>,
  signalId: string,
  type: IndicatorType,
  value: string,
  hashAlgorithm?: "md5" | "sha1" | "sha256",
): void {
  const key = `${type}:${value}`;
  const existing = accumulators.get(key);
  if (existing) {
    existing.signalIds.add(signalId);
  } else {
    accumulators.set(key, {
      key,
      type,
      value,
      hashAlgorithm,
      signalIds: new Set([signalId]),
    });
  }
}

function extractFromGuardResult(
  accumulators: Map<string, IndicatorAccumulator>,
  signalId: string,
  gr: { guardId: string; message: string; evidence?: Record<string, unknown> },
): void {
  extractFromText(accumulators, signalId, gr.message);

  if (gr.evidence) {
    for (const [key, value] of Object.entries(gr.evidence)) {
      if (typeof value === "string") {
        if (isIpKey(key)) {
          const ips = extractIpsFromString(value);
          for (const ip of ips) {
            addIndicator(accumulators, signalId, "ip", ip);
          }
        }
        if (isDomainKey(key)) {
          const domains = extractDomainsFromString(value);
          for (const domain of domains) {
            addIndicator(accumulators, signalId, "domain", domain);
          }
        }
        if (isHashKey(key)) {
          const hashes = extractHashesFromString(value);
          for (const h of hashes) {
            addIndicator(accumulators, signalId, "hash", h.value, h.algorithm);
          }
        }
        extractFromText(accumulators, signalId, value);
      }
    }
  }
}

function extractFromText(
  accumulators: Map<string, IndicatorAccumulator>,
  signalId: string,
  text: string,
): void {
  const ips = extractIpsFromString(text);
  for (const ip of ips) {
    addIndicator(accumulators, signalId, "ip", ip);
  }

  const hashes = extractHashesFromString(text);
  for (const h of hashes) {
    addIndicator(accumulators, signalId, "hash", h.value, h.algorithm);
  }

  // Note: We avoid extracting domains from general text to reduce false positives.
  // Domain extraction is handled via evidence keys.
}

function isIpKey(key: string): boolean {
  const lower = key.toLowerCase();
  return (
    lower === "ip" ||
    lower === "address" ||
    lower === "source_ip" ||
    lower === "dest_ip" ||
    lower === "remote_ip"
  );
}

function isDomainKey(key: string): boolean {
  const lower = key.toLowerCase();
  return (
    lower === "domain" ||
    lower === "host" ||
    lower === "blocked_domain" ||
    lower === "hostname" ||
    lower === "target_domain"
  );
}

function isHashKey(key: string): boolean {
  const lower = key.toLowerCase();
  return (
    lower === "hash" ||
    lower === "file_hash" ||
    lower === "sha256" ||
    lower === "sha1" ||
    lower === "md5" ||
    lower === "checksum"
  );
}
