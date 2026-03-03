import * as fs from "node:fs/promises";
import { IocError } from "../errors.js";
import type { IocEntry, IocMatch, IocType, TimelineEvent } from "../types.js";

// ---------------------------------------------------------------------------
// Auto-detection
// ---------------------------------------------------------------------------

/**
 * Auto-detect the IOC type from the indicator string format.
 */
export function detectIocType(indicator: string): IocType | undefined {
  const trimmed = indicator.trim();
  if (trimmed.length === 0) return undefined;

  const lower = trimmed.toLowerCase();

  // Hex-only hashes
  if (lower.length === 64 && /^[0-9a-f]+$/.test(lower)) return "sha256";
  if (lower.length === 40 && /^[0-9a-f]+$/.test(lower)) return "sha1";
  if (lower.length === 32 && /^[0-9a-f]+$/.test(lower)) return "md5";

  // URL
  if (lower.startsWith("http://") || lower.startsWith("https://")) return "url";

  // IPv4
  if (isIpv4(trimmed)) return "ipv4";

  // IPv6: contains colons and hex digits
  if (trimmed.includes(":") && /^[0-9a-fA-F:]+$/.test(trimmed)) return "ipv6";

  // Domain: contains dot, no spaces, no slashes, no colons
  if (
    trimmed.includes(".") &&
    !trimmed.includes(" ") &&
    !trimmed.includes("/") &&
    !trimmed.includes(":")
  ) {
    return "domain";
  }

  return undefined;
}

function isIpv4(s: string): boolean {
  const parts = s.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (p.length === 0) return false;
    const n = Number(p);
    return Number.isInteger(n) && n >= 0 && n <= 255 && String(n) === p;
  });
}

// ---------------------------------------------------------------------------
// Word-boundary matching
// ---------------------------------------------------------------------------

function isIocWordChar(ch: number): boolean {
  // alphanumeric, dot, hyphen
  return (
    (ch >= 0x30 && ch <= 0x39) || // 0-9
    (ch >= 0x41 && ch <= 0x5a) || // A-Z
    (ch >= 0x61 && ch <= 0x7a) || // a-z
    ch === 0x2e || // .
    ch === 0x2d    // -
  );
}

/**
 * Check whether `needle` appears in `haystack` at word boundaries.
 * Word chars = alphanumeric + '.' + '-'.
 */
export function containsWordBounded(haystack: string, needle: string): boolean {
  if (needle.length === 0) return false;

  let start = 0;
  while (true) {
    const pos = haystack.indexOf(needle, start);
    if (pos === -1) return false;

    const endPos = pos + needle.length;
    const leftOk = pos === 0 || !isIocWordChar(haystack.charCodeAt(pos - 1));
    const rightOk = endPos >= haystack.length || !isIocWordChar(haystack.charCodeAt(endPos));

    if (leftOk && rightOk) return true;
    start = pos + 1;
  }
}

// ---------------------------------------------------------------------------
// CSV parsing
// ---------------------------------------------------------------------------

function splitCsvFields(line: string): string[] {
  const fields: string[] = [];
  let current = "";
  let inQuotes = false;
  let i = 0;

  while (i < line.length) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (i + 1 < line.length && line[i + 1] === '"') {
          current += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
      } else {
        current += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      fields.push(current.trim());
      current = "";
    } else {
      current += ch;
    }
    i++;
  }
  fields.push(current.trim());
  return fields;
}

function parseIocTypeStr(s: string): IocType | undefined {
  switch (s.trim().toLowerCase()) {
    case "sha256":
    case "sha-256":
      return "sha256";
    case "sha1":
    case "sha-1":
      return "sha1";
    case "md5":
      return "md5";
    case "domain":
    case "domain-name":
      return "domain";
    case "ipv4":
    case "ipv4-addr":
    case "ip":
      return "ipv4";
    case "ipv6":
    case "ipv6-addr":
      return "ipv6";
    case "url":
      return "url";
    default:
      return undefined;
  }
}

function parseCsvLine(line: string): IocEntry | undefined {
  const fields = splitCsvFields(line);
  if (fields.length === 0) return undefined;

  const indicator = fields[0].trim();
  if (indicator.length === 0) return undefined;

  let iocType: IocType | undefined;
  if (fields.length > 1 && fields[1].length > 0) {
    iocType = parseIocTypeStr(fields[1]) ?? detectIocType(indicator);
  } else {
    iocType = detectIocType(indicator);
  }

  if (iocType === undefined) return undefined;

  return {
    indicator,
    iocType,
    description: fields[2] && fields[2].length > 0 ? fields[2] : undefined,
    source: fields[3] && fields[3].length > 0 ? fields[3] : undefined,
  };
}

// ---------------------------------------------------------------------------
// STIX pattern parsing
// ---------------------------------------------------------------------------

function stixLhsToIocType(lhs: string): IocType | undefined {
  const lower = lhs.toLowerCase();
  if (lower.includes("sha-256") || lower.includes("sha256")) return "sha256";
  if (lower.includes("sha-1") || lower.includes("sha1")) return "sha1";
  if (lower.includes("md5")) return "md5";
  if (lower.startsWith("domain-name")) return "domain";
  if (lower.startsWith("ipv4-addr")) return "ipv4";
  if (lower.startsWith("ipv6-addr")) return "ipv6";
  if (lower.startsWith("url")) return "url";
  return undefined;
}

function parseStixPattern(pattern: string): { indicator: string; iocType: IocType } | undefined {
  const trimmed = pattern.trim();
  if (!trimmed.startsWith("[") || !trimmed.endsWith("]")) return undefined;

  const inner = trimmed.slice(1, -1);
  const eqIdx = inner.indexOf("=");
  if (eqIdx === -1) return undefined;

  const lhs = inner.slice(0, eqIdx).trim();
  const rhs = inner.slice(eqIdx + 1).trim();

  // Extract value from single quotes
  if (!rhs.startsWith("'") || !rhs.endsWith("'")) return undefined;
  const value = rhs.slice(1, -1);
  if (value.length === 0) return undefined;

  const iocType = stixLhsToIocType(lhs);
  if (iocType === undefined) return undefined;

  return { indicator: value, iocType };
}

// ---------------------------------------------------------------------------
// IocDatabase
// ---------------------------------------------------------------------------

/**
 * In-memory IOC database with index structures for fast lookup.
 */
export class IocDatabase {
  private entries: IocEntry[] = [];
  private hashIndex: Map<string, number[]> = new Map();
  private domainIndex: Map<string, number[]> = new Map();
  private ipIndex: Map<string, number[]> = new Map();
  private urlIndex: Map<string, number[]> = new Map();

  constructor() {}

  addEntry(entry: IocEntry): void {
    const indicator = entry.indicator.trim();
    if (indicator.length === 0) return;

    const normalizedEntry: IocEntry = { ...entry, indicator };
    const idx = this.entries.length;
    const key = indicator.toLowerCase();

    switch (normalizedEntry.iocType) {
      case "sha256":
      case "sha1":
      case "md5": {
        const arr = this.hashIndex.get(key) ?? [];
        arr.push(idx);
        this.hashIndex.set(key, arr);
        break;
      }
      case "domain": {
        const arr = this.domainIndex.get(key) ?? [];
        arr.push(idx);
        this.domainIndex.set(key, arr);
        break;
      }
      case "ipv4":
      case "ipv6": {
        const arr = this.ipIndex.get(key) ?? [];
        arr.push(idx);
        this.ipIndex.set(key, arr);
        break;
      }
      case "url": {
        const arr = this.urlIndex.get(key) ?? [];
        arr.push(idx);
        this.urlIndex.set(key, arr);
        break;
      }
    }

    this.entries.push(normalizedEntry);
  }

  get size(): number {
    return this.entries.length;
  }

  get isEmpty(): boolean {
    return this.entries.length === 0;
  }

  merge(other: IocDatabase): void {
    for (const entry of other.entries) {
      this.addEntry(entry);
    }
  }

  // -- Loaders -------------------------------------------------------------

  /**
   * Load IOCs from a plain-text file (one indicator per line).
   * Empty lines and lines starting with '#' are skipped.
   */
  static async loadTextFile(path: string): Promise<IocDatabase> {
    const content = await fs.readFile(path, "utf-8");
    const db = new IocDatabase();
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (trimmed.length === 0 || trimmed.startsWith("#")) continue;
      const iocType = detectIocType(trimmed);
      if (iocType !== undefined) {
        db.addEntry({ indicator: trimmed, iocType });
      }
    }
    return db;
  }

  /**
   * Load IOCs from a CSV file.
   * Expected columns: indicator, type, description, source.
   */
  static async loadCsvFile(path: string): Promise<IocDatabase> {
    const content = await fs.readFile(path, "utf-8");
    const db = new IocDatabase();
    const lines = content.split("\n");

    let startIdx = 0;
    if (lines.length > 0) {
      const firstLower = lines[0].trim().toLowerCase();
      const isHeader =
        firstLower.startsWith("indicator,") ||
        firstLower.startsWith("indicator_type,") ||
        firstLower === "indicator";
      if (isHeader) {
        startIdx = 1;
      }
    }

    for (let i = startIdx; i < lines.length; i++) {
      if (lines[i].trim().length === 0) continue;
      const entry = parseCsvLine(lines[i]);
      if (entry) db.addEntry(entry);
    }

    return db;
  }

  /**
   * Load IOCs from a STIX 2.1 JSON bundle.
   */
  static async loadStixBundle(path: string): Promise<IocDatabase> {
    const content = await fs.readFile(path, "utf-8");
    let bundle: Record<string, unknown>;
    try {
      bundle = JSON.parse(content) as Record<string, unknown>;
    } catch (e) {
      throw new IocError(`STIX JSON parse error: ${e instanceof Error ? e.message : String(e)}`);
    }

    const db = new IocDatabase();
    const objects = bundle.objects;
    if (!Array.isArray(objects)) {
      throw new IocError("STIX bundle missing 'objects' array");
    }

    for (const obj of objects) {
      if (typeof obj !== "object" || obj === null) continue;
      const sdo = obj as Record<string, unknown>;
      if (sdo.type !== "indicator") continue;

      const pattern = sdo.pattern;
      if (typeof pattern !== "string") continue;

      const parsed = parseStixPattern(pattern);
      if (!parsed) continue;

      const description = typeof sdo.description === "string" ? sdo.description : undefined;
      const source = typeof sdo.name === "string" ? sdo.name : undefined;

      db.addEntry({
        indicator: parsed.indicator,
        iocType: parsed.iocType,
        description,
        source,
      });
    }

    return db;
  }

  // -- Matching ------------------------------------------------------------

  /**
   * Check a single timeline event against the IOC database.
   */
  matchEvent(event: TimelineEvent): IocMatch | undefined {
    const summary = event.summary.toLowerCase();
    const process = (event.process ?? "").toLowerCase();
    let raw = "";
    if (event.raw !== undefined) {
      try {
        raw = JSON.stringify(event.raw).toLowerCase();
      } catch {
        // Skip raw field if it cannot be serialized (e.g. circular refs).
      }
    }

    const allMatched: IocEntry[] = [];
    let matchField: string | undefined;

    // Helper to scan an index
    const scanIndex = (
      index: Map<string, number[]>,
      matcher: (haystack: string, needle: string) => boolean
    ): void => {
      for (const [needle, indices] of index) {
        const field = matcher(summary, needle)
          ? "summary"
          : matcher(process, needle)
            ? "process"
            : matcher(raw, needle)
              ? "raw"
              : undefined;
        if (field !== undefined) {
          if (matchField === undefined) matchField = field;
          for (const i of indices) {
            allMatched.push(this.entries[i]);
          }
        }
      }
    };

    // Hashes: plain substring match
    scanIndex(this.hashIndex, (haystack, needle) => haystack.includes(needle));

    // Domains: word-boundary match
    scanIndex(this.domainIndex, containsWordBounded);

    // IPs: word-boundary match
    scanIndex(this.ipIndex, containsWordBounded);

    // URLs: word-boundary match
    scanIndex(this.urlIndex, containsWordBounded);

    if (allMatched.length === 0) return undefined;

    return {
      event,
      matchedIocs: allMatched,
      matchField: matchField!,
    };
  }

  /**
   * Batch-match timeline events against the IOC database.
   */
  matchEvents(events: TimelineEvent[]): IocMatch[] {
    const matches: IocMatch[] = [];
    for (const event of events) {
      const m = this.matchEvent(event);
      if (m) matches.push(m);
    }
    return matches;
  }
}
