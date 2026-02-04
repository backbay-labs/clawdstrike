import { readFile, writeFile } from "node:fs/promises";

import type { ParsedIndicator } from "./types";

export interface IndicatorCacheOptions {
  ttlHours?: number;
  maxSize?: number;
  persistent?: boolean;
  path?: string;
}

type CacheEntry = {
  expiresAt: number;
  indicator: ParsedIndicator;
};

export class IndicatorCache {
  private readonly ttlMs: number;
  private readonly maxSize: number;
  private readonly persistent: boolean;
  private readonly path?: string;

  private readonly domains = new Map<string, CacheEntry>();
  private readonly ips = new Map<string, CacheEntry>();
  private readonly fileNames = new Map<string, CacheEntry>();
  private readonly fileHashes = new Map<string, CacheEntry>();

  updatedAt: Date | null = null;

  constructor(options: IndicatorCacheOptions = {}) {
    this.ttlMs = (options.ttlHours ?? 24) * 60 * 60 * 1000;
    this.maxSize = options.maxSize ?? 100_000;
    this.persistent = options.persistent ?? false;
    this.path = options.path;
  }

  size(): number {
    return this.domains.size + this.ips.size + this.fileNames.size + this.fileHashes.size;
  }

  add(indicators: ParsedIndicator[]): void {
    const now = Date.now();
    this.prune(now);

    for (const ind of indicators) {
      if (this.size() >= this.maxSize) {
        break;
      }

      const expiresAt = ind.validUntil ? ind.validUntil.getTime() : now + this.ttlMs;
      const entry: CacheEntry = { expiresAt, indicator: ind };

      switch (ind.type) {
        case "domain":
          this.domains.set(ind.value.trim().replace(/\.$/, "").toLowerCase(), entry);
          break;
        case "ipv4":
        case "ipv6":
          this.ips.set(ind.value.trim(), entry);
          break;
        case "file_name":
          this.fileNames.set(ind.value.trim(), entry);
          break;
        case "file_hash":
          this.fileHashes.set(ind.value.trim().toLowerCase(), entry);
          break;
        case "url":
          // URLs are normalized to domains by the parser; ignore if still present.
          break;
        default: {
          const exhaustive: never = ind.type;
          void exhaustive;
        }
      }
    }

    this.updatedAt = new Date();
  }

  isDomainBlocked(host: string): boolean {
    const now = Date.now();
    const normalized = host.trim().replace(/\.$/, "").toLowerCase();
    if (!normalized) {
      return false;
    }

    if (this.isLive(this.domains.get(normalized), now)) {
      return true;
    }

    // Subdomain match: foo.bar.example.com -> bar.example.com -> example.com
    const parts = normalized.split(".");
    for (let i = 1; i < parts.length - 1; i++) {
      const candidate = parts.slice(i).join(".");
      if (this.isLive(this.domains.get(candidate), now)) {
        return true;
      }
    }

    return false;
  }

  isIpBlocked(ip: string): boolean {
    return this.isLive(this.ips.get(ip.trim()), Date.now());
  }

  isFileNameBlocked(name: string): boolean {
    return this.isLive(this.fileNames.get(name.trim()), Date.now());
  }

  isFileHashBlocked(sha256Hex: string): boolean {
    return this.isLive(this.fileHashes.get(sha256Hex.trim().toLowerCase()), Date.now());
  }

  prune(now: number = Date.now()): void {
    pruneMap(this.domains, now);
    pruneMap(this.ips, now);
    pruneMap(this.fileNames, now);
    pruneMap(this.fileHashes, now);
  }

  private isLive(entry: CacheEntry | undefined, now: number): boolean {
    return !!entry && entry.expiresAt > now;
  }

  async load(): Promise<void> {
    if (!this.persistent || !this.path) {
      return;
    }

    const raw = await readFile(this.path, "utf8");
    const parsed: {
      updatedAt?: string;
      domains?: Record<string, CacheEntry>;
      ips?: Record<string, CacheEntry>;
      fileNames?: Record<string, CacheEntry>;
      fileHashes?: Record<string, CacheEntry>;
    } = JSON.parse(raw);

    this.updatedAt = parsed.updatedAt ? new Date(parsed.updatedAt) : null;
    if (parsed.domains) {
      this.domains.clear();
      for (const [k, v] of Object.entries(parsed.domains)) {
        this.domains.set(k, reviveEntry(v));
      }
    }
    if (parsed.ips) {
      this.ips.clear();
      for (const [k, v] of Object.entries(parsed.ips)) {
        this.ips.set(k, reviveEntry(v));
      }
    }
    if (parsed.fileNames) {
      this.fileNames.clear();
      for (const [k, v] of Object.entries(parsed.fileNames)) {
        this.fileNames.set(k, reviveEntry(v));
      }
    }
    if (parsed.fileHashes) {
      this.fileHashes.clear();
      for (const [k, v] of Object.entries(parsed.fileHashes)) {
        this.fileHashes.set(k, reviveEntry(v));
      }
    }
  }

  async save(): Promise<void> {
    if (!this.persistent || !this.path) {
      return;
    }

    const snap = {
      updatedAt: this.updatedAt?.toISOString(),
      domains: Object.fromEntries(this.domains),
      ips: Object.fromEntries(this.ips),
      fileNames: Object.fromEntries(this.fileNames),
      fileHashes: Object.fromEntries(this.fileHashes),
    };

    await writeFile(this.path, JSON.stringify(snap, null, 2), "utf8");
  }
}

function pruneMap(map: Map<string, CacheEntry>, now: number): void {
  for (const [k, v] of map.entries()) {
    if (v.expiresAt <= now) {
      map.delete(k);
    }
  }
}

function reviveEntry(entry: CacheEntry): CacheEntry {
  return {
    expiresAt: entry.expiresAt,
    indicator: {
      ...entry.indicator,
      validFrom: new Date(entry.indicator.validFrom),
      validUntil: entry.indicator.validUntil ? new Date(entry.indicator.validUntil) : undefined,
    },
  };
}

