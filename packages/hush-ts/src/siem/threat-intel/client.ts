import { EventEmitter } from "node:events";

import type { SecurityEvent } from "../types";
import { IndicatorCache } from "./cache";
import { StixPatternParser } from "./stix";
import { TaxiiClient } from "./taxii";
import type { ParsedIndicator, StixIndicator, StixObject, ThreatIntelConfig } from "./types";

export interface ThreatIntelEvents {
  updated: (count: number) => void;
  error: (err: Error) => void;
}

export class ThreatIntelClient extends EventEmitter {
  private readonly config: {
    enabled: boolean;
    servers: ThreatIntelConfig["servers"];
    feed: {
      intervalMinutes: number;
      pageSize: number;
      includeTypes: string[];
      minConfidence: number;
      addedAfter?: string;
      cacheTtlHours: number;
    };
    cache: {
      persistent: boolean;
      path?: string;
      maxSize: number;
    };
    actions: {
      blockEgress: boolean;
      blockPaths: boolean;
      enrichEvents: boolean;
    };
  };
  private readonly parser = new StixPatternParser();
  readonly cache: IndicatorCache;

  private timer: ReturnType<typeof setInterval> | null = null;
  private readonly cursors = new Map<string, string>();

  constructor(config: ThreatIntelConfig) {
    super();

    this.config = {
      enabled: config.enabled,
      servers: config.servers,
      feed: {
        intervalMinutes: config.feed?.intervalMinutes ?? 15,
        pageSize: config.feed?.pageSize ?? 100,
        includeTypes: config.feed?.includeTypes ?? ["indicator"],
        minConfidence: config.feed?.minConfidence ?? 0,
        addedAfter: config.feed?.addedAfter,
        cacheTtlHours: config.feed?.cacheTtlHours ?? 24,
      },
      cache: {
        persistent: config.cache?.persistent ?? false,
        path: config.cache?.path,
        maxSize: config.cache?.maxSize ?? 100_000,
      },
      actions: {
        blockEgress: config.actions?.blockEgress ?? true,
        blockPaths: config.actions?.blockPaths ?? false,
        enrichEvents: config.actions?.enrichEvents ?? false,
      },
    };

    this.cache = new IndicatorCache({
      ttlHours: this.config.feed.cacheTtlHours,
      maxSize: this.config.cache.maxSize,
      persistent: this.config.cache.persistent,
      path: this.config.cache.path,
    });
  }

  async start(): Promise<void> {
    if (!this.config.enabled) {
      return;
    }
    if (!this.config.servers.length) {
      throw new Error("Threat intel enabled but no TAXII servers configured");
    }

    if (this.config.cache.persistent) {
      try {
        await this.cache.load();
      } catch (err) {
        this.emit("error", err instanceof Error ? err : new Error(String(err)));
      }
    }

    if (this.config.feed.addedAfter) {
      for (const s of this.config.servers) {
        this.cursors.set(s.collectionId, this.config.feed.addedAfter);
      }
    }

    await this.pollOnce();

    const intervalMs = this.config.feed.intervalMinutes * 60_000;
    this.timer = setInterval(() => {
      void this.pollOnce();
    }, intervalMs);
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  isDomainBlocked(host: string): boolean {
    return this.cache.isDomainBlocked(host);
  }

  isIpBlocked(ip: string): boolean {
    return this.cache.isIpBlocked(ip);
  }

  enrichEvent(event: SecurityEvent): SecurityEvent {
    if (!this.config.actions.enrichEvents) {
      return event;
    }

    // Best-effort enrichment: annotate threat.indicator when the resource is known-bad.
    const cloned = JSON.parse(JSON.stringify(event)) as SecurityEvent;
    if (event.resource.type === "network") {
      const host = event.resource.host ?? event.resource.name;
      if (host && this.isDomainBlocked(host)) {
        cloned.threat = { ...(cloned.threat ?? {}), indicator: { type: "domain", value: host } };
      }
    }
    if (event.resource.type === "file" && event.resource.path) {
      const name = event.resource.path.split("/").pop() ?? event.resource.path;
      if (this.cache.isFileNameBlocked(name)) {
        cloned.threat = { ...(cloned.threat ?? {}), indicator: { type: "file_path", value: event.resource.path } };
      }
    }
    return cloned;
  }

  private async pollOnce(): Promise<void> {
    const nowIso = new Date().toISOString();
    let totalAdded = 0;

    for (const server of this.config.servers) {
      const client = new TaxiiClient(server);
      const cursor = this.cursors.get(server.collectionId);

      try {
        const indicators: ParsedIndicator[] = [];

        for await (const objects of client.getAllObjects({
          addedAfter: cursor,
          type: this.config.feed.includeTypes,
          pageSize: this.config.feed.pageSize,
        })) {
          indicators.push(...this.extractIndicators(objects, server.url));
        }

        const filtered = indicators.filter(i => i.confidence >= this.config.feed.minConfidence);
        if (filtered.length) {
          this.cache.add(filtered);
          totalAdded += filtered.length;
        }

        this.cursors.set(server.collectionId, nowIso);
      } catch (err) {
        this.emit("error", err instanceof Error ? err : new Error(String(err)));
      }
    }

    if (totalAdded) {
      this.emit("updated", totalAdded);
    }

    if (this.config.cache.persistent) {
      try {
        await this.cache.save();
      } catch (err) {
        this.emit("error", err instanceof Error ? err : new Error(String(err)));
      }
    }
  }

  private extractIndicators(objects: StixObject[], source: string): ParsedIndicator[] {
    const out: ParsedIndicator[] = [];
    for (const obj of objects) {
      if (obj.type !== "indicator") {
        continue;
      }
      const ind = obj as unknown as StixIndicator;
      out.push(...this.parser.extractIndicators(ind, source));
    }
    return out;
  }
}

export interface ThreatIntelClient {
  on<T extends keyof ThreatIntelEvents>(event: T, listener: ThreatIntelEvents[T]): this;
  emit<T extends keyof ThreatIntelEvents>(event: T, ...args: Parameters<ThreatIntelEvents[T]>): boolean;
}
