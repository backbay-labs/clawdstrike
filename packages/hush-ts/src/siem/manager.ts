import type { ExportResult, Exporter } from "./framework";
import type { SecurityEvent } from "./types";
import type { EventFilter } from "./filter";

import { EventBus, type Unsubscribe } from "./event-bus";
import { eventMatchesFilter } from "./filter";

export interface ManagedExporter {
  exporter: Exporter;
  enabled: boolean;
  filter?: EventFilter;
}

export class ExporterManager {
  private readonly exporters: ManagedExporter[] = [];
  private unsubscribe: Unsubscribe | null = null;

  constructor(private readonly bus: EventBus<SecurityEvent>) {}

  register(exporter: Exporter, options: { enabled?: boolean; filter?: EventFilter } = {}): void {
    this.exporters.push({
      exporter,
      enabled: options.enabled ?? true,
      filter: options.filter,
    });
  }

  start(): void {
    if (this.unsubscribe) {
      return;
    }

    this.unsubscribe = this.bus.subscribe(event => {
      for (const entry of this.exporters) {
        if (!entry.enabled) {
          continue;
        }
        if (entry.filter && !eventMatchesFilter(event, entry.filter)) {
          continue;
        }

        const maybeEnqueue = (entry.exporter as Partial<{ enqueue: (e: SecurityEvent) => Promise<void> }>).enqueue;
        if (maybeEnqueue) {
          void maybeEnqueue.call(entry.exporter, event);
        } else {
          void entry.exporter.export([event]);
        }
      }
    });
  }

  stop(): void {
    if (this.unsubscribe) {
      this.unsubscribe();
      this.unsubscribe = null;
    }
  }

  async flushAll(): Promise<Record<string, ExportResult>> {
    const out: Record<string, ExportResult> = {};
    for (const entry of this.exporters) {
      if (!entry.enabled) {
        continue;
      }
      const maybeFlush = (entry.exporter as Partial<{ flush: () => Promise<ExportResult> }>).flush;
      if (!maybeFlush) {
        continue;
      }
      out[entry.exporter.name] = await maybeFlush.call(entry.exporter);
    }
    return out;
  }

  async shutdown(): Promise<void> {
    this.stop();
    for (const entry of this.exporters) {
      if (!entry.enabled) {
        continue;
      }
      await entry.exporter.shutdown();
    }
  }
}

