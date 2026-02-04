import os from "node:os";
import { gzipSync } from "node:zlib";

import type { ExportResult, ExporterConfig } from "../framework";
import { BaseExporter, SchemaFormat } from "../framework";
import { readResponseBody } from "../http";
import type { SecurityEvent } from "../types";

export type SumoFormat = "json" | "text" | "key_value";

export interface SumoLogicConfig extends Partial<ExporterConfig> {
  httpSourceUrl: string;
  sourceCategory?: string;
  sourceName?: string;
  sourceHost?: string;
  format?: SumoFormat;
  timestampField?: string;
  compression?: boolean;
  fields?: {
    includeAll?: boolean;
    include?: string[];
    exclude?: string[];
  };
}

export class SumoLogicExporter extends BaseExporter {
  readonly name = "sumo-logic";
  readonly schema = SchemaFormat.Native;

  private readonly cfg: {
    httpSourceUrl: string;
    sourceCategory: string;
    sourceName: string;
    sourceHost: string;
    format: SumoFormat;
    timestampField: string;
    compression: boolean;
    fields: {
      includeAll: boolean;
      include: string[];
      exclude: string[];
    };
  };

  constructor(config: SumoLogicConfig) {
    super(config);
    this.cfg = {
      httpSourceUrl: config.httpSourceUrl.trim(),
      sourceCategory: config.sourceCategory ?? "security/clawdstrike",
      sourceName: config.sourceName ?? "clawdstrike",
      sourceHost: config.sourceHost ?? os.hostname(),
      format: config.format ?? "json",
      timestampField: config.timestampField ?? "timestamp",
      compression: config.compression ?? true,
      fields: {
        includeAll: config.fields?.includeAll ?? true,
        include: config.fields?.include ?? [],
        exclude: config.fields?.exclude ?? [],
      },
    };
  }

  async export(events: SecurityEvent[]): Promise<ExportResult> {
    if (events.length === 0) {
      return { exported: 0, failed: 0, errors: [] };
    }

    const bodyText = events.map(e => this.formatEvent(e)).join("\n");
    const headers: Record<string, string> = {
      "X-Sumo-Category": this.cfg.sourceCategory,
      "X-Sumo-Name": this.cfg.sourceName,
      "X-Sumo-Host": this.cfg.sourceHost,
    };

    const contentType = this.cfg.format === "json" ? "application/json" : "text/plain";
    headers["Content-Type"] = contentType;

    const payload = this.cfg.compression ? gzipSync(bodyText) : bodyText;
    if (this.cfg.compression) {
      headers["Content-Encoding"] = "gzip";
    }

    const response = await fetch(this.cfg.httpSourceUrl, {
      method: "POST",
      headers,
      body: payload as any,
    });

    if (!response.ok && response.status !== 202) {
      const text = await readResponseBody(response);
      throw new Error(`Sumo HTTP ${response.status}: ${text}`);
    }

    return { exported: events.length, failed: 0, errors: [] };
  }

  private formatEvent(event: SecurityEvent): string {
    switch (this.cfg.format) {
      case "json":
        return JSON.stringify(this.filterFields(event));
      case "text": {
        const action = event.decision.allowed ? "ALLOWED" : "BLOCKED";
        return (
          `${event.timestamp} [${event.decision.severity.toUpperCase()}] ` +
          `${event.decision.guard}: ${action} - ${event.decision.reason} ` +
          `| event_id=${event.event_id} session_id=${event.session.id}`
        );
      }
      case "key_value": {
        const allowed = event.decision.allowed ? "true" : "false";
        return (
          `event_id=${event.event_id} event_type=${event.event_type} guard=${event.decision.guard} ` +
          `severity=${event.decision.severity} allowed=${allowed} session_id=${event.session.id} ` +
          `resource=${escapeKv(event.resource.name)} reason=${escapeKv(event.decision.reason)}`
        );
      }
      default: {
        const exhaustive: never = this.cfg.format;
        return exhaustive;
      }
    }
  }

  private filterFields(event: SecurityEvent): Record<string, unknown> {
    if (this.cfg.fields.includeAll) {
      const data = JSON.parse(JSON.stringify(event)) as any;
      for (const field of this.cfg.fields.exclude) {
        deletePath(data, field);
      }
      return data as Record<string, unknown>;
    }

    const out: Record<string, unknown> = {};
    for (const field of this.cfg.fields.include) {
      const value = getPath(event as any, field);
      if (value !== undefined) {
        setPath(out as any, field, value);
      }
    }

    for (const field of this.cfg.fields.exclude) {
      deletePath(out as any, field);
    }

    return out;
  }

  async healthCheck(): Promise<void> {
    const response = await fetch(this.cfg.httpSourceUrl, {
      method: "POST",
      headers: {
        "X-Sumo-Category": this.cfg.sourceCategory,
        "X-Sumo-Name": this.cfg.sourceName,
        "X-Sumo-Host": this.cfg.sourceHost,
      },
      body: "",
    });
    if (!response.ok && response.status !== 202) {
      const text = await readResponseBody(response);
      throw new Error(`Sumo health check failed: HTTP ${response.status}: ${text}`);
    }
  }
}

function escapeKv(value: string): string {
  return value.replace(/"/g, "'").replace(/\s+/g, " ");
}

function getPath(obj: Record<string, any>, path: string): unknown {
  const parts = path.split(".").filter(Boolean);
  let cur: any = obj;
  for (const part of parts) {
    if (cur == null || typeof cur !== "object") {
      return undefined;
    }
    cur = cur[part];
  }
  return cur;
}

function setPath(obj: Record<string, any>, path: string, value: unknown): void {
  const parts = path.split(".").filter(Boolean);
  let cur: any = obj;
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i];
    if (i === parts.length - 1) {
      cur[part] = value;
      return;
    }
    if (!cur[part] || typeof cur[part] !== "object") {
      cur[part] = {};
    }
    cur = cur[part];
  }
}

function deletePath(obj: Record<string, any>, path: string): void {
  const parts = path.split(".").filter(Boolean);
  let cur: any = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (!cur || typeof cur !== "object") {
      return;
    }
    cur = cur[part];
  }
  const last = parts[parts.length - 1];
  if (cur && typeof cur === "object" && last) {
    delete cur[last];
  }
}
