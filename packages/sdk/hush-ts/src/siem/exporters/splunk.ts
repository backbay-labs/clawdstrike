import { randomUUID } from "node:crypto";
import os from "node:os";
import { gzipSync } from "node:zlib";

import type { ExportResult, ExporterConfig } from "../framework";
import { BaseExporter, SchemaFormat } from "../framework";
import { HttpClient, readResponseBody } from "../http";
import type { SecurityEvent } from "../types";

export interface SplunkTlsConfig {
  insecureSkipVerify?: boolean;
  caCertPath?: string;
  clientCertPath?: string;
  clientKeyPath?: string;
}

export interface SplunkConnectionConfig {
  timeoutMs?: number;
  keepAliveMs?: number;
  maxConnections?: number;
}

export interface SplunkConfig extends Partial<ExporterConfig> {
  hecUrl: string;
  hecToken: string;
  index?: string;
  sourceType?: string;
  source?: string;
  host?: string;
  useAck?: boolean;
  ackChannel?: string;
  ackTimeoutMs?: number;
  ackPollIntervalMs?: number;
  compression?: boolean;
  tls?: SplunkTlsConfig;
  connection?: SplunkConnectionConfig;
}

interface SplunkEvent {
  time: number;
  index?: string;
  sourcetype: string;
  source: string;
  host: string;
  event: Record<string, unknown>;
  fields?: Record<string, string>;
}

interface HecResponse {
  text: string;
  code: number;
  ackId?: number;
}

export class SplunkExporter extends BaseExporter {
  readonly name = "splunk";
  readonly schema = SchemaFormat.Native;

  private readonly cfg: {
    hecUrl: string;
    hecToken: string;
    index: string;
    sourceType: string;
    source: string;
    host: string;
    useAck: boolean;
    ackChannel: string;
    ackTimeoutMs: number;
    ackPollIntervalMs: number;
    compression: boolean;
    tls: SplunkTlsConfig;
    connection: Required<SplunkConnectionConfig>;
  };
  private readonly client: HttpClient;
  private readonly channel: string;

  constructor(config: SplunkConfig) {
    super(config);
    this.cfg = this.mergeDefaults(config);
    this.client = this.createClient();
    this.channel = this.cfg.ackChannel || randomUUID();
  }

  private mergeDefaults(config: SplunkConfig): SplunkExporter["cfg"] {
    return {
      hecUrl: config.hecUrl.replace(/\/+$/, ""),
      hecToken: config.hecToken,
      index: config.index ?? "main",
      sourceType: config.sourceType ?? "clawdstrike:security",
      source: config.source ?? "clawdstrike",
      host: config.host ?? os.hostname(),
      useAck: config.useAck ?? true,
      ackChannel: config.ackChannel ?? "",
      ackTimeoutMs: config.ackTimeoutMs ?? 30_000,
      ackPollIntervalMs: config.ackPollIntervalMs ?? 1000,
      compression: config.compression ?? true,
      tls: config.tls ?? {},
      connection: {
        timeoutMs: config.connection?.timeoutMs ?? 30_000,
        keepAliveMs: config.connection?.keepAliveMs ?? 60_000,
        maxConnections: config.connection?.maxConnections ?? 10,
      },
    };
  }

  private createClient(): HttpClient {
    const headers: Record<string, string> = {
      Authorization: `Splunk ${this.cfg.hecToken}`,
    };
    return new HttpClient({ baseUrl: this.cfg.hecUrl, headers });
  }

  private toSplunkEvent(event: SecurityEvent): SplunkEvent {
    const time = new Date(event.timestamp).getTime() / 1000;
    return {
      time,
      index: this.cfg.index,
      sourcetype: this.cfg.sourceType,
      source: this.cfg.source,
      host: this.cfg.host,
      event: {
        event_id: event.event_id,
        event_type: event.event_type,
        event_category: event.event_category,
        outcome: event.outcome,
        action: event.action,
        agent: event.agent,
        session: event.session,
        threat: event.threat,
        decision: event.decision,
        resource: event.resource,
        metadata: event.metadata,
        labels: event.labels,
        schema_version: event.schema_version,
      },
      fields: {
        severity: event.decision.severity,
        guard: event.decision.guard,
        environment: event.session.environment ?? "unknown",
        tenant_id: event.session.tenant_id ?? "default",
      },
    };
  }

  async export(events: SecurityEvent[]): Promise<ExportResult> {
    if (events.length === 0) {
      return { exported: 0, failed: 0, errors: [] };
    }

    const body = events.map(e => JSON.stringify(this.toSplunkEvent(e))).join("\n");

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.cfg.useAck) {
      headers["X-Splunk-Request-Channel"] = this.channel;
    }

    const payload = this.cfg.compression ? gzipSync(body) : body;
    if (this.cfg.compression) {
      headers["Content-Encoding"] = "gzip";
    }

    const response = await this.client.post("/services/collector/event", payload, { headers });
    if (!response.ok) {
      const text = await readResponseBody(response);
      throw new Error(`Splunk HEC HTTP ${response.status}: ${text}`);
    }

    const hec = (await response.json()) as HecResponse;
    if (hec.code !== 0) {
      throw new Error(`Splunk HEC error code ${hec.code}: ${hec.text}`);
    }

    if (this.cfg.useAck && typeof hec.ackId === "number") {
      await this.waitForAck(hec.ackId);
    }

    return { exported: events.length, failed: 0, errors: [] };
  }

  private async waitForAck(ackId: number): Promise<void> {
    const start = Date.now();
    for (;;) {
      if (Date.now() - start > this.cfg.ackTimeoutMs) {
        throw new Error(`Splunk HEC ack timeout after ${this.cfg.ackTimeoutMs}ms (ackId=${ackId})`);
      }

      const response = await this.client.post(
        "/services/collector/ack",
        { acks: [ackId] },
        { headers: { "X-Splunk-Request-Channel": this.channel } }
      );

      if (!response.ok) {
        const text = await readResponseBody(response);
        throw new Error(`Splunk HEC ack HTTP ${response.status}: ${text}`);
      }

      const body = (await response.json()) as { acks?: Record<string, boolean> };
      if (body.acks?.[String(ackId)]) {
        return;
      }

      await this.sleep(this.cfg.ackPollIntervalMs);
    }
  }

  async healthCheck(): Promise<void> {
    const response = await this.client.post("/services/collector/event", "", {
      headers: { "Content-Type": "application/json" },
    });
    if (!response.ok) {
      const text = await readResponseBody(response);
      throw new Error(`Splunk health check failed: HTTP ${response.status}: ${text}`);
    }
  }
}
