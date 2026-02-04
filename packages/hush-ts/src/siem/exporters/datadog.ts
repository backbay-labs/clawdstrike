import type { ExportResult, ExporterConfig } from "../framework";
import { BaseExporter, SchemaFormat } from "../framework";
import { HttpClient, readResponseBody } from "../http";
import type { SecurityEvent } from "../types";

export interface DatadogLogsConfig {
  service?: string;
  source?: string;
  tags?: string[];
  hostname?: string;
}

export interface DatadogMetricsConfig {
  enabled?: boolean;
  prefix?: string;
  tags?: string[];
}

export interface DatadogConfig extends Partial<ExporterConfig> {
  apiKey: string;
  appKey?: string;
  site?: string;
  logs?: DatadogLogsConfig;
  metrics?: DatadogMetricsConfig;
}

export class DatadogExporter extends BaseExporter {
  readonly name = "datadog";
  readonly schema = SchemaFormat.Native;

  private readonly cfg: {
    apiKey: string;
    appKey?: string;
    site: string;
    logs: {
      service: string;
      source: string;
      tags: string[];
      hostname?: string;
    };
    metrics: {
      enabled: boolean;
      prefix: string;
      tags: string[];
    };
  };

  private readonly logsClient: HttpClient;
  private readonly metricsClient: HttpClient;

  constructor(config: DatadogConfig) {
    super(config);

    const site = (config.site ?? "datadoghq.com").replace(/^\.+/, "").trim();
    this.cfg = {
      apiKey: config.apiKey,
      appKey: config.appKey,
      site,
      logs: {
        service: config.logs?.service ?? "clawdstrike",
        source: config.logs?.source ?? "clawdstrike",
        tags: config.logs?.tags ?? [],
        hostname: config.logs?.hostname,
      },
      metrics: {
        enabled: config.metrics?.enabled ?? true,
        prefix: config.metrics?.prefix ?? "clawdstrike",
        tags: config.metrics?.tags ?? [],
      },
    };

    this.logsClient = new HttpClient({
      baseUrl: `https://http-intake.logs.${this.cfg.site}`,
      headers: { "DD-API-KEY": this.cfg.apiKey },
    });
    this.metricsClient = new HttpClient({
      baseUrl: `https://api.${this.cfg.site}`,
      headers: { "DD-API-KEY": this.cfg.apiKey },
    });
  }

  async export(events: SecurityEvent[]): Promise<ExportResult> {
    if (events.length === 0) {
      return { exported: 0, failed: 0, errors: [] };
    }

    await this.sendLogs(events);
    await this.sendMetrics(events);

    return { exported: events.length, failed: 0, errors: [] };
  }

  private hostname(event: SecurityEvent): string {
    return this.cfg.logs.hostname ?? event.agent.name ?? "clawdstrike";
  }

  private async sendLogs(events: SecurityEvent[]): Promise<void> {
    const logs = events.map(e => {
      const tags = [...this.cfg.logs.tags];
      tags.push(`guard:${e.decision.guard}`);
      tags.push(`event_type:${e.event_type}`);
      tags.push(`severity:${e.decision.severity}`);
      tags.push(`outcome:${e.outcome}`);
      if (e.session.environment) {
        tags.push(`env:${e.session.environment}`);
      }
      if (e.session.tenant_id) {
        tags.push(`tenant:${e.session.tenant_id}`);
      }

      return {
        message: e.decision.reason,
        ddsource: this.cfg.logs.source,
        service: this.cfg.logs.service,
        hostname: this.hostname(e),
        status: this.statusFor(e),
        ddtags: tags.join(","),
        event: e,
      };
    });

    const response = await this.logsClient.post("/api/v2/logs", logs);
    if (!response.ok && response.status !== 202) {
      const text = await readResponseBody(response);
      throw new Error(`Datadog logs HTTP ${response.status}: ${text}`);
    }
  }

  private async sendMetrics(events: SecurityEvent[]): Promise<void> {
    if (!this.cfg.metrics.enabled) {
      return;
    }

    const now = Math.floor(Date.now() / 1000);
    const total = events.length;
    const denied = events.filter(e => !e.decision.allowed).length;
    const allowed = total - denied;

    const tags = [...this.cfg.metrics.tags, "source:clawdstrike"];

    const series = [
      {
        metric: `${this.cfg.metrics.prefix}.security.events.total`,
        type: "count",
        points: [[now, total]],
        tags,
      },
      {
        metric: `${this.cfg.metrics.prefix}.security.events.allowed`,
        type: "count",
        points: [[now, allowed]],
        tags,
      },
      {
        metric: `${this.cfg.metrics.prefix}.security.events.denied`,
        type: "count",
        points: [[now, denied]],
        tags,
      },
    ];

    const response = await this.metricsClient.post("/api/v1/series", { series });
    if (!response.ok) {
      const text = await readResponseBody(response);
      throw new Error(`Datadog metrics HTTP ${response.status}: ${text}`);
    }
  }

  private statusFor(event: SecurityEvent): string {
    if (!event.decision.allowed) {
      return event.decision.severity === "critical" ? "critical" : "error";
    }

    switch (event.decision.severity) {
      case "critical":
        return "critical";
      case "high":
        return "error";
      case "medium":
      case "low":
        return "warn";
      case "info":
        return "info";
      default: {
        const exhaustive: never = event.decision.severity;
        return exhaustive;
      }
    }
  }

  async healthCheck(): Promise<void> {
    const response = await this.metricsClient.get("/api/v1/validate");
    if (!response.ok) {
      const text = await readResponseBody(response);
      throw new Error(`Datadog health check failed: HTTP ${response.status}: ${text}`);
    }
  }
}
