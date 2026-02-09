import type { ExportError, ExportResult, ExporterConfig } from "../framework";
import { BaseExporter, SchemaFormat } from "../framework";
import { HttpClient, readResponseBody } from "../http";
import { toEcs } from "../transforms/ecs";
import type { SecurityEvent } from "../types";

export interface ElasticAuthConfig {
  apiKey?: string;
  username?: string;
  password?: string;
}

export interface ElasticTlsConfig {
  insecureSkipVerify?: boolean;
  caCertPath?: string;
  clientCertPath?: string;
  clientKeyPath?: string;
}

export interface ElasticConfig extends Partial<ExporterConfig> {
  baseUrl: string;
  index: string;
  auth?: ElasticAuthConfig;
  tls?: ElasticTlsConfig;
}

export class ElasticExporter extends BaseExporter {
  readonly name = "elastic";
  readonly schema = SchemaFormat.ECS;

  private readonly cfg: {
    baseUrl: string;
    index: string;
    auth: ElasticAuthConfig;
    tls: ElasticTlsConfig;
  };
  private readonly client: HttpClient;

  constructor(config: ElasticConfig) {
    super(config);
    this.cfg = {
      baseUrl: config.baseUrl.replace(/\/+$/, ""),
      index: config.index,
      auth: config.auth ?? {},
      tls: config.tls ?? {},
    };

    const headers: Record<string, string> = {};
    if (this.cfg.auth.apiKey) {
      headers.Authorization = `ApiKey ${this.cfg.auth.apiKey}`;
    }
    this.client = new HttpClient({
      baseUrl: this.cfg.baseUrl,
      headers,
      auth:
        !this.cfg.auth.apiKey && this.cfg.auth.username && this.cfg.auth.password
          ? { username: this.cfg.auth.username, password: this.cfg.auth.password }
          : undefined,
    });
  }

  async export(events: SecurityEvent[]): Promise<ExportResult> {
    if (events.length === 0) {
      return { exported: 0, failed: 0, errors: [] };
    }

    const lines: string[] = [];
    for (const event of events) {
      lines.push(JSON.stringify({ index: { _index: this.cfg.index } }));
      lines.push(JSON.stringify(toEcs(event)));
    }
    const body = lines.join("\n") + "\n";

    const response = await this.client.post("/_bulk", body, {
      headers: { "Content-Type": "application/x-ndjson" },
    });

    if (!response.ok) {
      const text = await readResponseBody(response);
      throw new Error(`Elastic bulk HTTP ${response.status}: ${text}`);
    }

    const payload = (await response.json()) as {
      errors?: boolean;
      items?: Array<Record<string, { status: number; error?: unknown }>>;
    };

    if (!payload.errors) {
      return { exported: events.length, failed: 0, errors: [] };
    }

    const errors: ExportError[] = [];
    const items = payload.items ?? [];
    for (let i = 0; i < items.length; i++) {
      const entry = items[i];
      const op = entry.index ?? entry.create ?? entry.update ?? entry.delete;
      if (!op) {
        continue;
      }
      if (op.status >= 200 && op.status <= 299) {
        continue;
      }
      const eventId = events[i]?.event_id ?? "unknown";
      const retryable = op.status === 429 || (op.status >= 500 && op.status <= 599);
      errors.push({
        eventId,
        error: op.error ? JSON.stringify(op.error) : `bulk item failed with status ${op.status}`,
        retryable,
      });
    }

    return {
      exported: events.length - errors.length,
      failed: errors.length,
      errors,
    };
  }

  async healthCheck(): Promise<void> {
    const response = await this.client.get("/");
    if (!response.ok) {
      const text = await readResponseBody(response);
      throw new Error(`Elastic health check failed: HTTP ${response.status}: ${text}`);
    }
  }
}
