import type { ExportError, ExportResult, ExporterConfig } from "../framework";
import { BaseExporter, SchemaFormat } from "../framework";
import { readResponseBody } from "../http";
import type { SecurityEvent, SecuritySeverity } from "../types";

export interface SlackConfig {
  webhookUrl: string;
}

export interface TeamsFormattingConfig {
  useAdaptiveCards?: boolean;
  themeColor?: string;
}

export interface TeamsConfig {
  webhookUrl: string;
  formatting?: TeamsFormattingConfig;
}

export type WebhookAuth =
  | { type: "bearer"; token: string }
  | { type: "basic"; username: string; password?: string }
  | { type: "header"; headerName: string; headerValue: string };

export interface GenericWebhookConfig {
  url: string;
  method?: "POST" | "PUT";
  headers?: Record<string, string>;
  auth?: WebhookAuth;
  bodyTemplate?: string;
  contentType?: string;
}

export interface WebhookExporterConfig extends Partial<ExporterConfig> {
  slack?: SlackConfig;
  teams?: TeamsConfig;
  webhooks?: GenericWebhookConfig[];
  minSeverity?: SecuritySeverity;
  includeGuards?: string[];
  excludeGuards?: string[];
}

export class WebhookExporter extends BaseExporter {
  readonly name = "webhooks";
  readonly schema = SchemaFormat.Native;

  private readonly cfg: {
    slack?: SlackConfig;
    teams?: TeamsConfig;
    webhooks: GenericWebhookConfig[];
    minSeverity?: SecuritySeverity;
    includeGuards: string[];
    excludeGuards: string[];
  };

  constructor(config: WebhookExporterConfig) {
    super(config);
    this.cfg = {
      slack: config.slack,
      teams: config.teams,
      webhooks: config.webhooks ?? [],
      minSeverity: config.minSeverity,
      includeGuards: config.includeGuards ?? [],
      excludeGuards: config.excludeGuards ?? [],
    };
  }

  async export(events: SecurityEvent[]): Promise<ExportResult> {
    if (events.length === 0) {
      return { exported: 0, failed: 0, errors: [] };
    }

    let exported = 0;
    const errors: ExportError[] = [];

    for (const event of events) {
      if (!this.shouldNotify(event)) {
        exported += 1;
        continue;
      }

      try {
        await this.sendAll(event);
        exported += 1;
      } catch (err) {
        errors.push({
          eventId: event.event_id,
          error: err instanceof Error ? err.message : String(err),
          retryable: true,
        });
      }
    }

    return { exported, failed: errors.length, errors };
  }

  private shouldNotify(event: SecurityEvent): boolean {
    if (this.cfg.minSeverity && severityOrd(event.decision.severity) < severityOrd(this.cfg.minSeverity)) {
      return false;
    }

    if (this.cfg.includeGuards.length && !this.cfg.includeGuards.includes(event.decision.guard)) {
      return false;
    }
    if (this.cfg.excludeGuards.includes(event.decision.guard)) {
      return false;
    }

    return true;
  }

  private async sendAll(event: SecurityEvent): Promise<void> {
    const jobs: Promise<void>[] = [];
    if (this.cfg.slack) {
      jobs.push(this.postSlack(this.cfg.slack, event));
    }
    if (this.cfg.teams) {
      jobs.push(this.postTeams(this.cfg.teams, event));
    }
    for (const hook of this.cfg.webhooks) {
      jobs.push(this.postGeneric(hook, event));
    }
    await Promise.all(jobs);
  }

  private async postSlack(cfg: SlackConfig, event: SecurityEvent): Promise<void> {
    const title = event.decision.allowed ? "Clawdstrike security event (allowed)" : "Clawdstrike security event (blocked)";
    const payload = {
      text: `${title}: ${event.decision.guard} (${event.decision.severity})`,
      blocks: [
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text:
              `*${title}*\n` +
              `*Guard:* \`${event.decision.guard}\`\n` +
              `*Severity:* \`${event.decision.severity}\`\n` +
              `*Reason:* ${event.decision.reason}`,
          },
        },
        {
          type: "context",
          elements: [{ type: "mrkdwn", text: `Session: \`${event.session.id}\`  Event: \`${event.event_id}\`` }],
        },
      ],
    };

    const response = await fetch(cfg.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok && response.status !== 202) {
      const text = await readResponseBody(response);
      throw new Error(`Slack webhook HTTP ${response.status}: ${text}`);
    }
  }

  private async postTeams(cfg: TeamsConfig, event: SecurityEvent): Promise<void> {
    const formatting = cfg.formatting ?? {};
    const useAdaptiveCards = formatting.useAdaptiveCards ?? true;
    const themeColor = formatting.themeColor ?? "D32F2F";

    const title = event.decision.allowed ? "Clawdstrike security event (allowed)" : "Clawdstrike security event (blocked)";

    const payload = useAdaptiveCards ? this.teamsAdaptiveCard(title, themeColor, event) : this.teamsMessageCard(title, themeColor, event);

    const response = await fetch(cfg.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok && response.status !== 202) {
      const text = await readResponseBody(response);
      throw new Error(`Teams webhook HTTP ${response.status}: ${text}`);
    }
  }

  private teamsMessageCard(title: string, themeColor: string, event: SecurityEvent): Record<string, unknown> {
    return {
      "@type": "MessageCard",
      "@context": "http://schema.org/extensions",
      summary: title,
      themeColor,
      title,
      sections: [
        {
          facts: [
            { name: "Guard", value: event.decision.guard },
            { name: "Severity", value: event.decision.severity },
            { name: "Session", value: event.session.id },
            { name: "Event ID", value: event.event_id },
          ],
          text: event.decision.reason,
        },
      ],
    };
  }

  private teamsAdaptiveCard(title: string, themeColor: string, event: SecurityEvent): Record<string, unknown> {
    return {
      type: "message",
      attachments: [
        {
          contentType: "application/vnd.microsoft.card.adaptive",
          content: {
            $schema: "http://adaptivecards.io/schemas/adaptive-card.json",
            type: "AdaptiveCard",
            version: "1.5",
            body: [
              { type: "TextBlock", text: title, weight: "Bolder", size: "Large", color: "Attention" },
              {
                type: "FactSet",
                facts: [
                  { title: "Guard", value: event.decision.guard },
                  { title: "Severity", value: event.decision.severity },
                  { title: "Session", value: event.session.id },
                  { title: "Event", value: event.event_id },
                ],
              },
              { type: "TextBlock", text: event.decision.reason, wrap: true, color: "Default" },
            ],
            backgroundImage: undefined,
            msteams: { width: "Full" },
            style: themeColor,
          },
        },
      ],
    };
  }

  private async postGeneric(cfg: GenericWebhookConfig, event: SecurityEvent): Promise<void> {
    const method = cfg.method ?? "POST";
    const headers: Record<string, string> = {
      ...(cfg.headers ?? {}),
      "Content-Type": cfg.contentType ?? "application/json",
    };

    if (cfg.auth) {
      if (cfg.auth.type === "bearer") {
        headers.Authorization = `Bearer ${cfg.auth.token}`;
      } else if (cfg.auth.type === "basic") {
        const token = Buffer.from(`${cfg.auth.username}:${cfg.auth.password ?? ""}`).toString("base64");
        headers.Authorization = `Basic ${token}`;
      } else if (cfg.auth.type === "header") {
        headers[cfg.auth.headerName] = cfg.auth.headerValue;
      } else {
        const exhaustive: never = cfg.auth;
        void exhaustive;
      }
    }

    const body = this.renderGenericBody(cfg.bodyTemplate, event, headers["Content-Type"]);

    const response = await fetch(cfg.url, {
      method,
      headers,
      body: body as any,
    });

    if (!response.ok && response.status !== 202) {
      const text = await readResponseBody(response);
      throw new Error(`Webhook HTTP ${response.status}: ${text}`);
    }
  }

  private renderGenericBody(
    template: string | undefined,
    event: SecurityEvent,
    contentType: string
  ): string | Uint8Array {
    if (!template) {
      return JSON.stringify(event);
    }

    const rendered = renderTemplate(template, event as any);
    if (contentType.includes("application/json")) {
      try {
        const parsed = JSON.parse(rendered);
        return JSON.stringify(parsed);
      } catch {
        return JSON.stringify({ message: rendered, event });
      }
    }
    return rendered;
  }

  async healthCheck(): Promise<void> {
    if (!this.cfg.slack && !this.cfg.teams && this.cfg.webhooks.length === 0) {
      throw new Error("No webhooks configured");
    }
  }
}

function severityOrd(sev: SecuritySeverity): number {
  switch (sev) {
    case "info":
      return 0;
    case "low":
      return 1;
    case "medium":
      return 2;
    case "high":
      return 3;
    case "critical":
      return 4;
    default: {
      const exhaustive: never = sev;
      return exhaustive;
    }
  }
}

function renderTemplate(template: string, data: Record<string, any>): string {
  return template.replace(/\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}/g, (_match, path: string) => {
    const value = getByPath(data, path);
    if (value === undefined) {
      return "";
    }
    if (typeof value === "string") {
      return value;
    }
    if (typeof value === "number" || typeof value === "boolean") {
      return String(value);
    }
    return JSON.stringify(value);
  });
}

function getByPath(obj: Record<string, any>, path: string): unknown {
  const parts = path.split(".").filter(Boolean);
  let cur: any = obj;
  for (const p of parts) {
    if (cur == null || typeof cur !== "object") {
      return undefined;
    }
    cur = cur[p];
  }
  return cur;
}
