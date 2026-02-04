import type { ExportError, ExportResult, ExporterConfig } from "../framework";
import { BaseExporter, SchemaFormat } from "../framework";
import { HttpClient } from "../http";
import type { SecurityEvent, SecuritySeverity } from "../types";

export type AlertAction = "trigger" | "acknowledge" | "resolve";

export type AlertSeverity = "critical" | "error" | "warning" | "info";

export interface PagerDutyConfig {
  routingKey: string;
  apiEndpoint?: string;
  severityMapping?: {
    critical?: AlertSeverity;
    high?: AlertSeverity;
    medium?: AlertSeverity;
    low?: AlertSeverity;
    info?: AlertSeverity;
  };
  routing?: {
    byGuard?: Record<string, string>;
    byTenant?: Record<string, string>;
  };
  deduplication?: {
    keyTemplate?: string;
    windowSeconds?: number;
  };
  customDetails?: boolean;
  autoResolve?: {
    enabled?: boolean;
    afterMinutes?: number;
  };
}

export interface OpsGenieConfig {
  apiKey: string;
  apiEndpoint?: string;
  responders?: Array<{
    type: "team" | "user" | "escalation" | "schedule";
    id?: string;
    name?: string;
  }>;
  priorityMapping?: {
    critical?: "P1" | "P2" | "P3" | "P4" | "P5";
    high?: "P1" | "P2" | "P3" | "P4" | "P5";
    medium?: "P1" | "P2" | "P3" | "P4" | "P5";
    low?: "P1" | "P2" | "P3" | "P4" | "P5";
    info?: "P1" | "P2" | "P3" | "P4" | "P5";
  };
  tags?: string[];
  routing?: {
    byGuard?: Record<string, string[]>;
    bySeverity?: Record<string, string[]>;
  };
  heartbeat?: {
    enabled?: boolean;
    name?: string;
    intervalMinutes?: number;
  };
}

export interface AlertingConfig extends Partial<ExporterConfig> {
  pagerduty?: PagerDutyConfig;
  opsgenie?: OpsGenieConfig;
  minSeverity?: SecuritySeverity;
  includeGuards?: string[];
  excludeGuards?: string[];
}

interface PagerDutyEvent {
  routing_key: string;
  event_action: AlertAction;
  dedup_key?: string;
  payload: {
    summary: string;
    source: string;
    severity: AlertSeverity;
    timestamp?: string;
    component?: string;
    group?: string;
    class?: string;
    custom_details?: Record<string, unknown>;
  };
}

class PagerDutyClient {
  private readonly config: {
    routingKey: string;
    apiEndpoint: string;
    severityMapping: Record<SecuritySeverity, AlertSeverity>;
    routing: {
      byGuard: Record<string, string>;
      byTenant: Record<string, string>;
    };
    deduplication: {
      keyTemplate?: string;
      windowSeconds: number;
    };
    customDetails: boolean;
    autoResolve: {
      enabled: boolean;
      afterMinutes: number;
    };
  };
  private readonly client: HttpClient;
  private readonly openAlerts: Map<string, { lastViolationAt: Date }> = new Map();
  private autoResolveTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: PagerDutyConfig) {
    this.config = {
      routingKey: config.routingKey,
      apiEndpoint: config.apiEndpoint ?? "https://events.pagerduty.com",
      severityMapping: normalizePagerDutySeverityMapping(config.severityMapping),
      routing: {
        byGuard: config.routing?.byGuard ?? {},
        byTenant: config.routing?.byTenant ?? {},
      },
      deduplication: {
        keyTemplate: config.deduplication?.keyTemplate,
        windowSeconds: config.deduplication?.windowSeconds ?? 300,
      },
      customDetails: config.customDetails ?? true,
      autoResolve: {
        enabled: config.autoResolve?.enabled ?? false,
        afterMinutes: config.autoResolve?.afterMinutes ?? 30,
      },
    };

    this.client = new HttpClient({ baseUrl: this.config.apiEndpoint });

    if (this.config.autoResolve.enabled) {
      this.autoResolveTimer = setInterval(() => {
        void this.checkAutoResolve();
      }, 60_000);
    }
  }

  async trigger(event: SecurityEvent): Promise<void> {
    const dedupKey = renderDedupeKey(this.config.deduplication.keyTemplate, event);
    const payload: PagerDutyEvent = {
      routing_key: this.config.routingKey,
      event_action: "trigger",
      dedup_key: dedupKey,
      payload: {
        summary: `Clawdstrike security violation: ${event.decision.guard}`,
        source: "clawdstrike",
        severity: mapPagerDutySeverity(event.decision.severity, this.config.severityMapping),
        timestamp: event.timestamp,
        component: event.resource.name,
        group: event.session.id,
        class: event.event_type,
        custom_details: this.config.customDetails ? (event as any) : undefined,
      },
    };

    const response = await this.client.post("/v2/enqueue", payload);
    if (!response.ok) {
      throw new Error(`PagerDuty HTTP ${response.status}`);
    }

    this.openAlerts.set(dedupKey, { lastViolationAt: new Date() });
  }

  async resolve(dedupKey: string): Promise<void> {
    const payload: PagerDutyEvent = {
      routing_key: this.config.routingKey,
      event_action: "resolve",
      dedup_key: dedupKey,
      payload: {
        summary: "Clawdstrike security violation resolved",
        source: "clawdstrike",
        severity: "info",
      },
    };

    const response = await this.client.post("/v2/enqueue", payload);
    if (!response.ok) {
      throw new Error(`PagerDuty resolve HTTP ${response.status}`);
    }
  }

  private async checkAutoResolve(): Promise<void> {
    if (!this.config.autoResolve.enabled) {
      return;
    }

    const thresholdMs = this.config.autoResolve.afterMinutes * 60_000;
    const now = Date.now();
    for (const [dedupKey, info] of this.openAlerts.entries()) {
      if (now - info.lastViolationAt.getTime() < thresholdMs) {
        continue;
      }
      await this.resolve(dedupKey);
      this.openAlerts.delete(dedupKey);
    }
  }

  shutdown(): void {
    if (this.autoResolveTimer) {
      clearInterval(this.autoResolveTimer);
      this.autoResolveTimer = null;
    }
  }
}

interface OpsGenieAlert {
  message: string;
  alias?: string;
  description?: string;
  responders?: Array<{ type: string; id?: string; name?: string }>;
  tags?: string[];
  details?: Record<string, string>;
  source?: string;
  priority?: string;
}

class OpsGenieClient {
  private readonly config: {
    apiKey: string;
    apiEndpoint: string;
    responders: Array<{ type: string; id?: string; name?: string }>;
    priorityMapping: Record<SecuritySeverity, string>;
    tags: string[];
    routing: {
      byGuard: Record<string, string[]>;
      bySeverity: Record<string, string[]>;
    };
    heartbeat: {
      enabled: boolean;
      name: string;
      intervalMinutes: number;
    };
  };
  private readonly client: HttpClient;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: OpsGenieConfig) {
    this.config = {
      apiKey: config.apiKey,
      apiEndpoint: config.apiEndpoint ?? "https://api.opsgenie.com",
      responders: config.responders ?? [],
      priorityMapping: normalizeOpsGeniePriorityMapping(config.priorityMapping),
      tags: config.tags ?? [],
      routing: {
        byGuard: config.routing?.byGuard ?? {},
        bySeverity: config.routing?.bySeverity ?? {},
      },
      heartbeat: {
        enabled: config.heartbeat?.enabled ?? false,
        name: config.heartbeat?.name ?? "clawdstrike",
        intervalMinutes: config.heartbeat?.intervalMinutes ?? 5,
      },
    };

    this.client = new HttpClient({
      baseUrl: this.config.apiEndpoint,
      headers: { Authorization: `GenieKey ${this.config.apiKey}` },
    });

    if (this.config.heartbeat.enabled) {
      this.startHeartbeat();
    }
  }

  async createAlert(event: SecurityEvent): Promise<void> {
    const alias = renderDedupeKey(undefined, event);
    const priority = mapOpsGeniePriority(event.decision.severity, this.config.priorityMapping);

    const tags = [...this.config.tags, `guard:${event.decision.guard}`, `severity:${event.decision.severity}`];
    const body: OpsGenieAlert = {
      message: `Clawdstrike violation: ${event.decision.guard}`,
      alias,
      description: event.decision.reason,
      responders: this.config.responders,
      tags,
      details: {
        event_id: event.event_id,
        session_id: event.session.id,
        event_type: event.event_type,
        resource: event.resource.name,
      },
      source: "clawdstrike",
      priority,
    };

    const response = await this.client.post("/v2/alerts", body);
    if (response.status !== 202 && !response.ok) {
      throw new Error(`OpsGenie HTTP ${response.status}`);
    }
  }

  async closeAlert(alias: string): Promise<void> {
    const response = await this.client.post(`/v2/alerts/${encodeURIComponent(alias)}/close`, {
      identifierType: "alias",
      source: "clawdstrike",
    });
    if (!response.ok) {
      throw new Error(`OpsGenie close HTTP ${response.status}`);
    }
  }

  private startHeartbeat(): void {
    const intervalMs = this.config.heartbeat.intervalMinutes * 60_000;
    this.heartbeatTimer = setInterval(() => {
      void this.pingHeartbeat();
    }, intervalMs);
    void this.pingHeartbeat();
  }

  private async pingHeartbeat(): Promise<void> {
    const name = encodeURIComponent(this.config.heartbeat.name);
    await this.client.post(`/v2/heartbeats/${name}/ping`, {});
  }

  stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }
}

export class AlertingExporter extends BaseExporter {
  readonly name = "alerting";
  readonly schema = SchemaFormat.Native;

  private readonly cfg: {
    pagerduty?: PagerDutyConfig;
    opsgenie?: OpsGenieConfig;
    minSeverity: SecuritySeverity;
    includeGuards: string[];
    excludeGuards: string[];
  };
  private readonly pagerduty?: PagerDutyClient;
  private readonly opsgenie?: OpsGenieClient;

  private readonly severityOrder: SecuritySeverity[] = ["info", "low", "medium", "high", "critical"];

  constructor(config: AlertingConfig) {
    super(config);
    this.cfg = {
      pagerduty: config.pagerduty,
      opsgenie: config.opsgenie,
      minSeverity: config.minSeverity ?? "high",
      includeGuards: config.includeGuards ?? [],
      excludeGuards: config.excludeGuards ?? [],
    };

    if (this.cfg.pagerduty) {
      this.pagerduty = new PagerDutyClient(this.cfg.pagerduty);
    }
    if (this.cfg.opsgenie) {
      this.opsgenie = new OpsGenieClient(this.cfg.opsgenie);
    }
  }

  private shouldAlert(event: SecurityEvent): boolean {
    if (event.decision.allowed) {
      return false;
    }

    const minIndex = this.severityOrder.indexOf(this.cfg.minSeverity);
    const eventIndex = this.severityOrder.indexOf(event.decision.severity);
    if (eventIndex < minIndex) {
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

  async export(events: SecurityEvent[]): Promise<ExportResult> {
    const alertEvents = events.filter(e => this.shouldAlert(e));
    if (alertEvents.length === 0) {
      return { exported: 0, failed: 0, errors: [] };
    }

    const errors: ExportError[] = [];
    let exported = 0;

    for (const event of alertEvents) {
      try {
        await this.sendAlerts(event);
        exported += 1;
      } catch (error) {
        errors.push({
          eventId: event.event_id,
          error: error instanceof Error ? error.message : String(error),
          retryable: true,
        });
      }
    }

    return { exported, failed: errors.length, errors };
  }

  private async sendAlerts(event: SecurityEvent): Promise<void> {
    const jobs: Promise<void>[] = [];
    if (this.pagerduty) {
      jobs.push(this.pagerduty.trigger(event));
    }
    if (this.opsgenie) {
      jobs.push(this.opsgenie.createAlert(event));
    }
    await Promise.all(jobs);
  }

  async healthCheck(): Promise<void> {
    // PagerDuty Events API doesn't have a stable health endpoint; OpsGenie heartbeat is best-effort.
    if (!this.pagerduty && !this.opsgenie) {
      throw new Error("No alerting targets configured");
    }
  }

  async shutdown(): Promise<void> {
    this.pagerduty?.shutdown();
    this.opsgenie?.stopHeartbeat();
  }
}

function mapPagerDutySeverity(
  sev: SecuritySeverity,
  mapping: Record<SecuritySeverity, AlertSeverity>
): AlertSeverity {
  switch (sev) {
    case "critical":
      return mapping.critical;
    case "high":
      return mapping.high;
    case "medium":
      return mapping.medium;
    case "low":
      return mapping.low;
    case "info":
      return mapping.info;
    default: {
      const exhaustive: never = sev;
      return exhaustive;
    }
  }
}

function mapOpsGeniePriority(
  sev: SecuritySeverity,
  mapping: Record<SecuritySeverity, string>
): string {
  switch (sev) {
    case "critical":
      return mapping.critical;
    case "high":
      return mapping.high;
    case "medium":
      return mapping.medium;
    case "low":
      return mapping.low;
    case "info":
      return mapping.info;
    default: {
      const exhaustive: never = sev;
      return exhaustive;
    }
  }
}

function normalizePagerDutySeverityMapping(
  input: PagerDutyConfig["severityMapping"]
): Record<SecuritySeverity, AlertSeverity> {
  return {
    critical: input?.critical ?? "critical",
    high: input?.high ?? "error",
    medium: input?.medium ?? "warning",
    low: input?.low ?? "info",
    info: input?.info ?? "info",
  };
}

function normalizeOpsGeniePriorityMapping(
  input: OpsGenieConfig["priorityMapping"]
): Record<SecuritySeverity, string> {
  return {
    critical: input?.critical ?? "P1",
    high: input?.high ?? "P2",
    medium: input?.medium ?? "P3",
    low: input?.low ?? "P4",
    info: input?.info ?? "P5",
  };
}

function renderDedupeKey(template: string | undefined, event: SecurityEvent): string {
  const fallback = `${event.decision.guard}:${event.session.id}:${event.resource.name}`;
  if (!template) {
    return fallback;
  }
  return template
    .replaceAll("{guard}", event.decision.guard)
    .replaceAll("{session_id}", event.session.id)
    .replaceAll("{resource}", event.resource.name)
    .replaceAll("{tenant}", event.session.tenant_id ?? "")
    .replaceAll("{event_type}", event.event_type);
}
